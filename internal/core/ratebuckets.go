package core

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// Rate-limit buckets shared through the store (§6.6, Addendum D.8).
//
// A bucket's check and its deduction are one atomic step across every
// instance that shares the store (§6.6 Cost). On Postgres the buckets are
// rows of rate_buckets, and a request's draw is one call of rate_draw
// (migration 004_rate_buckets), one statement: it adds the rows of
// buckets never drawn on, full, then locks the rows of every bucket the request draws on in
// key order, so two draws never wait on each other in a cycle (and the
// sweep of full buckets never waits on a draw: maybeSweep), refills
// them to now, and deducts each cost only if every one holds a token.
// Instances sharing a database therefore admit no more between them than
// one instance would.
//
// The statement commits on its own, at the end of step 1, before the
// write it admits can commit: an admitted write's deduction is never lost,
// and a request refused after admission, or whose transaction runs again,
// keeps it (§6.6). It runs on a pool of its own, so a draw never waits for
// a connection that transactions waiting on draws hold, and it takes no
// lock a write transaction holds: bucket rows don't join the advisory and
// log locks whose order pglock.go keeps, and a principal's writes to
// different namespaces don't wait for each other's commits. Hot buckets
// (a namespace's, a busy principal's) serialise their draws on their row
// lock, for one round trip each. The pool's sessions commit without
// waiting for the WAL flush (synchronous_commit off): a write's own commit
// flushes the WAL past its draw, so a crash can lose only the deductions
// of requests that wrote nothing.
//
// SQLite, written by one instance, keeps the buckets in memory
// (rateLimiter), as does an instance on Postgres with LocalRateBuckets.

// bucketStore draws on the buckets of rate_buckets (Postgres).
type bucketStore struct {
	db *sql.DB
	mu sync.Mutex
	// swept is when this instance last swept full buckets; sweeping marks
	// a sweep running, closed that the store is closed.
	swept    time.Time
	sweeping bool
	closed   bool
	wg       sync.WaitGroup
	// retried counts the draws Postgres rolled back for a deadlock that
	// ran again (tests).
	retried atomic.Int64
}

// openBucketStore opens the bucket pool on the Postgres database url.
func openBucketStore(url string) (*bucketStore, error) {
	url, pool, err := parsePGPool(url)
	if err != nil {
		return nil, err
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["synchronous_commit"] = "off"
	db := stdlib.OpenDB(*cfg)
	pool.sizeBuckets(db)
	return &bucketStore{db: db}, nil
}

// bucketConns is the size of the bucket pool: a quarter of the main
// pool's (mainConns, 4 × GOMAXPROCS), a connection per CPU, at least two
// (a sweep holds one). A draw is one short statement, a fraction of the
// round trips of the write that waits for it on the main pool, and draws
// on one bucket queue on its row lock whatever the pool's size: more
// connections would only hold more of the server's max_connections, which
// every instance's two pools share.
func bucketConns() int { return max(2, runtime.GOMAXPROCS(0)) }

// close waits for a running sweep and closes the pool.
func (s *bucketStore) close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
	return s.db.Close()
}

// drawSQL draws on the buckets $1 (keys, sorted, distinct) with rates $2,
// bursts $3 and costs $4 at $5 (Unix microseconds), deducting the costs
// whatever the buckets hold with $6 (a charge): see rate_draw.
const drawSQL = `SELECT k, t, admitted FROM rate_draw($1::bytea[], $2::float8[], $3::float8[], $4::float8[], $5::bigint, $6::boolean)`

// merged is draws with one entry per bucket, in key order (bytes): the
// costs of a bucket drawn on twice add up, as two draws on one bucket in
// memory do. A batch draws on a bucket per item, so it finds a bucket's
// entry through a map, not by a search of the entries so far.
func merged(draws []draw) []draw {
	out := make([]draw, 0, len(draws))
	at := make(map[string]int, len(draws))
	for _, d := range draws {
		if i, ok := at[d.key]; ok {
			out[i].cost += d.cost
			continue
		}
		at[d.key] = len(out)
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b draw) int { return strings.Compare(a.key, b.key) })
	return out
}

// admit is rateLimiter.admit on the store: it checks every bucket holds a
// token, then deducts each cost, in one statement (above). It returns the
// wait until every empty bucket holds a token again, and the limit with
// the longest wait, the first in draws among equal ones.
func (s *bucketStore) admit(ctx context.Context, now time.Time, draws []draw) (time.Duration, string, bool, error) {
	tokens, ok, err := s.draw(ctx, now, draws, false)
	if err != nil || ok {
		return 0, "", ok, err
	}
	var wait time.Duration
	var hit string
	for _, d := range draws {
		if t := tokens[d.key]; t < 1 {
			if w := time.Duration((1 - t) / d.rate.Rate * float64(time.Second)); w > wait {
				wait, hit = w, d.name
			}
		}
	}
	if wait <= 0 {
		// Refused for a bucket that holds a token by a hair: wait the
		// least the clock tells apart.
		wait, hit = time.Microsecond, draws[0].name
	}
	return wait, hit, false, nil
}

// charge is rateLimiter.charge on the store: it deducts d's cost whatever
// the bucket holds (an upload's bytes beyond what it declared, §7.8).
func (s *bucketStore) charge(ctx context.Context, now time.Time, d draw) error {
	_, _, err := s.draw(ctx, now, []draw{d}, true)
	return err
}

// draw runs drawSQL, again if a sweep deleted a row between rate_draw's
// insert and its lock, or if Postgres rolled it back for a deadlock with
// a statement that locks bucket rows out of key order (none of this
// package's does; an operator's might): rate_draw is one statement, so a
// draw rolled back deducted nothing. It returns the buckets' tokens
// before any deduction, by key, and whether it deducted.
//
// After a deadlock it pauses first (drawPause): the statement that
// survived waits for a row the draw held, and a draw run again at once
// could lock that row again before the survivor, woken, takes it, and
// close the same cycle, as often as it runs.
func (s *bucketStore) draw(ctx context.Context, now time.Time, draws []draw, force bool) (map[string]float64, bool, error) {
	ds := merged(draws)
	keys := make([][]byte, len(ds))
	rates := make([]float64, len(ds))
	bursts := make([]float64, len(ds))
	costs := make([]float64, len(ds))
	for i, d := range ds {
		keys[i], rates[i], bursts[i], costs[i] = []byte(d.key), d.rate.Rate, d.rate.Burst, d.cost
	}
	var err error
	for attempt := 1; attempt <= drawAttempts; attempt++ {
		var tokens map[string]float64
		var ok bool
		tokens, ok, err = s.drawOnce(ctx, now, keys, rates, bursts, costs, force)
		switch {
		case deadlocked(err):
			if attempt < drawAttempts {
				if err := drawPause(ctx, attempt); err != nil {
					return nil, false, err
				}
				s.retried.Add(1)
			}
			continue
		case err != nil:
			return nil, false, err
		case len(tokens) == len(ds):
			if ok {
				s.maybeSweep(now)
			}
			return tokens, ok, nil
		}
		// A sweep deletes only full buckets, so not on every attempt.
		err = errBucketsVanish
	}
	return nil, false, err
}

// drawAttempts bounds how often draw runs drawSQL.
const drawAttempts = 3

// deadlockPause is the pause before a draw rolled back for a deadlock
// runs again the first time, doubled the next (drawPause): long enough
// for the woken survivor to be scheduled and lock its row, while such
// deadlocks stay rare.
const deadlockPause = 10 * time.Millisecond

// drawPause waits attempt times deadlockPause, give or take half (so
// draws rolled back together don't run again together), or until ctx is
// done.
func drawPause(ctx context.Context, attempt int) error {
	d := time.Duration(attempt) * deadlockPause
	d += time.Duration(rand.Int64N(int64(d))) - d/2
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drawOnce runs drawSQL once.
func (s *bucketStore) drawOnce(ctx context.Context, now time.Time, keys [][]byte, rates, bursts, costs []float64, force bool) (map[string]float64, bool, error) {
	rows, err := s.db.QueryContext(ctx, drawSQL, keys, rates, bursts, costs, now.UnixMicro(), force)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	tokens := make(map[string]float64, len(keys))
	ok := false
	for rows.Next() {
		var k []byte
		var t float64
		if err := rows.Scan(&k, &t, &ok); err != nil {
			return nil, false, err
		}
		tokens[string(k)] = t
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return tokens, ok, nil
}

// deadlocked reports whether Postgres rolled a statement back as the
// victim of a deadlock.
func deadlocked(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "40P01"
}

type bucketError string

func (e bucketError) Error() string { return string(e) }

const errBucketsVanish = bucketError("rate buckets: rows deleted under every draw")

// sweepEvery is how often an instance deletes the buckets that have
// refilled to their burst, which are the same as no row (rate_draw), as
// rateLimiter.sweep drops them from memory: rows were otherwise kept for
// every resource and principal ever written.
const sweepEvery = time.Minute

// maybeSweep starts a sweep if this instance hasn't swept for sweepEvery.
func (s *bucketStore) maybeSweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sweeping || now.Sub(s.swept) < sweepEvery {
		return
	}
	s.swept, s.sweeping = now, true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// The sweep locks the rows it deletes first, skipping any a draw
		// holds: it never waits for a draw, so it never waits in a cycle
		// with one, as deleting full rows in the table's order could (a
		// draw that saw a row before the sweep deleted it, waiting for
		// it, while holding a row the sweep comes to later). A row a draw
		// changed meanwhile is judged again as it now is (READ
		// COMMITTED), so a bucket drawn on isn't deleted; one a draw
		// holds is drawn on, and the next sweep judges it.
		if _, err := s.db.Exec(`DELETE FROM rate_buckets WHERE key IN (
			SELECT key FROM rate_buckets WHERE tokens + ($1::bigint - last) * rate / 1e6 >= burst FOR UPDATE SKIP LOCKED)`, now.UnixMicro()); err != nil {
			log.Printf("rate buckets: sweep: %v", err)
		}
		s.mu.Lock()
		s.sweeping = false
		s.mu.Unlock()
	}()
}
