package core

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Rate-limit buckets shared through the store (§6.6, Addendum D.8).
//
// A bucket's check and its deduction are one atomic step across every
// instance that shares the store (§6.6 Cost). On Postgres the buckets are
// rows of rate_buckets, and a request's draw is one call of rate_draw
// (pgschema.go), one statement: it adds the rows of buckets never drawn
// on, full, then locks the rows of every bucket the request draws on in
// key order, so two draws never wait on each other in a cycle, refills
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
}

// openBucketStore opens the bucket pool on the Postgres database url.
func openBucketStore(url string) (*bucketStore, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["synchronous_commit"] = "off"
	db := stdlib.OpenDB(*cfg)
	n := 2 * runtime.GOMAXPROCS(0)
	db.SetMaxOpenConns(n)
	db.SetMaxIdleConns(n)
	return &bucketStore{db: db}, nil
}

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

// merged is draws with one entry per bucket, in key order: the costs of a
// bucket drawn on twice add up, as two draws on one bucket in memory do.
func merged(draws []draw) []draw {
	out := make([]draw, 0, len(draws))
	for _, d := range draws {
		if i := slices.IndexFunc(out, func(o draw) bool { return o.key == d.key }); i >= 0 {
			out[i].cost += d.cost
			continue
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b draw) int { return bytes.Compare([]byte(a.key), []byte(b.key)) })
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
// insert and its lock. It returns the buckets' tokens before any
// deduction, by key, and whether it deducted.
func (s *bucketStore) draw(ctx context.Context, now time.Time, draws []draw, force bool) (map[string]float64, bool, error) {
	ds := merged(draws)
	keys := make([][]byte, len(ds))
	rates := make([]float64, len(ds))
	bursts := make([]float64, len(ds))
	costs := make([]float64, len(ds))
	for i, d := range ds {
		keys[i], rates[i], bursts[i], costs[i] = []byte(d.key), d.rate.Rate, d.rate.Burst, d.cost
	}
	for range 3 {
		rows, err := s.db.QueryContext(ctx, drawSQL, keys, rates, bursts, costs, now.UnixMicro(), force)
		if err != nil {
			return nil, false, err
		}
		tokens := make(map[string]float64, len(ds))
		ok := false
		for rows.Next() {
			var k []byte
			var t float64
			if err := rows.Scan(&k, &t, &ok); err != nil {
				rows.Close()
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
		if len(tokens) == len(ds) {
			if ok {
				s.maybeSweep(now)
			}
			return tokens, ok, nil
		}
	}
	// A sweep deletes only full buckets, so not on every attempt.
	return nil, false, errBucketsVanish
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
		// A row a draw locked or changed meanwhile is judged again as it
		// now is (READ COMMITTED), so a bucket drawn on isn't deleted.
		if _, err := s.db.Exec(`DELETE FROM rate_buckets WHERE tokens + ($1::bigint - last) * rate / 1e6 >= burst`, now.UnixMicro()); err != nil {
			log.Printf("rate buckets: sweep: %v", err)
		}
		s.mu.Lock()
		s.sweeping = false
		s.mu.Unlock()
	}()
}
