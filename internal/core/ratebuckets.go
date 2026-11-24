package core

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
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
// a connection that transactions waiting on draws hold. A write checked
// outside the lock (D.3) draws after its check's read transaction, so it
// holds no connection of the main pool while it waits (checkOutside); one
// checked in the lock, on its own (writeLocked), draws in its transaction,
// as config writes, branch writes and prunes do. The draw takes no
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
//
// Concurrent draws batch (draw, drawBatch), as group commit's writes do:
// while a batch draws on a bucket, the draws on it queued meanwhile go in
// the next batch, one statement, rate_draws (migration
// 031_rate_draws_batched), which locks the rows of all their buckets
// once, in key order, and judges the requests in queue order, each as
// rate_draw would have after the ones before it. One draw per write, each
// a round trip and a lock of its buckets' rows, was what bounded writes on
// one database (docs/CAPACITY.md, "Several namespaces on one database").

// bucketStore draws on the buckets of rate_buckets (Postgres).
type bucketStore struct {
	db *sql.DB
	// spanner: the draws run as statements of a transaction, in Go
	// (drawsSpanner), since Spanner has no functions.
	spanner bool
	mu      sync.Mutex
	// swept is when this instance last swept full buckets; sweeping marks
	// a sweep running, closed that the store is closed.
	swept    time.Time
	sweeping bool
	closed   bool
	wg       sync.WaitGroup
	// retried counts the draws Postgres rolled back for a deadlock that
	// ran again (tests).
	retried atomic.Int64
	// stopped counts the checks that stopped at a draw on a bucket known
	// empty and were admitted, so ran again (checkOutside; tests).
	stopped atomic.Int64
	// batches counts the batches of more than one draw (drawsSQL), and
	// batched the draws in them (tests).
	batches, batched atomic.Int64
	// drawing counts the draws taken for a batch and not yet answered
	// (tests).
	drawing atomic.Int64

	// qmu guards the queue of draws (draw): queue holds the draws no
	// batch has taken yet, and queuedOn counts them by bucket key;
	// drawingOn counts by key the batches running that draw on it;
	// running counts the goroutines that run batches (drain), at most
	// slots, the bucket pool's size, and qclosed that the store is
	// closed; drains waits for them.
	qmu       sync.Mutex
	queue     []*drawReq
	queuedOn  map[string]int
	drawingOn map[string]int
	running   int
	slots     int
	qclosed   bool
	drains    sync.WaitGroup
	// empty holds, by key, the buckets this instance's last draw on found
	// empty, until when (Unix microseconds) they stay so if no other
	// instance's draws refill them: knownEmpty.
	empty sync.Map
}

// openBucketStore opens the bucket pool on the Postgres database url.
func openBucketStore(url0 string) (*bucketStore, error) {
	url, pool, err := parsePGPool(url0)
	if err != nil {
		return nil, err
	}
	var db *sql.DB
	spanner := isSpannerURL(url0)
	if spanner {
		if db, err = sqlOpen(url); err != nil {
			return nil, err
		}
	} else {
		cfg, err := pgx.ParseConfig(url)
		if err != nil {
			return nil, err
		}
		cfg.RuntimeParams["synchronous_commit"] = "off"
		db = stdlib.OpenDB(*cfg)
	}
	pool.sizeSide(db)
	return &bucketStore{db: db, slots: min(pool.sideSize(), drawBatches), spanner: spanner}, nil
}

// The bucket pool is a quarter of the main pool's size, at least two
// (pgPool.sideSize), and runs as many batches at once, up to drawBatches,
// on disjoint buckets (draw): a draw is
// one short statement, a fraction of the round trips of the write that
// waits for it, and batches on one bucket queue on its row lock whatever
// the pool's size: more connections would only hold more of the server's
// max_connections, which every instance's pools share.

// close waits for the running batches and sweep, and closes the pool.
func (s *bucketStore) close() error {
	s.qmu.Lock()
	s.qclosed = true
	s.qmu.Unlock()
	s.drains.Wait()
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
	if err != nil {
		return 0, "", ok, err
	}
	if ok {
		for _, d := range draws {
			if _, was := s.empty.Load(d.key); was {
				s.empty.Delete(d.key)
			}
		}
		return 0, "", ok, err
	}
	var wait time.Duration
	var hit string
	for _, d := range draws {
		if t := tokens[d.key]; t < 1 {
			w := time.Duration((1 - t) / d.rate.Rate * float64(time.Second))
			s.empty.Store(d.key, now.Add(w).UnixMicro())
			if w > wait {
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

// knownEmpty reports whether this instance's last draw on a bucket of
// draws found it empty, and it can't have refilled a token by now. Draws
// of other instances only take tokens, so it is then empty unless the
// bucket's rate was raised meanwhile: a write's check stops at its draw
// then, as at a 429, and doesn't go on to its later steps first (admit,
// checkOutside). It is a hint, never an answer: the draw decides.
func (s *bucketStore) knownEmpty(now time.Time, draws []draw) bool {
	for _, d := range draws {
		if until, ok := s.empty.Load(d.key); ok && now.UnixMicro() < until.(int64) {
			return true
		}
	}
	return false
}

// charge is rateLimiter.charge on the store: it deducts d's cost whatever
// the bucket holds (an upload's bytes beyond what it declared, §7.8).
func (s *bucketStore) charge(ctx context.Context, now time.Time, d draw) error {
	_, _, err := s.draw(ctx, now, []draw{d}, true)
	return err
}

// draw queues a request's draw for the next batch (drawBatch) and waits
// for its answer: the buckets' tokens before any deduction, by key, and
// whether it deducted.
//
// Draws batch as group commit's writes do. Up to slots batches run at
// once (drawBatches), each on a connection of the bucket pool, but at most
// drawKeyBatches of them on any one bucket: a draw on a bucket a batch
// draws on queues for the next batch on it, rather than starting a batch
// of its own that would only wait for the first's row lock, and a draw
// on buckets no batch draws on starts one at once if a connection is
// free (a lone draw on an idle instance waits for nothing). Each batch,
// as it ends, takes every draw queued meanwhile that it can (up to
// drawBatchItems buckets), as one statement: a hot bucket's row (a
// namespace's, a busy principal's) is locked once per batch rather than
// once per write, and no draw waits for a connection of the pool, only
// for the batch before it on its buckets (docs/CAPACITY.md, "Several
// namespaces on one database"). A draw whose request is gone before its
// batch starts is dropped.
func (s *bucketStore) draw(ctx context.Context, now time.Time, draws []draw, force bool) (map[string]float64, bool, error) {
	r := &drawReq{ctx: ctx, now: now, ds: merged(draws), force: force, done: make(chan drawRes, 1)}
	s.qmu.Lock()
	if s.qclosed {
		s.qmu.Unlock()
		return nil, false, errBucketsClosed
	}
	// Every draw queued waits for a batch on its buckets (or a connection,
	// which a drain that ends takes the next batch on), so r can start a
	// batch at once only if no draw queued draws on its buckets.
	start := s.running < s.slots && s.free(r)
	s.enqueue(r)
	if start {
		s.running++
		s.drains.Add(1)
	}
	s.qmu.Unlock()
	if start {
		go s.drain()
	}
	select {
	case res := <-r.done:
		return res.tokens, res.ok, res.err
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

// drawReq is a draw queued for a batch (draw).
type drawReq struct {
	ctx   context.Context
	now   time.Time
	ds    []draw // merged
	force bool
	done  chan drawRes
}

// drawRes answers a drawReq.
type drawRes struct {
	tokens map[string]float64
	ok     bool
	err    error
}

// drawBatchItems bounds the buckets a batch draws on, so that one batch
// doesn't hold its rows' locks for long while the next queues; a request
// drawing on more has a batch of its own.
const drawBatchItems = 4096

// drawKeyBatches bounds the batches running at once that draw on one
// bucket (draw). Batches on one bucket serialise on its row's lock
// whatever their number: each one more is a statement more, and a lock
// handed over more, for the same draws. One lets the draws that queue
// while a batch runs all go in the next; the EC2 bench drew two in five
// draws alone with a batch per connection (docs/CAPACITY.md, "Several
// namespaces on one database").
const drawKeyBatches = 1

// drawBatches bounds the batches running at once (slots), on any
// buckets. Every batch is a statement, and a batch more at once is a
// batch less of the draws queued meanwhile: with a batch per connection,
// draws by a principal per namespace, sharing no bucket, ran some 2 to a
// statement where 4 batches at once ran 7 or 8 and drew twice as fast
// (BenchmarkDrawContended); 2 at once ran 15, no faster, and serialise
// disjoint draws behind each other more.
const drawBatches = 4

// enqueue queues r for a batch. s.qmu is held.
func (s *bucketStore) enqueue(r *drawReq) {
	if s.queuedOn == nil {
		s.queuedOn, s.drawingOn = map[string]int{}, map[string]int{}
	}
	s.queue = append(s.queue, r)
	for _, d := range r.ds {
		s.queuedOn[d.key]++
	}
}

// free reports whether r, not queued, could start a batch now: no draw
// queued, and fewer than drawKeyBatches batches running, draw on any of
// its buckets. s.qmu is held.
func (s *bucketStore) free(r *drawReq) bool {
	for _, d := range r.ds {
		if s.queuedOn[d.key] > 0 || s.drawingOn[d.key] >= drawKeyBatches {
			return false
		}
	}
	return true
}

// count adds n to m[k], deleting it at 0.
func count(m map[string]int, k string, n int) {
	if m[k] += n; m[k] == 0 {
		delete(m, k)
	}
}

// drain runs batches of the queued draws until none it can take is
// queued.
func (s *bucketStore) drain() {
	defer s.drains.Done()
	for {
		s.qmu.Lock()
		b, more := s.take()
		if len(b) == 0 {
			s.running--
			s.qmu.Unlock()
			return
		}
		// Draws left at drawBatchItems that no batch draws on go in a
		// batch of their own, if a connection is free; if not, the next
		// drain to end a batch takes them.
		start := more && s.running < s.slots
		if start {
			s.running++
			s.drains.Add(1)
		}
		s.qmu.Unlock()
		if start {
			go s.drain()
		}
		s.drawBatch(b)
		s.qmu.Lock()
		s.drawn(b)
		s.qmu.Unlock()
	}
}

// drawn records that b, a batch take took, has ended. s.qmu is held.
func (s *bucketStore) drawn(b []*drawReq) {
	for _, r := range b {
		for _, d := range r.ds {
			count(s.drawingOn, d.key, -1)
		}
	}
}

// take takes the queued draws for a batch, in queue order: every draw
// none of whose buckets more than drawKeyBatches-1 running batches, or a
// draw queued before it and not taken, draw on, up to drawBatchItems
// buckets, but at least one draw. Draws on one bucket are therefore
// taken in queue order, and judged so (rate_draws). more reports that a
// draw was left at drawBatchItems that could have been taken. A draw
// whose request is gone is answered so, and dropped. s.qmu is held.
func (s *bucketStore) take() (b []*drawReq, more bool) {
	var left map[string]bool // the buckets of draws left queued
	items, n := 0, 0
	for _, r := range s.queue {
		if err := r.ctx.Err(); err != nil {
			r.done <- drawRes{err: err}
			for _, d := range r.ds {
				count(s.queuedOn, d.key, -1)
			}
			continue
		}
		ok := !more
		for _, d := range r.ds {
			if !ok {
				break
			}
			ok = !left[d.key] && s.drawingOn[d.key] < drawKeyBatches
		}
		if ok && len(b) > 0 && items+len(r.ds) > drawBatchItems {
			ok, more = false, true
		}
		if !ok {
			if left == nil {
				left = map[string]bool{}
			}
			for _, d := range r.ds {
				left[d.key] = true
			}
			s.queue[n] = r
			n++
			continue
		}
		b = append(b, r)
		items += len(r.ds)
	}
	clear(s.queue[n:])
	s.queue = s.queue[:n]
	for _, r := range b {
		for _, d := range r.ds {
			count(s.queuedOn, d.key, -1)
			count(s.drawingOn, d.key, 1)
		}
	}
	s.drawing.Add(int64(len(b)))
	return b, more
}

// drawBatch draws b, a batch, and answers each draw: a single draw with
// drawSQL, as before batches, more with drawsSQL. It runs again if a
// sweep deleted a row between the statement's insert and its lock, or if
// Postgres rolled it back for a deadlock with a statement that locks
// bucket rows out of key order (none of this package's does; an
// operator's might): either is one statement, so a batch rolled back
// deducted nothing.
//
// After a deadlock it pauses first (drawPause): the statement that
// survived waits for a row the draw held, and a draw run again at once
// could lock that row again before the survivor, woken, takes it, and
// close the same cycle, as often as it runs.
//
// The batch's statement runs until every request in it is gone, or it
// ends: a request gone meanwhile may have drawn, as one gone during its
// own statement may have.
func (s *bucketStore) drawBatch(b []*drawReq) {
	ctx, stop := batchContext(b)
	defer stop()
	var res []drawRes
	var err error
	for attempt := 1; attempt <= drawAttempts; attempt++ {
		var complete bool
		switch {
		case s.spanner:
			res, complete, err = s.drawsSpanner(ctx, b)
		case len(b) == 1:
			res, complete, err = s.drawOnce(ctx, b[0])
		default:
			res, complete, err = s.drawsOnce(ctx, b)
		}
		if deadlocked(err) || s.spanner && aborted(err) {
			if attempt < drawAttempts {
				if perr := drawPause(ctx, attempt); perr != nil {
					err = perr
					break
				}
				s.retried.Add(1)
			}
			continue
		}
		if err != nil || complete {
			break
		}
		// A sweep deletes only full buckets, so not on every attempt.
		err = errBucketsVanish
	}
	defer s.drawing.Add(-int64(len(b)))
	if err != nil {
		for _, r := range b {
			r.done <- drawRes{err: err}
		}
		return
	}
	if len(b) > 1 {
		s.batches.Add(1)
		s.batched.Add(int64(len(b)))
	}
	// The sweep, if one is due, starts before the draws are answered, as
	// it did before draws batched.
	var swept time.Time
	for i, r := range b {
		if res[i].ok && r.now.After(swept) {
			swept = r.now
		}
	}
	if !swept.IsZero() {
		s.maybeSweep(swept)
	}
	for i, r := range b {
		r.done <- res[i]
	}
}

// batchContext is the context of b's statement: done once every request
// of b is.
func batchContext(b []*drawReq) (context.Context, func()) {
	if len(b) == 1 {
		return b[0].ctx, func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var left atomic.Int64
	left.Store(int64(len(b)))
	stops := make([]func() bool, len(b))
	for i, r := range b {
		stops[i] = context.AfterFunc(r.ctx, func() {
			if left.Add(-1) == 0 {
				cancel()
			}
		})
	}
	return ctx, func() {
		for _, stop := range stops {
			stop()
		}
		cancel()
	}
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

// drawOnce runs drawSQL once for r. complete is false if a bucket's row
// went (rate_draw deducted nothing then).
func (s *bucketStore) drawOnce(ctx context.Context, r *drawReq) ([]drawRes, bool, error) {
	keys := make([][]byte, len(r.ds))
	rates := make([]float64, len(r.ds))
	bursts := make([]float64, len(r.ds))
	costs := make([]float64, len(r.ds))
	for i, d := range r.ds {
		keys[i], rates[i], bursts[i], costs[i] = []byte(d.key), d.rate.Rate, d.rate.Burst, d.cost
	}
	rows, err := s.db.QueryContext(ctx, drawSQL, keys, rates, bursts, costs, r.now.UnixMicro(), r.force)
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
	return []drawRes{{tokens: tokens, ok: ok}}, len(tokens) == len(r.ds), nil
}

// drawsSQL draws a batch of requests (drawsOnce): item i of the keys $2,
// rates $3, bursts $4 and costs $5 is a draw of request $1[i] (1, 2, ...),
// which draws at $6[$1[i]] (Unix microseconds), deducting whatever its
// buckets hold if $7[$1[i]] (a charge): see rate_draws (migration
// 031_rate_draws_batched).
const drawsSQL = `SELECT r, k, t, admitted FROM rate_draws($1::int[], $2::bytea[], $3::float8[], $4::float8[], $5::float8[], $6::bigint[], $7::boolean[])`

// drawsOnce runs drawsSQL once for b, a batch. complete is false if a
// bucket's row went (rate_draws deducted nothing then).
func (s *bucketStore) drawsOnce(ctx context.Context, b []*drawReq) ([]drawRes, bool, error) {
	n := 0
	for _, r := range b {
		n += len(r.ds)
	}
	rq := make([]int32, 0, n)
	keys := make([][]byte, 0, n)
	rates := make([]float64, 0, n)
	bursts := make([]float64, 0, n)
	costs := make([]float64, 0, n)
	nows := make([]int64, len(b))
	forced := make([]bool, len(b))
	res := make([]drawRes, len(b))
	for i, r := range b {
		for _, d := range r.ds {
			rq = append(rq, int32(i+1))
			keys = append(keys, []byte(d.key))
			rates = append(rates, d.rate.Rate)
			bursts = append(bursts, d.rate.Burst)
			costs = append(costs, d.cost)
		}
		nows[i], forced[i] = r.now.UnixMicro(), r.force
		res[i].tokens = make(map[string]float64, len(r.ds))
	}
	rows, err := s.db.QueryContext(ctx, drawsSQL, rq, keys, rates, bursts, costs, nows, forced)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	got := 0
	for rows.Next() {
		var q int
		var k []byte
		var t float64
		var ok bool
		if err := rows.Scan(&q, &k, &t, &ok); err != nil {
			return nil, false, err
		}
		if q < 1 || q > len(b) {
			return nil, false, fmt.Errorf("rate buckets: rate_draws answered request %d of %d", q, len(b))
		}
		res[q-1].tokens[string(k)], res[q-1].ok = t, ok
		got++
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return res, got == n, nil
}

// deadlocked reports whether Postgres rolled a statement back as the
// victim of a deadlock.
func deadlocked(err error) bool { return sqlState(err) == "40P01" }

type bucketError string

func (e bucketError) Error() string { return string(e) }

const errBucketsVanish = bucketError("rate buckets: rows deleted under every draw")

const errBucketsClosed = bucketError("rate buckets: closed")

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
	// Hints past their time (knownEmpty) go with the full buckets.
	s.empty.Range(func(k, until any) bool {
		if now.UnixMicro() >= until.(int64) {
			s.empty.Delete(k)
		}
		return true
	})
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
		q := `DELETE FROM rate_buckets WHERE key IN (
			SELECT key FROM rate_buckets WHERE tokens + ($1::bigint - last) * rate / 1e6 >= burst FOR UPDATE SKIP LOCKED)`
		if s.spanner {
			// No SKIP LOCKED: a draw holding a row aborts the sweep, or
			// the sweep the draw, which runs again; full rows are judged
			// as of the sweep's own read, under its locks.
			q = `DELETE FROM rate_buckets WHERE tokens + ($1::bigint - last) * rate / 1e6 >= burst`
		}
		if _, err := s.db.Exec(q, now.UnixMicro()); err != nil {
			log.Printf("rate buckets: sweep: %v", err)
		}
		s.mu.Lock()
		s.sweeping = false
		s.mu.Unlock()
	}()
}
