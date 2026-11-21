package core

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Concurrent draws on the store's buckets batch (ratebuckets.go, draw,
// drawBatch, rate_draws): with every connection of the bucket pool
// drawing, the draws queued meanwhile go in one statement, each request
// judged as rate_draw would have judged it after the ones before it.

// queued is how many draws wait for a batch (tests).
func (s *bucketStore) queued() int {
	s.qmu.Lock()
	defer s.qmu.Unlock()
	return len(s.queue)
}

// take takes queued draws in order, up to drawBatchItems buckets but at
// least one draw, and drops (answering) draws whose request is gone.
func TestDrawBatchTake(t *testing.T) {
	req := func(ctx context.Context, n int) *drawReq {
		ds := make([]draw, n)
		for i := range ds {
			ds[i] = draw{key: fmt.Sprint(i)}
		}
		return &drawReq{ctx: ctx, ds: ds, done: make(chan drawRes, 1)}
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	bg := context.Background()
	a, x, b, c, d := req(bg, drawBatchItems-10), req(gone, 1), req(bg, 10), req(bg, 1), req(bg, drawBatchItems+5)
	s := &bucketStore{slots: 1, queue: []*drawReq{a, x, b, c, d}}
	if got := s.take(); len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("first batch: %d draws, want a and b (up to %d buckets)", len(got), drawBatchItems)
	}
	if res := <-x.done; res.err != context.Canceled {
		t.Fatalf("the gone draw: %v, want its context's error", res.err)
	}
	if got := s.take(); len(got) != 1 || got[0] != c {
		t.Fatalf("second batch: %d draws, want c alone (d is above the bound)", len(got))
	}
	if got := s.take(); len(got) != 1 || got[0] != d {
		t.Fatalf("third batch: %d draws, want d, alone however many buckets it draws on", len(got))
	}
	if got := s.take(); len(got) != 0 || s.queued() != 0 {
		t.Fatalf("empty queue: %d draws taken, %d left", len(got), s.queued())
	}
}

// A batch's statement runs until every request of the batch is gone.
func TestDrawBatchContext(t *testing.T) {
	c1, cancel1 := context.WithCancel(context.Background())
	c2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	ctx, stop := batchContext([]*drawReq{{ctx: c1}, {ctx: c2}})
	defer stop()
	cancel1()
	time.Sleep(10 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("the batch's context is done while one of its requests isn't")
	}
	cancel2()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the batch's context isn't done once all its requests are")
	}
}

// A closed store draws nothing.
func TestDrawClosedStore(t *testing.T) {
	s := &bucketStore{slots: 1, qclosed: true}
	if _, _, err := s.draw(context.Background(), time.Now(), []draw{{key: "a", rate: Rate{1, 1}, cost: 1}}, false); err != errBucketsClosed {
		t.Fatalf("draw on a closed store: %v", err)
	}
}

// batchEngine is an engine on Postgres whose bucket pool runs one batch at
// a time, and the time now on its clock.
func batchEngine(t *testing.T, fresh bool) (*Engine, *bucketStore, time.Time) {
	t.Helper()
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	url := pgtest.NewDB(t)
	if fresh {
		url = pgtest.FreshDB(t)
	}
	e := p17RateEngine(t, url, t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	s.qmu.Lock()
	s.slots = 1
	s.qmu.Unlock()
	return e, s, time.UnixMilli(clock.Load())
}

// holdBucket holds the row of bucket key (adding it, full, if need be)
// until the returned release, and starts a draw on it, which waits for
// it: the store's one batch is busy, and draws queue behind it. The
// draw's answer is sent on the returned channel.
func holdBucket(t *testing.T, e *Engine, s *bucketStore, now time.Time, key string) (release func(), blocked <-chan error) {
	t.Helper()
	// Not full, so no sweep deletes it.
	r := Rate{1, 1e9}
	if _, err := e.db.Exec(`INSERT INTO rate_buckets (key, tokens, last, rate, burst) VALUES ($1, $2 - 2, $3, $4, $2) ON CONFLICT (key) DO NOTHING`,
		[]byte(key), r.Burst, now.UnixMicro(), r.Rate); err != nil {
		t.Fatal(err)
	}
	tx, err := e.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	var pid int
	if err := tx.QueryRow(`SELECT pg_backend_pid() FROM rate_buckets WHERE key = $1 FOR UPDATE`, []byte(key)).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, ok, err := s.admit(context.Background(), now, []draw{{key, r, 1, "held"}})
		if err == nil && !ok {
			err = fmt.Errorf("refused")
		}
		done <- err
	}()
	p17DrawBlockedBy(t, e, pid)
	return func() { tx.Rollback() }, done
}

type admitted struct {
	wait  time.Duration
	limit string
	ok    bool
	err   error
}

// queueDraws queues each of fns behind the store's busy batch, in order,
// and returns their answers once release lets the batch go.
func queueDraws(t *testing.T, s *bucketStore, release func(), blocked <-chan error, fns ...func() admitted) []admitted {
	t.Helper()
	out := make([]chan admitted, len(fns))
	for i, fn := range fns {
		out[i] = make(chan admitted, 1)
		go func() { out[i] <- fn() }()
		within(t, 10*time.Second, fmt.Sprintf("draw %d queues", i), func() bool { return s.queued() == i+1 })
	}
	batches, batched := s.batches.Load(), s.batched.Load()
	release()
	if err := <-blocked; err != nil {
		t.Fatalf("the held draw: %v", err)
	}
	res := make([]admitted, len(fns))
	for i := range out {
		res[i] = <-out[i]
		if res[i].err != nil {
			t.Fatalf("draw %d: %v", i, res[i].err)
		}
	}
	if b, n := s.batches.Load()-batches, s.batched.Load()-batched; b != 1 || n != int64(len(fns)) {
		t.Fatalf("%d batches of %d draws, want one of %d", b, n, len(fns))
	}
	return res
}

func tokensOf(t *testing.T, e *Engine, key string) float64 {
	t.Helper()
	var tokens float64
	if err := e.db.QueryRow(`SELECT tokens FROM rate_buckets WHERE key = $1`, []byte(key)).Scan(&tokens); err != nil {
		t.Fatalf("bucket %q: %v", key, err)
	}
	return tokens
}

// One batch of admitted and refused requests, two on one bucket, and a
// charge: each is judged in queue order against what the requests before
// it left, a refused one deducts nothing, not even from its buckets that
// hold a token, a charge deducts whatever the bucket holds, and a refused
// one's 429 names the limit with the longest wait, and that wait.
func TestPGDrawBatchMixed(t *testing.T) {
	e, s, now := batchEngine(t, false)
	release, blocked := holdBucket(t, e, s, now, "held")
	ra, rb, rc := Rate{2, 2}, Rate{0.5, 1}, Rate{1, 1}
	adm := func(ds ...draw) func() admitted {
		return func() admitted {
			w, l, ok, err := s.admit(context.Background(), now, ds)
			return admitted{w, l, ok, err}
		}
	}
	res := queueDraws(t, s, release, blocked,
		adm(draw{"a", ra, 1, "limA"}),                                                     // a 2 -> 1
		adm(draw{"a", ra, 1, "limA"}, draw{"b", rb, 1, "limB"}),                           // a 1 -> 0, b 1 -> 0
		adm(draw{"a", ra, 1, "limA"}),                                                     // refused: a empty, wait 0.5 s
		adm(draw{"c", rc, 1, "limC"}, draw{"a", ra, 1, "limA"}, draw{"b", rb, 1, "limB"}), // refused: b's wait 2 s is the longest
		func() admitted { // a charge: a 0 -> -3
			err := s.charge(context.Background(), now, draw{"a", ra, 3, "limA"})
			return admitted{ok: true, err: err}
		},
		adm(draw{"c", rc, 1, "limC"}), // c is full: the refusal before took nothing
		adm(draw{"a", ra, 1, "limA"}), // refused: a at -3, wait 2 s
	)
	want := []admitted{
		{ok: true}, {ok: true},
		{wait: 500 * time.Millisecond, limit: "limA"},
		{wait: 2 * time.Second, limit: "limB"},
		{ok: true}, {ok: true},
		{wait: 2 * time.Second, limit: "limA"},
	}
	for i := range want {
		if res[i] != want[i] {
			t.Errorf("draw %d: %+v, want %+v", i, res[i], want[i])
		}
	}
	for k, want := range map[string]float64{"a": -3, "b": 0, "c": 0} {
		if got := tokensOf(t, e, k); got != want {
			t.Errorf("bucket %s: %v tokens, want %v", k, got, want)
		}
	}
	// The 429 a write is answered with.
	p17Rate(t, "refused in a batch", rateRefused(res[3].wait, res[3].limit), "limB", 2)
}

// Requests of a batch at different times: each refills its buckets to its
// own time, and a bucket's time doesn't run backwards for a request that
// read the clock before the one queued ahead of it.
func TestPGDrawBatchTimes(t *testing.T) {
	e, s, now := batchEngine(t, false)
	r := Rate{1, 10}
	if _, _, ok, err := s.admit(context.Background(), now, []draw{{"a", r, 10, "x"}}); err != nil || !ok {
		t.Fatalf("emptying a: %v %v", ok, err)
	}
	release, blocked := holdBucket(t, e, s, now, "held")
	at := func(d time.Duration) func() admitted {
		return func() admitted {
			w, l, ok, err := s.admit(context.Background(), now.Add(d), []draw{{"a", r, 1, "x"}})
			return admitted{w, l, ok, err}
		}
	}
	res := queueDraws(t, s, release, blocked,
		at(1500*time.Millisecond), // 1.5 tokens -> 0.5
		at(time.Second),           // earlier: no refill, 0.5 -> refused, wait 0.5 s
		at(3*time.Second),         // 0.5 + 1.5 -> 1 after
	)
	want := []admitted{{ok: true}, {wait: 500 * time.Millisecond, limit: "x"}, {ok: true}}
	for i := range want {
		if res[i] != want[i] {
			t.Errorf("draw %d: %+v, want %+v", i, res[i], want[i])
		}
	}
	var tokens float64
	var last int64
	if err := e.db.QueryRow(`SELECT tokens, last FROM rate_buckets WHERE key = 'a'`).Scan(&tokens, &last); err != nil || tokens != 1 || last != now.Add(3*time.Second).UnixMicro() {
		t.Fatalf("a: %v tokens at %d (%v), want 1 at %d", tokens, last, err, now.Add(3*time.Second).UnixMicro())
	}
}

// rate_draws judges a batch as rate_draw judges its requests one after
// another: random batches on a few buckets, drawn both ways on buckets of
// their own, leave the same tokens and answer the same.
func TestPGDrawBatchMatchesSequential(t *testing.T) {
	e, s, now := batchEngine(t, false)
	rng := rand.New(rand.NewPCG(1, 2))
	rates := []Rate{{1, 3}, {0.5, 2}, {10, 5}, {1e-3, 1}}
	for round := range 20 {
		var b []*drawReq
		var seq []*drawReq
		for range 1 + rng.IntN(12) {
			n := 1 + rng.IntN(3)
			var ds, dseq []draw
			for range n {
				k := rng.IntN(4)
				d := draw{fmt.Sprintf("%d/%d", round, k), rates[k], float64(rng.IntN(3)), "x"}
				ds = append(ds, d)
				d.key = "seq/" + d.key
				dseq = append(dseq, d)
			}
			at := now.Add(time.Duration(rng.IntN(3000)) * time.Millisecond)
			force := rng.IntN(5) == 0
			b = append(b, &drawReq{ctx: context.Background(), now: at, ds: merged(ds), force: force})
			seq = append(seq, &drawReq{ctx: context.Background(), now: at, ds: merged(dseq), force: force})
		}
		got, complete, err := s.drawsOnce(context.Background(), b)
		if err != nil || !complete {
			t.Fatalf("round %d: batch: %v (complete %v)", round, err, complete)
		}
		for i, r := range seq {
			want, complete, err := s.drawOnce(context.Background(), r)
			if err != nil || !complete {
				t.Fatalf("round %d: draw %d: %v (complete %v)", round, i, err, complete)
			}
			if got[i].ok != want[0].ok || len(got[i].tokens) != len(want[0].tokens) {
				t.Fatalf("round %d, draw %d: batch %+v, one by one %+v", round, i, got[i], want[0])
			}
			for k, tk := range got[i].tokens {
				if want[0].tokens["seq/"+k] != tk {
					t.Fatalf("round %d, draw %d, bucket %s: batch %v tokens, one by one %v", round, i, k, tk, want[0].tokens["seq/"+k])
				}
			}
		}
		rows, err := e.db.Query(`SELECT a.key, a.tokens, a.last, a.rate, a.burst, b.tokens, b.last, b.rate, b.burst
			FROM rate_buckets a JOIN rate_buckets b ON b.key = 'seq/'::bytea || a.key WHERE a.key LIKE $1`, []byte(fmt.Sprintf("%d/%%", round)))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			var k []byte
			var at, bt, ar, br, ab, bb float64
			var al, bl int64
			if err := rows.Scan(&k, &at, &al, &ar, &ab, &bt, &bl, &br, &bb); err != nil {
				t.Fatal(err)
			}
			if at != bt || al != bl || ar != br || ab != bb {
				t.Fatalf("round %d, bucket %s: batch (%v, %d, %v, %v), one by one (%v, %d, %v, %v)", round, k, at, al, ar, ab, bt, bl, br, bb)
			}
			n++
		}
		rows.Close()
		if n == 0 {
			t.Fatalf("round %d: no buckets", round)
		}
	}
}

// A batch Postgres rolls back for a deadlock deducted nothing, and runs
// again, as a single draw does (TestV073P17DrawRetriesDeadlock).
func TestPGDrawBatchRetriesDeadlock(t *testing.T) {
	e, s, now := batchEngine(t, true)
	for _, q := range []string{
		`ALTER FUNCTION rate_draws(int[], bytea[], float8[], float8[], float8[], bigint[], boolean[]) RENAME TO rb_rate_draws`,
		`CREATE SEQUENCE rb_draws`,
		`CREATE FUNCTION rate_draws(rq int[], ks bytea[], rs float8[], bs float8[], cs float8[], nows bigint[], forced boolean[])
		RETURNS TABLE (r int, k bytea, t float8, admitted boolean) LANGUAGE plpgsql AS $$
		BEGIN
		  -- Deduct, then fail: the rollback must undo the deduction.
		  RETURN QUERY SELECT * FROM rb_rate_draws(rq, ks, rs, bs, cs, nows, forced);
		  IF nextval('rb_draws') = 1 THEN
		    RAISE EXCEPTION 'injected deadlock' USING ERRCODE = '40P01';
		  END IF;
		END $$`,
	} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	r := Rate{1, 10}
	b := []*drawReq{
		{ctx: context.Background(), now: now, ds: []draw{{"a", r, 1, "x"}}, done: make(chan drawRes, 1)},
		{ctx: context.Background(), now: now, ds: []draw{{"a", r, 2, "x"}, {"b", r, 1, "x"}}, done: make(chan drawRes, 1)},
	}
	retried := s.retried.Load()
	s.drawBatch(b)
	for i, req := range b {
		if res := <-req.done; res.err != nil || !res.ok {
			t.Fatalf("draw %d: %+v", i, res)
		}
	}
	if n := s.retried.Load() - retried; n != 1 {
		t.Fatalf("%d batches ran again, want 1", n)
	}
	if a, b := tokensOf(t, e, "a"), tokensOf(t, e, "b"); a != 7 || b != 9 {
		t.Fatalf("after the batch: a %v, b %v tokens; want one deduction each (7, 9)", a, b)
	}
}

// A batch that finds a bucket's row gone (a sweep deleted it after the
// insert) deducts nothing and runs again (errBucketsVanish).
func TestPGDrawBatchRowGone(t *testing.T) {
	e, s, now := batchEngine(t, true)
	// The row of b goes once, after the batch added it and before it locks
	// it: here, a trigger deletes it as it is added.
	for _, q := range []string{
		`CREATE SEQUENCE rb_gone`,
		`CREATE FUNCTION rb_gone() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		  IF NEW.key = 'b' AND nextval('rb_gone') = 1 THEN RETURN NULL; END IF; RETURN NEW; END $$`,
		`CREATE TRIGGER rb_gone BEFORE INSERT ON rate_buckets FOR EACH ROW EXECUTE FUNCTION rb_gone()`,
	} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	r := Rate{1, 10}
	b := []*drawReq{
		{ctx: context.Background(), now: now, ds: []draw{{"a", r, 1, "x"}}, done: make(chan drawRes, 1)},
		{ctx: context.Background(), now: now, ds: []draw{{"a", r, 1, "x"}, {"b", r, 1, "x"}}, done: make(chan drawRes, 1)},
	}
	s.drawBatch(b)
	for i, req := range b {
		if res := <-req.done; res.err != nil || !res.ok {
			t.Fatalf("draw %d: %+v", i, res)
		}
	}
	if a, b := tokensOf(t, e, "a"), tokensOf(t, e, "b"); a != 8 || b != 9 {
		t.Fatalf("after the batch: a %v, b %v tokens; want 8, 9", a, b)
	}
}

// End to end: many writes as one principal, more than the bucket pool's
// connections, draw in batches, and each draws once.
func TestPGDrawBatchWrites(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	release, blocked := holdBucket(t, e, e.rate.store, time.Now(), "held")
	const n = 24
	s := e.rate.store
	before := s.batched.Load()
	done := make(chan []error)
	go func() {
		_, errs := concurrently(n, func(i int) (*WriteResult, error) {
			return writeCtx(context.Background(), e, "n", fmt.Sprint("c", i), i)
		})
		done <- errs
	}()
	// Every connection but the held draw's draws, and some draws queue.
	within(t, 10*time.Second, "draws queue", func() bool { return s.queued() > 0 })
	release()
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	for i, err := range <-done {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if s.batched.Load() == before {
		t.Fatal("no write drew in a batch")
	}
}
