package core

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// P39: the group-commit cancellation tests and the rate-draw deadlock test
// wait for the state they test, not for any lock wait or a fixed time.

// FL-1, FL-2: the writes of a group draw their rate-limit tokens in their
// check phase (rate_draw, ratebuckets.go), and draws on one bucket wait
// for each other's row lock: a lock wait before any group forms. The
// cancellation tests took any lock wait for their group's, and cancelled
// a request still in its check phase, or queued, which is then never
// written. groupBlocked holds only once the group has formed and waits
// for the namespace's lock. Here the namespace's bucket row is held while
// the writes check, so their draws wait: groupBlocked doesn't hold until
// the row is released and the group forms.
func TestV073P39GroupBlockedIgnoresRateDraws(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	key := lockKey(nsIDOf(t, e, "n"))
	releaseNS := holdLock(t, e, lockClass, key)
	bucket := []byte("n\x00n")
	if _, err := e.db.Exec(`INSERT INTO rate_buckets (key, tokens, last, rate, burst) VALUES ($1, 1e9, 0, 1e9, 1e9) ON CONFLICT (key) DO NOTHING`, bucket); err != nil {
		t.Fatal(err)
	}
	rtx, err := e.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rtx.Rollback()
	if _, err := rtx.Exec(`SELECT 1 FROM rate_buckets WHERE key = $1 FOR UPDATE`, bucket); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := rtx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	const n = 2
	holdChecked(t, e, n, nil)
	res, errs := make([]*WriteResult, n), make([]error, n)
	done := make(chan struct{})
	go func() {
		res, errs = concurrently(n, func(i int) (*WriteResult, error) {
			return writeCtx(context.Background(), e, "n", fmt.Sprint("c", i), i)
		})
		close(done)
	}()
	// The first draw waits for the held row, the other for the first.
	within(t, 10*time.Second, "both draws wait for the bucket row", func() bool {
		var w, held int
		e.db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE $1 = ANY (pg_blocking_pids(pid))) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%rate_draw(%'`, pid).Scan(&w, &held)
		return w == n && held > 0
	})
	if waiting(e) == 0 {
		t.Fatal("no lock wait while the draws wait")
	}
	if groupBlocked(e, "n", key) {
		t.Fatal("a group waits for the namespace's lock while its writes draw tokens")
	}
	if err := rtx.Rollback(); err != nil {
		t.Fatal(err)
	}
	within(t, 10*time.Second, "the group waits for the lock", func() bool { return groupBlocked(e, "n", key) })
	releaseNS()
	<-done
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	xids := checkChain(t, e, "n")
	if len(xids) != 1+n || xids[res[0].NSID] != xids[res[1].NSID] {
		t.Fatalf("entries %v: want both writes in one transaction", xids)
	}
}

// FL-1: a write holdChecked still holds when its test has ended goes on
// without reporting to the test, which would panic and end the whole run
// (one failure of TestPGGroupCommitCancelBlockedGroup cut a run of the
// package short so).
func TestV073P39HoldCheckedAfterItsTest(t *testing.T) {
	e := &Engine{}
	t.Run("held", func(t *testing.T) {
		holdCheckedFor(t, e, 2, 20*time.Millisecond, nil)
	})
	// One write of the two arrives, after the test that held them ended.
	e.opt.BeforeWriteLock()
}

// FL-3: p17DrawBlockedBy returns only once the draw holds its first row
// and waits for the second, however late the draw starts (here later than
// the fixed 200 ms TestV073P17DrawRetriesDeadlock slept), so the deadlock
// that test provokes is the one it means: the draw waits first.
func TestV073P39DrawBlockedByWaitsForTheDraw(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	e := p17RateEngine(t, pgtest.NewDB(t), t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	now := time.UnixMilli(clock.Load())
	r := Rate{1, 10}
	p17FullBuckets(t, e, now, r, "a", "b")
	ctx := context.Background()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT 1 FROM rate_buckets WHERE key = 'b' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _, ok, err := s.admit(ctx, now, []draw{{"a", r, 1, "x"}, {"b", r, 1, "x"}})
		if err == nil && !ok {
			err = fmt.Errorf("refused")
		}
		done <- err
	}()
	p17DrawBlockedBy(t, e, pid)
	// The draw holds a.
	_, err = e.db.Exec(`SELECT 1 FROM rate_buckets WHERE key = 'a' FOR UPDATE NOWAIT`)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" {
		t.Fatalf("locking a while the draw waits for b: %v, want lock_not_available", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the draw: %v", err)
	}
}

// FL-3: a draw Postgres rolls back for a deadlock pauses before it runs
// again (drawPause), so the statement that survived the deadlock, woken,
// takes the row it waited for first: run again at once, the draw locked
// that row again first now and then and closed the same cycle, up to
// every attempt (TestV073P17DrawRetriesDeadlock failed so about once in
// 60 runs). Here rate_draw fails its second call as a deadlock's victim,
// and records when each call starts (setval, which no rollback undoes),
// on one connection, warmed by the first call.
func TestV073P39DrawPausesAfterDeadlock(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	e := p17RateEngine(t, pgtest.FreshDB(t), t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	s.db.SetMaxOpenConns(1)
	for _, q := range []string{
		`ALTER FUNCTION rate_draw(bytea[], float8[], float8[], float8[], bigint, boolean) RENAME TO p39_rate_draw`,
		`CREATE SEQUENCE p39_draws`,
		`CREATE SEQUENCE p39_at MINVALUE 0`,
		`CREATE SEQUENCE p39_retry_at MINVALUE 0`,
		`CREATE FUNCTION rate_draw(ks bytea[], rs float8[], bs float8[], cs float8[], now_us bigint, forced boolean)
		RETURNS TABLE (k bytea, t float8, admitted boolean) LANGUAGE plpgsql AS $$
		DECLARE
		  n bigint := nextval('p39_draws');
		  at bigint := (extract(epoch FROM clock_timestamp()) * 1e6)::bigint;
		BEGIN
		  IF n = 2 THEN
		    PERFORM setval('p39_at', at);
		    RAISE EXCEPTION 'injected deadlock' USING ERRCODE = '40P01';
		  END IF;
		  IF n = 3 THEN
		    PERFORM setval('p39_retry_at', at);
		  END IF;
		  RETURN QUERY SELECT * FROM p39_rate_draw(ks, rs, bs, cs, now_us, forced);
		END $$`,
	} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	r := Rate{1, 10}
	now := time.UnixMilli(clock.Load())
	for i, k := range []string{"a", "b"} {
		_, _, ok, err := s.admit(context.Background(), now, []draw{{k, r, 1, "x"}})
		if err != nil || !ok {
			t.Fatalf("draw %d: %v, %v", i, ok, err)
		}
	}
	if n := s.retried.Load(); n != 1 {
		t.Fatalf("%d draws ran again, want 1", n)
	}
	var calls, at, retryAt int64
	if err := e.db.QueryRow(`SELECT (SELECT last_value FROM p39_draws), (SELECT last_value FROM p39_at), (SELECT last_value FROM p39_retry_at)`).Scan(&calls, &at, &retryAt); err != nil || calls != 3 {
		t.Fatalf("rate_draw ran %d times (%v), want 3", calls, err)
	}
	if gap := time.Duration(retryAt-at) * time.Microsecond; gap < deadlockPause/2 {
		t.Fatalf("the draw ran again %v after its deadlock, want a pause of at least %v", gap, deadlockPause/2)
	}
}

// TestPGGroupCommitLostRaceLeavesLoserOut let the single write append once
// two lock waits showed, taken for the group waiting for its row, the
// cause of FL-1: a draw of the group's write of x waiting for x's bucket
// row is a second wait before any group forms, the single write then
// appended first and the group never lost the race (one attempt, not two).
// Here x's bucket row is held while the group's writes check, so that
// draw waits; the test waits for the group itself (groupWaitsOn).
func TestV073P39LostRaceWaitsForTheGroup(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	lostRaceLeavesLoserOut(t, func(a *Engine, single int) {
		rtx, err := a.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rtx.Rollback() })
		var held, pid int
		if err := rtx.QueryRow(`WITH l AS (SELECT 1 FROM rate_buckets WHERE substring(key from 1 for 6) = $1 FOR UPDATE)
			SELECT COUNT(*), pg_backend_pid() FROM l`, []byte("r\x00n\x00x\x00")).Scan(&held, &pid); err != nil || held != 1 {
			t.Fatalf("holding x's bucket row: %d, %v", held, err)
		}
		done := make(chan struct{})
		t.Cleanup(func() { <-done })
		go func() {
			defer close(done)
			defer rtx.Rollback()
			if !waitFor(10*time.Second, func() bool {
				var n int
				a.db.QueryRow(`SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()
					AND wait_event_type = 'Lock' AND query LIKE '%rate_draw(%' AND $1 = ANY (pg_blocking_pids(pid))`, pid).Scan(&n)
				return n > 0
			}) {
				t.Error("no draw waited for x's bucket row")
				return
			}
			if w := waiting(a); w < 2 {
				t.Errorf("%d lock waits while a draw waits, want the single write's and the draw's", w)
			}
			if groupWaitsOn(a, "n", single) {
				t.Error("the group waits for the single write's row while a write draws its tokens")
			}
		}()
	})
}
