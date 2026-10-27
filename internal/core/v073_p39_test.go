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
