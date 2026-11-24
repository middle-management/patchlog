package core

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A write's rate-limit draw on the store's buckets (ratebuckets.go) is made
// after its check's read transaction (checkOutside, drawLater), and the
// group commits have connections of their own (commitPool). These tests run
// only with PATCHLOG_TEST_PG set.

// While the writes' draws wait for their bucket's row, their checks hold
// no connection of the main pool: the checks have ended, and the draws
// wait on the bucket pool or the row. Inside the check's transaction, each
// would hold one, idle in a transaction, and with more writes than
// connections the main pool would have none left for anything else.
func TestPGDrawHoldsNoMainConn(t *testing.T) {
	if !pgtest.Enabled() || pgtest.Spanner() {
		t.Skip("Postgres only: pg_backend_pid")
	}
	const size = 4 // the main pool; the bucket pool is 2
	url := strings.Replace(pgtest.NewDB(t), "pool_max_conns=8", fmt.Sprintf("pool_max_conns=%d", size), 1)
	e := openInstance(t, url, t.TempDir())
	// Every write checks outside the lock and queues for a group.
	e.noSolo = true
	mkNS(t, e, "n", map[string]any{"read": "public"})
	bucket := []byte("n\x00n")
	if _, err := e.db.Exec(`INSERT INTO rate_buckets (key, tokens, last, rate, burst) VALUES ($1, 1e9, 0, 1e9, 1e9) ON CONFLICT (key) DO NOTHING`, bucket); err != nil {
		t.Fatal(err)
	}
	// The test's own connections, of a pool no write waits for.
	mon, err := sql.Open(pgtest.Driver(url), pgtest.DSN(url))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mon.Close() })
	rtx, err := mon.BeginTx(context.Background(), nil)
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

	const n = 3 * size
	errs := make([]error, n)
	done := make(chan struct{})
	go func() {
		_, errs = concurrently(n, func(i int) (*WriteResult, error) {
			return writeCtx(context.Background(), e, "n", fmt.Sprint("c", i), i)
		})
		close(done)
	}()
	// Before the engine closes (cleanups run last first), however the
	// test ends: the row released, the writes done.
	t.Cleanup(func() {
		rtx.Rollback()
		<-done
	})
	// One draw statement waits, for the held row, with one draw or a
	// batch of them, and the other draws, on the same buckets, queue for
	// the next batch (ratebuckets.go, draw).
	within(t, 10*time.Second, "every write's check ends and its draw waits", func() bool {
		var w, held int
		mon.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE $1 = ANY (pg_blocking_pids(pid))) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%rate_draw%'`, pid).Scan(&w, &held)
		s := e.rate.store
		return w == 1 && held > 0 && s.drawing.Load()+int64(s.queued()) == n
	})
	// The main pool's connections are free, but for the leader lock's and
	// one the tailer may hold.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var conns []*sql.Conn
	for range size - 2 {
		c, err := e.db.Conn(ctx)
		if err != nil {
			t.Fatalf("a connection of the main pool while %d draws wait: %v (%d in use)", n, err, e.db.Stats().InUse)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.Close()
	}
	if err := rtx.Rollback(); err != nil {
		t.Fatal(err)
	}
	<-done
	for i, err := range errs {
		if err != nil {
			t.Errorf("write %d: %v", i, err)
		}
	}
}

// A write checked outside the lock, its draw made after the check
// (grouped), is answered and draws as one whose draw is made inside its
// transaction (a write on its own, checked in the lock, the baseline): a write refused after its draw
// (412) draws, one refused before it (400) doesn't, and once the bucket is
// empty the 429 answers instead of what the check found after the draw.
// Then the instance knows the bucket empty, and a check stops at its draw
// (errDrawFirst); if the bucket has a token after all, the write is
// checked again and admitted, drawing once.
func TestPGDrawAfterCheck(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	for _, grouped := range []bool{false, true} {
		t.Run(fmt.Sprintf("grouped=%v", grouped), func(t *testing.T) {
			var clock atomic.Int64
			clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
			lim := p17Fast()
			lim.RatePerPrincipal = Rate{0.001, 3}
			e := p17RateEngine(t, pgtest.NewDB(t), t.TempDir(), &clock, lim, false)
			e.noSolo = grouped
			mkNS(t, e, "n", map[string]any{})
			w := Credentials{Author: "w"}
			// The principal's bucket: its name, authentication disabled.
			pkey := []byte("p\x00w")
			tokens := func() float64 {
				t.Helper()
				var v float64
				if err := e.db.QueryRow(`SELECT tokens FROM rate_buckets WHERE key = $1`, pkey).Scan(&v); err != nil {
					t.Fatal(err)
				}
				return v
			}
			create := func(name string, v int) error {
				it := Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"v": float64(v)}}}}}}
				_, err := e.WriteResource(context.Background(), Request{NS: "n", Cred: w}, it)
				return err
			}
			if err := create("x", 0); err != nil {
				t.Fatal(err)
			}
			if err := create("x", 1); status(err) != 412 {
				t.Fatalf("a second create of x: %v, want 412", err)
			}
			if got := tokens(); got != 1 {
				t.Fatalf("after a create and a 412: %v tokens, want 1", got)
			}
			if _, err := e.Batch(context.Background(), Request{NS: "n", Cred: w}, nil, nil, nil, false); status(err) != 400 {
				t.Fatalf("an empty batch: %v, want 400", err)
			}
			if err := create("y", 0); err != nil {
				t.Fatalf("the last token: %v", err)
			}
			if got := tokens(); got != 0 {
				t.Fatalf("after the 400 and the last token: %v tokens, want 0", got)
			}
			for _, name := range []string{"x", "z"} {
				err := create(name, 2)
				p17Rate(t, "create of "+name+" once the bucket is empty", err, "ratePerPrincipal", 1000)
			}
			stopped := e.rate.store.stopped.Load()
			if !e.rate.store.knownEmpty(e.now(), []draw{{key: string(pkey)}}) {
				t.Fatal("the instance doesn't know the bucket empty after its 429")
			}
			// A token the instance doesn't know of (another instance's
			// bucket at a raised rate, say).
			if _, err := e.db.Exec(`UPDATE rate_buckets SET tokens = 1 WHERE key = $1`, pkey); err != nil {
				t.Fatal(err)
			}
			if err := create("z", 3); err != nil {
				t.Fatalf("a create once the bucket has a token: %v", err)
			}
			if got := tokens(); got != 0 {
				t.Fatalf("after it: %v tokens, want 0 (drawn once)", got)
			}
			// Checked outside the lock, it stopped at its draw and ran
			// again; checked in the lock, it drew there.
			if got := e.rate.store.stopped.Load() - stopped; got != map[bool]int64{false: 0, true: 1}[grouped] {
				t.Fatalf("checks stopped at the draw and run again: %d", got)
			}
			if e.rate.store.knownEmpty(e.now(), []draw{{key: string(pkey)}}) {
				t.Fatal("the instance still knows the bucket empty after a draw it admitted")
			}
		})
	}
}

// A group's transaction takes a connection of the commit pool, which no
// check queues for; with none free it takes one of the main pool, and the
// group commits all the same.
func TestPGCommitPool(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	for _, free := range []bool{true, false} {
		t.Run(fmt.Sprintf("free=%v", free), func(t *testing.T) {
			e := groupEngine(t)
			mkNS(t, e, "n", map[string]any{"read": "public"})
			var pools []*sql.DB
			e.groupStart = func(t *tx, size int) {
				// database/sql's Tx keeps the DB it began on unexported:
				// tell the pools apart by which has a connection in use.
				pools = append(pools, nil)
				if e.commits.db.Stats().InUse > 0 {
					pools[len(pools)-1] = e.commits.db
				}
			}
			if !free {
				for e.commits.take() {
				}
				defer func() {
					for range cap(e.commits.free) {
						e.commits.give()
					}
				}()
			}
			const n = 4
			before := e.groups.committed.Load()
			holdChecked(t, e, n, nil)
			_, errs := concurrently(n, func(i int) (*WriteResult, error) {
				return writeCtx(context.Background(), e, "n", fmt.Sprint("c", i), i)
			})
			for i, err := range errs {
				if err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
			}
			if e.groups.committed.Load() == before || len(pools) == 0 {
				t.Fatal("no group committed")
			}
			for i, p := range pools {
				if got := p == e.commits.db; got != free {
					t.Errorf("group transaction %d on the commit pool: %v, want %v", i, got, free)
				}
			}
			if free && len(e.commits.free) != 0 {
				t.Errorf("%d of the commit pool's connections still taken after the groups", len(e.commits.free))
			}
		})
	}
}
