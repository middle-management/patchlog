package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Several instances on one Postgres database (Addendum D.8). These tests
// run only with PATCHLOG_TEST_PG set.

const tailEvery = 20 * time.Millisecond

type discardPurger struct{}

func (discardPurger) PurgeTags([]string) {}

// openInstance opens an engine on url, with blob files in dir.
func openInstance(t *testing.T, url, dir string) *Engine {
	t.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: url, BlobDir: dir, AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: tailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// twoInstances opens two engines on a fresh database, sharing a blob
// directory.
func twoInstances(t *testing.T) (*Engine, *Engine) {
	url, dir := pgtest.NewDB(t), t.TempDir()
	return openInstance(t, url, dir), openInstance(t, url, dir)
}

var who = Request{Cred: Credentials{Author: "a"}}

func mkNS(t *testing.T, e *Engine, ns string, doc map[string]any) string {
	t.Helper()
	r := who
	r.NS = ns
	res, err := e.WriteConfig(context.Background(), r, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}})
	if err != nil {
		t.Fatal(err)
	}
	return res.ConfigID
}

// put writes {"n": n} to ns/name: a create with ifMatch "", else an append.
func put(e *Engine, ns, name, ifMatch string, n int) (string, error) {
	r := who
	r.NS = ns
	it := Item{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == ""}
	op := "replace"
	if ifMatch == "" {
		op = "add"
	}
	it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(n)}}}}}
	res, err := e.WriteResource(context.Background(), r, it)
	if err != nil {
		return "", err
	}
	return res.Items[0].IDs[0], nil
}

func status(err error) int {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// within polls cond until it holds or d passes, and reports how long it took.
func within(t testing.TB, d time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > d {
			t.Fatalf("%s: not within %v", what, d)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return time.Since(start)
}

// Writers to different namespaces run in parallel, and so do writers of
// different resources of one namespace, which hold its lock shared; a
// config write, which takes it exclusively, waits for them.
func TestPGParallelNamespaces(t *testing.T) {
	a, b := twoInstances(t)
	cfg1 := mkNS(t, a, "n1", map[string]any{"read": "public"})
	mkNS(t, a, "n2", map[string]any{"read": "public"})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.afterWriteLock = func(ns string) {
		if ns == "n1" {
			once.Do(func() {
				close(entered)
				<-release
			})
		}
	}
	held := make(chan error, 1)
	go func() {
		_, err := put(a, "n1", "r", "", 1)
		held <- err
	}()
	<-entered // a holds n1's lock

	done := make(chan error, 1)
	go func() {
		_, err := put(b, "n2", "r", "", 1)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write to n2 waited for a write to n1")
	}

	same := make(chan error, 1)
	go func() {
		_, err := put(b, "n1", "s", "", 1)
		same <- err
	}()
	select {
	case err := <-same:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write to n1's s waited for a write to n1's r")
	}

	cfg := make(chan error, 1)
	go func() {
		r := who
		r.NS = "n1"
		_, err := b.WriteConfig(context.Background(), r, ConfigChange{IfMatch: cfg1, Patches: []any{map[string]any{"op": "add", "path": "/x-title", "value": "t"}}})
		cfg <- err
	}()
	select {
	case err := <-cfg:
		t.Fatalf("a config write to n1 didn't wait for n1's lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	for _, c := range []chan error{held, cfg} {
		if err := <-c; err != nil {
			t.Fatal(err)
		}
	}
	info, err := b.NamespaceLog(context.Background(), "n1", "", "", 0, who.Cred)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Entries) != 4 { // config, s, r, config
		t.Fatalf("n1's log has %d entries, want 4", len(info.Entries))
	}
	if e := info.Entries[len(info.Entries)-1]; e["kind"] != "config" {
		t.Fatalf("n1's last entry is %v, want the config write's", e["kind"])
	}
}

// Appends to one resource from both instances: every acknowledged write is
// in the chain, and a lost race answers 412 with the new head (D.3).
func TestPGNoLostUpdates(t *testing.T) {
	a, b := twoInstances(t)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	head, err := put(a, "n", "r", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var ok, stale atomic.Int64
	var wg sync.WaitGroup
	const workers, each = 4, 10
	for w := 0; w < 2*workers; w++ {
		e := a
		if w%2 == 1 {
			e = b
		}
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			h := head
			for i := 0; i < each; {
				id, err := put(e, "n", "r", h, w*100+i)
				switch status(err) {
				case 0:
					if err != nil {
						t.Error(err)
						return
					}
					ok.Add(1)
					h = id
					i++
				case 412:
					stale.Add(1)
					var ae *Error
					errors.As(err, &ae)
					h, _ = ae.Body["head"].(string)
				default:
					t.Error(err)
					return
				}
			}
		}(w)
		// Writers of other resources of the namespace never see a 412:
		// their races are retried inside the write path.
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			name := fmt.Sprint("x", w)
			h := ""
			for i := 0; i < each; i++ {
				id, err := put(e, "n", name, h, i)
				if err != nil {
					t.Error(err)
					return
				}
				h = id
			}
		}(w)
	}
	wg.Wait()
	if ok.Load() != 2*workers*each {
		t.Fatalf("%d writes acknowledged", ok.Load())
	}
	lg, err := a.ResourceLog(context.Background(), "n", "r", "", "", 0, who.Cred)
	if err != nil {
		t.Fatal(err)
	}
	if len(lg.Entries) != 1+2*workers*each {
		t.Fatalf("r's log has %d entries, want %d (%d stale answers)", len(lg.Entries), 1+2*workers*each, stale.Load())
	}
	nl, err := b.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + 1 + 2*workers*each + 2*workers*each; len(nl.Entries) != want {
		t.Fatalf("the namespace log has %d entries, want %d", len(nl.Entries), want)
	}
	t.Logf("%d stale answers", stale.Load())
}

// The same precondition on both instances at once: one write wins, the
// other is answered 412 with the winner's id.
func TestPGRace412(t *testing.T) {
	a, b := twoInstances(t)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	head, err := put(a, "n", "r", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 10; round++ {
		start := make(chan struct{})
		var ids [2]string
		var errs [2]error
		var wg sync.WaitGroup
		for i, e := range []*Engine{a, b} {
			wg.Add(1)
			go func(i int, e *Engine) {
				defer wg.Done()
				<-start
				ids[i], errs[i] = put(e, "n", "r", head, round*10+i)
			}(i, e)
		}
		close(start)
		wg.Wait()
		win := 0
		if errs[0] != nil {
			win = 1
		}
		lose := 1 - win
		if errs[win] != nil || status(errs[lose]) != 412 {
			t.Fatalf("round %d: %v, %v", round, errs[0], errs[1])
		}
		var ae *Error
		errors.As(errs[lose], &ae)
		if ae.Body["head"] != ids[win] {
			t.Fatalf("round %d: 412 names %v, the winner is %s", round, ae.Body["head"], ids[win])
		}
		head = ids[win]
	}
}

// barrier holds the first n writers that reach it until all n have, so
// they are known to hold their namespace's lock at once; later ones pass.
type barrier struct {
	mu      sync.Mutex
	n       int
	arrived chan struct{}
}

func newBarrier(n int) *barrier { return &barrier{n: n, arrived: make(chan struct{})} }

func (b *barrier) wait(t *testing.T) {
	b.mu.Lock()
	if b.n == 0 {
		b.mu.Unlock()
		return
	}
	if b.n--; b.n == 0 {
		close(b.arrived)
	}
	b.mu.Unlock()
	select {
	case <-b.arrived:
	case <-time.After(5 * time.Second):
		t.Error("the writers didn't hold the namespace's lock at once")
	}
}

// Writers of one namespace hold its lock shared, checked (inside the lock,
// or first outside it with the D.3 re-check inside) and inserting at once:
// writers of different resources both succeed, and of the same resource
// one wins and the other is answered 412 with the winner's head, on both
// paths and from both instances. Every chain stays linear.
func TestPGSharedNamespaceLock(t *testing.T) {
	for _, mode := range []struct {
		name   string
		locked int
	}{{"check-inside", 0}, {"re-check", -1}} {
		t.Run(mode.name, func(t *testing.T) {
			a, b := twoInstances(t)
			mkNS(t, a, "n", map[string]any{"read": "public"})
			var bar atomic.Pointer[barrier]
			for _, e := range []*Engine{a, b} {
				e.opt.LockedCheckBytes = mode.locked
				e.afterWriteLock = func(ns string) {
					if br := bar.Load(); br != nil && ns == "n" {
						br.wait(t)
					}
				}
			}
			// both runs f on a and b at once, past the barrier together.
			both := func(f func(e *Engine, i int) (string, error)) (ids [2]string, errs [2]error) {
				bar.Store(newBarrier(2))
				defer bar.Store(nil)
				var wg sync.WaitGroup
				for i, e := range []*Engine{a, b} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ids[i], errs[i] = f(e, i)
					}()
				}
				wg.Wait()
				return
			}
			oneWins := func(what string, ids [2]string, errs [2]error) string {
				t.Helper()
				win := 0
				if errs[0] != nil {
					win = 1
				}
				if errs[win] != nil || status(errs[1-win]) != 412 {
					t.Fatalf("%s: %v, %v", what, errs[0], errs[1])
				}
				var ae *Error
				errors.As(errs[1-win], &ae)
				if ae.Body["head"] != ids[win] {
					t.Fatalf("%s: 412 names %v, the winner is %s", what, ae.Body["head"], ids[win])
				}
				return ids[win]
			}

			// Different resources: both proceed.
			ids, errs := both(func(e *Engine, i int) (string, error) { return put(e, "n", fmt.Sprint("r", i), "", i) })
			if errs[0] != nil || errs[1] != nil {
				t.Fatal(errs)
			}
			heads := map[string]string{"r0": ids[0], "r1": ids[1]}
			// The same new resource.
			ids, errs = both(func(e *Engine, i int) (string, error) { return put(e, "n", "c", "", i) })
			heads["c"] = oneWins("create", ids, errs)
			// The same head of one resource, a few times over.
			for round := 0; round < 5; round++ {
				h := heads["r0"]
				ids, errs := both(func(e *Engine, i int) (string, error) { return put(e, "n", "r0", h, 10+round*2+i) })
				heads["r0"] = oneWins(fmt.Sprint("append ", round), ids, errs)
			}
			// A batch and a single write racing for one resource; the
			// batch's other item doesn't land either when it loses.
			h := heads["r1"]
			ids, errs = both(func(e *Engine, i int) (string, error) {
				if i == 1 {
					return put(e, "n", "r1", h, 100)
				}
				r := who
				r.NS = "n"
				res, err := e.Batch(context.Background(), r, []Item{
					{Resource: "r1", IfMatch: h, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 101.0}}}}},
					{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
				}, nil, nil, false)
				if err != nil {
					var ae *Error
					if errors.As(err, &ae) && ae.Status == 412 {
						items, _ := ae.Body["items"].([]any)
						if len(items) == 1 {
							return "", &Error{Status: 412, Body: items[0].(map[string]any)}
						}
					}
					return "", err
				}
				heads["d"] = res.Items[1].IDs[0]
				return res.Items[0].IDs[0], nil
			})
			heads["r1"] = oneWins("batch", ids, errs)

			// The namespace chain holds one entry per success, in a
			// linear chain, and every resource's head is its last write.
			info, err := b.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
			if err != nil {
				t.Fatal(err)
			}
			if want := 1 + 2 + 1 + 5 + 1; len(info.Entries) != want {
				t.Fatalf("n's log has %d entries, want %d", len(info.Entries), want)
			}
			prev := ""
			for i, en := range info.Entries {
				if p, _ := en["prev"].(string); i > 0 && p != prev {
					t.Fatalf("entry %d's prev is %q, want %q", i, p, prev)
				}
				prev, _ = en["id"].(string)
			}
			for name, want := range heads {
				hd, err := a.ResourceHead(context.Background(), "n", name, who.Cred)
				if err != nil || hd.Head != want {
					t.Fatalf("%s: head %v %v, want %s", name, hd, err, want)
				}
			}
			if _, ok := heads["d"]; !ok {
				if hd, err := a.ResourceHead(context.Background(), "n", "d", who.Cred); err != nil || hd.State != NotFound {
					t.Fatalf("the losing batch's other item: %v %v", hd, err)
				}
			}
		})
	}
}

// A write on one instance wakes a live reader of the other.
func TestPGWakeOtherInstance(t *testing.T) {
	a, b := twoInstances(t)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	time.Sleep(3 * tailEvery) // the creation's own wake-ups
	wait := b.Wait("n")
	start := time.Now()
	if _, err := put(a, "n", "r", "", 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wait:
		t.Logf("woken after %v", time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("the other instance's live reader wasn't woken")
	}
}

// A purge on one instance: the other stops serving the content from its
// transaction-free cache within freshFor of the purge's commit.
func TestPGPurgeStopsOtherInstance(t *testing.T) {
	a, b := twoInstances(t)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	id, err := put(a, "n", "r", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// b caches only while its tailer is fresh, which a loaded machine can
	// interrupt: read until it does.
	within(t, 5*time.Second, "b serving the revision from its cache", func() bool {
		rev, err := b.ResourceRev(ctx, "n", "r", id, who.Cred)
		if err != nil || rev.Status != 200 {
			t.Fatalf("%v %v", rev, err)
		}
		return b.rc.rev("n", "r", id) != nil
	})
	r := who
	r.NS = "n"
	if _, err := a.Purge(ctx, r, "r", id, false); err != nil {
		t.Fatal(err)
	}
	purged := time.Now()
	took := within(t, 5*time.Second, "b serving the purged revision", func() bool {
		rev, err := b.ResourceRev(ctx, "n", "r", id, who.Cred)
		return err == nil && rev.Status == 410
	})
	if bound := b.freshFor(); took > bound {
		t.Fatalf("b served the purged revision for %v, past %v", took, bound)
	}
	t.Logf("b stopped serving the purged revision %v after the purge committed", time.Since(purged))
}

// A namespace made private on one instance is honoured by the other: its
// head pointers stop being public (cacheable at the edge) within freshFor.
func TestPGConfigOtherInstance(t *testing.T) {
	a, b := twoInstances(t)
	cfg := mkNS(t, a, "n", map[string]any{"read": "public"})
	if _, err := put(a, "n", "r", "", 1); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	within(t, 5*time.Second, "b's tailer", b.fresh)
	for i := 0; i < 2; i++ {
		h, err := b.ResourceHead(ctx, "n", "r", who.Cred)
		if err != nil || !h.Public {
			t.Fatalf("%v %v", h, err)
		}
	}
	r := who
	r.NS = "n"
	if _, err := a.WriteConfig(ctx, r, ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}}); err != nil {
		t.Fatal(err)
	}
	took := within(t, 5*time.Second, "b serving the namespace as public", func() bool {
		h, err := b.ResourceHead(ctx, "n", "r", who.Cred)
		return err == nil && !h.Public
	})
	if bound := b.freshFor(); took > bound {
		t.Fatalf("b served the namespace as public for %v, past %v", took, bound)
	}
}

// A lock below one held is only tried: busy, the transaction runs again
// with its locks in order, so two writers wanting each other's keys don't
// deadlock.
func TestPGLockOrder(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	holding, release := make(chan struct{}), make(chan struct{})
	bDone := make(chan error, 1)
	go func() {
		bDone <- b.update(ctx, func(t *tx) error {
			t.lockNS(1, lockExclusive)
			close(holding)
			<-release
			t.lockNS(2, lockExclusive) // waits for a, if a still holds 2
			return nil
		})
	}()
	<-holding
	var runs atomic.Int64
	aDone := make(chan error, 1)
	go func() {
		aDone <- a.update(ctx, func(t *tx) error {
			if runs.Add(1) == 1 {
				defer close(release)
			}
			t.lockNS(2, lockExclusive)
			t.lockNS(1, lockShared) // below 2 and held by b: tried
			return nil
		})
	}()
	for _, c := range []chan error{aDone, bDone} {
		select {
		case err := <-c:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("deadlock")
		}
	}
	if runs.Load() != 2 {
		t.Fatalf("a ran %d times, want 2 (rolled back once to lock in order)", runs.Load())
	}
}

// One instance at a time runs the background loops.
func TestPGLeader(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	if !a.leader(ctx) || b.leader(ctx) {
		t.Fatal("want a leading and b not")
	}
	a.Close()
	if !b.leader(ctx) {
		t.Fatal("b didn't take over")
	}
}

// D.8: a leader checks that it still holds the lock before each step of a
// job, and stops once it lost it. Calls outside a leader's job proceed.
func TestPGLeaderJobStep(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	if !a.leader(ctx) {
		t.Fatal("a isn't leading")
	}
	job := leaderJob(ctx)
	if err := a.jobStep(job); err != nil {
		t.Fatalf("leader's step: %v", err)
	}
	if err := b.jobStep(job); !errors.Is(err, errLostLeader) {
		t.Fatalf("non-leader's step: %v", err)
	}
	if err := b.jobStep(ctx); err != nil {
		t.Fatalf("a call outside a job: %v", err)
	}
	// a loses its session: its next step stops.
	a.leaderMu.Lock()
	_, err := a.leaderConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1, 0)`, leaderClass)
	a.leaderMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.jobStep(job); !errors.Is(err, errLostLeader) {
		t.Fatalf("step after losing the lock: %v", err)
	}
}

// D.8: on SQLite the one instance always leads.
func TestLeaderJobStepSQLite(t *testing.T) {
	e, err := Open(Options{Path: ":memory:", AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.jobStep(leaderJob(context.Background())); err != nil {
		t.Fatal(err)
	}
}
