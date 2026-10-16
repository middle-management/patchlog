package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// liveEngine is authEngine with a writer and a reader of n, and the reader's
// first long-poll read at the head: its empty log and pass.
func liveEngine(t *testing.T, clock *atomic.Int64, reader map[string]any) (e *Engine, admin, rd Credentials, cfg, head string, pass *LivePass) {
	t.Helper()
	e, mint, cfg := authEngine(t, clock)
	admin = Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"n"}, "can": []any{"read", "create", "append", "config"}})}
	rd = Credentials{Bearer: mint(reader)}
	ctx := context.Background()
	if _, err := e.WriteResource(ctx, Request{NS: "n", Cred: admin}, Item{Resource: "a", IfNoneMatch: true,
		Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 0.0}}}}}}); err != nil {
		t.Fatal(err)
	}
	h, err := e.NamespaceHead(ctx, "n", admin)
	if err != nil {
		t.Fatal(err)
	}
	lg, pass, err := e.NamespaceLiveLog(ctx, "n", h.Head, 1000, rd, nil)
	if err != nil || lg.Status != 200 || len(lg.Entries) != 0 {
		t.Fatalf("first read: %+v %v", lg, err)
	}
	return e, admin, rd, cfg, h.Head, pass
}

func appendA(t *testing.T, e *Engine, admin Credentials, n float64) {
	t.Helper()
	h, err := e.ResourceHead(context.Background(), "n", "a", admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteResource(context.Background(), Request{NS: "n", Cred: admin}, Item{Resource: "a", IfMatch: h.Head,
		Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": n}}}}}); err != nil {
		t.Fatal(err)
	}
}

// Waiters of a namespace woken by one write make one read between them
// (§7.7, live.go): every waiter holding a pass joins it, or asks after it
// is done, and each gets the write's entry.
func TestLiveLogShared(t *testing.T) {
	var clock atomic.Int64
	e, admin, rd, _, head, pass := liveEngine(t, &clock, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})
	if pass == nil {
		t.Fatal("no pass for a grant without time-dependent rules")
	}
	appendA(t, e, admin, 1)
	const waiters = 50
	joins, reads := e.liveJoins.Load(), e.liveShared.Load()
	// The shared read waits until every waiter has asked for it.
	testLiveRead = func(e *Engine) {
		within(t, 10*time.Second, "the waiters", func() bool { return e.liveJoins.Load() >= joins+waiters })
	}
	t.Cleanup(func() { testLiveRead = nil })
	var wg sync.WaitGroup
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lg, p, err := e.NamespaceLiveLog(context.Background(), "n", head, 1000, rd, pass)
			switch {
			case err != nil:
				errs <- err
			case p != pass || len(lg.Entries) != 1 || lg.Entries[0]["resource"] != "a":
				errs <- fmt.Errorf("waiter: %+v, pass %v", lg, p)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := e.liveShared.Load() - reads; n != 1 {
		t.Fatalf("%d reads for %d waiters", n, waiters)
	}
	// A waiter of the same write that asks once the read is done gets
	// its answer too, without another read.
	testLiveRead = nil
	lg, _, err := e.NamespaceLiveLog(context.Background(), "n", head, 1000, rd, pass)
	if err != nil || len(lg.Entries) != 1 || e.liveShared.Load()-reads != 1 {
		t.Fatalf("a late waiter: %+v %v, %d reads", lg, err, e.liveShared.Load()-reads)
	}
	// After the next write, the answer is read again.
	appendA(t, e, admin, 2)
	lg, _, err = e.NamespaceLiveLog(context.Background(), "n", head, 1000, rd, pass)
	if err != nil || len(lg.Entries) != 2 || e.liveShared.Load()-reads != 2 {
		t.Fatalf("after the next write: %+v %v, %d reads", lg, err, e.liveShared.Load()-reads)
	}
}

// A waiter woken by a later write doesn't join a read that began before
// it (which may not see the write): it reads on its own, and gets the
// write, while the earlier read is still under way.
func TestLiveLogLaterWrite(t *testing.T) {
	var clock atomic.Int64
	e, admin, rd, _, head, pass := liveEngine(t, &clock, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})
	started, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	testLiveRead = func(*Engine) {
		if first.CompareAndSwap(false, true) {
			close(started)
			<-release
		}
	}
	t.Cleanup(func() { testLiveRead = nil })
	early := make(chan error, 1)
	go func() {
		_, _, err := e.NamespaceLiveLog(context.Background(), "n", head, 1000, rd, pass)
		early <- err
	}()
	<-started
	appendA(t, e, admin, 1)
	type res struct {
		n   int
		err error
	}
	later := make(chan res, 1)
	go func() {
		lg, _, err := e.NamespaceLiveLog(context.Background(), "n", head, 1000, rd, pass)
		if err != nil {
			later <- res{err: err}
			return
		}
		later <- res{n: len(lg.Entries)}
	}()
	select {
	case r := <-later:
		if r.err != nil || r.n != 1 {
			t.Fatalf("after the write: %d entries, %v", r.n, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the later waiter joined the read that began before the write")
	}
	close(release)
	if err := <-early; err != nil {
		t.Fatal(err)
	}
}

// A pass ends with the configuration it was decided under (a revocation
// here), with its grant's expiry, and isn't given for a decision that
// depends on the time.
func TestLivePassEnds(t *testing.T) {
	ctx := context.Background()
	t.Run("revoked", func(t *testing.T) {
		var clock atomic.Int64
		e, admin, rd, cfg, head, pass := liveEngine(t, &clock, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})
		g, err := grant.Decode(rd.Bearer, 0)
		if err != nil {
			t.Fatal(err)
		}
		revoke := []any{map[string]any{"op": "add", "path": "/revoked", "value": []any{g.RevocationIDs()[0]}}}
		gen := e.rc.nsGen("n").Load()
		if _, err := e.WriteConfig(ctx, Request{NS: "n", Cred: admin}, ConfigChange{Patches: revoke, IfMatch: cfg}); err != nil {
			t.Fatal(err)
		}
		tailed(t, e, "n", gen)
		if _, p, err := e.NamespaceLiveLog(ctx, "n", head, 1000, rd, pass); status(err) != 401 || p != nil {
			t.Fatalf("a revoked grant's pass: %v %v", p, err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		var clock atomic.Int64
		clock.Store(time.Now().UnixMilli())
		exp := time.UnixMilli(clock.Load()).Add(time.Minute).UTC().Format(time.RFC3339)
		e, _, rd, _, head, pass := liveEngine(t, &clock, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}, "exp": exp})
		if pass == nil {
			t.Fatal("no pass")
		}
		clock.Add(2 * time.Minute.Milliseconds())
		if _, p, err := e.NamespaceLiveLog(ctx, "n", head, 1000, rd, pass); status(err) != 401 || p != nil {
			t.Fatalf("an expired grant's pass: %v %v", p, err)
		}
	})
	t.Run("time-dependent", func(t *testing.T) {
		var clock atomic.Int64
		_, _, _, _, _, pass := liveEngine(t, &clock, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"},
			"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
		if pass != nil {
			t.Fatal("a pass for a grant whose rules read /now")
		}
	})
}
