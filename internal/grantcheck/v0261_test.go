package grantcheck_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
)

// G1 (security review of v0.26.0), §C.4 requireAt: an at the cached heads
// don't reach has the heads read again at once, bypassing the TTL, before
// it is refused (TestV077ChainAtPastCachedHead). Any holder of a validly
// signed grant under a requireAt key could name an at in no chain, so
// each check of it read the chain's heads again, and reloaded what moved,
// with no single-flight and no minimum interval. Now those reads are one
// per namespace at a time, at least an interval apart, shared by the
// checks that wait meanwhile: many concurrent and back-to-back checks of
// such a grant cost a bounded number of head reads, and each is still
// refused (403). An at newer than every read is still found once the
// interval is out.
func TestV0261ForcedReloadBounded(t *testing.T) {
	ctx := context.Background()
	f := newChainFixture(t)
	ch := f.checker(time.Hour)
	const interval = 100 * time.Millisecond
	ch.SetMinForced(interval)
	head := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if _, err := ch.Verify(ctx, "sec", f.grantAt(head)); err != nil {
		t.Fatalf("at the head: %v", err)
	}
	bogus := f.grantAt("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	const workers, each = 32, 4
	n0 := f.heads.Load()
	start := time.Now()
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				if _, err := ch.Verify(ctx, "sec", bogus); authStatus(err) != 403 {
					t.Errorf("at not in the chain: %v, want 403", err)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	reads := f.heads.Load() - n0
	// One read per interval, and one more at each end.
	if bound := int64(elapsed/interval) + 2; reads > bound {
		t.Errorf("%d checks of an at in no chain read the head %d times in %v, want at most %d", workers*each, reads, elapsed, bound)
	}

	// Right after them, a grant at the new head verifies: its check waits
	// out the interval and reads the heads again.
	h := must(f.adminC.NSHead(ctx, "cat-season"))
	must(f.adminC.PatchConfig(ctx, "cat-season", h.Config, []any{map[string]any{"op": "add", "path": "/maxLag", "value": "PT90S"}}))
	moved := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if _, err := ch.Verify(ctx, "sec", bogus); authStatus(err) != 403 {
		t.Fatalf("at not in the chain: %v, want 403", err)
	}
	if _, err := ch.Verify(ctx, "sec", f.grantAt(moved)); err != nil {
		t.Fatalf("at the new head, right after a forced read: %v", err)
	}
}

// A check whose context ends while it waits for the heads to be read
// again gives up: a chain it can't read yet (503 behind), never a
// refusal.
func TestV0261ForcedReloadCanceled(t *testing.T) {
	f := newChainFixture(t)
	ch := f.checker(time.Hour)
	ch.SetMinForced(2 * time.Second)
	ctx := context.Background()
	head := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if _, err := ch.Verify(ctx, "sec", f.grantAt(head)); err != nil {
		t.Fatalf("at the head: %v", err)
	}
	bogus := f.grantAt("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	// The first forced read is due at once, the next one 2s later.
	if _, err := ch.Verify(ctx, "sec", bogus); authStatus(err) != 403 {
		t.Fatalf("at not in the chain: %v, want 403", err)
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err := ch.Verify(short, "sec", bogus)
	var ce *grantcheck.ChainError
	if !errors.As(err, &ce) || !ce.ChainUnreadable() {
		t.Fatalf("waiting past its deadline: %v, want a transient ChainError", err)
	}
}

// The same for a check whose context is canceled while it waits (its
// request gone): transient, 503 behind, not 502.
func TestV0261ForcedReloadCanceledTransient(t *testing.T) {
	f := newChainFixture(t)
	ch := f.checker(time.Hour)
	ch.SetMinForced(2 * time.Second)
	ctx := context.Background()
	head := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if _, err := ch.Verify(ctx, "sec", f.grantAt(head)); err != nil {
		t.Fatalf("at the head: %v", err)
	}
	bogus := f.grantAt("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := ch.Verify(ctx, "sec", bogus); authStatus(err) != 403 {
		t.Fatalf("at not in the chain: %v, want 403", err)
	}
	gone, cancel := context.WithCancel(ctx)
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := ch.Verify(gone, "sec", bogus)
	var ce *grantcheck.ChainError
	if !errors.As(err, &ce) || !ce.ChainUnreadable() {
		t.Fatalf("canceled while waiting: %v, want a transient ChainError", err)
	}
}

// A load of a namespace's state that began before an Observe of it (a
// follower applying a config entry, say) and ends after it is not stored:
// it may hold the document the Observe said is gone, fresh for the TTL.
// Here the checker's read of sec's document is held while sec is made
// private and the checker told so; the next check reads again, and gets
// the private document.
func TestV0261ObserveOvertakesLoad(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	var gate atomic.Value
	gate.Store("")
	hit, release := make(chan struct{}), make(chan struct{})
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := gate.Load().(string); p != "" && r.Method == "GET" && r.URL.Path == p && gate.CompareAndSwap(p, "") {
				close(hit)
				<-release
			}
			h.ServeHTTP(w, r)
		})
	}})
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "config"})), client.WithKeys(client.NewKeys(nil)))
	ch := grantcheck.New(s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:x", []string{"sec"}, []string{"read"})), client.WithKeys(client.NewKeys(nil))),
		grantcheck.WithClock(s.Now), grantcheck.WithTTL(time.Hour))
	h0 := must(w.NSHead(ctx, "sec"))
	gate.Store("/ns/sec/rev/" + h0.ID)
	done := make(chan *grantcheck.Config, 1)
	go func() { done <- must(ch.Config(ctx, "sec")) }()
	<-hit
	must(w.PatchConfig(ctx, "sec", h0.Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	ch.Observe("sec", must(w.NSHead(ctx, "sec")).ID)
	close(release)
	if c := <-done; c.Read != "public" {
		t.Fatalf("the load held: read %q, want the document it began at", c.Read)
	}
	if c := must(ch.Config(ctx, "sec")); c.Read != "grant" {
		t.Errorf("after the Observe, within the TTL: read %q, want grant (a load the Observe overtook was kept)", c.Read)
	}
}
