package index_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// Final review (I2; v0.26.1): pr, public and indexed, is made private, and the
// index's grant stops verifying for it in the same config write (its key
// is replaced), as TestV0261PrivateAndLockedOutPurged does for the tree
// service. The follower can't read the entry (401), so no apply narrows
// (narrowed), and the index's follow loop restarts on any error without
// purging: idx:pr is never sent to its Purger, and the public, immutable
// results it served for pr stay in a CDN only the index purges idx:pr in
// (§9, §A.1). The tree service purges for such a refusal (purgeStopped).
func TestV0261IndexPrivateAndLockedOutPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k, k2 := clienttest.NewKey("k"), clienttest.NewKey("k2")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret q7zx"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now})
	x.caughtUp("pr")
	r := x.raw("/pr?limit=7", "")
	loc := r.header.Get("Location")
	got := x.raw(loc, "")
	if got.status != 200 || !strings.Contains(fmt.Sprint(got.body), "/r/pr/a/") || !strings.Contains(got.header.Get("Cache-Control"), "public") {
		t.Fatalf("setup: %s %d %q %v", loc, got.status, got.header.Get("Cache-Control"), got.body)
	}
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{
		map[string]any{"op": "replace", "path": "/read", "value": "grant"},
		map[string]any{"op": "replace", "path": "/keys", "value": []any{k2.Entry("*")}},
	}))
	sent := func() bool {
		x.mu.Lock()
		defer x.mu.Unlock()
		for _, tags := range x.purges {
			for _, tag := range tags {
				if tag == "idx:pr" {
					return true
				}
			}
		}
		return false
	}
	deadline := time.Now().Add(3 * time.Second)
	for !sent() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !sent() {
		t.Errorf("pr made private with the index locked out: idx:pr never sent to the Purger; %s was served %q with pr's hits", loc, got.header.Get("Cache-Control"))
	}
	if f := x.raw(loc, ""); f.status == 200 {
		t.Errorf("anonymous GET %s after: 200 %q", loc, f.header.Get("Cache-Control"))
	}
}

// Final review (I2; v0.26.1): pr, public and indexed, is raised to e2e, which an
// index without a keyring recipient key can't follow: Apply's
// keys.Recheck stops the follower without applying the batch (running),
// or follow()'s keys.Check skips pr for good at the start (down), and
// neither purges: idx:pr is never sent to the Purger, so the public,
// immutable results it served of pr in the clear stay in its CDN (§9,
// §A.1, §E.2.6). The tree service purges in both cases (purgeStopped).
//
// Since v0.81 the raise is to sealed and private for an index that holds
// no keys and fetches none: a raise to e2e is 422 (v0.78).
func TestV0261IndexRaiseToE2EWithoutKeys(t *testing.T) {
	t.Parallel()
	for _, down := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "while down"}[down], func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
			wJWK, wPriv, err := seal.GenerateRecipient()
			if err != nil {
				t.Fatal(err)
			}
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"}, map[string]any{"enc": wJWK})),
				client.WithKeys(client.NewKeys(wPriv)))
			must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret"}))
			ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})), client.WithKeys(client.StaticKeys()))
			db := filepath.Join(t.TempDir(), "i.db")
			x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
			x.caughtUp("pr")
			loc := x.raw("/pr?limit=7", "").header.Get("Location")
			got := x.raw(loc, "")
			if got.status != 200 || !strings.Contains(fmt.Sprint(got.body), "/r/pr/a/") || !strings.Contains(got.header.Get("Cache-Control"), "public") {
				t.Fatalf("setup: %s %d %q %v", loc, got.status, got.header.Get("Cache-Control"), got.body)
			}
			if down {
				x.stop()
			}
			must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{
				map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}},
				map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
			if down {
				x = startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
			}
			sent := func() bool {
				x.mu.Lock()
				defer x.mu.Unlock()
				for _, tags := range x.purges {
					for _, tag := range tags {
						if tag == "idx:pr" {
							return true
						}
					}
				}
				return false
			}
			deadline := time.Now().Add(3 * time.Second)
			for !sent() && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			st := x.raw("/pr?limit=7", "").status
			if !sent() {
				t.Errorf("pr raised to e2e, its keys out of the index's reach: idx:pr never sent to the Purger (anonymous /pr now %d); %s was served %q", st, loc, got.header.Get("Cache-Control"))
			}
		})
	}
}

// TestV0261IndexStopOncePerCheckpoint: as
// TestV0261IndexPrivateAndLockedOutPurged, then the index restarts on
// its database: refused again at the checkpoint it was stopped at, it
// purges nothing more (ns_stopped). Once pr is readable to it again (its
// key restored) and made public, the index applies that, the stop ends,
// and pr is answered anonymously.
func TestV0261IndexStopOncePerCheckpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k, k2 := clienttest.NewKey("k"), clienttest.NewKey("k2")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr")))
	must(op.CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "a"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	db := filepath.Join(t.TempDir(), "i.db")
	x := startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
	x.caughtUp("pr")
	count := func(x *svc) int {
		x.mu.Lock()
		defer x.mu.Unlock()
		n := 0
		for _, tags := range x.purges {
			for _, tag := range tags {
				if tag == "idx:pr" {
					n++
				}
			}
		}
		return n
	}
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{
		map[string]any{"op": "replace", "path": "/read", "value": "grant"},
		map[string]any{"op": "replace", "path": "/keys", "value": []any{k2.Entry("*")}},
	}))
	waitFor(t, "idx:pr purged", func() bool { return count(x) > 0 })
	time.Sleep(300 * time.Millisecond) // the follower's retries
	if n := count(x); n != 1 {
		t.Errorf("idx:pr purged %d times while refused at one checkpoint, want 1", n)
	}
	x.stop()
	x = startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
	time.Sleep(500 * time.Millisecond) // refused again at the same checkpoint
	if n := count(x); n != 0 {
		t.Errorf("after a restart, refused at the checkpoint it was stopped at: idx:pr purged %d times more", n)
	}
	w2 := s.Client(t, client.WithBearer(k2.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w2.PatchConfig(ctx, "pr", must(w2.NSHead(ctx, "pr")).Config, []any{
		map[string]any{"op": "replace", "path": "/keys", "value": []any{k.Entry("*"), k2.Entry("*")}},
		map[string]any{"op": "replace", "path": "/read", "value": "public"},
	}))
	waitFor(t, "anonymous /pr answered once the index follows pr again", func() bool {
		return x.follow("/pr?limit=5", "").status == 200
	})
}
