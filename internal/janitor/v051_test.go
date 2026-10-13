package janitor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// A sealed branch's document and log are 410 purged once it is purged,
// with head its purge-ns entry (§8.5): a branch whose successor is such a
// branch isn't superseded, a purged branch checked directly is kept as
// already purged, and the sweep leaves it out, as any purged branch.
func TestSealedPurged(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "merge": devAuthors, "encryption": map[string]any{"level": "sealed"}}))
	must(c.Create(ctx, "matches", "derby", append(client.GenesisPatches(map[string]any{"score": "0-0"}), op("add", "/$nonce", seal.NewNonce()))))
	must(c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "old", Patches: []any{op("add", "/cleanup", map[string]any{"superseded": "P1D"})}}))
	// A change of its own, which the successor doesn't carry.
	h := must(c.Head(ctx, "old", "derby"))
	must(c.Append(ctx, "old", "derby", h.ID, []any{op("replace", "/score", "1-0"), op("replace", "/$nonce", seal.NewNonce())}))
	must(c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "new"}))
	must(c.PatchConfig(ctx, "old", must(c.NSHead(ctx, "old")).Config, []any{op("add", "/frozen", true), op("add", "/successor", "new")}))
	must(c.PatchConfig(ctx, "new", must(c.NSHead(ctx, "new")).Config, []any{op("add", "/frozen", true)}))
	head := must(c.PurgeNamespace(ctx, "new", must(c.NSHead(ctx, "new")).ID))
	if _, err := c.NSDoc(ctx, "new", head); !client.IsPurged(err) {
		t.Fatalf("the purged sealed branch's document: %v", err)
	}

	j := janitor.New(c, janitor.Options{Bases: []string{"matches"}, Now: s.Clock.Now})
	d, err := j.Check(ctx, "matches", "old")
	if err != nil {
		t.Fatal(err)
	}
	wantKeep(t, d, "successor new is purged")
	d, err = j.Check(ctx, "matches", "new")
	if err != nil {
		t.Fatal(err)
	}
	wantKeep(t, d, "already purged (purge-ns "+head+")")
	if d.Purge != "" {
		t.Fatalf("decision %+v: the janitor purged nothing", d)
	}
	ds, err := j.Sweep(ctx)
	if err != nil || len(ds) != 1 || ds[0].NS != "old" {
		t.Fatalf("sweep %+v %v", ds, err)
	}

	// A base that is a purged sealed namespace ends its follower at once,
	// its long-poll being 410 (§8.5): Run goes on sweeping the others.
	must(c.CreateNamespace(ctx, "gone", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	must(c.PatchConfig(ctx, "gone", must(c.NSHead(ctx, "gone")).Config, []any{op("add", "/frozen", true)}))
	must(c.PurgeNamespace(ctx, "gone", must(c.NSHead(ctx, "gone")).ID))
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sweeps := make(chan struct{}, 16)
	j = janitor.New(c, janitor.Options{Bases: []string{"gone", "matches"}, Now: s.Clock.Now, Interval: 20 * time.Millisecond,
		OnDecision: func(d janitor.Decision) {
			if d.NS == "old" {
				select {
				case sweeps <- struct{}{}:
				default:
				}
			}
		}})
	ran := make(chan error, 1)
	go func() { ran <- j.Run(rctx) }()
	for n := 0; n < 3; n++ {
		select {
		case <-sweeps:
		case err := <-ran:
			t.Fatalf("Run ended after %d sweeps: %v", n, err)
		case <-rctx.Done():
			t.Fatal("no sweeps")
		}
	}
	cancel()
	if err := <-ran; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
}
