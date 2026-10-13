package janitor_test

import (
	"testing"

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
	wantKeep(t, d, "already purged")
	if d.Purge != head {
		t.Fatalf("decision %+v, want the purge %s", d, head)
	}
	ds, err := j.Sweep(ctx)
	if err != nil || len(ds) != 1 || ds[0].NS != "old" {
		t.Fatalf("sweep %+v %v", ds, err)
	}
}
