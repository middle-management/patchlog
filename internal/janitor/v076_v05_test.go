package janitor_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

// v05ConfigBatch writes a batch on ns that changes its config (merge
// authors) and, where items is given, those items too (§7.5: items may be
// empty when config is present).
func v05ConfigBatch(t *testing.T, e *env, ns string, items ...client.BatchItem) {
	t.Helper()
	h := must(e.c.NSHead(ctx, ns))
	must(e.c.Batch(ctx, ns, client.BatchRequest{
		Config: &client.BatchConfig{IfMatch: h.Config, Patches: []any{
			op("add", "/merge", map[string]any{"authors": []any{map[string]any{"sub": "bob", "kid": "dev"}}}),
		}},
		Items: items,
	}, false))
}

// OTHER-1 (§F.6, CONFORMANCE Merge 61): a batch in the branch's log counts
// as a batch entry only through its items. A config-only batch after
// source.at leaves the merged check passing, and a branch whose only write
// is one has no entries of its own. A batch with items fails the check
// after source.at, even where its items are for resources purged in the
// branch since (those aren't own entries, but the rule after source.at
// names every batch with items).
func TestV076ConfigOnlyBatchAfterSourceAt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)

	// r7: merged with a counting batch, then a config-only batch.
	e.branch("matches", "r7", map[string]any{"merged": "P1D"})
	e.edit("r7", "derby", "1-0")
	at := e.merge("r7")
	v05ConfigBatch(t, e, "r7")
	must(merge.Freeze(ctx, e.c, "r7", at))

	// r8: never merged, its only write a config-only batch.
	e.branch("matches", "r8", map[string]any{"merged": "P1D"})
	v05ConfigBatch(t, e, "r8")
	must(merge.Freeze(ctx, e.c, "r8", must(e.c.NSHead(ctx, "matches")).ID))

	// r9: merged, then a batch with a config change and an item for a
	// resource purged in the branch afterwards.
	e.branch("matches", "r9", map[string]any{"merged": "P1D"})
	e.edit("r9", "derby", "2-0")
	at9 := e.merge("r9")
	v05ConfigBatch(t, e, "r9", client.BatchItem{Resource: "x", IfNoneMatch: true,
		Steps: []client.Step{client.PatchStep([]any{op("add", "", map[string]any{"score": "0-0"})})}})
	must(e.c.Purge(ctx, "r9", "x", must(e.c.Head(ctx, "r9", "x")).ID, false))
	must(merge.Freeze(ctx, e.c, "r9", at9))

	e.s.Clock.Advance(2 * day)
	ds := e.sweep(false)
	for _, ns := range []string{"r7", "r8"} {
		if d := ds[ns]; d.Action != janitor.ActionPurged || d.Claim != "merged" || !e.purged(ns) {
			t.Errorf("%s: decision %+v, want purged as merged", ns, d)
		}
	}
	wantKeep(t, ds["r9"], "the branch changed documents after")
	if e.purged("r9") {
		t.Fatal("r9 purged")
	}
}
