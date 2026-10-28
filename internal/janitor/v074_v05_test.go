package janitor_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/janitor"
)

// TOOLS-1 (§F.6, MRG-4, Open 112): a branch whose only entries of its own
// are for resources purged in it counts as merged, with no merged claim
// and no merge batch in the base.
func TestV074MergedSkipsPurgedResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "scratch", map[string]any{"merged": "PT0S"})
	must(e.c.CreateDoc(ctx, "scratch", "x", map[string]any{"score": "0-0"}))
	e.edit("scratch", "x", "2")
	h := must(e.c.Head(ctx, "scratch", "x"))
	must(e.c.Purge(ctx, "scratch", "x", h.ID, false))
	e.config("scratch", op("add", "/frozen", true))
	if d := e.sweep(false)["scratch"]; d.Action != janitor.ActionPurged || d.Claim != "merged" {
		t.Fatalf("decision %+v, want purged as merged", d)
	}

}
