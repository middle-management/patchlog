package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 §E.3.2 (ENC-25): a revision a fold flags only for its padding is
// still folded, so OpenLog gives a merge its patches and the merge carries
// it, re-sealed and padded for the target, rather than calling it
// unreadable.
func TestV073P29MergeCarriesUnpaddedRevision(t *testing.T) {
	t.Parallel()
	e := newE3(t, map[string]any{"encryption": map[string]any{"level": "e2e", "pad": true}, "merge": devAuthors})
	e.branch("b")
	h := must(e.c.Head(ctx, "b", "derby"))
	kr := must(seal.ResourceKey(must(e.x.Key(ctx, "b#1")), "b", "derby"))
	unpadded := must(seal.SealPatchSet(kr, "b#1", "b", "derby", h.ID, jsonv.FromGo(ops(map[string]any{"op": "replace", "path": "/score", "value": "2-0"}))))
	must(e.c.Append(ctx, "b", "derby", h.ID, unpadded))
	_, d := must2(e.x.LoadE2E(ctx, "b", "derby"))
	if len(d.Flagged) != 1 {
		t.Fatalf("the unpadded revision isn't flagged: %+v", d)
	}
	p := e.plan("m", "b")
	r := p.Resource("derby")
	if r == nil || len(r.Conflicts) != 0 || !r.HasItem() {
		t.Fatalf("derby in the plan: %+v", r)
	}
	must(p.Apply(ctx))
	if got := e.doc("m", "derby").(map[string]any)["score"]; got != "2-0" {
		t.Fatalf("merged score %v", got)
	}
}
