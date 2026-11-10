package client_test

import (
	"context"
	"testing"
	"time"
)

// v0.73 §7.1 Paging, P35, re-pinned on a namespace e2e from its creation
// (v0.78: a raise to e2e is 422, and the folds across it are gone, with
// TestV073P35FoldAcrossRaiseFromSealed, FoldAcrossRaiseFromNone,
// ValidatesAgainstPreRaiseSchema and ValidatesUnderPreRaiseSchemaRules):
// an E3 reader folds a restore over a tombstone from the last live
// document before it, and a prune's snapshot of the fold seals under the
// epoch in force, which the reader then starts from (§E.3.1, §8.6).
func TestV073P35FoldRestoreOverTombstone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "e2e", "pad": true})
	r1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0})).ID
	r2 := must(v.x.AppendSealed(ctx, "e", "d", r1, ops(op("replace", "/n", 2.0)))).ID
	t1 := must(v.x.CreateDocSealed(ctx, "e", "t", map[string]any{"m": 1.0})).ID
	tomb := must(v.c.Delete(ctx, "e", "t", t1)).ID
	t2 := must(v.x.RestoreSealed(ctx, "e", "t", tomb, ops(op("replace", "/m", 2.0)))).ID
	d := must(v.x.DocE2E(ctx, "e", "t", t2))
	if d.Value.(map[string]any)["m"] != 2.0 || len(d.Flagged) != 0 || d.ValidID != t2 {
		t.Fatalf("fold of a restore over a tombstone: %+v", d)
	}
	r3 := must(v.x.AppendSealed(ctx, "e", "d", r2, ops(op("replace", "/n", 3.0)))).ID
	v.s.Clock.Advance(10 * time.Minute)
	must(v.x.PruneE2E(ctx, "e", "d", r3))
	if d := must(v.x.DocE2E(ctx, "e", "d", r3)); d.Value.(map[string]any)["n"] != 3.0 || d.Kid() != "e#1" {
		t.Fatalf("after the prune: %+v", d)
	}
}
