package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// v0.73 §E.3.1 (P35 x P36), re-pinned on a base e2e from its creation
// (v0.78: no raise, so no base content from before one; formerly
// TestV073W4IntBranchPruneOfPreRaiseContent): a prune in an e2e branch
// whose horizon's chain is, past tombstones and restores with [], the
// base's content read through seals its snapshot under the branch's own
// epoch in force (snapshotKid always names the namespace pruned: the
// base's op isn't the branch's own), with K_r and pl the branch's, as the
// server checks it; a revision the branch writes itself sets it from then
// on. At the tombstone horizon the snapshot is bound to the tombstone's
// parent (§7.1, E2E-5).
func TestV073W4IntBranchPruneOfBaseContent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	r1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0})).ID
	r2 := must(v.x.AppendSealed(ctx, "e", "d", r1, ops(op("replace", "/n", 2.0)))).ID
	must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	must(v.x.InitKeyring(ctx, "eb"))
	v.s.Clock.Advance(10 * time.Minute) // past what a prune protects

	if d := must(v.x.DocE2E(ctx, "eb", "d", r2)); d.Value.(map[string]any)["n"] != 2.0 || len(d.Flagged) != 0 {
		t.Fatalf("the base's revision read through the branch: %+v", d)
	}
	// The branch prunes nothing of the base's, but checks the snapshot.
	if _, err := v.x.PruneE2E(ctx, "eb", "d", r2); err != nil {
		t.Fatalf("prune in the branch at the base's revision: %v", err)
	}

	// Past a tombstone and a restore with [] of the branch's own, the
	// snapshot is still set by the base's revision: the epoch in force.
	tomb := must(v.c.Delete(ctx, "eb", "d", r2)).ID
	back := must(v.x.RestoreSealed(ctx, "eb", "d", tomb, nil)).ID
	v.s.Clock.Advance(10 * time.Minute)
	if _, err := v.x.PruneE2E(ctx, "eb", "d", back); err != nil {
		t.Fatalf("prune in the branch past its tombstone and restore with []: %v", err)
	}
	// A revision written end to end in the branch sets it from then on:
	// the branch's own epoch, from its keyring.
	w := must(v.x.AppendSealed(ctx, "eb", "d", back, ops(op("replace", "/n", 3.0)))).ID
	v.s.Clock.Advance(10 * time.Minute)
	if _, err := v.x.PruneE2E(ctx, "eb", "d", w); err != nil {
		t.Fatalf("prune in the branch at a revision written end to end: %v", err)
	}
	if d := must(v.x.DocE2E(ctx, "eb", "d", w)); d.Value.(map[string]any)["n"] != 3.0 || d.Kid() != "eb#1" {
		t.Fatalf("after the prune: %+v (kid %q)", d, d.Kid())
	}
}
