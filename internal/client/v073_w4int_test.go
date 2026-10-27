package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 §E.3.1, Addendum E Levels (P35 x P36): a prune in an e2e branch
// whose horizon's chain is, past tombstones and restores with [], a
// base's content from before the base's raise from sealed seals its
// snapshot under the epoch the base serves that revision under: kid and
// K_r name the base, pl the branch, as the server checks it (P36's
// snapshotKid). The key comes from /keys as at E2, with no sender, which
// is enough for content the server held before the raise.
func TestV073W4IntBranchPruneOfPreRaiseContent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed"})
	t0 := v.s.Now()
	r1 := must(v.c.Create(ctx, "e", "d", ops(op("add", "", map[string]any{"n": 1.0}), op("add", "/$nonce", seal.NewNonce())))).ID
	r2 := must(v.c.Append(ctx, "e", "d", r1, ops(op("replace", "/n", 2.0), op("replace", "/$nonce", seal.NewNonce())))).ID
	v.s.Clock.Advance(time.Minute)
	v.p35Raise(t, map[string]any{"level": "e2e", "epoch": 2.0})
	must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	v.s.Clock.Advance(10 * time.Minute) // past what a prune protects

	// A reader whose grant's nbf reaches back before the raise: /keys
	// gives it the base's epoch 1 as at E2 (ENC-42).
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	g := v.k.Grant(t, v.s.Now(), "user:a", []string{"e", "eb"}, p29Verbs, map[string]any{"enc": jwk, "nbf": t0.Format(time.RFC3339)})
	c := v.s.Client(t, client.WithBearer(g))
	x := c.E2E(priv)

	if d := must(x.DocE2E(ctx, "eb", "d", r2)); !d.PreRaise || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("the base's revision from before its raise, read through the branch: %+v", d)
	}
	// The branch prunes nothing of the base's, but checks the snapshot.
	if _, err := x.PruneE2E(ctx, "eb", "d", r2); err != nil {
		t.Fatalf("prune in the branch at the base's pre-raise revision: %v", err)
	}

	// Past a tombstone and a restore with [] of the branch's own, the
	// snapshot is still set by the base's pre-raise revision.
	tomb := must(c.Delete(ctx, "eb", "d", r2)).ID
	back := must(x.RestoreSealed(ctx, "eb", "d", tomb, nil)).ID
	v.s.Clock.Advance(10 * time.Minute)
	if _, err := x.PruneE2E(ctx, "eb", "d", back); err != nil {
		t.Fatalf("prune in the branch past its tombstone and restore with []: %v", err)
	}
	// A revision written end to end in the branch sets it from then on:
	// the branch's own epoch, from its keyring.
	must(v.x.InitKeyring(ctx, "eb", priv.PublicKey()))
	x = x.WithSenders(v.priv.PublicKey())
	w := must(x.AppendSealed(ctx, "eb", "d", back, ops(op("replace", "/n", 3.0)))).ID
	v.s.Clock.Advance(10 * time.Minute)
	if _, err := x.PruneE2E(ctx, "eb", "d", w); err != nil {
		t.Fatalf("prune in the branch at a revision written end to end: %v", err)
	}
}
