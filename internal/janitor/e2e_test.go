package janitor_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// newE3Merged returns an e2e base "matches" and a branch r7 (with its own
// keyring and cleanup merged: P1D) merged into it, not yet frozen, with a
// key holder x and the merge batch's ns_id.
func newE3Merged(t *testing.T) (*env, *client.E2E, string) {
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"))
	e := &env{t: t, s: s, c: c}
	_, priv, _ := seal.GenerateRecipient()
	x := c.E2E(priv)
	must(c.CreateNamespace(ctx, "matches", map[string]any{"encryption": map[string]any{"level": "e2e"}, "merge": devAuthors}))
	must(x.InitKeyring(ctx, "matches"))
	must(x.CreateDocSealed(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
	e.branch("matches", "r7", map[string]any{"merged": "P1D"})
	must(x.InitKeyring(ctx, "r7"))
	h := must(c.Head(ctx, "r7", "derby"))
	must(x.AppendSealed(ctx, "r7", "derby", h.ID, []any{op("replace", "/score", "1-0")}))

	p := must(merge.NewPlan(ctx, c, "matches", "r7", merge.Options{E2E: x}))
	res := must(p.Apply(ctx))
	if must(c.Head(ctx, "matches", "derby")).ID == must(c.Head(ctx, "r7", "derby")).ID {
		t.Fatal("fast-forwarded")
	}
	return e, x, res.NSID
}

// An e2e branch's merge re-encrypts (no ids in common with the base), yet
// the merged claim verifies from the base's plaintext namespace log alone:
// the merge batch's source and merge.authors. The janitor holds no keys
// (§F.6, §F.8.1). Keyring edits after the merge, a head entry and a batch
// with the epoch bump, don't count against it (the keyring is never
// merged), and the base still folds after the purge.
func TestE2EMergedBranchPurgedWithoutKeys(t *testing.T) {
	e, x, at := newE3Merged(t)
	_, reader, _ := seal.GenerateRecipient()
	must(x.AddReader(ctx, "r7", reader.PublicKey(), false))
	must(x.RotateEpoch(ctx, "r7", reader.PublicKey()))
	must(merge.Freeze(ctx, e.c, "r7", at))
	e.s.Clock.Advance(2 * day)
	d := e.sweep(false)["r7"]
	if d.Action != janitor.ActionPurged || d.Claim != "merged" {
		t.Fatalf("decision %+v", d)
	}
	_, doc := must2(e.c.E2EKeys(map[string][]byte{"matches#1": must(x.Key(ctx, "matches#1"))}).LoadE2E(ctx, "matches", "derby"))
	if doc.Value.(map[string]any)["score"] != "1-0" || len(doc.Flagged) > 0 {
		t.Fatalf("base after purge %+v", doc)
	}
}

// Any other document change after the merge still keeps the branch.
func TestE2EBranchChangedAfterMergeKept(t *testing.T) {
	e, x, at := newE3Merged(t)
	h := must(e.c.Head(ctx, "r7", "derby"))
	must(x.AppendSealed(ctx, "r7", "derby", h.ID, []any{op("replace", "/score", "2-0")}))
	must(merge.Freeze(ctx, e.c, "r7", at))
	e.s.Clock.Advance(2 * day)
	wantKeep(t, e.sweep(false)["r7"], "changed documents after")
	if e.purged("r7") {
		t.Fatal("purged")
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}
