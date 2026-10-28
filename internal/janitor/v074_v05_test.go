package janitor_test

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
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

// TOOLS-2 (§F.6, §8.5, Open 113): a successor purged after the branch was
// last frozen still counts for superseded only where the janitor read what
// the check needs before the purge. A replay under a * key of the branch
// (tmp, not in merge.authors) needs its stored grant, which the purged
// successor no longer serves: a janitor that never read it keeps the
// branch (r7), and one that checked the branch while the successor was
// live, reading its /grants, purges it as superseded later (r8).
func TestV074SupersededGrantReadBeforePurge(t *testing.T) {
	t.Parallel()
	a := newAuthEnv(t, []string{"r7", "r7-b", "r8", "r8-b"}, nil)
	var after time.Duration
	j := janitor.New(a.janitor, janitor.Options{Now: func() time.Time { return a.s.Now().Add(after) }})
	for _, br := range []string{"r7", "r8"} {
		a.branch(t, "matches", br, map[string]any{"superseded": "P1D"})
		must(merge.Rebase(ctx, a.as(a.tmp, "user:tmp"), merge.RebaseOptions{Branch: br, New: br + "-b", Switch: true}))
	}
	// Before the purge, within the cleanup period: r8 is verified, its
	// replay's grant read from r8-b.
	if d := must(j.Check(ctx, "matches", "r8")); d.Action != janitor.ActionKeep || d.Claim != "superseded" {
		t.Fatalf("r8 before the purge: %+v", d)
	}
	a.s.Clock.Advance(time.Minute)
	for _, ns := range []string{"r7-b", "r8-b"} {
		patchConfig(t, a.admin, ns, op("add", "/frozen", true))
		must(a.admin.PurgeNamespace(ctx, ns, must(a.admin.NSHead(ctx, ns)).ID))
	}
	after = 2 * day
	wantKeep(t, must(j.Check(ctx, "matches", "r7")), "can't be read since r7-b was purged (§8.5), and the janitor didn't read it before the purge")
	if d := must(j.Check(ctx, "matches", "r8")); d.Action != janitor.ActionPurged || d.Claim != "superseded" {
		t.Fatalf("r8 after the purge: %+v", d)
	}
}

// A batch of the branch's own that changes only its config (§7.5: items
// may be empty when config is present), or its config and resources purged
// in it, is a batch entry of its own: the branch doesn't count as merged
// by the no-own-entries rule (§F.6), and its unmerged config change isn't
// purged.
func TestV074ConfigBatchIsOwnEntry(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	authors := op("add", "/merge", map[string]any{"authors": []any{map[string]any{"sub": "bob", "kid": "dev"}}})
	e.branch("matches", "scratch", map[string]any{"merged": "PT0S"})
	h := must(e.c.NSHead(ctx, "scratch"))
	must(e.c.Batch(ctx, "scratch", client.BatchRequest{Config: &client.BatchConfig{IfMatch: h.Config, Patches: []any{authors}}}, false))
	e.config("scratch", op("add", "/frozen", true))

	e.branch("matches", "drafts", map[string]any{"merged": "PT0S"})
	h = must(e.c.NSHead(ctx, "drafts"))
	must(e.c.Batch(ctx, "drafts", client.BatchRequest{
		Config: &client.BatchConfig{IfMatch: h.Config, Patches: []any{authors}},
		Items:  []client.BatchItem{{Resource: "x", IfNoneMatch: true, Steps: []client.Step{client.PatchStep([]any{op("add", "", map[string]any{"score": "0-0"})})}}},
	}, false))
	must(e.c.Purge(ctx, "drafts", "x", must(e.c.Head(ctx, "drafts", "x")).ID, false))
	e.config("drafts", op("add", "/frozen", true))

	ds := e.sweep(false)
	for _, ns := range []string{"scratch", "drafts"} {
		if d := ds[ns]; d.Action == janitor.ActionPurged || e.purged(ns) {
			t.Errorf("%s: decision %+v, a branch with a config batch of its own purged as merged", ns, d)
		}
	}
}

// newE3Branch returns an e2e base "matches" with a branch r7 (its own
// keyring, cleanup merged: P1D) that changes no document, and a key holder.
func newE3Branch(t *testing.T) (*env, *client.E2E) {
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
	return e, x
}

// At E3 the keyring is excepted (§F.6), and a batch with a keyring item
// counts only if it has other items: an epoch bump, config and keyring in
// one batch, leaves a branch with nothing else of its own merged. A batch
// with only a config change counts, as at other levels.
func TestV074E3ConfigBatchIsOwnEntry(t *testing.T) {
	t.Parallel()
	t.Run("epoch bump", func(t *testing.T) {
		t.Parallel()
		e, x := newE3Branch(t)
		_, reader, _ := seal.GenerateRecipient()
		must(x.RotateEpoch(ctx, "r7", reader.PublicKey()))
		e.config("r7", op("add", "/frozen", true))
		e.s.Clock.Advance(2 * day)
		if d := e.sweep(false)["r7"]; d.Action != janitor.ActionPurged || d.Claim != "merged" {
			t.Fatalf("decision %+v, want purged as merged", d)
		}
	})
	t.Run("config only", func(t *testing.T) {
		t.Parallel()
		e, _ := newE3Branch(t)
		h := must(e.c.NSHead(ctx, "r7"))
		must(e.c.Batch(ctx, "r7", client.BatchRequest{Config: &client.BatchConfig{IfMatch: h.Config,
			Patches: []any{op("add", "/merge", map[string]any{"authors": []any{map[string]any{"sub": "bob", "kid": "dev"}}})}}}, false))
		e.config("r7", op("add", "/frozen", true))
		e.s.Clock.Advance(2 * day)
		if d := e.sweep(false)["r7"]; d.Action == janitor.ActionPurged || e.purged("r7") {
			t.Fatalf("decision %+v, a branch with a config batch of its own purged as merged", d)
		}
	})
}
