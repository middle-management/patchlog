package janitor_test

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
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
