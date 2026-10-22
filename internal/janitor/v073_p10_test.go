package janitor_test

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

// §F.6 (v0.63): a branch is purged as a state only by a member of its own
// cleanup for that state; the base's cleanup sets minimums only, and cleanup
// isn't copied into branches (§7.6). Here the base declares its period
// after the branch was created, so the branch has none of its own whatever
// the branch's genesis copies.
func TestV073BaseCleanupAloneNeverPurges(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "r7", nil)
	e.edit("r7", "derby", "1-0")
	e.config("matches", op("add", "/cleanup", map[string]any{"merged": "P1D"}))
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	e.s.Clock.Advance(30 * day)
	d := e.sweep(false)["r7"]
	wantKeep(t, d, "merged, but no cleanup period for merged in the branch")
	if d.Claim != "merged" {
		t.Fatalf("decision %+v: the claim is verified", d)
	}
	if e.purged("r7") {
		t.Fatal("purged on the base's cleanup alone")
	}
}

// §F.6: without a member for one verified state the branch isn't purged as
// that state, but may be as another. A branch with no document entries of
// its own counts as merged; with cleanup only for abandoned, it is purged
// as abandoned (the flag set in development mode, which counts while the
// deployment runs with authentication disabled, §1).
func TestV073PurgedAsTheStateWithAPeriod(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "empty", map[string]any{"abandoned": "PT1H"})
	e.config("empty", op("add", "/frozen", true), op("add", "/abandoned", true))
	e.s.Clock.Advance(2 * time.Hour)
	if d := e.sweep(false)["empty"]; d.Action != janitor.ActionPurged || d.Claim != "abandoned" {
		t.Fatalf("decision %+v, want purged as abandoned", d)
	}
}

// §F.6 (v0.63): the cleanup period counts from the last config write that
// froze the branch or set merged, successor or abandoned, not from the
// first freezing write; other config writes, such as one changing
// cleanup, don't restart it.
func TestV073PeriodFromLastClaimWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"merged": "P10D"})
	e.branch("matches", "r8", map[string]any{"merged": "P10D"})
	e.edit("r7", "derby", "1-0")
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	must(e.c.CreateDoc(ctx, "r8", "cup", map[string]any{"score": "2-0"}))
	must(merge.Freeze(ctx, e.c, "r8", e.merge("r8")))
	t0 := e.s.Clock.Now()

	e.s.Clock.Advance(5 * day)
	t5 := e.s.Clock.Now()
	e.config("r7", op("add", "/abandoned", true))                                                    // sets a claim: restarts
	e.config("r8", op("replace", "/cleanup", map[string]any{"merged": "P10D", "superseded": "P1D"})) // doesn't

	e.s.Clock.Advance(6 * day) // t0+11d
	ds := e.sweep(false)
	wantKeep(t, ds["r7"], "merged; cleanup period runs until "+t5.Add(10*day).UTC().Format(time.RFC3339))
	if !ds["r7"].FrozenAt.Equal(t5) || !ds["r7"].EligibleAt.Equal(t5.Add(10*day)) {
		t.Fatalf("r7 %+v, want the period from %v", ds["r7"], t5)
	}
	if ds["r8"].Action != janitor.ActionPurged || !ds["r8"].FrozenAt.Equal(t0) {
		t.Fatalf("r8 %+v, want purged, its period from %v", ds["r8"], t0)
	}

	e.s.Clock.Advance(5 * day) // t5+11d
	if d := e.sweep(false)["r7"]; d.Action != janitor.ActionPurged || d.Claim != "merged" {
		t.Fatalf("r7 %+v", d)
	}
}
