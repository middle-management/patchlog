package janitor_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

// §F.6 superseded, §7.4, §F.4, §F.5: a stacked branch rebased onto its
// base's base with -switch is frozen naming a successor further up its base
// chain. The core accepts that successor since v0.73 (wave 2), so the
// janitor verifies the claim from the documents the switch left, not only
// from a document built by hand (TestV073SuccessorUpTheBaseChain).
func TestV073W2SupersededUpTheChain(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "b1", nil)
	e.branch("b1", "r7", map[string]any{"superseded": "P1D"})
	e.edit("r7", "derby", "1-0")
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Onto: "matches", Switch: true}))
	if !res.Switched {
		t.Fatalf("not switched: %+v", res)
	}
	e.s.Clock.Advance(2 * day)
	if d := e.sweep(true)["r7"]; d.Action != janitor.ActionWouldPurge || d.Claim != "superseded" {
		t.Fatalf("r7 %+v", d)
	}
}
