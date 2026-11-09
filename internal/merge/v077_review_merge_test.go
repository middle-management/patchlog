package merge_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/merge"
)

// Review (§F.5 Switch: "Then replay whatever the old branch received after
// step 2"): the gate of a switch counts every resource whatever
// Plan.Resources limits the replay to, so the catch-up after the switch
// replays every resource changed since the first replay too. Here cup,
// outside the limit, changes after the first replay's source.at and
// before the freeze: the catch-up fast-forwards it into r7b.
func TestV077RebaseCatchUpWidened(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	// cup is replayed first, on its own, without a switch.
	must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b", Plan: merge.Options{Resources: []string{"cup"}}}))
	changed := false
	opt := merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{Resources: []string{"derby"}},
		Prepare: func(ctx context.Context, p *merge.Plan) error {
			if !changed {
				changed = true
				e.append("r7", "cup", op("replace", "/score", "3-1"))
			}
			return nil
		}}
	res, err := merge.Rebase(ctx, e.c, opt)
	if err != nil || !res.Switched || len(res.LeftOut) != 0 {
		t.Fatalf("rebase: %v, %+v", err, res)
	}
	if res.CatchUp == nil || res.CatchUp.Resource("cup") == nil || res.CatchUp.Resource("cup").Class != merge.FastForward {
		t.Fatalf("catch-up: %+v", res.CatchUp)
	}
	if got := e.doc("r7b", "cup").(map[string]any)["score"]; got != "3-1" {
		t.Fatalf("r7b's cup is %v, not r7's 3-1", got)
	}
	if got := e.doc("r7b", "derby").(map[string]any)["score"]; got != "1-0" {
		t.Fatalf("r7b's derby is %v", got)
	}
}
