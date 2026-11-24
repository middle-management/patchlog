package merge_test

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/merge"
)

// v0.90 TOOLS §F.9 Merging, step 3 (CONFORMANCE Tools scenario 39):
// planning again after a stop takes step 3's documents still live and
// unset from the stored plan, and reports those no longer live, which the
// approved plan named; it doesn't drop them silently.
func TestV090BReplanReportsNoLongerLive(t *testing.T) {
	t.Parallel()
	w, _ := publishWorld(t)
	w.release7p()
	o := w.publishOpts("release-7")
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	must(merge.ApproveRelease(ctx, w.anna, o))
	o.AfterStep = func(st *merge.ReleaseStep) error {
		if st.Step == merge.StepContent {
			// Someone deletes final between steps 2 and 3.
			h := must(w.anna.Head(ctx, "matches", "final"))
			must(w.anna.Delete(ctx, "matches", "final", h.ID))
		}
		return nil
	}
	if _, err := merge.ApplyRelease(ctx, w.anna, o); err == nil {
		t.Fatal("apply went through with final deleted before step 3")
	}
	o.AfterStep = nil
	old := must(merge.LoadReleasePlan(ctx, w.anna, o))
	o.AcceptFrozen = old.FrozenBy()
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	for _, st := range rp.Steps {
		if _, ok := st.Carried["final"]; ok && st.Step == merge.StepPublish {
			t.Fatalf("step 3 carries deleted final: %+v", st)
		}
	}
	reported := false
	for _, n := range rp.Notes {
		reported = reported || strings.Contains(n, "final in matches") && strings.Contains(n, "no longer live")
	}
	if !reported {
		t.Fatalf("the new plan doesn't report final: notes %q", rp.Notes)
	}
}
