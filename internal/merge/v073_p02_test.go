package merge_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/merge"
)

// §F.8, §F.9, §12.2: rulesPerGrant counts every rule form, nested ones
// included (32 by default), and a catalog batch's grant allows exactly
// its pairs of /resource and /action. A release whose catalog batches
// have more than ten items merges: step 2 (a folder with $access and
// eleven narrowing moves) under the approver's grant narrowed by the
// merge service, step 4 (eleven placements) under the catalog's merge
// grant, each rule one alternative per action, not per item.
func TestV073P02ReleaseManyCatalogItems(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	const n = 11
	for i := 0; i < n; i++ {
		m := fmt.Sprintf("m%d", i)
		must(w.ops.CreateDoc(ctx, "matches", m, map[string]any{"home": m, "away": "B"}))
		must(w.ops.CreateDoc(ctx, "cat-season", "matches."+m, map[string]any{"parents": parentsOf("season")}))
	}
	w.branch("matches", "matches-r7")
	w.branch("cat-season", "cat-season-r7")
	must(w.anna.CreateDoc(ctx, "cat-season-r7", "locked", map[string]any{"title": "Locked", "parents": parentsOf("root"),
		"$access": map[string]any{"inherit": false, "group:match-desk": sAny("desk")}}))
	for i := 0; i < n; i++ {
		w.appendTo("cat-season-r7", fmt.Sprintf("matches.m%d", i), op("replace", "/parents", parentsOf("locked")))
		nn := fmt.Sprintf("n%d", i)
		must(w.anna.CreateDoc(ctx, "matches-r7", nn, map[string]any{"home": nn, "away": "B"}))
		must(w.anna.CreateDoc(ctx, "cat-season-r7", "matches."+nn, map[string]any{"parents": parentsOf("season")}))
	}
	w.writeRelease("release-7", map[string]string{"matches": "matches-r7", "cat-season": "cat-season-r7"})

	o := w.opts("release-7")
	rp, err := merge.PlanRelease(ctx, w.anna, o)
	noErr(t, err)
	if !rp.Clean() {
		t.Fatalf("conflicts: %+v", rp.Conflicts)
	}
	sizes := map[int]int{}
	for _, st := range rp.Steps {
		if st.Key == "cat-season" {
			sizes[st.Step] = len(st.Resources)
		}
	}
	if sizes[2] != n+1 || sizes[4] != n {
		t.Fatalf("catalog batches %v: %q", sizes, stepsOf(rp))
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	rp, err = merge.ApplyRelease(ctx, w.anna, o)
	noErr(t, err)
	if rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
	for i := 0; i < n; i++ {
		if got := parentNames(w.doc("cat-season", fmt.Sprintf("matches.m%d", i))); strings.Join(got, ",") != "locked" {
			t.Fatalf("matches.m%d parents %v", i, got)
		}
		if got := parentNames(w.doc("cat-season", fmt.Sprintf("matches.n%d", i))); strings.Join(got, ",") != "season" {
			t.Fatalf("matches.n%d parents %v", i, got)
		}
		if !w.live("matches", fmt.Sprintf("n%d", i)) {
			t.Fatalf("matches/n%d not merged", i)
		}
	}
}
