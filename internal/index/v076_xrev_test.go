package index_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// Cross-review, scenario 109 at the index (§B.11.9 Branches, gs; §A.4):
// at matches-r7's at, reader has not /principal/groups contains
// "contractors", which matches has since removed; a reader in contractors
// -> a query of the branch keeps derby hidden through reader; in matches
// itself, derby is a hit.
func TestV076IndexScenario109(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, true)
	not := []any{map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups",
		"schema": map[string]any{"contains": map[string]any{"const": "contractors"}}}}}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
		[]any{map[string]any{"op": "add", "path": "/roles/reader/rules", "value": not}}))
	w.x.caughtUp("matches")
	must(w.admin.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	w.x.caughtUp("matches-r7")
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
		[]any{map[string]any{"op": "remove", "path": "/roles/reader/rules"}}))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
	fan := w.reader("user:fan", []any{"fans", "contractors"}, "matches-r7")
	if got := strings.Join(resources(w.x.search("/matches-r7", fan)), ","); strings.Contains(got, "derby") {
		t.Errorf("contractor sees %s in the branch, want derby hidden as of baseAt", got)
	}
	plain := w.reader("user:fan", []any{"fans"}, "matches-r7")
	if got := strings.Join(resources(w.x.search("/matches-r7", plain)), ","); !strings.Contains(got, "derby") {
		t.Errorf("non-contractor sees %s in the branch, want derby", got)
	}
	mfan := w.reader("user:fan", []any{"fans", "contractors"})
	if got := strings.Join(resources(w.x.search("/matches", mfan)), ","); !strings.Contains(got, "derby") {
		t.Errorf("contractor sees %s in matches, want derby", got)
	}
}
