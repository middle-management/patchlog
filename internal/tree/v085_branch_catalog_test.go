package tree_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// v0.85 SERVICES §B.5 Previews (SVC-25): "A catalog branch, previewed or
// served directly, lists the nodes it reads through from its base as of
// the branch's at (§7.6)." cat-b is a branch of cat, and the service's
// catalog: its graph holds cat's folders and placements as of the branch
// point, the branch's own writes on top, and nothing cat wrote after the
// branch. Until v0.85 only a preview's branch was followed so, and a
// branch catalog served directly listed its own writes alone.
//
// The nodes it reads through keep the parents their documents name,
// /r/cat/…, which in a catalog served as cat-b link to another namespace
// (§B.7): they are listed, as roots and orphans, and a node is placed in
// the branch's tree once the branch writes parents naming itself. (A
// preview is served under the base's name, where those links are its
// own.)
func TestV085BranchCatalogListsReadThrough(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	must(w.c.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-b"}))
	// After the branch: one folder in the base, one in the branch.
	w.folder(t, "later", "Later in the base", "root@b0")
	inBranch := func(name, order string) []any {
		return []any{map[string]any{"href": "/r/cat-b/" + name, "order": order}}
	}
	must(w.c.CreateDoc(ctx, "cat-b", "own", map[string]any{"title": "The branch's own", "parents": inBranch("root", "b1")}))

	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, w.c, svcOpts{catalog: "cat-b", db: db})
	x.caughtUp("cat-b", "matches")
	listed := func() []string {
		var out []string
		for _, k := range []string{"roots", "orphans"} {
			if s := names(x.get("/cat-b/"+k, "")[k]); s != "" {
				out = append(out, strings.Split(s, ",")...)
			}
		}
		out = append(out, strings.Split(names(x.get("/cat-b/children?of=root", "")["children"]), ",")...)
		slices.Sort(out)
		return slices.Compact(out)
	}
	want := []string{"derbies", "matches.cup", "matches.derby", "matches.opener", "own", "root", "season"}
	if got := listed(); !slices.Equal(got, want) {
		t.Errorf("the branch catalog lists %v, want %v: the base's nodes as of at and the branch's own", got, want)
	}
	if got := names(x.get("/cat-b/children?of=root", "")["children"]); got != "own" {
		t.Errorf("children of root in the branch: %s", got)
	}
	// A node read through is the base's as of at: its item resolves.
	for _, n := range x.get("/cat-b/orphans", "")["orphans"].([]any) {
		if n := n.(map[string]any); n["name"] == "matches.derby" && (n["item"] != "/r/matches/derby" || n["head"] == nil) {
			t.Errorf("a placement read through: %v", n)
		}
	}
	// A write in the branch to a node it read through replaces it there:
	// with parents naming the branch, it is placed in the branch's tree.
	h := must(w.c.Head(ctx, "cat-b", "season"))
	must(w.c.Append(ctx, "cat-b", "season", h.ID, []any{
		map[string]any{"op": "replace", "path": "/title", "value": "Season, in the branch"},
		map[string]any{"op": "replace", "path": "/parents", "value": inBranch("root", "a0")}}))
	x.caughtUp("cat-b")
	kids := x.get("/cat-b/children?of=root", "")["children"]
	if got := names(kids); got != "season,own" {
		t.Errorf("children of root after the branch's write: %s", got)
	}
	if n := kids.([]any)[0].(map[string]any); n["title"] != "Season, in the branch" {
		t.Errorf("season after the branch's write: %v", n)
	}
	// A restart on the same store reads nothing through twice, and keeps
	// what it read.
	x.stop()
	y := startSvc(t, w.c, svcOpts{catalog: "cat-b", db: db})
	y.caughtUp("cat-b", "matches")
	x = y
	if got := listed(); !slices.Equal(got, want) {
		t.Errorf("after a restart the branch catalog lists %v, want %v", got, want)
	}
}
