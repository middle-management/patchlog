package tree_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// v0.86 SERVICES §B.5 Previews (SVC-25), CONFORMANCE Tree 150: "A catalog
// branch, previewed or served directly, lists the nodes it reads through
// from its base as of the branch's at (§7.6). There a link into a
// namespace of its local base chain counts as a link to the branch's node
// of that name (§B.3)." cat-b is a branch of cat, and the service's
// catalog: its graph holds cat's folders and placements as of the branch
// point, the branch's own writes on top, and nothing cat wrote after the
// branch.
//
// The nodes it reads through keep the parents their documents name,
// /r/cat/…: in cat-b those are links to cat-b's own nodes, so the base's
// tree stands in the branch as it stood in the base, and a node read
// through is no root and no orphan. Under v0.85 such a link was one to
// another namespace (§B.7), and every node read through a root or an
// orphan until the branch rewrote its parents.
func TestV086BranchCatalogLinksThroughBase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	// An implicit placement, whose $parents name the base's folder (§B.9).
	must(w.c.CreateDoc(ctx, "matches", "friendly", map[string]any{"title": "friendly",
		"$parents": []any{map[string]any{"href": "/r/cat/derbies", "order": "a0"}}}))
	must(w.c.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-b"}))
	// After the branch: one folder in the base, and in the branch one
	// that names the branch, one that names the base, and one that names
	// a namespace outside the chain.
	w.folder(t, "later", "Later in the base", "root@b0")
	at := func(ns, name, order string) []any {
		return []any{map[string]any{"href": "/r/" + ns + "/" + name, "order": order}}
	}
	must(w.c.CreateDoc(ctx, "cat-b", "own", map[string]any{"title": "The branch's own", "parents": at("cat-b", "root", "b1")}))
	must(w.c.CreateDoc(ctx, "cat-b", "via-base", map[string]any{"title": "Named through the base", "parents": at("cat", "root", "b2")}))
	must(w.c.CreateDoc(ctx, "cat-b", "stray", map[string]any{"title": "Elsewhere", "parents": at("matches", "root", "b3")}))

	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, w.c, svcOpts{catalog: "cat-b", db: db, selfPlacing: true})
	x.caughtUp("cat-b", "matches")
	check := func(when string) {
		t.Helper()
		for _, c := range []struct{ path, key, want string }{
			// x read through, with parents naming /r/cat/f, is listed
			// under f, with the branch's own nodes, in order.
			{"/cat-b/children?of=root", "children", "season,derbies,own,via-base"},
			{"/cat-b/children?of=season", "children", "matches.opener,matches.derby"},
			{"/cat-b/children?of=derbies", "children", "matches.derby,matches.friendly"},
			// … and isn't under /roots or /orphans: only the base's root
			// is a root, and only a link outside the chain an orphan's.
			{"/cat-b/roots", "roots", "root"},
			{"/cat-b/orphans", "orphans", "stray"},
		} {
			if got := names(x.get(c.path, "")[c.key]); got != c.want {
				t.Errorf("%s: %s lists %q, want %q", when, c.path, got, c.want)
			}
		}
	}
	check("served as a branch")
	// A node read through is the base's as of at: its item resolves.
	for _, n := range x.get("/cat-b/children?of=season", "")["children"].([]any) {
		if n := n.(map[string]any); n["name"] == "matches.derby" && (n["item"] != "/r/matches/derby" || n["head"] == nil) {
			t.Errorf("a placement read through: %v", n)
		}
	}
	// The link outside the chain is still one to another namespace.
	// (/problems lists it, and none of the links through the base.)
	probs := x.get("/cat-b/problems", "")["danglingParents"].([]any)
	if len(probs) != 1 || probs[0].(map[string]any)["href"] != "/r/cat-b/stray" || probs[0].(map[string]any)["reason"] != "links to another namespace" {
		t.Errorf("dangling parents: %v, want only the link outside the chain", probs)
	}
	// A restart on the same store reads nothing through twice, and loads
	// its graph under the same chain.
	x.stop()
	x = startSvc(t, w.c, svcOpts{catalog: "cat-b", db: db, selfPlacing: true})
	x.caughtUp("cat-b", "matches")
	check("after a restart")

	// A write in the branch to a node it read through replaces it there.
	h := must(w.c.Head(ctx, "cat-b", "season"))
	must(w.c.Append(ctx, "cat-b", "season", h.ID, []any{
		map[string]any{"op": "replace", "path": "/title", "value": "Season, in the branch"},
		map[string]any{"op": "replace", "path": "/parents", "value": at("cat-b", "root", "c0")}}))
	x.caughtUp("cat-b")
	kids := x.get("/cat-b/children?of=root", "")["children"]
	if got := names(kids); got != "derbies,own,via-base,season" {
		t.Errorf("children of root after the branch's write: %s", got)
	}
	if n := kids.([]any)[3].(map[string]any); n["title"] != "Season, in the branch" {
		t.Errorf("season after the branch's write: %v", n)
	}
	if got := names(x.get("/cat-b/children?of=season", "")["children"]); got != "matches.opener,matches.derby" {
		t.Errorf("children of season after the branch's write: %s", got)
	}
	x.stop()

	// A branch of the branch: both bases' names are its own.
	must(w.c.CreateBranch(ctx, "cat-b", client.BranchRequest{Name: "cat-c"}))
	must(w.c.CreateDoc(ctx, "cat-c", "third", map[string]any{"title": "In the second branch", "parents": at("cat-b", "derbies", "z0")}))
	y := startSvc(t, w.c, svcOpts{catalog: "cat-c", selfPlacing: true})
	y.caughtUp("cat-c", "matches")
	for path, want := range map[string]string{
		"/cat-c/children?of=root":    "derbies,own,via-base,season",
		"/cat-c/children?of=derbies": "matches.derby,matches.friendly,third",
	} {
		k := "children"
		if got := names(y.get(path, "")[k]); got != want {
			t.Errorf("a branch of the branch: %s lists %q, want %q", path, got, want)
		}
	}
	if got := names(y.get("/cat-c/roots", "")["roots"]); got != "root" {
		t.Errorf("a branch of the branch: roots %q", got)
	}
	if got := names(y.get("/cat-c/orphans", "")["orphans"]); got != "stray" {
		t.Errorf("a branch of the branch: orphans %q", got)
	}

	// The base itself, served as before, counts no link into its branch.
	z := startSvc(t, w.c, svcOpts{selfPlacing: true})
	z.caughtUp("cat", "matches")
	if got := names(z.get("/cat/children?of=root", "")["children"]); got != "season,derbies,later" {
		t.Errorf("the base's children of root: %s", got)
	}
}
