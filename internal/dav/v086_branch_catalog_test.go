package dav_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/dav"
)

// v0.86 SERVICES §B.5 Previews, CONFORMANCE Tree 150: in a catalog branch
// "a link into a namespace of its local base chain counts as a link to
// the branch's node of that name". A file tree served from branch cat-b
// of cat reads the base's nodes through, whose parents name /r/cat/…: it
// shows the base's tree, and a move replaces the entry that names the
// base's folder, in the branch alone. Before, those links were ones to
// another namespace: the branch's tree had no top level, and a move would
// have added a second parent beside the base's.
func TestV086BranchCatalogTree(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	must(e.c.CreateBranch(e.ctx, "cat", client.BranchRequest{Name: "cat-b"}))
	opt := e.opt
	opt.Catalogs = []string{"cat-b"}
	opt.Client = e.s.Client(t, client.WithAuthor("dav"))
	srv, err := dav.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	b := *e
	b.opt, b.dav = opt, newTestServer(t, srv)

	sameStrings(t, "cat-b", names(b.propfind("/cat-b/"), "/cat-b/"), []string{"Empty/", "Season/"})
	sameStrings(t, "Season", names(b.propfind("/cat-b/Season/"), "/cat-b/Season/"), []string{"derby.json"})
	b.expect(b.do("MOVE", "/cat-b/Season/derby.json", "", "Destination", "/cat-b/Empty/derby.json"), 201, "a move in the branch")
	sameJSON(t, b.lastEntry("cat-b", "matches.derby").Patches, []any{map[string]any{"op": "replace", "path": "/parents/0",
		"value": map[string]any{"href": "/r/cat-b/empty", "order": "a0"}}})
	sameStrings(t, "Empty", names(b.propfind("/cat-b/Empty/"), "/cat-b/Empty/"), []string{"derby.json"})
	sameStrings(t, "Season after the move", names(b.propfind("/cat-b/Season/"), "/cat-b/Season/"), nil)
	// The base is as it was.
	sameJSON(t, e.parentsOf("matches.derby"), parents("cat", "season"))
	sameStrings(t, "the base's Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
}
