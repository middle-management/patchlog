package dav_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

func parents(cat string, folders ...string) []any {
	out := []any{}
	for _, f := range folders {
		out = append(out, map[string]any{"href": "/r/" + cat + "/" + f})
	}
	return out
}

// catalogEnv: content namespace matches, catalog cat (a DAG) with
// root/{season,derbies}, the derby placed in both, and an empty folder.
func catalogEnv(t *testing.T) *env {
	e := newEnv(t, []string{"matches"}, []string{"cat"}, map[string]map[string]any{
		"cat": {"catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}},
	})
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	e.create("cat", "season", map[string]any{"parents": parents("cat", "root")})
	e.create("cat", "derbies", map[string]any{"parents": []any{map[string]any{"href": "/r/cat/root", "order": "a1"}}})
	e.create("cat", "empty", map[string]any{"parents": parents("cat", "root")})
	e.create("cat", "matches.derby", map[string]any{"parents": parents("cat", "season", "derbies")})
	return e
}

func (e *env) parentsOf(name string) []any {
	e.t.Helper()
	h, doc := e.load("cat", name)
	if h.State != client.Live {
		e.t.Fatalf("cat/%s is %v", name, h.State)
	}
	ps, _ := doc.(map[string]any)["parents"].([]any)
	return ps
}

// A catalog is a folder tree: folders as directories, placements as
// {ns}.{name}.json holding their item, a DAG node under each parent.
func TestCatalogListing(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{"cat/", "matches/"})
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"root/"})
	sameStrings(t, "cat/root", names(e.propfind("/cat/root/"), "/cat/root/"), []string{"derbies/", "empty/", "season/"})
	want := rendered(map[string]any{"title": "Derby"})
	for _, f := range []string{"season", "derbies"} {
		l := e.propfind("/cat/root/" + f + "/")
		sameStrings(t, f, names(l, "/cat/root/"+f+"/"), []string{"matches.derby.json"})
		if en := l["/cat/root/"+f+"/matches.derby.json"]; en.size != strconv.Itoa(len(want)) {
			t.Fatalf("%s: %+v", f, en)
		}
	}
	if b := e.expect(e.do("GET", "/cat/root/season/matches.derby.json", ""), 200, "GET placement").body; b != want {
		t.Fatalf("placement %q", b)
	}
	e.expect(e.do("GET", "/cat/root/matches.derby.json", ""), 404, "not under root")
	e.expect(e.do("PROPFIND", "/cat/season/", "", "Depth", "1"), 404, "season isn't at the catalog's root")
	// A placement's file edits its item, as the flat view does.
	served := e.expect(e.do("GET", "/cat/root/derbies/matches.derby.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/cat/root/derbies/matches.derby.json", strings.Replace(served, "Derby", "The derby", 1)), 201, "PUT placement")
	sameJSON(t, e.lastEntry("matches", "derby").Patches, []any{map[string]any{"op": "replace", "path": "/title", "value": "The derby"}})
	if b := e.expect(e.do("GET", "/matches/derby.json", ""), 200, "GET flat").body; !strings.Contains(b, "The derby") {
		t.Fatalf("flat view %q", b)
	}
}

// MKCOL makes a folder; MOVE moves a placement or folder between folders
// by replacing one parents entry; a folder can't go into itself, and a
// node can't be renamed.
func TestCatalogMkcolMove(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	e.expect(e.do("MKCOL", "/cat/root/new", ""), 201, "MKCOL")
	sameJSON(t, e.parentsOf("new"), parents("cat", "root"))
	e.expect(e.do("MKCOL", "/cat/top", ""), 201, "MKCOL at the catalog's root")
	sameJSON(t, e.parentsOf("top"), []any{})
	e.expect(e.do("MKCOL", "/cat/root/new", ""), 405, "MKCOL again")
	e.expect(e.do("MKCOL", "/cat/root/season/new", ""), 409, "MKCOL of a name used elsewhere")
	e.expect(e.do("MKCOL", "/cat/root/Untitled Folder", ""), 403, "MKCOL of a name that isn't a folder name")
	e.expect(e.do("MKCOL", "/cat/root/nowhere/x", ""), 409, "MKCOL below a missing folder")

	// The placement from season to new: only that entry changes.
	e.expect(e.do("MOVE", "/cat/root/season/matches.derby.json", "", "Destination", "/cat/root/new/matches.derby.json"), 201, "MOVE placement")
	sameJSON(t, e.parentsOf("matches.derby"), parents("cat", "new", "derbies"))
	sameStrings(t, "season", names(e.propfind("/cat/root/season/"), "/cat/root/season/"), nil)
	sameStrings(t, "new", names(e.propfind("/cat/root/new/"), "/cat/root/new/"), []string{"matches.derby.json"})
	// Into a folder it is already in (a DAG): the source's entry goes.
	e.expect(e.do("MOVE", "/cat/root/new/matches.derby.json", "", "Destination", "/cat/root/derbies/matches.derby.json", "Overwrite", "T"), 204, "MOVE onto itself elsewhere")
	sameJSON(t, e.parentsOf("matches.derby"), parents("cat", "derbies"))
	if h, _ := e.load("cat", "matches.derby"); h.State != client.Live {
		t.Fatal("moving over the node's other place deleted it")
	}

	// A folder, with what is in it.
	e.expect(e.do("MOVE", "/cat/root/derbies", "", "Destination", "/cat/root/season/derbies"), 201, "MOVE folder")
	sameJSON(t, e.parentsOf("derbies"), parents("cat", "season"))
	sameStrings(t, "season/derbies", names(e.propfind("/cat/root/season/derbies/"), "/cat/root/season/derbies/"), []string{"matches.derby.json"})
	e.expect(e.do("MOVE", "/cat/root/season", "", "Destination", "/cat/root/season/derbies/season"), 409, "MOVE folder into itself")
	e.expect(e.do("MOVE", "/cat/root/season/derbies", "", "Destination", "/cat/root/season/renamed"), 403, "rename folder")
	e.expect(e.do("MOVE", "/cat/root/season/derbies/matches.derby.json", "", "Destination", "/cat/root/season/derbies/matches.other.json"), 403, "rename placement")
	e.expect(e.do("MOVE", "/cat/root/season/derbies/matches.derby.json", "", "Destination", "/matches/derby2.json"), 403, "placement out of the catalog")
	// To the catalog's root and back.
	e.expect(e.do("MOVE", "/cat/top", "", "Destination", "/cat/root/top"), 201, "MOVE from the catalog root")
	sameJSON(t, e.parentsOf("top"), parents("cat", "root"))
	e.expect(e.do("MOVE", "/cat/root/top", "", "Destination", "/cat/top"), 201, "MOVE to the catalog root")
	sameJSON(t, e.parentsOf("top"), []any{})
}

// DELETE of a placement unplaces it, leaving its item; in a DAG it is
// unlinked from that folder only. A folder is deleted only when empty.
// PUT of a new placement file creates the item (or edits it) and places
// it; an item placed elsewhere is a 409.
func TestCatalogDeletePut(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	e.expect(e.do("DELETE", "/cat/root/season/matches.derby.json", ""), 204, "DELETE one link")
	sameJSON(t, e.parentsOf("matches.derby"), parents("cat", "derbies"))
	e.expect(e.do("DELETE", "/cat/root/derbies/matches.derby.json", ""), 204, "DELETE the last link")
	if h, _ := e.load("cat", "matches.derby"); h.State != client.Tombstoned {
		t.Fatalf("placement %v", h.State)
	}
	if h, _ := e.load("matches", "derby"); h.State != client.Live {
		t.Fatalf("the item went with its placement: %v", h.State)
	}
	e.expect(e.do("DELETE", "/cat/root", ""), 409, "DELETE a folder with folders in it")
	e.expect(e.do("DELETE", "/cat/root/empty", ""), 204, "DELETE an empty folder")
	if h, _ := e.load("cat", "empty"); h.State != client.Tombstoned {
		t.Fatalf("empty %v", h.State)
	}

	// A new item, created and placed.
	e.expect(e.do("PUT", "/cat/root/season/matches.opener.json", `{"title": "Opener"}`), 201, "PUT new placement")
	_, doc := e.load("matches", "opener")
	sameJSON(t, doc, map[string]any{"title": "Opener"})
	sameJSON(t, e.parentsOf("matches.opener"), parents("cat", "season"))
	sameStrings(t, "season", names(e.propfind("/cat/root/season/"), "/cat/root/season/"), []string{"matches.opener.json"})
	e.expect(e.do("PUT", "/cat/root/derbies/matches.opener.json", `{"title": "Again"}`), 409, "PUT of an item placed elsewhere")
	if _, doc := e.load("matches", "opener"); doc.(map[string]any)["title"] != "Opener" {
		t.Fatal("a refused placement wrote its item")
	}
	// An existing item, placed again (its placement was deleted): edited
	// and placed; the placement is restored on its chain.
	e.expect(e.do("PUT", "/cat/root/derbies/matches.derby.json", `{"title": "Derby 2"}`), 201, "PUT existing item")
	_, doc = e.load("matches", "derby")
	sameJSON(t, doc, map[string]any{"title": "Derby 2"})
	sameJSON(t, e.parentsOf("matches.derby"), parents("cat", "derbies"))
	log := must(e.c.Log(e.ctx, "cat", "matches.derby", "", ""))
	if log[len(log)-2].Kind != "tombstone" {
		t.Fatalf("placement log %+v", log)
	}
	// A copy from the flat view places the item, writing nothing to it.
	before, _ := e.load("matches", "derby")
	e.do("GET", "/matches/derby.json", "")
	e.expect(e.do("COPY", "/matches/derby.json", "", "Destination", "/cat/root/season/matches.derby.json"), 409, "COPY of an item placed elsewhere")
	e.expect(e.do("PUT", "/matches/final.json", `{"title": "Final"}`), 201, "PUT flat")
	e.expect(e.do("COPY", "/matches/final.json", "", "Destination", "/cat/root/season/matches.final.json"), 201, "COPY into a folder")
	sameJSON(t, e.parentsOf("matches.final"), parents("cat", "season"))
	if en := e.lastEntry("matches", "final"); en.Parent != "" {
		t.Fatal("placing by COPY wrote the item")
	}
	if after, _ := e.load("matches", "derby"); after.ID != before.ID {
		t.Fatal("a refused COPY wrote the item")
	}
	e.expect(e.do("MOVE", "/cat/root/season/matches.final.json", "", "Destination", "/cat/root/derbies/matches.final.json"), 201, "MOVE out")
	// Names that aren't placements are scratch files there too.
	e.expect(e.do("PUT", "/cat/root/season/.DS_Store", "Bud1"), 201, ".DS_Store in a folder")
	sameStrings(t, "season", names(e.propfind("/cat/root/season/"), "/cat/root/season/"), []string{".DS_Store", "matches.opener.json"})
	// Deleting the folder takes the user's own scratch files with it.
	e.expect(e.do("MOVE", "/cat/root/season/matches.opener.json", "", "Destination", "/cat/root/derbies/matches.opener.json"), 201, "MOVE out")
	e.expect(e.do("DELETE", "/cat/root/season", ""), 204, "DELETE a folder with only scratch files")
}

// Listings of namespaces and catalogs longer than a /heads page (§7.1
// Paging) list everything.
func TestPagedFlows(t *testing.T) {
	clienttest.Paged(t, 2, func(t *testing.T) {
		e := catalogEnv(t)
		for _, n := range []string{"a", "b", "c", "d"} {
			e.create("matches", n, map[string]any{"n": n})
		}
		sameStrings(t, "matches", names(e.propfind("/matches/"), "/matches/"), []string{"a.json", "b.json", "c.json", "d.json", "derby.json"})
		sameStrings(t, "cat/root", names(e.propfind("/cat/root/"), "/cat/root/"), []string{"derbies/", "empty/", "season/"})
		e.expect(e.do("PUT", "/cat/root/season/matches.e.json", `{"n": "e"}`), 201, "PUT placement")
		sameStrings(t, "season", names(e.propfind("/cat/root/season/"), "/cat/root/season/"), []string{"matches.derby.json", "matches.e.json"})
	})
}
