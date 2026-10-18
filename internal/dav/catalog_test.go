package dav_test

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
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
	e.expect(e.do("MKCOL", "/cat/root/nowhere/x", ""), 409, "MKCOL below a missing folder")
	// A file manager's New Folder: made under a name that isn't a folder
	// name (a scratch directory, nothing written), then named.
	before := must(e.c.NSHead(e.ctx, "cat")).ID
	e.expect(e.do("MKCOL", "/cat/root/untitled folder", ""), 201, "New Folder")
	if now := must(e.c.NSHead(e.ctx, "cat")).ID; now != before {
		t.Fatal("a scratch directory was written to the catalog")
	}
	sameStrings(t, "root", names(e.propfind("/cat/root/"), "/cat/root/"), []string{"derbies/", "empty/", "new/", "season/", "untitled folder/"})
	e.expect(e.do("MOVE", "/cat/root/untitled folder", "", "Destination", "/cat/root/named"), 201, "named")
	sameJSON(t, e.parentsOf("named"), parents("cat", "root"))
	sameStrings(t, "root", names(e.propfind("/cat/root/"), "/cat/root/"), []string{"derbies/", "empty/", "named/", "new/", "season/"})

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
	e.expect(e.do("GET", "/matches/derby.json", ""), 200, "GET the item")
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

// Writes through a placement go only where the server would write: items
// in a namespace the catalog trusts (§B.3) or that is served (-ns), never
// a catalog's own nodes. A placement of an existing item is made before
// the item is written, so one the core refuses (a frozen catalog) leaves
// the item as it was.
func TestCatalogPlacementWrites(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	must(e.c.CreateNamespace(e.ctx, "secret", map[string]any{"read": "public"}))
	e.create("secret", "plans", map[string]any{"launch": "monday", "budget": 1})
	e.expect(e.do("PUT", "/cat/root/season/secret.new.json", `{"planted": true}`), 403, "PUT a new item in a namespace not trusted nor served")
	e.expect(e.do("PUT", "/cat/root/season/secret.plans.json", `{"launch": "never"}`), 403, "PUT over an item not trusted nor served")
	_, doc := e.load("secret", "plans")
	sameJSON(t, doc, map[string]any{"launch": "monday", "budget": 1})
	if h, _ := e.load("secret", "new"); h.State != client.NotFound {
		t.Fatal("an untrusted item was created")
	}
	e.expect(e.do("PUT", "/cat/root/season/cat.empty.json", `{"parents": [], "x": 1}`), 403, "PUT through a placement of a catalog node")
	sameJSON(t, e.parentsOf("empty"), parents("cat", "root"))
	e.expect(e.do("PUT", "/matches/.goutputstream-tmp", `{"planted": true}`), 201, "temporary file")
	e.expect(e.do("MOVE", "/matches/.goutputstream-tmp", "", "Destination", "/cat/root/season/secret.moved.json"), 403, "MOVE onto an untrusted placement")

	// A frozen catalog refuses the placement: the item isn't written.
	e.create("matches", "final", map[string]any{"title": "Final", "score": "2-1"})
	nh := must(e.c.NSHead(e.ctx, "cat"))
	must(e.c.PatchConfig(e.ctx, "cat", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	e.expect(e.do("GET", "/matches/final.json", ""), 200, "GET the item")
	e.expect(e.do("PUT", "/cat/root/season/matches.final.json", `{"title": "Final (draft)"}`), 403, "PUT a placement in a frozen catalog")
	_, doc = e.load("matches", "final")
	sameJSON(t, doc, map[string]any{"title": "Final", "score": "2-1"})
}

// counted is a catalog environment whose core counts the requests the
// WebDAV server makes (its writes carry X-Author dav).
func counted(t *testing.T) (*env, func() int64) {
	var n atomic.Int64
	e := newEnv(t, []string{"matches"}, []string{"cat"}, map[string]map[string]any{
		"cat": {"catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}},
	}, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Author") == "dav" {
					n.Add(1)
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "season", map[string]any{"parents": parents("cat", "root")})
	e.create("cat", "sub", map[string]any{"parents": parents("cat", "season")})
	for i := 0; i < 20; i++ {
		name := "m" + strconv.Itoa(i)
		e.create("matches", name, map[string]any{"n": i})
		folder := "season"
		if i >= 10 {
			folder = "sub"
		}
		e.create("cat", "matches."+name, map[string]any{"parents": parents("cat", folder)})
	}
	return e, func() int64 { return n.Swap(0) }
}

// What a listing costs upstream: the root's each namespace's document
// once every 30 seconds (sealed and end-to-end ones aren't offered,
// §H.7), a folder's entries their own items only (not a subfolder's), a
// catalog's tree and its items' heads once per CatalogTTL, a file's
// properties two heads (its name could be a raw file's, §H.2).
func TestCatalogRequests(t *testing.T) {
	t.Parallel()
	e, reqs := counted(t)
	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{"cat/", "matches/"})
	if n := reqs(); n != 4 {
		t.Fatalf("PROPFIND / made %d requests", n)
	}
	e.propfind("/")
	if n := reqs(); n != 0 {
		t.Fatalf("PROPFIND / again made %d requests", n)
	}
	sameStrings(t, "cat/root", names(e.propfind("/cat/root/"), "/cat/root/"), []string{"season/"})
	reqs()
	l := e.propfind("/cat/root/season/")
	if len(l) != 12 {
		t.Fatalf("season lists %d", len(l))
	}
	if n := reqs(); n > 2*10 {
		t.Fatalf("PROPFIND of a folder with 10 placements and a subfolder made %d requests", n)
	}
	e.propfind("/cat/root/season/")
	e.expect(e.do("GET", "/cat/root/season/matches.m3.json", ""), 200, "GET a placement")
	if n := reqs(); n > 1 {
		t.Fatalf("a folder listed again and a placement read made %d requests", n)
	}
	e.propfind("/matches/m3.json", "0")
	if n := reqs(); n > 2 {
		t.Fatalf("PROPFIND Depth 0 of a file made %d requests", n)
	}
	// A write through the server is seen at once.
	e.expect(e.do("MKCOL", "/cat/root/season/new", ""), 201, "MKCOL")
	if l := e.propfind("/cat/root/season/"); l["/cat/root/season/new/"].dir != true {
		t.Fatalf("after MKCOL %v", names(l, "/cat/root/season/"))
	}
}

// A PUT of a new placement whose item exists edits the item, so it takes
// the PUT's preconditions (If-None-Match: * is 412, and nothing is
// placed), and, as a file the user never opened, it is refused when its
// content differs, rather than replacing what the user never saw.
func TestCatalogPlacementOfExisting(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	e.create("matches", "cup", map[string]any{"title": "Cup", "score": "3-0"})
	e.expect(e.do("PUT", "/cat/root/empty/matches.cup.json", `{"title": "Cup (old copy)"}`, "If-None-Match", "*"), 412, "create-only PUT of a placement of an existing item")
	e.expect(e.do("PUT", "/cat/root/empty/matches.cup.json", `{"title": "Cup (old copy)"}`), 409, "PUT of a placement of an item never opened")
	_, doc := e.load("matches", "cup")
	sameJSON(t, doc, map[string]any{"title": "Cup", "score": "3-0"})
	if h, _ := e.load("cat", "matches.cup"); h.State != client.NotFound {
		t.Fatalf("a refused PUT placed the item: %v", h.State)
	}
	// The same content places it; an edit of a version the user read is
	// rebased as usual.
	buf := e.expect(e.do("GET", "/matches/cup.json", ""), 200, "GET").body
	e.theirs("matches", "cup", replace("/score", "3-1"))
	e.expect(e.do("PUT", "/cat/root/empty/matches.cup.json", edit(t, buf, `"Cup"`, `"The cup"`)), 201, "PUT of a placement of an item opened")
	_, doc = e.load("matches", "cup")
	sameJSON(t, doc, map[string]any{"title": "The cup", "score": "3-1"})
	sameJSON(t, e.parentsOf("matches.cup"), parents("cat", "empty"))
}

// A PUT of a new placement whose item doesn't exist writes nothing when
// the core refuses the placement: a dry run of it (§7.5) comes before the
// item is created, so a frozen catalog, or its rules, leave no unplaced
// item behind, and the refusal isn't retried as a lock would be (403,
// not 423).
func TestCatalogRefusedPlacementWritesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches"}, []string{"cat", "ruled"}, map[string]map[string]any{
		"cat": {"catalog": map[string]any{"trust": []any{"matches"}}},
		"ruled": {"catalog": map[string]any{"trust": []any{"matches"}},
			"rules": []any{map[string]any{"op": "test", "path": "/doc/order", "schema": map[string]any{"type": "string"}}}},
	})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "season", map[string]any{"parents": parents("cat", "root")})
	e.create("ruled", "root", map[string]any{"parents": []any{}, "order": "a"})
	r := e.expect(e.do("PUT", "/ruled/root/matches.ruled.json", `{"title": "Ruled"}`), 422, "PUT of a placement the catalog's rules refuse")
	if !strings.Contains(r.body, "rule") {
		t.Fatalf("422 text %q", r.body)
	}
	if h, _ := e.load("matches", "ruled"); h.State != client.NotFound {
		t.Fatalf("a refused placement created its item: %v", h.State)
	}
	nh := must(e.c.NSHead(e.ctx, "cat"))
	must(e.c.PatchConfig(e.ctx, "cat", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	e.expect(e.do("PUT", "/cat/root/season/matches.orphan.json", `{"title": "Orphan"}`), 403, "PUT of a placement in a frozen catalog")
	if h, _ := e.load("matches", "orphan"); h.State != client.NotFound {
		t.Fatalf("a refused placement created its item: %v", h.State)
	}
	e.expect(e.do("MKCOL", "/cat/root/frozen", ""), 403, "MKCOL in a frozen catalog")
	// A tombstoned item, restored for a placement: refused, it stays so.
	e.create("matches", "old", map[string]any{"title": "Old"})
	h, _ := e.load("matches", "old")
	must(e.c.Delete(e.ctx, "matches", "old", h.ID))
	e.expect(e.do("PUT", "/cat/root/season/matches.old.json", `{"title": "Old again"}`), 403, "PUT of a placement in a frozen catalog")
	if h, _ := e.load("matches", "old"); h.State != client.Tombstoned {
		t.Fatalf("a refused placement restored its item: %v", h.State)
	}
}

// A placement whose item isn't live (dangling, §B.3) isn't listed, but it
// keeps its folder from being deleted: the 409 says so, and a DELETE of
// its path unplaces it.
func TestCatalogDanglingPlacement(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	e.create("cat", "ghostdir", map[string]any{"parents": parents("cat", "root")})
	e.create("matches", "ghost", map[string]any{"t": 1})
	e.create("cat", "matches.ghost", map[string]any{"parents": parents("cat", "ghostdir")})
	h, _ := e.load("matches", "ghost")
	must(e.c.Delete(e.ctx, "matches", "ghost", h.ID))
	sameStrings(t, "ghostdir", names(e.propfind("/cat/root/ghostdir/"), "/cat/root/ghostdir/"), nil)
	r := e.expect(e.do("DELETE", "/cat/root/ghostdir", ""), 409, "DELETE of a folder holding a dangling placement")
	if !strings.Contains(r.body, "isn't live") || !strings.Contains(r.body, "/cat/root/ghostdir/matches.ghost.json") {
		t.Fatalf("409 text %q", r.body)
	}
	e.expect(e.do("DELETE", "/cat/root/ghostdir/matches.ghost.json", "", "If-Match", `"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), 412, "DELETE with If-Match of a dangling placement")
	e.expect(e.do("DELETE", "/cat/root/ghostdir/matches.ghost.json", ""), 204, "DELETE of a dangling placement")
	if h, _ := e.load("cat", "matches.ghost"); h.State != client.Tombstoned {
		t.Fatalf("placement %v", h.State)
	}
	if h, _ := e.load("matches", "ghost"); h.State != client.Tombstoned {
		t.Fatalf("item %v", h.State)
	}
	e.expect(e.do("DELETE", "/cat/root/ghostdir", ""), 204, "DELETE of the folder, now empty")
}

// A document moves from a flat directory into a catalog folder as a COPY
// places it (the same document: it stays in the flat directory, and
// nothing is written to it), and a placement moved onto its own item's
// file is unplaced. Other moves keep names as identity, with messages
// that fit: a folder isn't copied.
func TestCatalogMoveBetweenViews(t *testing.T) {
	t.Parallel()
	e := catalogEnv(t)
	first := e.create("matches", "cup", map[string]any{"title": "Cup"})
	e.expect(e.do("MOVE", "/matches/cup.json", "", "Destination", "/cat/root/season/matches.cup.json"), 201, "MOVE into a folder")
	sameJSON(t, e.parentsOf("matches.cup"), parents("cat", "season"))
	if h, _ := e.load("matches", "cup"); h.ID != first {
		t.Fatal("placing by MOVE wrote the item")
	}
	sameStrings(t, "matches", names(e.propfind("/matches/"), "/matches/"), []string{"cup.json", "derby.json"})
	e.expect(e.do("MOVE", "/matches/cup.json", "", "Destination", "/cat/root/season/matches.cup.json"), 204, "MOVE into the folder it is in")
	e.expect(e.do("MOVE", "/matches/cup.json", "", "Destination", "/cat/root/derbies/matches.cup.json"), 409, "MOVE into another folder")
	sameJSON(t, e.parentsOf("matches.cup"), parents("cat", "season"))
	e.expect(e.do("MOVE", "/cat/root/season/matches.cup.json", "", "Destination", "/matches/cup.json"), 204, "MOVE of a placement onto its item")
	if h, _ := e.load("cat", "matches.cup"); h.State != client.Tombstoned {
		t.Fatalf("placement %v", h.State)
	}
	if h, _ := e.load("matches", "cup"); h.ID != first {
		t.Fatal("unplacing by MOVE wrote the item")
	}

	r := e.expect(e.do("MOVE", "/matches/cup.json", "", "Destination", "/cat/root/season/matches.other.json"), 403, "MOVE to another name")
	if !strings.Contains(r.body, "names are identity") {
		t.Fatalf("403 text %q", r.body)
	}
	r = e.expect(e.do("MOVE", "/cat/root/season", "", "Destination", "/cat/root/season2"), 403, "folder renamed")
	if !strings.Contains(r.body, "make a folder season2") || strings.Contains(r.body, "copy") {
		t.Fatalf("403 text %q", r.body)
	}
	r = e.expect(e.do("MOVE", "/cat/root/season", "", "Destination", "/matches/season"), 403, "folder out of its catalog")
	if !strings.Contains(r.body, "only between the folders") {
		t.Fatalf("403 text %q", r.body)
	}
}

// A placement the core refuses after its dry run passed (the catalog
// changed in between) deletes the item just created for it again: no
// unplaced item is left behind.
func TestCatalogPlacementRefusedAfterProbe(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches"}, []string{"cat"}, map[string]map[string]any{
		"cat": {"catalog": map[string]any{"trust": []any{"matches"}}},
	}, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" && r.URL.Path == "/r/cat/matches.race" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code": "forbidden", "message": "refused after the dry run"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	r := e.expect(e.do("PUT", "/cat/root/matches.race.json", `{"title": "Race"}`), 403, "PUT of a placement refused after its dry run")
	if !strings.Contains(r.body, "deleted again") {
		t.Fatalf("403 text %q", r.body)
	}
	if h, _ := e.load("matches", "race"); h.State != client.Tombstoned {
		t.Fatalf("the item created for a refused placement is %v", h.State)
	}
}
