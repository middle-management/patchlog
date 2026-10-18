package dav_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/schema"
)

func parents(cat string, folders ...string) []any {
	out := []any{}
	for _, f := range folders {
		out = append(out, map[string]any{"href": "/r/" + cat + "/" + f})
	}
	return out
}

// treeCatalog is a file tree's catalog object (§H.2): it trusts ns, and
// more, and creates files in ns, its top level folder node root's
// children.
func treeCatalog(ns string, trust ...string) map[string]any {
	ts := []any{ns}
	for _, t := range trust {
		ts = append(ts, t)
	}
	return map[string]any{"trust": ts, "mode": "tree", "files": map[string]any{"ns": ns, "root": "root"}}
}

// treeEnv: content namespace matches, served flat too, and file tree cat
// creating its files there: Season/ holding derby.json (a placement of
// matches/derby), and Empty/.
func treeEnv(t *testing.T, with ...func(*clienttest.Options, *dav.Options)) *env {
	e := newEnv(t, []string{"matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}}, with...)
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
	e.create("cat", "empty", map[string]any{"title": "Empty", "parents": parents("cat", "root")})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
	return e
}

// nodeDoc is catalog node name's live document.
func (e *env) nodeDoc(cat, name string) map[string]any {
	e.t.Helper()
	h, doc := e.load(cat, name)
	if h.State != client.Live {
		e.t.Fatalf("%s/%s is %v", cat, name, h.State)
	}
	return doc.(map[string]any)
}

func (e *env) parentsOf(name string) []any {
	e.t.Helper()
	ps, _ := e.nodeDoc("cat", name)["parents"].([]any)
	return ps
}

// liveNames are ns's live resources.
func (e *env) liveNames(ns string) []string {
	e.t.Helper()
	var out []string
	for _, it := range must(e.c.Heads(e.ctx, ns, must(e.c.NSHead(e.ctx, ns)).ID)) {
		if it.Kind == "head" {
			out = append(out, it.Resource)
		}
	}
	sort.Strings(out)
	return out
}

// titled is the one live node of cat titled title: its name and document.
func (e *env) titled(cat, title string) (string, map[string]any) {
	e.t.Helper()
	var name string
	var doc map[string]any
	for _, n := range e.liveNames(cat) {
		d := e.nodeDoc(cat, n)
		if d["title"] == title {
			if name != "" {
				e.t.Fatalf("%s: two nodes titled %q", cat, title)
			}
			name, doc = n, d
		}
	}
	if name == "" {
		e.t.Fatalf("%s: no node titled %q", cat, title)
	}
	return name, doc
}

// itemOf is the item of the placement of cat titled title.
func (e *env) itemOf(cat, title string) (string, string) {
	e.t.Helper()
	node, _ := e.titled(cat, title)
	ns, item, ok := strings.Cut(node, ".")
	if !ok {
		e.t.Fatalf("%s/%s isn't a placement", cat, node)
	}
	return ns, item
}

// opaque is a name drawn for a new item or folder (§H.2).
var opaque = regexp.MustCompile(`^[a-z2-7]{13}$`)

// A file tree's top level is its files.root's children; folders and files
// are named by their nodes' titles, a placement without one by its item's
// name and a folder by its node's; titles that break the rules another
// tool wrote are shown escaped; names are Unicode, with spaces and
// capitals. Placements whose items are gone (dangling) aren't listed. A
// name is found under any case.
func TestTreeListing(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	for name, title := range map[string]string{"odd": "a/b\\c", "dots": "..", "trail": "notes.", "ctl": "tab\there",
		"nfd": "Résumé", "spaced": "Match Reports 2026", "kanji": "日本語"} {
		e.create("cat", name, map[string]any{"title": title, "parents": parents("cat", "root")})
	}
	e.create("cat", "untitled", map[string]any{"parents": parents("cat", "root")})
	e.create("matches", "cup", map[string]any{"title": "Cup"})
	e.create("cat", "matches.cup", map[string]any{"parents": parents("cat", "season")})
	e.create("matches", "gone", map[string]any{"title": "Gone"})
	e.create("cat", "matches.gone", map[string]any{"title": "gone.json", "parents": parents("cat", "season")})
	h, _ := e.load("matches", "gone")
	must(e.c.Delete(e.ctx, "matches", "gone", h.ID))

	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{"cat/", "matches/"})
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"%2E%2E/", "Empty/", "Match Reports 2026/", "Résumé/", "Season/",
		"a%2Fb%5Cc/", "notes%2E/", "tab%09here/", "untitled/", "日本語/"})
	want := rendered(map[string]any{"title": "Derby"})
	l := e.propfind("/cat/Season/")
	sameStrings(t, "Season", names(l, "/cat/Season/"), []string{"cup", "derby.json"})
	if en := l["/cat/Season/derby.json"]; en.size != strconv.Itoa(len(want)) || en.ctype != "application/json" || en.etag != `"`+must(e.c.Head(e.ctx, "matches", "derby")).ID+`"` {
		t.Fatalf("derby.json %+v", en)
	}
	if b := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET").body; b != want {
		t.Fatalf("GET %q", b)
	}
	e.expect(e.do("GET", "/cat/season/DERBY.JSON", ""), 200, "GET under another case")
	e.expect(e.do("GET", "/cat/derby.json", ""), 404, "not at the top level")
	e.expect(e.do("PROPFIND", "/cat/Season/gone.json", "", "Depth", "0"), 404, "a dangling placement")
	e.propfind("/cat/a%252Fb%255Cc/")
	e.propfind("/cat/" + url.PathEscape("Résumé") + "/")
	// A placement's file edits its item, as the flat view does.
	served := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/cat/Season/derby.json", edit(t, served, "Derby", "The derby")), 201, "PUT")
	sameJSON(t, e.lastEntry("matches", "derby").Patches, []any{replace("/title", "The derby")})
}

// Siblings whose names compare equal, after NFC and case folding, as a
// race leaves them, are shown as name (2).ext, … in order of their nodes'
// creation, the first keeping its name, a number a real title has
// skipped (§H.2 "Siblings"); a folder's number is at its name's end. A
// case-sensitive server compares names after NFC only.
func TestTreeDuplicates(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	mk := func(item, title string) {
		e.create("matches", item, map[string]any{"item": item})
		e.create("cat", "matches."+item, map[string]any{"title": title, "parents": parents("cat", "season")})
		e.s.Clock.Advance(time.Second)
	}
	mk("zz", "notes.md") // the first, though its name sorts last
	mk("real", "notes (2).md")
	mk("aa", "notes.md")
	mk("mm", "Notes.md")
	e.create("cat", "dz", map[string]any{"title": "Docs.v1", "parents": parents("cat", "root")})
	e.s.Clock.Advance(time.Second)
	e.create("cat", "da", map[string]any{"title": "Docs.v1", "parents": parents("cat", "root")})

	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"Notes (4).md", "derby.json", "notes (2).md", "notes (3).md", "notes.md"})
	for name, item := range map[string]string{"notes.md": "zz", "notes%20(2).md": "real", "notes%20(3).md": "aa", "Notes%20(4).md": "mm"} {
		if b := e.expect(e.do("GET", "/cat/Season/"+name, ""), 200, "GET "+name).body; b != rendered(map[string]any{"item": item}) {
			t.Fatalf("%s reads %q", name, b)
		}
	}
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"Docs.v1 (2)/", "Docs.v1/", "Empty/", "Season/"})
	e.expect(e.do("MKCOL", "/cat/Docs.v1%20(2)/sub", ""), 201, "MKCOL in the duplicate folder")
	if sub, _ := e.titled("cat", "sub"); e.parentsOf(sub)[0].(map[string]any)["href"] != "/r/cat/da" {
		t.Fatalf("sub's parents %v", e.parentsOf(sub))
	}
	b := e.expect(e.do("GET", "/cat/Season/notes%20(3).md", ""), 200, "GET").body
	e.expect(e.do("PUT", "/cat/Season/notes%20(3).md", edit(t, b, `"aa"`, `"aa2"`)), 201, "PUT of a duplicate")
	if _, doc := e.load("matches", "aa"); doc.(map[string]any)["item"] != "aa2" {
		t.Fatalf("aa %v", doc)
	}

	cs := e.anotherWith(func(o *dav.Options) { o.CaseSensitive = true })
	sameStrings(t, "Season, case-sensitive", names(cs.propfind("/cat/Season/"), "/cat/Season/"), []string{"Notes.md", "derby.json", "notes (2).md", "notes (3).md", "notes.md"})
	cs.expect(cs.do("GET", "/cat/season/derby.json", ""), 404, "another case, case-sensitive")
}

// anotherWith is another server over e's core, as e's was set up but for
// what f changes.
func (e *env) anotherWith(f func(*dav.Options)) *env {
	e.t.Helper()
	opt := e.opt
	f(&opt)
	srv, err := dav.New(opt)
	if err != nil {
		e.t.Fatal(err)
	}
	o := *e
	o.opt = opt
	o.dav = newTestServer(e.t, srv)
	return &o
}

// A new file is a new item in files.ns with an opaque name, and its
// placement titled with the file's name, under its folder, ordered after
// its siblings (§H.2, §H.4): raw unless its name ends in .json and it is
// I-JSON (§H.1). Names are Unicode in NFC, with spaces and capitals; a
// name that breaks the rules is refused, and one a sibling has under any
// case is that sibling's.
func TestTreeNewFiles(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	r := e.expect(e.do("PUT", "/cat/Season/Match%20report.md", "# Derby\n", "Content-Type", "text/plain"), 201, "PUT a new raw file")
	node, doc := e.titled("cat", "Match report.md")
	ns, item, _ := strings.Cut(node, ".")
	if ns != "matches" || !opaque.MatchString(item) {
		t.Fatalf("placement %s", node)
	}
	sameJSON(t, doc["parents"], []any{map[string]any{"href": "/r/cat/season", "order": "a0"}})
	h, idoc := e.load("matches", item)
	if m := idoc.(map[string]any); m["type"] != "text/markdown" || m["size"] != 8.0 {
		t.Fatalf("item %v", idoc)
	}
	if r.header.Get("ETag") != `"`+h.ID+`"` {
		t.Fatalf("ETag %q, head %s", r.header.Get("ETag"), h.ID)
	}
	if g := e.expect(e.do("GET", "/cat/Season/Match%20report.md", ""), 200, "GET"); g.body != "# Derby\n" || g.header.Get("Content-Type") != "text/markdown" {
		t.Fatalf("GET %q %q", g.body, g.header.Get("Content-Type"))
	}
	e.expect(e.do("PUT", "/cat/Season/Data.json", `{"b": 1, "a": [1]}`), 201, "PUT a new JSON file")
	_, item = e.itemOf("cat", "Data.json")
	_, idoc = e.load("matches", item)
	sameJSON(t, idoc, map[string]any{"b": 1, "a": []any{1}})
	e.expect(e.do("PUT", "/cat/Season/broken.json", `{"a": 1,}`), 201, "PUT a .json that isn't I-JSON")
	_, item = e.itemOf("cat", "broken.json")
	if _, idoc = e.load("matches", item); idoc.(map[string]any)["type"] != "application/json" {
		t.Fatalf("broken.json %v", idoc)
	}
	e.expect(e.do("PUT", "/cat/Season/"+url.PathEscape("Résumé.txt"), "cv"), 201, "PUT an NFD name")
	e.titled("cat", "Résumé.txt")
	e.expect(e.do("GET", "/cat/Season/"+url.PathEscape("Résumé.txt"), ""), 200, "GET by the NFC name")
	e.expect(e.do("PUT", "/cat/Season/"+url.PathEscape("日本語 メモ.md"), "memo"), 201, "PUT another script")
	e.expect(e.do("MKCOL", "/cat/Season/Sub%20Folder", ""), 201, "MKCOL")
	folder, fdoc := e.titled("cat", "Sub Folder")
	if !opaque.MatchString(folder) {
		t.Fatalf("folder %s", folder)
	}
	e.expect(e.do("PUT", "/cat/Season/Sub%20Folder/inner.txt", "in"), 201, "PUT in the new folder")
	if _, d := e.titled("cat", "inner.txt"); d["parents"].([]any)[0].(map[string]any)["href"] != "/r/cat/"+folder {
		t.Fatalf("inner.txt %v", d)
	}
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"Data.json", "Match report.md", "Résumé.txt", "Sub Folder/", "broken.json", "derby.json", "日本語 メモ.md"})
	// Each new node orders after the last: by code unit, in creation order.
	var orders []string
	for _, title := range []string{"Match report.md", "Data.json", "broken.json", "Résumé.txt", "日本語 メモ.md"} {
		_, d := e.titled("cat", title)
		orders = append(orders, d["parents"].([]any)[0].(map[string]any)["order"].(string))
	}
	orders = append(orders, fdoc["parents"].([]any)[0].(map[string]any)["order"].(string))
	if !sort.StringsAreSorted(orders) || orders[0] == orders[1] {
		t.Fatalf("orders %q", orders)
	}

	before := len(e.liveNames("cat"))
	for _, n := range []string{"a%5Cb.md", "trailing.", "trailing%20", "tab%09.md", strings.Repeat("x", 256), "%C3%28.md"} {
		r := e.expect(e.do("PUT", "/cat/Season/"+n, "x"), 403, "PUT "+n)
		if !strings.Contains(r.body, "can't name a file or folder") {
			t.Fatalf("PUT %s: %q", n, r.body)
		}
		e.expect(e.do("MKCOL", "/cat/Season/"+n, ""), 403, "MKCOL "+n)
	}
	if after := len(e.liveNames("cat")); after != before {
		t.Fatalf("refused names made %d nodes", after-before)
	}
	// A sibling's name, under any case, is the sibling's.
	e.expect(e.do("PUT", "/cat/Season/DERBY.JSON", `{"title": "Derby!"}`), 201, "PUT to a sibling's name in capitals")
	if _, doc := e.load("matches", "derby"); doc.(map[string]any)["title"] != "Derby!" {
		t.Fatalf("derby %v", doc)
	}
	if after := len(e.liveNames("cat")); after != before {
		t.Fatal("a sibling's name made a node")
	}
	e.expect(e.do("MKCOL", "/cat/season", ""), 405, "MKCOL of a folder's name in lowercase")
	e.expect(e.do("MKCOL", "/cat/Season/derby.json", ""), 403, "MKCOL of a file's name")
	e.expect(e.do("PUT", "/cat/Season", "x"), 405, "PUT of a folder's name")
}

// A new file the core refuses writes nothing: a tree that doesn't trust
// files.ns creates none, a dry run of the placement comes before the item
// is created (a frozen catalog, its rules), and an item whose placement
// is refused after that (the catalog changed in between) is deleted again
// at once (§H.4 "New files").
func TestTreeNewFileRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches", "other"}, []string{"cat", "ruled", "untrusting", "racy"}, map[string]map[string]any{
		"cat":        {"catalog": treeCatalog("matches")},
		"untrusting": {"catalog": map[string]any{"trust": []any{"other"}, "files": map[string]any{"ns": "matches", "root": "root"}}},
		"racy":       {"catalog": treeCatalog("matches")},
		"ruled": {"catalog": treeCatalog("matches"), "rules": []any{map[string]any{
			"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "create"}},
			"then": []any{map[string]any{"op": "test", "path": "/doc/title", "schema": map[string]any{"maxLength": 5}}}}}},
	}, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/r/racy/matches.") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code": "forbidden", "message": "refused after the dry run"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	for _, cat := range []string{"cat", "ruled", "untrusting", "racy"} {
		e.create(cat, "root", map[string]any{"title": "Top", "parents": []any{}})
	}
	r := e.expect(e.do("PUT", "/untrusting/x.md", "x"), 403, "PUT in a tree that doesn't trust files.ns")
	if !strings.Contains(r.body, "doesn't trust") {
		t.Fatalf("403 %q", r.body)
	}
	r = e.expect(e.do("PUT", "/ruled/toolong.md", "x"), 422, "PUT the catalog's rules refuse")
	if !strings.Contains(r.body, "rule") {
		t.Fatalf("422 %q", r.body)
	}
	sameStrings(t, "matches", e.liveNames("matches"), nil)
	e.expect(e.do("PUT", "/ruled/ok.md", "x"), 201, "PUT the rules take")
	sameStrings(t, "ruled", names(e.propfind("/ruled/"), "/ruled/"), []string{"ok.md"})
	made := e.liveNames("matches")
	if len(made) != 1 {
		t.Fatalf("matches %q", made)
	}

	nh := must(e.c.NSHead(e.ctx, "cat"))
	must(e.c.PatchConfig(e.ctx, "cat", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	e.expect(e.do("PUT", "/cat/x.md", "x"), 403, "PUT in a frozen tree")
	e.expect(e.do("MKCOL", "/cat/Dir", ""), 403, "MKCOL in a frozen tree")
	sameStrings(t, "matches", e.liveNames("matches"), made)

	r = e.expect(e.do("PUT", "/racy/x.md", "x"), 403, "PUT whose placement is refused after its dry run")
	if !strings.Contains(r.body, "deleted again") {
		t.Fatalf("403 %q", r.body)
	}
	sameStrings(t, "matches", e.liveNames("matches"), made)
	heads := must(e.c.Heads(e.ctx, "matches", must(e.c.NSHead(e.ctx, "matches")).ID))
	if len(heads) != 2 {
		t.Fatalf("matches heads %+v", heads)
	}
}

// New nodes carry $schema from files.folder and files.placement, so the
// catalog's schemas take them; where the catalog requires nonces, every
// write to it carries a fresh $nonce (§H.7), as the files' writes do
// where files.ns requires them, a raw file's blob a nonce too; a JSON
// file whose root isn't an object is refused there.
func TestTreeSchemasNonces(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"files"}, []string{"cat"}, nil)
	must(e.c.CreateNamespace(e.ctx, "schemas", map[string]any{"read": "public"}))
	node := map[string]any{"$schema": schema.Dialect2020, "type": "object", "required": []any{"title", "parents"},
		"properties": map[string]any{"title": map[string]any{"type": "string"}, "parents": map[string]any{"type": "array"}}}
	folder := "/r/schemas/folder/rev/" + must(e.c.CreateDoc(e.ctx, "schemas", "folder", node)).ID
	placement := "/r/schemas/placement/rev/" + must(e.c.CreateDoc(e.ctx, "schemas", "placement", node)).ID
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	for ns, ps := range map[string][]any{
		"cat": {map[string]any{"op": "add", "path": "/catalog", "value": map[string]any{"trust": []any{"files"}, "mode": "tree",
			"files": map[string]any{"ns": "files", "root": "root", "folder": folder, "placement": placement}}},
			map[string]any{"op": "add", "path": "/nonce", "value": "required"}},
		"files": {map[string]any{"op": "add", "path": "/nonce", "value": "required"}},
	} {
		must(e.c.PatchConfig(e.ctx, ns, must(e.c.NSHead(e.ctx, ns)).Config, ps))
	}
	nonce := func(what string, doc map[string]any) {
		t.Helper()
		if s, _ := doc["$nonce"].(string); len(s) != 26 {
			t.Fatalf("%s: $nonce %v", what, doc["$nonce"])
		}
	}
	e.expect(e.do("MKCOL", "/cat/Photos", ""), 201, "MKCOL")
	fnode, fdoc := e.titled("cat", "Photos")
	if fdoc["$schema"] != folder {
		t.Fatalf("folder %v", fdoc)
	}
	nonce("folder", fdoc)
	e.expect(e.do("PUT", "/cat/Photos/pic.png", "\x89PNG"), 201, "PUT raw")
	pnode, pdoc := e.titled("cat", "pic.png")
	if pdoc["$schema"] != placement || pdoc["parents"].([]any)[0].(map[string]any)["href"] != "/r/cat/"+fnode {
		t.Fatalf("placement %v", pdoc)
	}
	nonce("placement", pdoc)
	_, item, _ := strings.Cut(pnode, ".")
	_, idoc := e.load("files", item)
	nonce("item", idoc.(map[string]any))
	if s, _ := idoc.(map[string]any)["nonce"].(string); len(s) != 26 {
		t.Fatalf("blob nonce in %v", idoc)
	}
	e.expect(e.do("MOVE", "/cat/Photos/pic.png", "", "Destination", "/cat/Photos/picture.png"), 201, "rename")
	en := e.lastEntry("cat", pnode)
	if ps := en.Patches.([]any); len(ps) != 2 || ps[0].(map[string]any)["path"] != "/title" || ps[1].(map[string]any)["path"] != "/$nonce" {
		t.Fatalf("rename %v", en.Patches)
	}
	e.expect(e.do("MOVE", "/cat/Photos/picture.png", "", "Destination", "/cat/picture.png"), 201, "move")
	nonce("moved placement", e.nodeDoc("cat", pnode))
	e.expect(e.do("PUT", "/cat/list.json", `[1, 2]`), 422, "PUT of a JSON array where nonces are required")
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"Photos/", "picture.png"})
	e.expect(e.do("DELETE", "/cat/picture.png", ""), 204, "DELETE")
	e.expect(e.do("DELETE", "/cat/Photos", ""), 204, "DELETE the folder")
}

// A rename is one append to the node's title, a move one to its parents
// (ordered after the last child there), both one append with both, with
// If-Match on the node's head: the item isn't touched, so its history and
// ETag stay (§H.2, §H.5). A rename to another case of the name is taken
// whatever Overwrite says. A folder renames and moves with what is in it,
// never into itself, and doesn't leave its tree.
func TestTreeRenameMove(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("cat", "archive", map[string]any{"title": "Archive", "parents": parents("cat", "season")})
	item := must(e.c.Head(e.ctx, "matches", "derby")).ID
	etag := e.propfind("/cat/Season/derby.json", "0")["/cat/Season/derby.json"].etag
	nodeHead := must(e.c.Head(e.ctx, "cat", "matches.derby")).ID

	e.expect(e.do("MOVE", "/cat/Season/derby.json", "", "Destination", "/cat/Season/The%20derby.json"), 201, "rename")
	en := e.lastEntry("cat", "matches.derby")
	if en.Parent != nodeHead {
		t.Fatalf("rename's parent %s, head was %s", en.Parent, nodeHead)
	}
	sameJSON(t, en.Patches, []any{map[string]any{"op": "add", "path": "/title", "value": "The derby.json"}})
	if got := e.propfind("/cat/Season/The%20derby.json", "0")["/cat/Season/The derby.json"].etag; got != etag {
		t.Fatalf("ETag %s after a rename, was %s", got, etag)
	}
	e.expect(e.do("MOVE", "/cat/Season/The%20derby.json", "", "Destination", "/cat/Empty/The%20derby.json"), 201, "move")
	sameJSON(t, e.lastEntry("cat", "matches.derby").Patches, []any{map[string]any{"op": "replace", "path": "/parents/0",
		"value": map[string]any{"href": "/r/cat/empty", "order": "a0"}}})
	e.expect(e.do("MOVE", "/cat/Empty/The%20derby.json", "", "Destination", "/cat/Season/Archive/derby.json"), 201, "rename and move")
	sameJSON(t, e.lastEntry("cat", "matches.derby").Patches, []any{map[string]any{"op": "add", "path": "/title", "value": "derby.json"},
		map[string]any{"op": "replace", "path": "/parents/0", "value": map[string]any{"href": "/r/cat/archive", "order": "a0"}}})
	e.expect(e.do("MOVE", "/cat/Season/Archive/derby.json", "", "Destination", "/cat/Season/Archive/Derby.json", "Overwrite", "F"), 201, "rename to another case")
	if e.nodeDoc("cat", "matches.derby")["title"] != "Derby.json" {
		t.Fatal("not renamed")
	}
	if h := must(e.c.Head(e.ctx, "matches", "derby")); h.ID != item || len(must(e.c.Log(e.ctx, "matches", "derby", "", ""))) != 1 {
		t.Fatal("a rename or move wrote the item")
	}
	if got := e.propfind("/cat/Season/Archive/Derby.json", "0")["/cat/Season/Archive/Derby.json"].etag; got != etag {
		t.Fatalf("ETag %s after moves, was %s", got, etag)
	}

	e.expect(e.do("MOVE", "/cat/Season/Archive", "", "Destination", "/cat/Season/Old%20Stuff"), 201, "rename a folder")
	if e.nodeDoc("cat", "archive")["title"] != "Old Stuff" {
		t.Fatal("folder not renamed")
	}
	sameStrings(t, "Old Stuff", names(e.propfind("/cat/Season/Old%20Stuff/"), "/cat/Season/Old Stuff/"), []string{"Derby.json"})
	e.expect(e.do("MOVE", "/cat/Season/Old%20Stuff", "", "Destination", "/cat/Empty/Old%20Stuff"), 201, "move a folder")
	sameJSON(t, e.parentsOf("archive"), []any{map[string]any{"href": "/r/cat/empty", "order": "a0"}})
	sameStrings(t, "Empty/Old Stuff", names(e.propfind("/cat/Empty/Old%20Stuff/"), "/cat/Empty/Old Stuff/"), []string{"Derby.json"})
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Empty/Old%20Stuff/Empty"), 403, "a folder into a folder in it")
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Empty/Empty"), 403, "a folder into itself")
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Season"), 403, "a folder over another")
	e.expect(e.do("MOVE", "/cat/Empty/Old%20Stuff/Derby.json", "", "Destination", "/cat/Season"), 403, "a file over a folder")
	e.expect(e.do("MOVE", "/cat/Season", "", "Destination", "/matches/Season"), 403, "a folder out of its tree")
	e.expect(e.do("MOVE", "/cat/Empty/Old%20Stuff/Derby.json", "", "Destination", "/cat/Season/bad."), 403, "a rename to a refused name")
	sameJSON(t, e.parentsOf("season"), parents("cat", "root"))
}

// Deleting a file deletes its placement, then its item where the tree
// owns its namespace (files.ns), else the item stays; with If-Match that
// isn't the head, nothing (§H.5). A folder is deleted only empty, the 409
// naming what is in it, dangling placements deleted first; the tree's
// top isn't deleted.
func TestTreeDelete(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches", "other"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches", "other")}})
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("other", "foreign", map[string]any{"title": "Foreign"})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
	e.create("cat", "empty", map[string]any{"title": "Empty", "parents": parents("cat", "root")})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
	e.create("cat", "other.foreign", map[string]any{"title": "foreign.json", "parents": parents("cat", "season")})

	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If-Match", `"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), 412, "DELETE with another If-Match")
	e.nodeDoc("cat", "matches.derby")
	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If-Match", `"`+must(e.c.Head(e.ctx, "matches", "derby")).ID+`"`), 204, "DELETE")
	e.expectTombstoned("cat", "matches.derby", "the placement")
	e.expectTombstoned("matches", "derby", "the item, in files.ns")
	e.expect(e.do("DELETE", "/cat/Season/foreign.json", ""), 204, "DELETE of a file of another namespace")
	e.expectTombstoned("cat", "other.foreign", "the placement")
	if h, _ := e.load("other", "foreign"); h.State != client.Live {
		t.Fatalf("an item outside files.ns is %v", h.State)
	}

	e.expect(e.do("PUT", "/cat/Empty/a.md", "a"), 201, "PUT")
	e.expect(e.do("MKCOL", "/cat/Empty/Sub", ""), 201, "MKCOL")
	r := e.expect(e.do("DELETE", "/cat/Empty", ""), 409, "DELETE of a folder with things in it")
	if !strings.Contains(r.body, `"Sub/"`) || !strings.Contains(r.body, `"a.md"`) {
		t.Fatalf("409 %q", r.body)
	}
	e.expect(e.do("DELETE", "/cat/Empty/a.md", ""), 204, "DELETE")
	e.expect(e.do("DELETE", "/cat/Empty/Sub", ""), 204, "DELETE an empty folder")
	e.create("matches", "ghost", map[string]any{"t": 1})
	e.create("cat", "matches.ghost", map[string]any{"title": "ghost.json", "parents": parents("cat", "empty")})
	h, _ := e.load("matches", "ghost")
	must(e.c.Delete(e.ctx, "matches", "ghost", h.ID))
	e.expect(e.do("PUT", "/cat/Empty/.DS_Store", "Bud1"), 201, "a scratch file in it")
	sameStrings(t, "Empty", names(e.propfind("/cat/Empty/"), "/cat/Empty/"), []string{".DS_Store"})
	e.expect(e.do("DELETE", "/cat/Empty", ""), 204, "DELETE of a folder holding a dangling placement")
	e.expectTombstoned("cat", "matches.ghost", "the dangling placement")
	e.expectTombstoned("cat", "empty", "the folder")
	e.expect(e.do("DELETE", "/cat", ""), 403, "DELETE of the tree's top")
	e.expect(e.do("DELETE", "/cat/Season/nothing.md", ""), 404, "DELETE of nothing")
}

// A write to a path the user deleted within 30 seconds restores that file,
// its placement then its item, rebased on its last live document; a
// refused one undoes the DELETE; one later makes a new file (§H.6).
func TestTreeDeleteThenWrite(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := treeEnv(t, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })
	served := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET").body
	e.theirs("matches", "derby", map[string]any{"op": "add", "path": "/score", "value": "1-0"})
	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "DELETE")
	e.expect(e.do("PUT", "/cat/Season/derby.json", edit(t, served, `"Derby"`, `"The derby"`)), 201, "PUT after the DELETE")
	if log := must(e.c.Log(e.ctx, "cat", "matches.derby", "", "")); len(log) != 3 || log[1].Kind != "tombstone" {
		t.Fatalf("placement log %+v", log)
	}
	log := must(e.c.Log(e.ctx, "matches", "derby", "", ""))
	if len(log) != 4 || log[2].Kind != "tombstone" {
		t.Fatalf("item log %+v", log)
	}
	sameJSON(t, log[3].Patches, []any{replace("/title", "The derby")})
	_, doc := e.load("matches", "derby")
	sameJSON(t, doc, map[string]any{"title": "The derby", "score": "1-0"})

	e.expect(e.do("PUT", "/cat/Season/notes.md", "v1"), 201, "PUT raw")
	_, item := e.itemOf("cat", "notes.md")
	e.expect(e.do("DELETE", "/cat/Season/notes.md", ""), 204, "DELETE raw")
	c.add(20 * time.Second)
	e.expect(e.do("PUT", "/cat/Season/notes.md", "v2"), 201, "PUT raw after the DELETE")
	if _, it := e.itemOf("cat", "notes.md"); it != item {
		t.Fatalf("a new item %s, not %s restored", it, item)
	}
	if b := e.expect(e.do("GET", "/cat/Season/notes.md", ""), 200, "GET").body; b != "v2" {
		t.Fatalf("GET %q", b)
	}

	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "DELETE")
	r := e.expect(e.do("PUT", "/cat/Season/derby.json", `{"title": `), 400, "PUT that isn't JSON after the DELETE")
	if !strings.Contains(r.body, "restored as it was") {
		t.Fatalf("400 %q", r.body)
	}
	e.nodeDoc("cat", "matches.derby")
	if _, doc = e.load("matches", "derby"); doc.(map[string]any)["title"] != "The derby" {
		t.Fatalf("derby %v", doc)
	}

	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "DELETE")
	c.add(31 * time.Second)
	e.expect(e.do("PUT", "/cat/Season/derby.json", `{"title": "New"}`), 201, "PUT 31 s after the DELETE")
	e.expectTombstoned("cat", "matches.derby", "the old placement")
	e.expectTombstoned("matches", "derby", "the old item")
	if _, it := e.itemOf("cat", "derby.json"); !opaque.MatchString(it) {
		t.Fatalf("new item %s", it)
	}
}

// A copy is a new item with the source's content, and a placement: a raw
// file's blob copied with Blob-From (§7.8), keeping its id, or uploaded
// again where the source's rank doesn't allow that (§H.5 "Copy"). A
// folder isn't copied.
func TestTreeCopy(t *testing.T) {
	t.Parallel()
	var froms, uploads atomic.Int64
	e := newEnv(t, []string{"matches", "priv"}, []string{"cat"}, map[string]map[string]any{
		"cat":  {"catalog": treeCatalog("matches")},
		"priv": {"read": "grant"},
	}, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" && strings.Contains(r.URL.Path, "/blob/") {
					if r.Header.Get("Blob-From") != "" {
						froms.Add(1)
					} else {
						uploads.Add(1)
					}
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})

	e.expect(e.do("PUT", "/cat/Season/pic.png", "\x89PNG pixels"), 201, "PUT")
	_, src := e.itemOf("cat", "pic.png")
	froms.Store(0)
	uploads.Store(0)
	e.expect(e.do("COPY", "/cat/Season/pic.png", "", "Destination", "/cat/Season/pic%20copy.png"), 201, "COPY")
	_, dst := e.itemOf("cat", "pic copy.png")
	_, sdoc := e.load("matches", src)
	_, ddoc := e.load("matches", dst)
	if dst == src || ddoc.(map[string]any)["$blob"] != sdoc.(map[string]any)["$blob"] {
		t.Fatalf("copy %s %v of %s %v", dst, ddoc, src, sdoc)
	}
	if froms.Load() != 1 || uploads.Load() != 0 {
		t.Fatalf("%d copies, %d uploads", froms.Load(), uploads.Load())
	}
	e.expect(e.do("COPY", "/cat/Season/derby.json", "", "Destination", "/cat/top.json"), 201, "COPY of a JSON file")
	_, item := e.itemOf("cat", "top.json")
	if item == "derby" {
		t.Fatal("a copy placed its source")
	}
	_, doc := e.load("matches", item)
	sameJSON(t, doc, map[string]any{"title": "Derby"})
	e.expect(e.do("COPY", "/matches/derby.json", "", "Destination", "/cat/Season/from%20flat.json"), 201, "COPY from the flat view")

	e.expect(e.do("PUT", "/priv/secret.png", "\x89PNG secret"), 201, "PUT in a private namespace")
	froms.Store(0)
	uploads.Store(0)
	e.expect(e.do("COPY", "/priv/secret.png", "", "Destination", "/cat/secret.png"), 201, "COPY from a higher rank")
	if froms.Load() != 1 || uploads.Load() != 1 {
		t.Fatalf("%d copies, %d uploads", froms.Load(), uploads.Load())
	}
	if b := e.expect(e.do("GET", "/cat/secret.png", ""), 200, "GET").body; b != "\x89PNG secret" {
		t.Fatalf("GET %q", b)
	}
	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/cat/Season2"), 403, "COPY of a folder")
}

// A file moved to another tree or namespace is copied, then deleted; its
// item, deleted, names the copy in $successor (§8.1), but a JSON file
// whose root isn't an object can't. Moved onto an existing file, its
// content is saved into it, which keeps its history: a temporary file
// renamed over a file (§H.5).
func TestTreeMoveAcross(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches", "docs"}, []string{"cat", "cat2"}, map[string]map[string]any{
		"cat":  {"catalog": treeCatalog("matches")},
		"cat2": {"catalog": treeCatalog("docs")},
	})
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	for _, cat := range []string{"cat", "cat2"} {
		e.create(cat, "root", map[string]any{"parents": []any{}})
	}
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "root")})

	e.expect(e.do("PUT", "/cat/report.md", "text"), 201, "PUT")
	_, a := e.itemOf("cat", "report.md")
	e.expect(e.do("MOVE", "/cat/report.md", "", "Destination", "/docs/report.md"), 201, "MOVE to the flat view")
	if b := e.expect(e.do("GET", "/docs/report.md", ""), 200, "GET").body; b != "text" {
		t.Fatalf("GET %q", b)
	}
	if h, _ := e.load("matches", a); h.State != client.Tombstoned || h.Successor != "/r/docs/report.md" {
		t.Fatalf("moved item %+v", h)
	}
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"derby.json"})

	e.expect(e.do("PUT", "/matches/notes.txt", "n"), 201, "PUT flat")
	e.expect(e.do("MOVE", "/matches/notes.txt", "", "Destination", "/cat/notes.txt"), 201, "MOVE into the tree")
	_, b := e.itemOf("cat", "notes.txt")
	if h, _ := e.load("matches", "notes.txt"); h.State != client.Tombstoned || h.Successor != b {
		t.Fatalf("moved resource %+v, copy %s", h, b)
	}
	e.expect(e.do("MOVE", "/cat/notes.txt", "", "Destination", "/cat2/notes.txt"), 201, "MOVE to another tree")
	_, c := e.itemOf("cat2", "notes.txt")
	if h, _ := e.load("matches", b); h.State != client.Tombstoned || h.Successor != "/r/docs/"+c {
		t.Fatalf("moved item %+v, copy %s", h, c)
	}
	if b := e.expect(e.do("GET", "/cat2/notes.txt", ""), 200, "GET").body; b != "n" {
		t.Fatalf("GET %q", b)
	}

	e.expect(e.do("PUT", "/cat/list.json", `[1, 2]`), 201, "PUT a JSON array")
	_, l := e.itemOf("cat", "list.json")
	e.expect(e.do("MOVE", "/cat/list.json", "", "Destination", "/docs/list.json"), 201, "MOVE a JSON array")
	if h, _ := e.load("matches", l); h.State != client.Tombstoned || h.Successor != "" {
		t.Fatalf("moved array %+v", h)
	}
	_, doc := e.load("docs", "list")
	sameJSON(t, doc, []any{1, 2})

	e.expect(e.do("PUT", "/cat/draft.md", "v1"), 201, "PUT")
	_, d := e.itemOf("cat", "draft.md")
	e.expect(e.do("PUT", "/cat/.draft.md.tmp", "v2"), 201, "PUT a temporary file")
	_, tmp := e.itemOf("cat", ".draft.md.tmp")
	e.expect(e.do("MOVE", "/cat/.draft.md.tmp", "", "Destination", "/cat/draft.md"), 204, "MOVE it over the file")
	if b := e.expect(e.do("GET", "/cat/draft.md", ""), 200, "GET").body; b != "v2" {
		t.Fatalf("GET %q", b)
	}
	if _, it := e.itemOf("cat", "draft.md"); it != d || len(must(e.c.Log(e.ctx, "matches", d, "", ""))) != 2 {
		t.Fatal("the file moved over lost its history")
	}
	if h, _ := e.load("matches", d); h.State != client.Live {
		t.Fatalf("draft %v", h.State)
	}
	e.expectTombstoned("matches", tmp, "the temporary file's item")
	if m := e.lastEntry("matches", "derby"); m.Parent != "" {
		t.Fatal("derby written")
	}
	r := e.expect(e.do("MOVE", "/matches/derby.json", "", "Destination", "/cat/derby.json"), 403, "MOVE of a document onto itself in the tree")
	if !strings.Contains(r.body, "one document") {
		t.Fatalf("403 %q", r.body)
	}
}

// Editors' saves in a tree: gedit moves a scratch file over the file,
// vim moves the file aside and writes it anew create-only; a copy's name
// (Finder's Duplicate) and a new folder's ("untitled folder") are real
// names, renamed by a title change; apps' own folders stay scratch.
func TestTreeEditorSaves(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.expect(e.do("PUT", "/cat/Season/notes.md", "v1"), 201, "PUT")
	_, item := e.itemOf("cat", "notes.md")
	nodes := len(e.liveNames("cat"))
	e.expect(e.do("GET", "/cat/Season/notes.md", ""), 200, "GET")
	e.expect(e.do("PUT", "/cat/Season/.goutputstream-ABC", "v2"), 201, "gedit's temporary file")
	e.expect(e.do("MOVE", "/cat/Season/.goutputstream-ABC", "", "Destination", "/cat/Season/notes.md"), 204, "moved over")
	e.expect(e.do("PUT", "/cat/Season/4913", ""), 201, "vim's test file")
	e.expect(e.do("DELETE", "/cat/Season/4913", ""), 204, "deleted")
	e.expect(e.do("MOVE", "/cat/Season/notes.md", "", "Destination", "/cat/Season/notes.md~"), 201, "vim's backup")
	e.expect(e.do("PUT", "/cat/Season/notes.md", "v3", "If-None-Match", "*"), 201, "vim's create-only write")
	if _, it := e.itemOf("cat", "notes.md"); it != item {
		t.Fatal("an editor's save made a new file")
	}
	if b := e.expect(e.do("GET", "/cat/Season/notes.md", ""), 200, "GET").body; b != "v3" {
		t.Fatalf("GET %q", b)
	}
	if n := len(e.liveNames("cat")); n != nodes {
		t.Fatalf("editors' scratch files made %d nodes", n-nodes)
	}

	e.expect(e.do("COPY", "/cat/Season/notes.md", "", "Destination", "/cat/Season/notes%20copy.md"), 201, "Finder's Duplicate")
	copyNode, _ := e.titled("cat", "notes copy.md")
	e.expect(e.do("MOVE", "/cat/Season/notes%20copy.md", "", "Destination", "/cat/Season/ideas.md"), 201, "renamed")
	if e.nodeDoc("cat", copyNode)["title"] != "ideas.md" {
		t.Fatal("not renamed")
	}
	e.expect(e.do("MKCOL", "/cat/untitled%20folder", ""), 201, "a file manager's new folder")
	folder, _ := e.titled("cat", "untitled folder")
	e.expect(e.do("MOVE", "/cat/untitled%20folder", "", "Destination", "/cat/Photos"), 201, "named")
	if e.nodeDoc("cat", folder)["title"] != "Photos" {
		t.Fatal("not named")
	}
	nodes = len(e.liveNames("cat"))
	dir := "/cat/(A%20Document%20Being%20Saved%20By%20TextEdit)"
	e.expect(e.do("MKCOL", dir, ""), 201, "TextEdit's folder")
	e.expect(e.do("PUT", dir+"/x.md", "x"), 201, "saved in it")
	e.expect(e.do("MKCOL", "/cat/.TemporaryItems", ""), 201, "macOS's folder")
	if n := len(e.liveNames("cat")); n != nodes {
		t.Fatal("apps' folders were written")
	}
	e.expect(e.do("MOVE", dir+"/x.md", "", "Destination", "/cat/Photos/x.md"), 201, "moved out")
	e.titled("cat", "x.md")
	e.expect(e.do("DELETE", dir, ""), 204, "TextEdit's folder deleted")
}

// A catalog without catalog.files isn't a file tree: Check refuses it at
// start, the root leaves it out, and it answers 404 saying why; so does
// one whose files.root isn't a folder.
func TestTreeNotTree(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches"}, []string{"cat", "plain", "rootless"}, map[string]map[string]any{
		"cat":      {"catalog": treeCatalog("matches")},
		"plain":    {"catalog": map[string]any{"trust": []any{"matches"}}},
		"rootless": {"catalog": treeCatalog("matches")},
	})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	srv := must(dav.New(e.opt))
	err := srv.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "plain") || !strings.Contains(err.Error(), "catalog.files") {
		t.Fatalf("Check: %v", err)
	}
	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{"cat/", "matches/", "rootless/"})
	r := e.expect(e.do("PROPFIND", "/plain/", "", "Depth", "1"), 404, "PROPFIND of a catalog that isn't a tree")
	if !strings.Contains(r.body, "catalog.files") {
		t.Fatalf("404 %q", r.body)
	}
	e.expect(e.do("PUT", "/plain/x.md", "x"), 404, "PUT there")
	r = e.expect(e.do("PROPFIND", "/rootless/", "", "Depth", "1"), 404, "PROPFIND of a tree without its root")
	if !strings.Contains(r.body, "files.root") {
		t.Fatalf("404 %q", r.body)
	}
	ok := newEnv(t, nil, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}})
	if err := must(dav.New(ok.opt)).Check(context.Background()); err != nil {
		t.Fatalf("Check of a tree: %v", err)
	}
}

// Listings of namespaces and trees longer than a /heads page (§7.1
// Paging) list everything.
func TestPagedFlows(t *testing.T) {
	clienttest.Paged(t, 2, func(t *testing.T) {
		e := treeEnv(t)
		for _, n := range []string{"a", "b", "c", "d"} {
			e.create("matches", n, map[string]any{"n": n})
			e.create("cat", "matches."+n, map[string]any{"title": n + ".json", "parents": parents("cat", "season")})
		}
		sameStrings(t, "matches", names(e.propfind("/matches/"), "/matches/"), []string{"a.json", "b.json", "c.json", "d.json", "derby.json"})
		sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"Empty/", "Season/"})
		e.expect(e.do("PUT", "/cat/Season/e.json", `{"n": "e"}`), 201, "PUT")
		sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"a.json", "b.json", "c.json", "d.json", "derby.json", "e.json"})
	})
}

// Writes through a placement go only where the server would write: items
// in a namespace the catalog trusts (§B.3) or that is served (-ns), never
// a catalog's own nodes.
func TestTreePlacementWrites(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	must(e.c.CreateNamespace(e.ctx, "secret", map[string]any{"read": "public"}))
	e.create("secret", "plans", map[string]any{"launch": "monday"})
	e.create("cat", "secret.plans", map[string]any{"title": "plans.json", "parents": parents("cat", "season")})
	e.create("cat", "cat.empty", map[string]any{"title": "node.json", "parents": parents("cat", "season")})
	e.expect(e.do("GET", "/cat/Season/plans.json", ""), 200, "GET a placement of an untrusted item")
	e.expect(e.do("PUT", "/cat/Season/plans.json", `{"launch": "never"}`), 403, "PUT over an item not trusted nor served")
	_, doc := e.load("secret", "plans")
	sameJSON(t, doc, map[string]any{"launch": "monday"})
	e.expect(e.do("PUT", "/cat/Season/node.json", `{"x": 1}`), 403, "PUT through a placement of a catalog node")
	e.expect(e.do("PUT", "/matches/.goutputstream-tmp", `{"planted": true}`), 201, "temporary file")
	e.expect(e.do("MOVE", "/matches/.goutputstream-tmp", "", "Destination", "/cat/Season/plans.json"), 403, "MOVE onto an untrusted placement")
}

// counted is a tree whose core counts the requests the WebDAV server
// makes (its writes carry X-Author dav): Season/ holds ten files and Sub/,
// which holds ten more.
func counted(t *testing.T) (*env, func() int64) {
	var n atomic.Int64
	e := newEnv(t, []string{"matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}},
		func(c *clienttest.Options, _ *dav.Options) {
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
	e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "season")})
	for i := 0; i < 20; i++ {
		name := "m" + strconv.Itoa(i)
		e.create("matches", name, map[string]any{"n": i})
		folder := "season"
		if i >= 10 {
			folder = "sub"
		}
		e.create("cat", "matches."+name, map[string]any{"title": name + ".json", "parents": parents("cat", folder)})
	}
	return e, func() int64 { return n.Swap(0) }
}

// What a listing costs upstream: the root's each namespace's document
// once every 30 seconds (sealed and end-to-end ones aren't offered,
// §H.7); a tree's nodes, and the heads of a folder's items (not a
// subfolder's), once per CatalogTTL; each revision's document once, for
// its file's size and type; a file's properties two heads in the flat
// view (its name could be a raw file's, §H.2), one in a tree.
func TestTreeRequests(t *testing.T) {
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
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"Season/"})
	reqs()
	l := e.propfind("/cat/Season/")
	if len(l) != 12 {
		t.Fatalf("Season lists %d", len(l))
	}
	if n := reqs(); n > 2*10 {
		t.Fatalf("PROPFIND of a folder with 10 files and a subfolder made %d requests", n)
	}
	e.propfind("/cat/Season/")
	e.expect(e.do("GET", "/cat/Season/m3.json", ""), 200, "GET a file")
	if n := reqs(); n > 1 {
		t.Fatalf("a folder listed again and a file read made %d requests", n)
	}
	e.propfind("/matches/m3.json", "0")
	if n := reqs(); n > 2 {
		t.Fatalf("PROPFIND Depth 0 of a file made %d requests", n)
	}
	// A write through the server is seen at once.
	e.expect(e.do("MKCOL", "/cat/Season/New", ""), 201, "MKCOL")
	if l := e.propfind("/cat/Season/"); l["/cat/Season/New/"].dir != true {
		t.Fatalf("after MKCOL %v", names(l, "/cat/Season/"))
	}
}

// A tree DELETE with If-Match whose item changes between the check and
// its delete is a 412, the placement restored: the file stays as it is,
// not unplaced (§H.5).
func TestTreeDeleteIfMatchRace(t *testing.T) {
	t.Parallel()
	h := &hook{}
	e := treeEnv(t, withHook(h))
	g := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET")
	h.set(at("DELETE", "/r/cat/matches.derby"), func() {
		e.theirs("matches", "derby", map[string]any{"op": "add", "path": "/theirs", "value": "important"})
	})
	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If-Match", g.header.Get("ETag")), 412, "DELETE If-Match, the item edited meanwhile")
	if hn, _ := e.load("cat", "matches.derby"); hn.State != client.Live {
		t.Fatalf("placement %v", hn.State)
	}
	if hi, doc := e.load("matches", "derby"); hi.State != client.Live || doc.(map[string]any)["theirs"] != "important" {
		t.Fatalf("item %v %v", hi.State, doc)
	}
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
}

// The item created for a new file whose placement the core refuses after
// the dry run is deleted again, a 429 on that delete waited out (§H.4):
// nothing else would remove it.
func TestTreeNewFileCleanupRetried(t *testing.T) {
	t.Parallel()
	var placed, deleted atomic.Int32
	e := treeEnv(t, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Header.Get("X-Author") != "dav":
				case strings.HasPrefix(r.URL.Path, "/r/cat/matches.") && r.Method != "GET" && r.Method != "HEAD" && placed.Add(1) == 1:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code": "forbidden", "message": "no placing now"}`))
					return
				case strings.HasPrefix(r.URL.Path, "/r/matches/") && r.Method == "DELETE" && deleted.Add(1) == 1:
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte(`{"code": "rate", "message": "rate limit exceeded"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	e.expect(e.do("PUT", "/cat/Season/new.md", "new"), 403, "PUT, its placement refused")
	sameStrings(t, "matches", e.liveNames("matches"), []string{"derby"})
}
