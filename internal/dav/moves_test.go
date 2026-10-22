package dav_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// A MOVE in the flat view (§H.8): to a free name in the namespace, one
// batch creates the new resource with the document and deletes the old
// one with $successor naming it (§8.1); a raw file's blob is copied with
// Blob-From (§7.8), or uploaded again under the type its new name gives
// (§H.1); a tombstoned name is restored so. To another namespace, a copy
// and a delete with $successor /r/{ns}/{name} (§H.5). Where nonces are
// required, every write carries a fresh one.
func TestFlatMoves(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "other", "priv"}, nil, map[string]map[string]any{"priv": {"nonce": "required"}})
	e.create("docs", "a", map[string]any{"v": 1.0, "list": []any{"x"}})
	nsBefore := must(e.c.NSHead(e.ctx, "docs")).ID
	e.expect(e.do("MOVE", "/docs/a.json", "", "Destination", "/docs/c.json"), 201, "MOVE a JSON file")
	if h, _ := e.load("docs", "a"); h.State != client.Tombstoned || h.Successor != "c" {
		t.Fatalf("a: %+v", h)
	}
	_, doc := e.load("docs", "c")
	sameJSON(t, doc, map[string]any{"v": 1.0, "list": []any{"x"}})
	ns := must(e.c.NSLog(e.ctx, "docs", must(e.c.NSHead(e.ctx, "docs")).ID, nsBefore))
	if len(ns) != 1 || ns[0].Kind != "batch" {
		t.Fatalf("not one batch: %+v", ns)
	}
	if b := e.expect(e.do("GET", "/docs/c.json", ""), 200, "GET c").body; b != rendered(doc) {
		t.Fatalf("c reads %q", b)
	}

	// Raw files: the blob copied, the same id; another type uploaded again.
	md := "# Notes\n"
	e.expect(e.do("PUT", "/docs/notes.md", md), 201, "PUT notes.md")
	ref, _ := e.rawOf("docs", "notes.md")
	e.expect(e.do("MOVE", "/docs/notes.md", "", "Destination", "/docs/kept.md"), 201, "MOVE a raw file")
	moved, b := e.rawOf("docs", "kept.md")
	if moved["$blob"] != ref["$blob"] || string(b) != md {
		t.Fatalf("kept.md %v %q, was %v", moved, b, ref)
	}
	if h, _ := e.load("docs", "notes.md"); h.Successor != "kept.md" {
		t.Fatalf("notes.md: %+v", h)
	}
	e.expect(e.do("MOVE", "/docs/kept.md", "", "Destination", "/docs/kept.txt"), 201, "MOVE a raw file to another type")
	moved, b = e.rawOf("docs", "kept.txt")
	if moved["type"] != "text/plain" || moved["$blob"] == ref["$blob"] || string(b) != md {
		t.Fatalf("kept.txt %v %q", moved, b)
	}
	if r := e.expect(e.do("GET", "/docs/kept.txt", ""), 200, "GET kept.txt"); r.body != md || !strings.HasPrefix(r.header.Get("Content-Type"), "text/plain") {
		t.Fatalf("kept.txt reads %q as %s", r.body, r.header.Get("Content-Type"))
	}

	// A tombstoned name is restored, the root replaced.
	e.create("docs", "old", map[string]any{"was": "here"})
	e.expect(e.do("DELETE", "/docs/old.json", ""), 204, "DELETE old")
	e.create("docs", "b", map[string]any{"v": "b"})
	e.expect(e.do("MOVE", "/docs/b.json", "", "Destination", "/docs/old.json"), 201, "MOVE onto a deleted name")
	_, doc = e.load("docs", "old")
	sameJSON(t, doc, map[string]any{"v": "b"})

	// To another namespace: a copy, then a delete with $successor.
	e.create("docs", "far", map[string]any{"v": "far"})
	e.expect(e.do("MOVE", "/docs/far.json", "", "Destination", "/other/far.json"), 201, "MOVE to another namespace")
	if h, _ := e.load("docs", "far"); h.Successor != "/r/other/far" {
		t.Fatalf("far: %+v", h)
	}
	_, doc = e.load("other", "far")
	sameJSON(t, doc, map[string]any{"v": "far"})

	// Nonces required: the new resource and the old one's last revision
	// carry fresh ones.
	e.expect(e.do("PUT", "/priv/p.json", `{"v": 1}`), 201, "PUT in priv")
	e.expect(e.do("MOVE", "/priv/p.json", "", "Destination", "/priv/q.json"), 201, "MOVE in priv")
	_, q := e.load("priv", "q")
	if n, _ := q.(map[string]any)["$nonce"].(string); len(n) != 26 {
		t.Fatalf("q: %v", q)
	}
	if h, _ := e.load("priv", "p"); h.Successor != "q" {
		t.Fatalf("p: %+v", h)
	}
}

// What the flat view doesn't move (§H.8 "403, or …"): a JSON file whose
// root can't carry $successor, a JSON file to a raw file's name or the
// other way round; a MOVE with Overwrite: F onto an existing file is 412.
// Nothing is written.
func TestFlatMovesRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	ra := e.create("docs", "arr", []any{1.0})
	e.expect(e.do("MOVE", "/docs/arr.json", "", "Destination", "/docs/b.json"), 403, "an array")
	rj := e.create("docs", "j", map[string]any{"v": 1.0})
	e.expect(e.do("MOVE", "/docs/j.json", "", "Destination", "/docs/j.md"), 403, "JSON to a raw name")
	e.expect(e.do("PUT", "/docs/r.md", "# r"), 201, "PUT r.md")
	rr, _ := e.load("docs", "r.md")
	e.expect(e.do("MOVE", "/docs/r.md", "", "Destination", "/docs/r2.json"), 201, "raw to a .json name: a raw r2.json")
	if ref, _ := e.rawOf("docs", "r2.json"); ref["type"] != "application/json" {
		t.Fatalf("r2.json %v", ref)
	}
	e.create("docs", "k", map[string]any{"v": "k"})
	rk, _ := e.load("docs", "k")
	e.expect(e.do("MOVE", "/docs/j.json", "", "Destination", "/docs/k.json", "Overwrite", "F"), 412, "Overwrite: F onto a file")
	for name, rev := range map[string]string{"arr": ra, "j": rj, "k": rk.ID} {
		if h, _ := e.load("docs", name); h.State != client.Live || h.ID != rev {
			t.Fatalf("%s changed: %+v", name, h)
		}
	}
	if h, _ := e.load("docs", "r.md"); h.State != client.Tombstoned || h.Successor != "r2.json" || rr.State != client.Live {
		t.Fatalf("r.md: %+v", h)
	}
	for _, n := range []string{"b", "j.md"} {
		if h, _ := e.load("docs", n); h.State != client.NotFound {
			t.Fatalf("%s made: %+v", n, h)
		}
	}
}

// A MOVE onto an existing file (Overwrite: T, or none) is a save of the
// source's content into it, its base taken as a PUT's, then a delete of
// the source (§H.5): the target keeps its history and others' edits
// since the user read it, the "write a temporary file, rename it over"
// save. A temporary file with a resource name (notes.md.tmp) saves so in
// the flat view.
func TestMoveOntoExisting(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	r0 := e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/x.tmp.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT the temporary file")
	e.expect(e.do("MOVE", "/docs/x.tmp.json", "", "Destination", "/docs/x.json"), 204, "MOVE over the original")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
	log := must(e.c.Log(e.ctx, "docs", "x", "", ""))
	if len(log) != 3 || log[0].ID != r0 {
		t.Fatalf("x's history: %d entries", len(log))
	}
	sameJSON(t, log[2].Patches, []any{replace("/a", "mine")})
	if h, _ := e.load("docs", "x.tmp"); h.State != client.Tombstoned || h.Successor != "" {
		t.Fatalf("x.tmp: %+v", h)
	}

	md := "# Notes\n\nv1\n"
	e.expect(e.do("PUT", "/docs/notes.md", md), 201, "PUT notes.md")
	before := len(must(e.c.Log(e.ctx, "docs", "notes.md", "", "")))
	e.expect(e.do("GET", "/docs/notes.md", ""), 200, "GET notes.md")
	e.expect(e.do("PUT", "/docs/notes.md.tmp", "# Notes\n\nv2\n"), 201, "PUT notes.md.tmp")
	e.expect(e.do("MOVE", "/docs/notes.md.tmp", "", "Destination", "/docs/notes.md"), 204, "MOVE over notes.md")
	if _, b := e.rawOf("docs", "notes.md"); string(b) != "# Notes\n\nv2\n" {
		t.Fatalf("notes.md %q", b)
	}
	if n := len(must(e.c.Log(e.ctx, "docs", "notes.md", "", ""))); n != before+1 {
		t.Fatalf("notes.md has %d entries, had %d", n, before)
	}
	if ref, _ := e.load("docs", "notes.md"); ref.State != client.Live {
		t.Fatal("notes.md isn't live")
	}
	e.expectTombstoned("docs", "notes.md.tmp", "after the MOVE")

	// A raw file over someone's change of its bytes: a conflict, nothing
	// moved or deleted.
	e.expect(e.do("GET", "/docs/notes.md", ""), 200, "GET notes.md")
	e.expect(e.do("PUT", "/docs/notes.md.tmp", "# Notes\n\nv3\n"), 201, "PUT notes.md.tmp")
	bid := must(e.c.UploadBlob(e.ctx, "docs", "notes.md", "text/markdown", "", []byte("theirs")))
	e.theirs("docs", "notes.md", replace("/$blob", bid), replace("/size", 6))
	e.expect(e.do("MOVE", "/docs/notes.md.tmp", "", "Destination", "/docs/notes.md"), 409, "MOVE over their change")
	if _, b := e.rawOf("docs", "notes.md"); string(b) != "theirs" {
		t.Fatalf("notes.md %q", b)
	}
	if h, _ := e.load("docs", "notes.md.tmp"); h.State != client.Live {
		t.Fatalf("the temporary file is %v", h.State)
	}
}

// A move to a scratch name (§H.5, vim's backup) copies the file into
// scratch; the next create-only PUT of the original path by the same user
// is taken as an edit, once, within asideFor of the move (davfs2 uploads
// 10 s after the close by default), not later.
func TestAsideWindow(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })
	e.create("docs", "x", map[string]any{"a": "1"})
	body := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.expect(e.do("MOVE", "/docs/x.json", "", "Destination", "/docs/x.json~"), 201, "MOVE to backup")
	c.add(12 * time.Second)
	e.expect(e.do("PUT", "/docs/x.json", edit(t, body, `"1"`, `"2"`), "If-None-Match", "*"), 201, "create-only PUT 12 s after")
	e.expect(e.do("MOVE", "/docs/x.json", "", "Destination", "/docs/x.json~", "Overwrite", "T"), 204, "MOVE to backup again")
	c.add(31 * time.Second)
	e.expect(e.do("PUT", "/docs/x.json", edit(t, body, `"1"`, `"3"`), "If-None-Match", "*"), 412, "create-only PUT 31 s after")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "2"})
}

// A DELETE of a file, then a MOVE of another file onto its path (rclone's
// mount without a cache saves through a temporary file so, and under a
// resource name the temporary file is a file of its own; sed -i's is a
// scratch file since v0.56, §H.6): the
// write restores the deleted file (§H.6), its placement and its item, or
// its resource, rebased on its last live document, so it keeps its
// history and others' edits; then the temporary file is deleted. One the
// core refuses puts the deleted file back as it was.
func TestDeleteThenMoveOnto(t *testing.T) {
	t.Parallel()
	e := treeDocsEnv(t)
	buf := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET").body
	e.theirs("matches", "derby", map[string]any{"op": "add", "path": "/venue", "value": "theirs"})
	e.expect(e.do("PUT", "/cat/Season/sedAb12Cd", edit(t, buf, `"Derby"`, `"Derby (sed)"`)), 201, "PUT the temporary file, sed -i's, a scratch file (§H.6)")
	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "DELETE the original")
	e.expect(e.do("MOVE", "/cat/Season/sedAb12Cd", "", "Destination", "/cat/Season/derby.json", "Overwrite", "F"), 201, "MOVE onto the name")
	if h, _ := e.load("cat", "matches.derby"); h.State != client.Live {
		t.Fatalf("the placement is %v", h.State)
	}
	_, doc := e.load("matches", "derby")
	sameJSON(t, doc, map[string]any{"title": "Derby (sed)", "venue": "theirs"})
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})

	// The flat view, a temporary file with a resource name.
	e.create("docs", "cup", map[string]any{"title": "Cup", "n": "1"})
	buf = e.expect(e.do("GET", "/docs/cup.json", ""), 200, "GET").body
	e.theirs("docs", "cup", replace("/n", "theirs"))
	e.expect(e.do("PUT", "/docs/cup.tmp.json", edit(t, buf, `"Cup"`, `"Cup (tmp)"`)), 201, "PUT the temporary file")
	e.expect(e.do("DELETE", "/docs/cup.json", ""), 204, "DELETE the original")
	e.expect(e.do("MOVE", "/docs/cup.tmp.json", "", "Destination", "/docs/cup.json", "Overwrite", "F"), 201, "MOVE onto the name")
	_, doc = e.load("docs", "cup")
	sameJSON(t, doc, map[string]any{"title": "Cup (tmp)", "n": "theirs"})
	if h, _ := e.load("docs", "cup.tmp"); h.State != client.Tombstoned || h.Successor != "" {
		t.Fatalf("cup.tmp: %+v", h)
	}

	// Refused (a conflict): the original is put back as it was.
	e.create("docs", "lid", map[string]any{"title": "Lid"})
	buf = e.expect(e.do("GET", "/docs/lid.json", ""), 200, "GET").body
	e.theirs("docs", "lid", replace("/title", "theirs"))
	e.expect(e.do("PUT", "/docs/lid.tmp.json", edit(t, buf, `"Lid"`, `"Lid (tmp)"`)), 201, "PUT the temporary file")
	e.expect(e.do("DELETE", "/docs/lid.json", ""), 204, "DELETE the original")
	r := e.expect(e.do("MOVE", "/docs/lid.tmp.json", "", "Destination", "/docs/lid.json", "Overwrite", "F"), 409, "MOVE of a conflicting version")
	if !strings.Contains(r.body, "restored") {
		t.Fatalf("409 %q", r.body)
	}
	now, doc := e.load("docs", "lid")
	sameJSON(t, doc, map[string]any{"title": "theirs"})
	if now.State != client.Live || len(must(e.c.Log(e.ctx, "docs", "lid", "", ""))) != 4 {
		t.Fatalf("lid isn't restored as it was: %+v", now)
	}
	sameJSON(t, e.lastEntry("docs", "lid").Patches, []any{})
	if h, _ := e.load("docs", "lid.tmp"); h.State != client.Live {
		t.Fatalf("the temporary file is %v after the refused MOVE", h.State)
	}
}

// A MOVE onto an existing file, or across trees or namespaces, deletes
// only the revision of the source it copied (§H.5): someone else's edit of
// the source made while the copy is written isn't tombstoned unseen; the
// MOVE is a 409, the target holding the version moved and the source as
// it is now.
func TestMoveSourceChanged(t *testing.T) {
	t.Parallel()
	h := &hook{}
	e := newEnv(t, []string{"docs", "other", "matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}}, withHook(h))
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	theirs := func(ns, name string) func() {
		return func() { e.theirs(ns, name, map[string]any{"op": "add", "path": "/theirs", "value": "important"}) }
	}
	check := func(ns, name, what string) {
		t.Helper()
		hd, doc := e.load(ns, name)
		if hd.State != client.Live || doc.(map[string]any)["theirs"] != "important" {
			t.Fatalf("%s: the source %v %v", what, hd.State, doc)
		}
	}
	e.create("docs", "a", map[string]any{"v": "a"})
	e.create("docs", "b", map[string]any{"v": "b"})
	h.set(at("PATCH", "/r/docs/b"), theirs("docs", "a"))
	e.expect(e.do("MOVE", "/docs/a.json", "", "Destination", "/docs/b.json"), 409, "MOVE onto, the source edited meanwhile")
	check("docs", "a", "onto")
	_, b := e.load("docs", "b")
	sameJSON(t, b, map[string]any{"v": "a"})

	e.create("docs", "c", map[string]any{"v": "c"})
	h.set(func(r *http.Request) bool {
		return r.URL.Path == "/r/other/c" && r.Method != "GET" && r.Method != "HEAD"
	}, theirs("docs", "c"))
	e.expect(e.do("MOVE", "/docs/c.json", "", "Destination", "/other/c.json"), 409, "MOVE across, the source edited meanwhile")
	check("docs", "c", "across")

	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "root")})
	e.create("matches", "cup", map[string]any{"title": "Cup"})
	e.create("cat", "matches.cup", map[string]any{"title": "cup.json", "parents": parents("cat", "root")})
	h.set(at("PATCH", "/r/matches/cup"), theirs("matches", "derby"))
	e.expect(e.do("MOVE", "/cat/derby.json", "", "Destination", "/cat/cup.json"), 409, "a tree's MOVE onto, the source edited meanwhile")
	check("matches", "derby", "a tree's onto")
	if hn, _ := e.load("cat", "matches.derby"); hn.State != client.Live {
		t.Fatalf("the source's placement %v", hn.State)
	}
	h.set(func(r *http.Request) bool {
		return r.URL.Path == "/r/docs/d" && r.Method != "GET" && r.Method != "HEAD"
	}, theirs("matches", "derby"))
	e.expect(e.do("MOVE", "/cat/derby.json", "", "Destination", "/docs/d.json"), 409, "a tree's MOVE across, the source edited meanwhile")
	check("matches", "derby", "a tree's across")
	sameStrings(t, "tree", names(e.propfind("/cat/"), "/cat/"), []string{"cup.json", "derby.json"})
}
