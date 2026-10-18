package dav_test

import (
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
