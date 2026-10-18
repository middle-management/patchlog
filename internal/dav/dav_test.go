package dav_test

import (
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// The root lists the served namespaces; a flat namespace lists its live
// resources as {name}.json, sized and tagged as GET serves them: the
// canonical form indented, ETag the revision.
func TestListAndGet(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	ra := e.create("docs", "a", map[string]any{"title": "A", "n": 1.5, "list": []any{1, "x"}})
	e.create("docs", "b", map[string]any{"title": "B"})
	rc := e.create("docs", "c", map[string]any{"title": "C"})
	must(e.c.Delete(e.ctx, "docs", "c", rc))

	root := e.propfind("/")
	sameStrings(t, "root", names(root, "/"), []string{"docs/"})
	if !root["/docs/"].dir {
		t.Fatalf("docs isn't a collection: %+v", root)
	}
	l := e.propfind("/docs/")
	sameStrings(t, "docs", names(l, "/docs/"), []string{"a.json", "b.json"})
	want := rendered(map[string]any{"title": "A", "n": 1.5, "list": []any{1, "x"}})
	a := l["/docs/a.json"]
	if a.size != strconv.Itoa(len(want)) || a.etag != `"`+ra+`"` || a.ctype != "application/json" || a.modified == "" {
		t.Fatalf("a.json %+v, want size %d etag %s", a, len(want), ra)
	}
	if one := e.propfind("/docs/a.json", "0"); one["/docs/a.json"] != a {
		t.Fatalf("Depth 0 %+v, listed %+v", one, a)
	}

	r := e.expect(e.do("GET", "/docs/a.json", ""), 200, "GET")
	if r.body != want || r.header.Get("ETag") != `"`+ra+`"` || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
		t.Fatalf("GET %q %v, want %q", r.body, r.header, want)
	}
	if !strings.HasPrefix(want, "{\n  \"list\": [\n    1,\n    \"x\"\n  ],\n  \"n\": 1.5,") {
		t.Fatalf("rendering %q", want)
	}
	e.expect(e.do("GET", "/docs/a.json", "", "If-None-Match", `"`+ra+`"`), 304, "conditional GET")
	e.expect(e.do("GET", "/docs/c.json", ""), 404, "GET tombstoned")
	e.expect(e.do("GET", "/docs/nope.json", ""), 404, "GET missing")
	e.expect(e.do("PROPFIND", "/", "", "Depth", "infinity"), 403, "PROPFIND infinity")
	// No Depth is 1 (§H.6), not RFC 4918's infinity.
	if r := e.expect(e.do("PROPFIND", "/docs/", ""), 207, "PROPFIND without Depth"); !strings.Contains(r.body, "/docs/a.json") {
		t.Fatalf("PROPFIND without Depth: %s", r.body)
	}
	if r := e.expect(e.do("OPTIONS", "/docs/a.json", ""), 200, "OPTIONS"); r.header.Get("DAV") != "1, 2" {
		t.Fatalf("OPTIONS %v", r.header)
	}
}

// A PUT of a new name creates it; a PUT of an edit appends the diff from
// what was served, so the log holds the minimal patch set; a save of
// unchanged content writes nothing; invalid JSON writes nothing. The
// writer reads a revision that holds exactly what it wrote as it wrote
// it, so its size checks out (others read the rendering).
func TestPutCreateEdit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	upload := `{"b": 1, "a": [1, 2], "keep": {"x": true}}`
	r := e.expect(e.do("PUT", "/docs/new.json", upload), 201, "PUT new")
	h, doc := e.load("docs", "new")
	sameJSON(t, doc, map[string]any{"b": 1, "a": []any{1, 2}, "keep": map[string]any{"x": true}})
	if r.header.Get("ETag") != `"`+h.ID+`"` {
		t.Fatalf("PUT ETag %s, head %s", r.header.Get("ETag"), h.ID)
	}
	if en := e.lastEntry("docs", "new"); en.Author != "dav" {
		t.Fatalf("author %q", en.Author)
	}
	if l := e.propfind("/docs/"); l["/docs/new.json"].size != strconv.Itoa(len(upload)) || l["/docs/new.json"].etag != `"`+h.ID+`"` {
		t.Fatalf("listed after PUT %+v, want size %d", l["/docs/new.json"], len(upload))
	}

	got := e.expect(e.do("GET", "/docs/new.json", ""), 200, "GET").body
	if got != upload {
		t.Fatalf("GET after PUT %q, want what was put", got)
	}
	edited := strings.Replace(strings.Replace(got, "[1, 2]", "[1, 3]", 1), `"b": 1,`, `"b": 1, "c": "new",`, 1)
	r = e.expect(e.do("PUT", "/docs/new.json", edited), 201, "PUT edit")
	en := e.lastEntry("docs", "new")
	sameJSON(t, en.Patches, []any{
		map[string]any{"op": "replace", "path": "/a/1", "value": 3},
		map[string]any{"op": "add", "path": "/c", "value": "new"},
	})
	if r.header.Get("ETag") != `"`+en.ID+`"` || en.Parent != h.ID {
		t.Fatalf("edit ETag %s, entry %+v", r.header.Get("ETag"), en)
	}

	// Saving what GET served writes nothing.
	again := e.expect(e.do("GET", "/docs/new.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/docs/new.json", again), 201, "PUT unchanged")
	if h2, _ := e.load("docs", "new"); h2.ID != en.ID {
		t.Fatalf("an unchanged save wrote %s", h2.ID)
	}
	// Formatting doesn't matter: the same document, another layout.
	e.expect(e.do("PUT", "/docs/new.json", `{"a":[1,3],"b":1,"c":"new","keep":{"x":true}}`), 201, "PUT reformatted")
	if h2, _ := e.load("docs", "new"); h2.ID != en.ID {
		t.Fatalf("a reformatted save wrote %s", h2.ID)
	}

	r = e.expect(e.do("PUT", "/docs/new.json", `{"a": [1, 3],`), 400, "PUT invalid JSON")
	if !strings.Contains(r.body, "JSON") {
		t.Fatalf("invalid JSON: %q", r.body)
	}
	if h2, _ := e.load("docs", "new"); h2.ID != en.ID {
		t.Fatalf("invalid JSON wrote %s", h2.ID)
	}
	// A new .json file that isn't I-JSON is a raw file of that name (§H.1).
	e.expect(e.do("PUT", "/docs/bad.json", `{"a": 1, "a": 2}`), 201, "PUT duplicate keys")
	if h2, _ := e.load("docs", "bad"); h2.State != client.NotFound {
		t.Fatalf("invalid JSON created bad: %v", h2.State)
	}
	if _, doc := e.load("docs", "bad.json"); client.RawBlobOf(doc) == "" {
		t.Fatalf("bad.json %v", doc)
	}
	// A byte order mark, as some Windows editors write, is fine.
	e.expect(e.do("PUT", "/docs/bom.json", "\xef\xbb\xbf{\"x\": 1}"), 201, "PUT with BOM")
}

// A save merges: another writer's edit to another path since our GET
// survives, and the patch set is only ours (§11 submit). Edits that
// overlap theirs, including one under a path they removed, are 409 and
// write nothing.
func TestMergeAndConflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"title": "A", "body": "x", "meta": map[string]any{"k": "v"}, "list": []any{"a", "b"}})
	served := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body

	h, _ := e.load("docs", "x")
	theirs := must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/body", "value": "theirs"}}))
	e.expect(e.do("PUT", "/docs/x.json", strings.Replace(served, `"A"`, `"B"`, 1)), 201, "PUT merged")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"title": "B", "body": "theirs", "meta": map[string]any{"k": "v"}, "list": []any{"a", "b"}})
	en := e.lastEntry("docs", "x")
	sameJSON(t, en.Patches, []any{map[string]any{"op": "replace", "path": "/title", "value": "B"}})
	if en.Parent != theirs.ID {
		t.Fatalf("parent %s, want their revision %s", en.Parent, theirs.ID)
	}
	// Our buffer still lacks their edit; a second save from it keeps it.
	mine := strings.Replace(strings.Replace(served, `"A"`, `"B"`, 1), `"v"`, `"w"`, 1)
	e.expect(e.do("PUT", "/docs/x.json", mine), 201, "PUT again from the same buffer")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"title": "B", "body": "theirs", "meta": map[string]any{"k": "w"}, "list": []any{"a", "b"}})
	sameJSON(t, e.lastEntry("docs", "x").Patches, []any{map[string]any{"op": "replace", "path": "/meta/k", "value": "w"}})

	// They remove /meta; our edit under it no longer applies.
	served = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	h, _ = e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "remove", "path": "/meta"}}))
	h, _ = e.load("docs", "x")
	r := e.expect(e.do("PUT", "/docs/x.json", strings.Replace(served, `"w"`, `"z"`, 1)), 409, "PUT under a removed path")
	if !strings.Contains(r.body, "/meta") {
		t.Fatalf("conflict text %q", r.body)
	}
	if h2, _ := e.load("docs", "x"); h2.ID != h.ID {
		t.Fatal("a conflicting save wrote")
	}
	// Both change the same value.
	served = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "C"}}))
	h, _ = e.load("docs", "x")
	e.expect(e.do("PUT", "/docs/x.json", strings.Replace(served, `"B"`, `"D"`, 1)), 409, "PUT of a value they changed")
	// An array: their insert shifts the indices our edit names.
	served = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "add", "path": "/list/0", "value": "first"}}))
	h, _ = e.load("docs", "x")
	e.expect(e.do("PUT", "/docs/x.json", strings.Replace(served, `"b"`, `"B"`, 1)), 409, "PUT into an array they changed")
	if h2, doc := e.load("docs", "x"); h2.ID != h.ID {
		t.Fatalf("a conflicting save wrote: %v", doc)
	}

	// They delete an element and append another, the array's length the
	// same: our edit inside the third element names an index that holds
	// their new one now.
	item := func(id string) map[string]any { return map[string]any{"id": id, "done": false} }
	e.create("docs", "todo", map[string]any{"items": []any{item("i1"), item("i2"), item("i3")}})
	served = e.expect(e.do("GET", "/docs/todo.json", ""), 200, "GET").body
	h, _ = e.load("docs", "todo")
	must(e.c.Append(e.ctx, "docs", "todo", h.ID, []any{
		map[string]any{"op": "remove", "path": "/items/1"},
		map[string]any{"op": "add", "path": "/items/-", "value": item("i4")},
	}))
	h, _ = e.load("docs", "todo")
	i := strings.LastIndex(served, `"done": false`)
	r = e.expect(e.do("PUT", "/docs/todo.json", served[:i]+`"done": true`+served[i+len(`"done": false`):]), 409, "PUT into an element they moved")
	if !strings.Contains(r.body, "/items") {
		t.Fatalf("conflict text %q", r.body)
	}
	if h2, doc := e.load("docs", "todo"); h2.ID != h.ID {
		t.Fatalf("a conflicting save wrote: %v", doc)
	}
}

// Documents that fail their schema or a rule are 422 with the core's
// errors; nothing is written.
func TestInvalid(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "ruled"}, nil, map[string]map[string]any{
		"ruled": {"rules": []any{map[string]any{"op": "test", "path": "/doc/title", "schema": map[string]any{"type": "string"}}}},
	})
	must(e.c.CreateNamespace(e.ctx, "schemas", map[string]any{"read": "public"}))
	sch := must(e.c.CreateDoc(e.ctx, "schemas", "item", map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"n": map[string]any{"type": "number"}}}))
	ref := "/r/schemas/item/rev/" + sch.ID
	e.create("docs", "typed", map[string]any{"$schema": ref, "n": 1})
	served := e.expect(e.do("GET", "/docs/typed.json", ""), 200, "GET").body
	r := e.expect(e.do("PUT", "/docs/typed.json", strings.Replace(served, `"n": 1`, `"n": "one"`, 1)), 422, "PUT schema-invalid")
	if !strings.Contains(r.body, "invalid") || !strings.Contains(r.body, "/n") {
		t.Fatalf("422 text %q", r.body)
	}
	if en := e.lastEntry("docs", "typed"); en.Parent != "" {
		t.Fatal("a schema-invalid save wrote")
	}
	r = e.expect(e.do("PUT", "/ruled/x.json", `{"title": 7}`), 422, "PUT against a rule")
	if !strings.Contains(r.body, "rule") {
		t.Fatalf("422 text %q", r.body)
	}
}

// DELETE tombstones (§8.1); a PUT of the name restores it on the same
// chain (§8.2), with the diff from the last live document, as a save over
// a live one from a user who never read it is the diff from the head (a
// whole new document would also count its full size against
// patchSetSize).
func TestDeleteRestore(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	first := e.create("docs", "a", map[string]any{"v": 1})
	e.expect(e.do("DELETE", "/docs/a.json", ""), 204, "DELETE")
	h, _ := e.load("docs", "a")
	if h.State != client.Tombstoned || h.Last != first {
		t.Fatalf("head %+v", h)
	}
	sameStrings(t, "after delete", names(e.propfind("/docs/"), "/docs/"), nil)
	e.expect(e.do("DELETE", "/docs/a.json", ""), 404, "DELETE again")
	e.expect(e.do("PUT", "/docs/a.json", `{"v": 2}`), 201, "PUT restores")
	log := must(e.c.Log(e.ctx, "docs", "a", "", ""))
	if len(log) != 3 || log[1].Kind != "tombstone" || log[2].Parent != log[1].ID || log[2].Kind != "rev" {
		t.Fatalf("log %+v", log)
	}
	sameJSON(t, log[2].Patches, []any{map[string]any{"op": "replace", "path": "/v", "value": 2}})
	_, doc := e.load("docs", "a")
	sameJSON(t, doc, map[string]any{"v": 2})
}

// Editors' save sequences: vim's (swap file, the original moved aside as a
// backup, the new version written, the backup deleted), and the atomic
// save of gedit or VS Code (a temporary file moved over the document).
// Each is one revision with the minimal patch set, and leaves no scratch
// file behind.
func TestEditorSaves(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	first := e.create("docs", "x", map[string]any{"title": "A", "n": 1})
	served := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body

	// vim
	e.expect(e.do("PUT", "/docs/.x.json.swp", "b0VIM swap"), 201, "swap file")
	e.expect(e.do("PUT", "/docs/4913", ""), 201, "vim's write test")
	e.expect(e.do("DELETE", "/docs/4913", ""), 204, "vim's write test gone")
	e.expect(e.do("MOVE", "/docs/x.json", "", "Destination", "/docs/x.json~"), 201, "original to backup")
	if h, _ := e.load("docs", "x"); h.State != client.Live || h.ID != first {
		t.Fatalf("moving to a backup changed the document: %+v", h)
	}
	if b := e.expect(e.do("GET", "/docs/x.json~", ""), 200, "GET backup").body; b != served {
		t.Fatalf("backup %q", b)
	}
	e.expect(e.do("PUT", "/docs/x.json", strings.Replace(served, `"A"`, `"vim"`, 1)), 201, "write")
	e.expect(e.do("DELETE", "/docs/x.json~", ""), 204, "backup gone")
	e.expect(e.do("DELETE", "/docs/.x.json.swp", ""), 204, "swap gone")
	log := must(e.c.Log(e.ctx, "docs", "x", "", ""))
	if len(log) != 2 {
		t.Fatalf("log %+v", log)
	}
	sameJSON(t, log[1].Patches, []any{map[string]any{"op": "replace", "path": "/title", "value": "vim"}})
	sameStrings(t, "after vim", names(e.propfind("/docs/"), "/docs/"), []string{"x.json"})

	// gedit / VS Code: write a temporary file, move it over the original.
	served = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/docs/.goutputstream-K2X9Q1", strings.Replace(served, `"n": 1`, `"n": 2`, 1)), 201, "temporary file")
	e.expect(e.do("MOVE", "/docs/.goutputstream-K2X9Q1", "", "Destination", "/docs/x.json", "Overwrite", "T"), 204, "temporary over original")
	log = must(e.c.Log(e.ctx, "docs", "x", "", ""))
	if len(log) != 3 || log[2].Kind != "rev" {
		t.Fatalf("log %+v", log)
	}
	sameJSON(t, log[2].Patches, []any{map[string]any{"op": "replace", "path": "/n", "value": 2}})
	sameStrings(t, "after gedit", names(e.propfind("/docs/"), "/docs/"), []string{"x.json"})
	// A new file saved the same way is a create.
	e.expect(e.do("PUT", "/docs/.goutputstream-new", `{"fresh": true}`), 201, "temporary file")
	e.expect(e.do("MOVE", "/docs/.goutputstream-new", "", "Destination", "/docs/new.json"), 201, "temporary to a new name")
	_, doc := e.load("docs", "new")
	sameJSON(t, doc, map[string]any{"fresh": true})
}

// macOS's AppleDouble and .DS_Store files, and other names that aren't
// {name}.json, stay scratch files: listed and readable, never written to
// the core.
func TestScratchFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"v": 1})
	e.expect(e.do("PUT", "/docs/._x.json", "\x00\x05\x16\x07apple"), 201, "AppleDouble")
	e.expect(e.do("PUT", "/docs/.DS_Store", "Bud1"), 201, ".DS_Store")
	e.expect(e.do("PUT", "/.DS_Store", "Bud1"), 201, ".DS_Store at the root")
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{".DS_Store", "._x.json", "x.json"})
	if b := e.expect(e.do("GET", "/docs/.DS_Store", ""), 200, "GET .DS_Store").body; b != "Bud1" {
		t.Fatalf(".DS_Store %q", b)
	}
	heads := must(e.c.Heads(e.ctx, "docs", must(e.c.NSHead(e.ctx, "docs")).ID))
	if len(heads) != 1 || heads[0].Resource != "x" {
		t.Fatalf("heads %+v", heads)
	}
	if en := e.lastEntry("docs", "x"); en.Parent != "" {
		t.Fatal("x changed")
	}
	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{".DS_Store", "docs/"})
}

// Moving or copying between documents: a move a flat namespace can't
// record with $successor is 403 (TestFlatMoves has the rest), a copy to a
// new name creates it, a directory can't be made or deleted in a flat
// namespace, and LOCK, then PUT with the token, then UNLOCK creates a
// document (as Finder does).
func TestCopyMoveLock(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "other"}, nil, nil)
	ra := e.create("docs", "a", map[string]any{"v": 1})
	e.create("docs", "b", map[string]any{"v": 2})
	// A flat namespace's files move as §H.8 says (TestFlatMoves), but for
	// one whose root can't carry $successor, or to a name of another kind
	// of file. (Moves were refused before Addendum H.)
	e.create("docs", "arr", []any{1.0})
	e.expect(e.do("MOVE", "/docs/arr.json", "", "Destination", "/docs/c.json"), 403, "rename an array")
	e.expect(e.do("MOVE", "/docs/a.json", "", "Destination", "/docs/c.md"), 403, "rename a JSON file to a raw file's name")
	if h, _ := e.load("docs", "a"); h.ID != ra {
		t.Fatal("a refused move changed a")
	}
	if h, _ := e.load("docs", "c"); h.State != client.NotFound {
		t.Fatal("a refused move made c")
	}
	e.expect(e.do("COPY", "/docs/a.json", "", "Destination", "/other/a2.json"), 201, "copy")
	_, doc := e.load("other", "a2")
	sameJSON(t, doc, map[string]any{"v": 1})
	e.expect(e.do("COPY", "/docs/a.json", "", "Destination", "/docs/b.json", "Overwrite", "T"), 204, "copy over")
	_, doc = e.load("docs", "b")
	sameJSON(t, doc, map[string]any{"v": 1})
	sameJSON(t, e.lastEntry("docs", "b").Patches, []any{map[string]any{"op": "replace", "path": "/v", "value": 1}})

	e.expect(e.do("MKCOL", "/docs/a.json", ""), 403, "MKCOL of a document name")
	e.expect(e.do("DELETE", "/docs", ""), 403, "DELETE a namespace")
	e.expect(e.do("PUT", "/docs/sub/x.json", "{}"), 409, "PUT below a missing directory")

	lock := `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`
	r := e.expect(e.do("LOCK", "/docs/locked.json", lock, "Timeout", "Second-60"), 201, "LOCK a new name")
	token := r.header.Get("Lock-Token")
	if h, _ := e.load("docs", "locked"); h.State != client.NotFound {
		t.Fatal("LOCK created the document")
	}
	if l := e.propfind("/docs/"); l["/docs/locked.json"].size != "0" {
		t.Fatalf("placeholder %+v", l)
	}
	e.expect(e.do("PUT", "/docs/locked.json", `{"locked": true}`), 423, "PUT without the token")
	e.expect(e.do("PUT", "/docs/locked.json", `{"locked": true}`, "If", "("+token+")"), 201, "PUT with the token")
	e.expect(e.do("UNLOCK", "/docs/locked.json", "", "Lock-Token", token), 204, "UNLOCK")
	_, doc = e.load("docs", "locked")
	sameJSON(t, doc, map[string]any{"locked": true})
	// An empty PUT over a JSON file is refused as any content that isn't
	// I-JSON (§H.1), and leaves the document as it was.
	e.expect(e.do("PUT", "/docs/locked.json", ""), 400, "empty PUT")
	_, doc = e.load("docs", "locked")
	sameJSON(t, doc, map[string]any{"locked": true})
	// PROPPATCH (Windows sets file times) succeeds and keeps nothing.
	pp := `<?xml version="1.0" encoding="utf-8"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop><Z:Win32LastModifiedTime>Wed, 01 Jan 2026 00:00:00 GMT</Z:Win32LastModifiedTime></D:prop></D:set></D:propertyupdate>`
	for _, p := range []string{"/docs/a.json", "/docs/", "/"} {
		if r := e.expect(e.do("PROPPATCH", p, pp), 207, "PROPPATCH "+p); !strings.Contains(r.body, "200 OK") || strings.Contains(r.body, "403") {
			t.Fatalf("PROPPATCH %s: %s", p, r.body)
		}
	}

	// Behind a proxy that passes its own Host on: a Destination naming
	// the host the client used (X-Forwarded-Host) is this server.
	e.expect(e.do("PUT", "/docs/.goutputstream-p", `{"v": 3}`), 201, "temporary file")
	e.expect(e.do("MOVE", "/docs/.goutputstream-p", "", "Destination", "http://dav.example/docs/p.json"), 502, "MOVE to another host")
	e.expect(e.do("MOVE", "/docs/.goutputstream-p", "", "Destination", "http://dav.example/docs/p.json", "X-Forwarded-Host", "dav.example"), 201, "MOVE through a proxy")
	_, doc = e.load("docs", "p")
	sameJSON(t, doc, map[string]any{"v": 3})
}

// A namespace that requires nonces (§C.7) gets a fresh $nonce with every
// write. A file's rendering leaves it out (§H.1), so the writer's file is
// stored as sent (its ETag), and the $nonce is never part of an edit.
func TestNonceRequired(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"priv"}, nil, map[string]map[string]any{"priv": {"nonce": "required"}})
	put := e.expect(e.do("PUT", "/priv/x.json", `{"title": "A"}`), 201, "PUT new")
	h, doc := e.load("priv", "x")
	n1, _ := doc.(map[string]any)["$nonce"].(string)
	if len(n1) != 26 || put.header.Get("ETag") != `"`+h.ID+`"` {
		t.Fatalf("created %v, ETag %q", doc, put.header.Get("ETag"))
	}
	if b := e.expect(e.do("GET", "/priv/x.json", ""), 200, "GET").body; b != `{"title": "A"}` {
		t.Fatalf("the writer's GET %q", b)
	}
	e2 := e.another()
	served := e2.expect(e2.do("GET", "/priv/x.json", ""), 200, "GET").body
	if served != rendered(map[string]any{"title": "A"}) || strings.Contains(served, n1) {
		t.Fatalf("GET %q", served)
	}
	e.expect(e.do("PUT", "/priv/x.json", served), 201, "PUT unchanged")
	if en := e.lastEntry("priv", "x"); en.Parent != "" {
		t.Fatal("an unchanged save wrote")
	}
	// Edited: no op on the $nonce but a fresh one.
	edited := strings.Replace(served, `"A"`, `"B"`, 1)
	e.expect(e.do("PUT", "/priv/x.json", edited), 201, "PUT edit")
	en := e.lastEntry("priv", "x")
	ps := en.Patches.([]any)
	if len(ps) != 2 || ps[0].(map[string]any)["path"] != "/title" || ps[1].(map[string]any)["path"] != "/$nonce" || ps[1].(map[string]any)["value"] == n1 {
		t.Fatalf("patches %v", en.Patches)
	}
	e.expect(e.do("DELETE", "/priv/x.json", ""), 204, "DELETE")
	e.expect(e.do("PUT", "/priv/x.json", `{"title": "again"}`), 201, "PUT restores")
	_, doc = e.load("priv", "x")
	if doc.(map[string]any)["title"] != "again" || doc.(map[string]any)["$nonce"] == nil {
		t.Fatalf("restored %v", doc)
	}
}

// Limits (§6.6): a patch set over patchSetSize is 413, a rate limit with
// a long wait is 503 with Retry-After.
func TestLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"small", "slow"}, nil, map[string]map[string]any{
		"small": {"limits": map[string]any{"patchSetSize": 1024}},
		"slow":  {"limits": map[string]any{"ratePerResource": map[string]any{"rate": 0.001, "burst": 1.0}}},
	})
	e.create("small", "x", map[string]any{"v": 1})
	e.do("GET", "/small/x.json", "")
	// A patch set over patchSetSize from the head is written as a root
	// replace, which may be as large as documentSize (§H.4, §6.6), where
	// it was a 413 before Addendum H (TestOversizeSave has more).
	e.expect(e.do("PUT", "/small/x.json", `{"v": 1, "big": "`+strings.Repeat("x", 2000)+`"}`), 201, "PUT over patchSetSize, from the head")
	if p := e.lastEntry("small", "x").Patches.([]any); len(p) != 1 || p[0].(map[string]any)["path"] != "" {
		t.Fatalf("not a root replace: %v", p)
	}
	// One merged with others' edits is a 413, which says what the core
	// doesn't: the sizes, and the limit the namespace sets (§6.6); not
	// the status again.
	e.create("small", "y", map[string]any{"v": 1, "w": 1})
	e.do("GET", "/small/y.json", "")
	e.theirs("small", "y", replace("/w", 2))
	r := e.expect(e.do("PUT", "/small/y.json", `{"v": 1, "w": 1, "big": "`+strings.Repeat("x", 2000)+`"}`), 413, "PUT over patchSetSize, merged")
	if strings.HasPrefix(r.body, "413") || !strings.Contains(r.body, "patch set too large") || !strings.Contains(r.body, "patch set is 2039 bytes") ||
		!strings.Contains(r.body, "patchSetSize 1024") || !strings.Contains(r.body, "merged") {
		t.Fatalf("413 text %q", r.body)
	}
	e.expect(e.do("PUT", "/slow/x.json", `{"v": 1}`), 201, "first write")
	r = e.expect(e.do("PUT", "/slow/x.json", `{"v": 2}`), 503, "rate limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatalf("503 without Retry-After: %v", r.header)
	}

	// A frozen namespace (§8.4) takes no writes, for good: 403, which
	// clients don't retry (rclone retries a 423, a lock that may go, 30
	// times over 45 seconds).
	nh := must(e.c.NSHead(e.ctx, "small"))
	must(e.c.PatchConfig(e.ctx, "small", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	r = e.expect(e.do("PUT", "/small/x.json", `{"v": 2, "big": "`+strings.Repeat("x", 2000)+`"}`), 403, "PUT to a frozen namespace")
	if !strings.Contains(r.body, "frozen") || strings.Contains(r.body, "409") {
		t.Fatalf("403 text %q", r.body)
	}
	// A frozen namespace takes no DELETE either: one right after the
	// refused save (rclone's cleanup) is the core's 403, not the guard's
	// 409 (which would say a second DELETE deletes it), though the 413
	// before set the guard.
	e.expect(e.do("DELETE", "/small/y.json", ""), 403, "DELETE in a frozen namespace")
	e.expect(e.do("PUT", "/small/new.json", `{"v": 1}`), 403, "create in a frozen namespace")
}

// A 429 with a short Retry-After is waited out (§6.6).
func TestRateLimitWait(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, map[string]map[string]any{
		"docs": {"limits": map[string]any{"ratePerResource": map[string]any{"rate": 4.0, "burst": 1.0}}},
	}, func(c *clienttest.Options, _ *dav.Options) { c.RealClock = true })
	e.expect(e.do("PUT", "/docs/x.json", `{"v": 1}`), 201, "first write")
	e.expect(e.do("PUT", "/docs/x.json", `{"v": 2}`), 201, "second write, after a wait")
	e.expect(e.do("PUT", "/docs/x.json", `{"v": 3}`), 201, "third write, after a wait")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 3})
}

// Scratch files are bounded per principal (507 beyond) and expire when
// left untouched for an hour.
func TestScratchBounds(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) {
		o.ScratchFiles, o.ScratchBytes = 2, 10
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	e.expect(e.do("PUT", "/docs/a.swp", "12345"), 201, "first")
	e.expect(e.do("PUT", "/docs/b.swp", "12345"), 201, "second")
	e.expect(e.do("PUT", "/docs/c.swp", "1"), 507, "third file")
	e.expect(e.do("PUT", "/docs/b.swp", "123456"), 507, "over the bytes")
	e.expect(e.do("PUT", "/docs/b.swp", "123"), 201, "smaller")
	e.expect(e.do("PUT", "/docs/c.swp", "1"), 507, "still two files")
	mu.Lock()
	now = now.Add(30 * time.Minute)
	mu.Unlock()
	e.expect(e.do("GET", "/docs/a.swp", ""), 200, "touched")
	mu.Lock()
	now = now.Add(45 * time.Minute)
	mu.Unlock()
	sameStrings(t, "after 75 minutes", names(e.propfind("/docs/"), "/docs/"), []string{"a.swp"})
	e.expect(e.do("PUT", "/docs/c.swp", "1"), 201, "room again")
}

// Sealed and end-to-end namespaces (Addendum E) need keys this server
// doesn't hold, so it doesn't offer them (§H.7): the root doesn't list
// them, and whatever is asked of them is 404, saying why. Nothing in them
// is shown as an empty file that seems writable, nor copied out as one.
func TestSealed(t *testing.T) {
	t.Parallel()
	ks := must(keystore.New(keystore.Generate()))
	e := newEnv(t, []string{"docs", "sec", "e2e"}, nil, map[string]map[string]any{
		"sec": {"encryption": map[string]any{"level": "sealed"}},
		"e2e": {"encryption": map[string]any{"level": "e2e"}},
	}, func(c *clienttest.Options, _ *dav.Options) { c.KeyStore = ks })
	w := e.s.Client(t, client.WithAuthor("other"), client.WithKeys(client.NewKeys(nil)))
	ps := append(client.GenesisPatches(map[string]any{"secret": true}), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	must(w.Create(e.ctx, "sec", "x", ps))
	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{"docs/"})
	for _, r := range []resp{
		e.do("PROPFIND", "/sec/", "", "Depth", "1"),
		e.do("PROPFIND", "/e2e/", "", "Depth", "1"),
		e.do("GET", "/sec/x.json", ""),
		e.do("PUT", "/sec/x.json", `{"secret": false}`),
		e.do("PUT", "/sec/y.json", `{"new": true}`),
		e.do("PUT", "/e2e/y.json", `{"new": true}`),
		e.do("COPY", "/sec/x.json", "", "Destination", "/docs/x.json"),
		e.do("MKCOL", "/sec/.TemporaryItems", ""),
	} {
		if r.status != 404 || !strings.Contains(r.body, "doesn't offer it (§H.7)") {
			t.Fatalf("%d %q", r.status, r.body)
		}
	}
	if h, _ := e.load("docs", "x"); h.State != client.NotFound {
		t.Fatalf("a COPY out of a sealed namespace made docs/x: %v", h.State)
	}
	sameStrings(t, "docs", names(e.propfind("/docs/"), "/docs/"), nil)
	if h, _ := e.load("sec", "y"); h.State != client.NotFound {
		t.Fatal("a PUT wrote to a sealed namespace")
	}
}

// A name a person gives a file that no file can have (a Save As
// "Report.json", capitals, a space, a copy's name without the original
// beside it, a dot) is refused: kept in memory only, it would vanish
// within the hour; in a flat namespace's directory every name but a
// resource name (§H.2), and every name a resource has is a file's; at the
// root, a .json name. (In a file tree such names are titles, TestTreeNewFiles.)
// Editors' and the system's own names stay scratch files (§H.6).
func TestRefusedNames(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("matches", "x", map[string]any{"a": "1"})
	for _, p := range []string{"/matches/Report.json", "/matches/Notes.JSON", "/matches/y copy.json", "/matches/Untitled", "/matches/My%20notes.md", "/matches/.x.json.tmp",
		"/Report.json"} {
		r := e.expect(e.do("PUT", p, `{"a": "2"}`), 403, "PUT "+p)
		if !strings.Contains(r.body, "names no") {
			t.Fatalf("PUT %s: %q", p, r.body)
		}
	}
	e.expect(e.do("PUT", "/matches/.goutputstream-x", `{"a": "3"}`), 201, "temporary file")
	e.expect(e.do("MOVE", "/matches/.goutputstream-x", "", "Destination", "/matches/Report.json"), 403, "MOVE to a refused name")
	lock := `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
	e.expect(e.do("LOCK", "/matches/Report.json", lock), 403, "LOCK of a refused name")
	for _, p := range []string{"/matches/x.json~", "/matches/._x.json", "/matches/.x.json.swp", "/matches/4913", "/matches/x.json___jb_tmp___",
		"/matches/x.json___jb_old___", "/matches/~$x.json", "/matches/%23x.json%23", "/matches/.DS_Store", "/matches/Thumbs.db"} {
		e.expect(e.do("PUT", p, "scratch"), 201, "PUT "+p)
	}
	sameStrings(t, "listing", names(e.propfind("/matches/"), "/matches/"), []string{"#x.json#", ".DS_Store", "._x.json", ".goutputstream-x", ".x.json.swp", "4913",
		"Thumbs.db", "derby.json", "x.json", "x.json___jb_old___", "x.json___jb_tmp___", "x.json~", "~$x.json"})
	if heads := must(e.c.Heads(e.ctx, "matches", must(e.c.NSHead(e.ctx, "matches")).ID)); len(heads) != 2 {
		t.Fatalf("scratch files reached the core: %+v", heads)
	}
}

// Directories a flat namespace or the root can't hold as documents are
// scratch directories: a macOS app's safe save writes the new version in
// one and moves it out; a file manager's "untitled folder" holds files
// for a while. Deleting one drops what is in it.
func TestScratchDirs(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"title": "A"})
	served := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body

	dir := "/docs/(A Document Being Saved By TextEdit)"
	e.expect(e.do("MKCOL", dir, ""), 201, "MKCOL")
	e.expect(e.do("MKCOL", dir, ""), 405, "MKCOL again")
	e.expect(e.do("PUT", dir+"/x.json", edit(t, served, `"A"`, `"B"`)), 201, "PUT in it")
	sameStrings(t, "temporary directory", names(e.propfind(dir+"/"), dir+"/"), []string{"x.json"})
	e.expect(e.do("MOVE", dir+"/x.json", "", "Destination", "/docs/x.json"), 204, "MOVE out over the document")
	e.expect(e.do("DELETE", dir, ""), 204, "DELETE the directory")
	sameJSON(t, e.lastEntry("docs", "x").Patches, []any{replace("/title", "B")})
	sameStrings(t, "docs", names(e.propfind("/docs/"), "/docs/"), []string{"x.json"})

	e.expect(e.do("MKCOL", "/.TemporaryItems", ""), 201, "MKCOL at the root")
	e.expect(e.do("MKCOL", "/.TemporaryItems/folders.501", ""), 201, "MKCOL in it")
	e.expect(e.do("PUT", "/.TemporaryItems/folders.501/f", "x"), 201, "PUT deeper")
	sameStrings(t, "root", names(e.propfind("/"), "/"), []string{".TemporaryItems/", "docs/"})
	e.expect(e.do("MOVE", "/.TemporaryItems", "", "Destination", "/.Trash"), 201, "MOVE a directory")
	if b := e.expect(e.do("GET", "/.Trash/folders.501/f", ""), 200, "GET moved").body; b != "x" {
		t.Fatalf("moved file %q", b)
	}
	e.expect(e.do("DELETE", "/.Trash", ""), 204, "DELETE")
	e.expect(e.do("GET", "/.Trash/folders.501/f", ""), 404, "GET after DELETE")
	e.expect(e.do("PUT", "/.Trash/f", "x"), 409, "PUT below a deleted directory")
	if heads := must(e.c.Heads(e.ctx, "docs", must(e.c.NSHead(e.ctx, "docs")).ID)); len(heads) != 1 {
		t.Fatalf("heads %+v", heads)
	}
}

// Over the bounds, the files macOS and Windows write beside others (._*,
// .DS_Store, Thumbs.db) make room, least recently used first, or are
// dropped, rather than failing a copy with 507 (a full disk to Finder);
// editors' temporary files still get the 507.
func TestJunkFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.ScratchFiles = 3 })
	e.expect(e.do("PUT", "/docs/.x.json.swp", "swap"), 201, "swap file")
	for i := 0; i < 5; i++ {
		e.expect(e.do("PUT", "/docs/._f"+strconv.Itoa(i)+".json", "apple"), 201, "AppleDouble")
	}
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{"._f3.json", "._f4.json", ".x.json.swp"})
	e.expect(e.do("PUT", "/docs/.y.json.swp", "swap"), 201, "a swap file pushes out junk")
	e.expect(e.do("PUT", "/docs/.z.json.swp", "swap"), 201, "and again")
	e.expect(e.do("PUT", "/docs/.w.json.swp", "swap"), 507, "but not another editor's file")
	e.expect(e.do("PUT", "/docs/.DS_Store", "Bud1"), 201, "junk that doesn't fit is dropped")
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{".x.json.swp", ".y.json.swp", ".z.json.swp"})
}

// A PUT whose body is cut short writes nothing, though x/net/webdav
// closes (commits) the file all the same.
func TestCutShortBody(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "n", 1.0)
	h, _ := e.load("docs", "n")
	srv := e.dav.Config.Handler
	req := httptest.NewRequest("PUT", "/docs/n.json", io.MultiReader(strings.NewReader("1234"), errReader{io.ErrUnexpectedEOF}))
	req.SetBasicAuth("u", e.pw)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code < 400 {
		t.Fatalf("cut short: %d %s", w.Code, w.Body)
	}
	if h2, doc := e.load("docs", "n"); h2.ID != h.ID {
		t.Fatalf("a cut-short body was written: %v", doc)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// Request bodies are bounded: XML ones (PROPFIND, PROPPATCH, LOCK) at a
// mebibyte, the written files buffered at once at InflightBytes (503).
func TestBodyLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.InflightBytes = 64 })
	big := `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>` + strings.Repeat("<D:a/>", 1<<18) + `</D:prop></D:propfind>`
	if r := e.do("PROPFIND", "/docs/", big, "Depth", "0"); r.status != 400 && r.status != 413 {
		t.Fatalf("a 1.5 MiB PROPFIND body: %d", r.status)
	}
	e.expect(e.do("PUT", "/docs/x.json", `{"v": 1}`), 201, "a small file")
	r := e.expect(e.do("PUT", "/docs/y.json", `{"v": "`+strings.Repeat("x", 100)+`"}`), 503, "more than InflightBytes")
	if r.header.Get("Retry-After") == "" {
		t.Fatalf("503 without Retry-After: %v", r.header)
	}
	if h, _ := e.load("docs", "y"); h.State != client.NotFound {
		t.Fatal("a refused file was written")
	}
}

// A core that can't be reached is a 502 whose text doesn't show where the
// core is (the log does).
func TestUnreachableCore(t *testing.T) {
	t.Parallel()
	ln := must(net.Listen("tcp", "127.0.0.1:0"))
	addr := ln.Addr().String()
	ln.Close()
	c := must(client.New("http://" + addr + "/internal-prefix"))
	var logged []string
	var mu sync.Mutex
	srv := must(dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Password: "pw", Logf: func(f string, a ...any) {
		mu.Lock()
		logged = append(logged, fmt.Sprintf(f, a...))
		mu.Unlock()
	}}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, dav: hs, pw: "pw"}
	r := e.expect(e.do("GET", "/docs/x.json", ""), 502, "GET")
	if strings.Contains(r.body, addr) || strings.Contains(r.body, "internal-prefix") || !strings.Contains(r.body, "can't be reached") {
		t.Fatalf("502 text %q", r.body)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(logged, "\n"), addr) {
		t.Fatalf("logged %q", logged)
	}
}

// vim (or emacs) on davfs2: the original is renamed to the backup, which
// copies it here (the document stays), then davfs2, which believes the
// name is free, creates it with LOCK and PUT, both If-None-Match: *. That
// PUT is the edit of the document moved aside, not a 412 (davfs2 would
// move the edit into its lost+found).
func TestVimOnDavfs2(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	body := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("MOVE", "/docs/x.json", "", "Destination", "/docs/x.json~", "Overwrite", "T"), 201, "MOVE to backup")
	lk := e.expect(e.do("LOCK", "/docs/x.json", `<?xml version="1.0"?><lockinfo xmlns="DAV:"><lockscope><exclusive/></lockscope><locktype><write/></locktype><owner>davfs2</owner></lockinfo>`,
		"If-None-Match", "*", "Depth", "0"), 200, "LOCK create")
	tok := lk.header.Get("Lock-Token")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, body, `"a": "1"`, `"a": "vim"`), "If-None-Match", "*", "If", "("+tok+")"), 201, "PUT create-only")
	e.expect(e.do("UNLOCK", "/docs/x.json", "", "Lock-Token", tok), 204, "UNLOCK")
	e.expect(e.do("DELETE", "/docs/x.json~", ""), 204, "DELETE backup")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "vim", "b": "theirs"})
	sameJSON(t, e.lastEntry("docs", "x").Patches, []any{replace("/a", "vim")})
	// Once only: the next create-only PUT is refused again, as after a
	// write that followed the move aside without the header.
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "again"}`, "If-None-Match", "*"), 412, "PUT create-only again")
	e.expect(e.do("MOVE", "/docs/x.json", "", "Destination", "/docs/x.json~", "Overwrite", "T"), 201, "MOVE to backup")
	body = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/docs/x.json", edit(t, body, `"a": "vim"`, `"a": "vim 2"`)), 201, "PUT")
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "again"}`, "If-None-Match", "*"), 412, "PUT create-only after it")
}

// Folders are made only where they can hold documents (file trees) and
// where apps save through them (a name starting with a dot, TextEdit's
// "(A Document Being Saved By …)"): a person's folder in a flat namespace
// or at the root would keep what is saved into it in memory only. In a
// tree, a file manager's "untitled folder" is a folder like any other,
// and holds files at once.
func TestFoldersWhereNoFolderCanBe(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	for _, p := range []string{"/matches/untitled folder", "/matches/archive", "/untitled folder", "/New folder"} {
		e.expect(e.do("MKCOL", p, ""), 403, "MKCOL "+p)
	}
	e.expect(e.do("MKCOL", "/matches/.hidden", ""), 201, "MKCOL a dot folder")
	e.expect(e.do("MOVE", "/matches/.hidden", "", "Destination", "/matches/archive"), 403, "MOVE it to a person's name")
	e.expect(e.do("PUT", "/matches/.hidden/q3.json", `{"draft": true}`), 201, "PUT in an app's folder")
	e.expect(e.do("MKCOL", "/cat/untitled folder", ""), 201, "New Folder in a tree")
	e.expect(e.do("PUT", "/cat/untitled folder/Report.json", `{"draft": true}`), 201, "PUT a file in it")
	e.expect(e.do("MOVE", "/cat/untitled folder", "", "Destination", "/cat/Draft Ideas"), 201, "MOVE it to a person's name")
	folder, _ := e.titled("cat", "Draft Ideas")
	sameJSON(t, e.parentsOf(folder), []any{map[string]any{"href": "/r/cat/root", "order": "a0"}})
	ns, item := e.itemOf("cat", "Report.json")
	if h, _ := e.load(ns, item); h.State != client.Live {
		t.Fatalf("%s/%s %v", ns, item, h.State)
	}
}

// Duplicating a document in place, then renaming the copy, is how a
// file manager starts a document from a template: in the flat view the
// copy names file managers give (Finder's "x copy.json", Explorer's "x -
// Copy.json", Keep Both's "x (1).json", ...) of a document beside them are
// scratch files, committed by the rename; other .json names a person
// gives are refused. In a tree the copy is a file, renamed by a title.
func TestDuplicateThenRename(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("matches", "template", map[string]any{"a": "1"})
	for i, n := range []string{"template copy.json", "template copy 2.json", "template - Copy.json", "template - Copy (2).json", "Copy of template.json",
		"template (1).json", "template 2.json", "template (copy).json", "template (another copy).json", "template (3rd copy).json"} {
		p := "/matches/" + url.PathEscape(n)
		e.expect(e.do("COPY", "/matches/template.json", "", "Destination", p), 201, "COPY to "+n)
		dst := "/matches/new" + strconv.Itoa(i) + ".json"
		e.expect(e.do("MOVE", p, "", "Destination", dst), 201, "MOVE "+n)
		_, doc := e.load("matches", "new"+strconv.Itoa(i))
		sameJSON(t, doc, map[string]any{"a": "1"})
	}
	for _, n := range []string{"Template copy.json", "other copy.json", "season 2026.json"} {
		e.expect(e.do("PUT", "/matches/"+url.PathEscape(n), `{}`), 403, "PUT "+n)
	}
	e.expect(e.do("COPY", "/cat/Season/derby.json", "", "Destination", "/cat/Season/derby%20copy.json"), 201, "Duplicate a file in a tree")
	e.expect(e.do("MOVE", "/cat/Season/derby%20copy.json", "", "Destination", "/cat/Season/derby2.json"), 201, "rename it")
	ns, item := e.itemOf("cat", "derby2.json")
	_, doc := e.load(ns, item)
	sameJSON(t, doc, map[string]any{"title": "Derby"})
}

// MKCOL of a directory that exists is 405 (RFC 4918 §9.3.1) and isn't
// logged: rclone sends one for the parent before every upload. MKCOL
// below a file is 409 saying so.
func TestMkcolExisting(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var logged []string
	e := newEnv(t, []string{"docs"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("docs")}}, func(_ *clienttest.Options, o *dav.Options) {
		o.Logf = func(format string, args ...any) {
			mu.Lock()
			logged = append(logged, fmt.Sprintf(format, args...))
			mu.Unlock()
		}
	})
	e.create("docs", "x", map[string]any{"v": 1})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "root")})
	e.create("cat", "docs.x", map[string]any{"title": "x.json", "parents": parents("cat", "root")})
	e.expect(e.do("MKCOL", "/docs/.TemporaryItems", ""), 201, "MKCOL scratch directory")
	for _, p := range []string{"/", "/docs/", "/docs", "/cat/", "/cat/Sub/", "/cat/sub", "/docs/.TemporaryItems"} {
		e.expect(e.do("MKCOL", p, ""), 405, "MKCOL "+p)
	}
	for _, p := range []string{"/docs/x.json/sub", "/cat/x.json/sub", "/cat/nowhere/sub"} {
		if r := e.expect(e.do("MKCOL", p, ""), 409, "MKCOL below a file"); !strings.Contains(r.body, "isn't a folder") {
			t.Fatalf("MKCOL %s: %q", p, r.body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logged {
		if strings.Contains(l, "MKCOL") && strings.Contains(l, "exist") {
			t.Fatalf("logged: %s", l)
		}
	}
}
