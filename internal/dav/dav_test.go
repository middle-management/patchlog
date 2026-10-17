package dav_test

import (
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
	if r := e.expect(e.do("OPTIONS", "/docs/a.json", ""), 200, "OPTIONS"); r.header.Get("DAV") != "1, 2" {
		t.Fatalf("OPTIONS %v", r.header)
	}
}

// A PUT of a new name creates it; a PUT of an edit appends the diff from
// what was served, so the log holds the minimal patch set; a save of
// unchanged content writes nothing; invalid JSON writes nothing.
func TestPutCreateEdit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	r := e.expect(e.do("PUT", "/docs/new.json", `{"b": 1, "a": [1, 2], "keep": {"x": true}}`), 201, "PUT new")
	h, doc := e.load("docs", "new")
	sameJSON(t, doc, map[string]any{"b": 1, "a": []any{1, 2}, "keep": map[string]any{"x": true}})
	if r.header.Get("ETag") != `"`+h.ID+`"` {
		t.Fatalf("PUT ETag %s, head %s", r.header.Get("ETag"), h.ID)
	}
	if en := e.lastEntry("docs", "new"); en.Author != "dav" {
		t.Fatalf("author %q", en.Author)
	}

	got := e.expect(e.do("GET", "/docs/new.json", ""), 200, "GET").body
	edited := strings.Replace(strings.Replace(got, "    2\n", "    3\n", 1), `"b": 1,`, `"b": 1, "c": "new",`, 1)
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
	e.expect(e.do("PUT", "/docs/bad.json", `{"a": 1, "a": 2}`), 400, "PUT duplicate keys")
	if h2, _ := e.load("docs", "new"); h2.ID != en.ID {
		t.Fatalf("invalid JSON wrote %s", h2.ID)
	}
	if h2, _ := e.load("docs", "bad"); h2.State != client.NotFound {
		t.Fatalf("invalid JSON created bad: %v", h2.State)
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

// DELETE tombstones (§8.1); a PUT of the name restores it with the whole
// document, on the same chain (§8.2).
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
	sameJSON(t, log[2].Patches, []any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"v": 2}}})
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
	e.expect(e.do("PUT", "/docs/.new.json.tmp", `{"fresh": true}`), 201, "temporary file")
	e.expect(e.do("MOVE", "/docs/.new.json.tmp", "", "Destination", "/docs/new.json"), 201, "temporary to a new name")
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
	e.expect(e.do("PUT", "/docs/Notes.JSON", `{"not": "a resource name"}`), 201, "uppercase name")
	e.expect(e.do("PUT", "/.DS_Store", "Bud1"), 201, ".DS_Store at the root")
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{".DS_Store", "._x.json", "Notes.JSON", "x.json"})
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

// Moving or copying between documents: a move between two names is 403
// (names are identity), a copy to a new name creates it, a directory
// can't be made or deleted in a flat namespace, and LOCK, then PUT with
// the token, then UNLOCK creates a document (as Finder does).
func TestCopyMoveLock(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "other"}, nil, nil)
	ra := e.create("docs", "a", map[string]any{"v": 1})
	e.create("docs", "b", map[string]any{"v": 2})
	e.expect(e.do("MOVE", "/docs/a.json", "", "Destination", "/docs/c.json"), 403, "rename")
	e.expect(e.do("MOVE", "/docs/a.json", "", "Destination", "/docs/b.json", "Overwrite", "T"), 403, "move over another document")
	e.expect(e.do("MOVE", "/docs/a.json", "", "Destination", "/other/a.json"), 403, "move to another namespace")
	if h, _ := e.load("docs", "a"); h.ID != ra {
		t.Fatal("a refused move changed a")
	}
	if h, _ := e.load("docs", "b"); h.State != client.Live {
		t.Fatal("a refused move deleted b")
	}
	e.expect(e.do("COPY", "/docs/a.json", "", "Destination", "/other/a2.json"), 201, "copy")
	_, doc := e.load("other", "a2")
	sameJSON(t, doc, map[string]any{"v": 1})
	e.expect(e.do("COPY", "/docs/a.json", "", "Destination", "/docs/b.json", "Overwrite", "T"), 204, "copy over")
	_, doc = e.load("docs", "b")
	sameJSON(t, doc, map[string]any{"v": 1})
	sameJSON(t, e.lastEntry("docs", "b").Patches, []any{map[string]any{"op": "replace", "path": "/v", "value": 1}})

	e.expect(e.do("MKCOL", "/docs/sub", ""), 403, "MKCOL in a flat namespace")
	e.expect(e.do("MKCOL", "/new", ""), 403, "MKCOL at the root")
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
	// An empty PUT doesn't truncate a live document.
	e.expect(e.do("PUT", "/docs/locked.json", ""), 201, "empty PUT")
	_, doc = e.load("docs", "locked")
	sameJSON(t, doc, map[string]any{"locked": true})
	// PROPPATCH (Windows sets file times) succeeds and keeps nothing.
	pp := `<?xml version="1.0" encoding="utf-8"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop><Z:Win32LastModifiedTime>Wed, 01 Jan 2026 00:00:00 GMT</Z:Win32LastModifiedTime></D:prop></D:set></D:propertyupdate>`
	if r := e.expect(e.do("PROPPATCH", "/docs/a.json", pp), 207, "PROPPATCH"); !strings.Contains(r.body, "200") {
		t.Fatalf("PROPPATCH %s", r.body)
	}
}

// A namespace that requires nonces (§C.7) gets a fresh $nonce with every
// write; the document's own $nonce is never part of an edit.
func TestNonceRequired(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"priv"}, nil, map[string]map[string]any{"priv": {"nonce": "required"}})
	e.expect(e.do("PUT", "/priv/x.json", `{"title": "A"}`), 201, "PUT new")
	_, doc := e.load("priv", "x")
	n1, _ := doc.(map[string]any)["$nonce"].(string)
	if len(n1) != 26 {
		t.Fatalf("created %v", doc)
	}
	served := e.expect(e.do("GET", "/priv/x.json", ""), 200, "GET").body
	if !strings.Contains(served, n1) {
		t.Fatalf("GET %q", served)
	}
	e.expect(e.do("PUT", "/priv/x.json", served), 201, "PUT unchanged")
	if en := e.lastEntry("priv", "x"); en.Parent != "" {
		t.Fatal("an unchanged save wrote")
	}
	// Edited, with the $nonce line dropped: no remove of it, a fresh one.
	edited := strings.Replace(served, `"A"`, `"B"`, 1)
	edited = strings.Replace(edited, `"$nonce": "`+n1+`",`, "", 1)
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
	e.expect(e.do("PUT", "/small/x.json", `{"v": 1, "big": "`+strings.Repeat("x", 2000)+`"}`), 413, "PUT over patchSetSize")
	e.expect(e.do("PUT", "/slow/x.json", `{"v": 1}`), 201, "first write")
	r := e.expect(e.do("PUT", "/slow/x.json", `{"v": 2}`), 503, "rate limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatalf("503 without Retry-After: %v", r.header)
	}

	// A frozen namespace (§8.4) takes no writes: 423.
	nh := must(e.c.NSHead(e.ctx, "small"))
	must(e.c.PatchConfig(e.ctx, "small", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	r = e.expect(e.do("PUT", "/small/x.json", `{"v": 2}`), 423, "PUT to a frozen namespace")
	if !strings.Contains(r.body, "frozen") {
		t.Fatalf("423 text %q", r.body)
	}
	e.expect(e.do("DELETE", "/small/x.json", ""), 423, "DELETE in a frozen namespace")
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
	e.expect(e.do("PUT", "/docs/.a", "12345"), 201, "first")
	e.expect(e.do("PUT", "/docs/.b", "12345"), 201, "second")
	e.expect(e.do("PUT", "/docs/.c", "1"), 507, "third file")
	e.expect(e.do("PUT", "/docs/.b", "123456"), 507, "over the bytes")
	e.expect(e.do("PUT", "/docs/.b", "123"), 201, "smaller")
	e.expect(e.do("PUT", "/docs/.c", "1"), 507, "still two files")
	mu.Lock()
	now = now.Add(30 * time.Minute)
	mu.Unlock()
	e.expect(e.do("GET", "/docs/.a", ""), 200, "touched")
	mu.Lock()
	now = now.Add(45 * time.Minute)
	mu.Unlock()
	sameStrings(t, "after 75 minutes", names(e.propfind("/docs/"), "/docs/"), []string{".a"})
	e.expect(e.do("PUT", "/docs/.c", "1"), 201, "room again")
}

// Sealed namespaces (Addendum E) are listed but not served: their files
// read and write as 501.
func TestSealed(t *testing.T) {
	t.Parallel()
	ks := must(keystore.New(keystore.Generate()))
	e := newEnv(t, []string{"sec"}, nil, map[string]map[string]any{"sec": {"encryption": map[string]any{"level": "sealed"}}},
		func(c *clienttest.Options, _ *dav.Options) { c.KeyStore = ks })
	w := e.s.Client(t, client.WithAuthor("other"), client.WithKeys(client.NewKeys(nil)))
	ps := append(client.GenesisPatches(map[string]any{"secret": true}), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	must(w.Create(e.ctx, "sec", "x", ps))
	l := e.propfind("/sec/")
	sameStrings(t, "listing", names(l, "/sec/"), []string{"x.json"})
	e.expect(e.do("GET", "/sec/x.json", ""), 501, "GET sealed")
	e.expect(e.do("PUT", "/sec/x.json", `{"secret": false}`), 501, "PUT sealed")
	e.expect(e.do("PUT", "/sec/y.json", `{"new": true}`), 501, "PUT new in a sealed namespace")
}
