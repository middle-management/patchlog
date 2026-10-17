package dav_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/dav"
)

// edit replaces old with new in a file's text, once, failing if it isn't
// there.
func edit(t *testing.T, text, old, new string) string {
	t.Helper()
	if !strings.Contains(text, old) {
		t.Fatalf("%q not in %q", old, text)
	}
	return strings.Replace(text, old, new, 1)
}

// theirs appends patches to ns/name straight to the core, as someone
// else.
func (e *env) theirs(ns, name string, patches ...any) {
	e.t.Helper()
	h, _ := e.load(ns, name)
	must(e.c.Append(e.ctx, ns, name, h.ID, patches))
}

func replace(path string, v any) map[string]any {
	return map[string]any{"op": "replace", "path": path, "value": v}
}

// The base of a save is the version the saver's buffer came from, not
// whatever the principal was served last: another program's GET (a
// preview pane, a second window) moves on without the editor's buffer,
// as does a second client's save. Others' edits survive either way.
func TestSaveBases(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)

	// A second reader: the editor GETs, someone else edits /b, another
	// program GETs the new revision, the editor saves its buffer.
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	editor := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET editor").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET preview")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, editor, `"a": "1"`, `"a": "mine"`)), 201, "PUT editor")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
	sameJSON(t, e.lastEntry("docs", "x").Patches, []any{replace("/a", "mine")})

	// Two clients of one principal edit from the same GET.
	e.create("docs", "y", map[string]any{"a": "1", "b": "1"})
	c1 := e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET c1").body
	c2 := e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET c2").body
	e.expect(e.do("PUT", "/docs/y.json", edit(t, c1, `"a": "1"`, `"a": "c1"`)), 201, "PUT c1")
	e.expect(e.do("PUT", "/docs/y.json", edit(t, c2, `"b": "1"`, `"b": "c2"`)), 201, "PUT c2")
	_, doc = e.load("docs", "y")
	sameJSON(t, doc, map[string]any{"a": "c1", "b": "c2"})

	// Saving, editing the same value again, saving again: the second
	// save's base is the first's content, no conflict with itself.
	e.create("docs", "z", map[string]any{"t": "A", "u": "1"})
	buf := e.expect(e.do("GET", "/docs/z.json", ""), 200, "GET").body
	buf = edit(t, buf, `"A"`, `"B"`)
	e.expect(e.do("PUT", "/docs/z.json", buf), 201, "first save")
	e.theirs("docs", "z", replace("/u", "theirs"))
	e.expect(e.do("PUT", "/docs/z.json", edit(t, buf, `"B"`, `"C"`)), 201, "second save, same value")
	_, doc = e.load("docs", "z")
	sameJSON(t, doc, map[string]any{"t": "C", "u": "theirs"})

	// Undoing a save, then saving: the save it undoes is the base.
	e.create("docs", "u", map[string]any{"t": "A", "u": "1"})
	orig := e.expect(e.do("GET", "/docs/u.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/docs/u.json", edit(t, orig, `"A"`, `"B"`)), 201, "save")
	e.theirs("docs", "u", replace("/u", "theirs"))
	e.expect(e.do("PUT", "/docs/u.json", orig), 201, "undo, save")
	_, doc = e.load("docs", "u")
	sameJSON(t, doc, map[string]any{"t": "A", "u": "theirs"})

	// Reloaded after someone else's edit: the new version is the base,
	// and their value in it isn't a conflict.
	e.create("docs", "r", map[string]any{"t": "A", "u": "1"})
	e.expect(e.do("GET", "/docs/r.json", ""), 200, "GET")
	e.theirs("docs", "r", replace("/u", "theirs"))
	reloaded := e.expect(e.do("GET", "/docs/r.json", ""), 200, "reload").body
	e.expect(e.do("PUT", "/docs/r.json", edit(t, reloaded, `"A"`, `"B"`)), 201, "PUT after reload")
	_, doc = e.load("docs", "r")
	sameJSON(t, doc, map[string]any{"t": "B", "u": "theirs"})
}

// A PUT's If-Match (or an If header's entity tag) names the revision it
// was edited from: that is the base, whatever else the principal read.
func TestSaveIfMatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET again")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, g.body, `"a": "1"`, `"a": "mine"`), "If-Match", g.header.Get("ETag")), 201, "PUT If-Match")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})

	// With no record at all (a restart), If-Match is all there is.
	e2 := newEnv(t, []string{"docs"}, nil, nil)
	r0 := e2.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	e2.theirs("docs", "x", replace("/b", "theirs"))
	text := rendered(map[string]any{"a": "mine", "b": "1"})
	e2.expect(e2.do("PUT", "/docs/x.json", text, "If-Match", `"`+r0+`"`), 201, "PUT If-Match, nothing served")
	_, doc = e2.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
}

// A PUT whose document isn't stored as sent (merged with others' edits,
// or an unchanged save over a moved head) gets no ETag: a cache keeping
// what it sent under the merged revision's tag would revalidate it (304)
// and save from it later. A 304 doesn't count as served either.
func TestSaveValidators(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"title": "A", "body": "x", "n": "0"})
	served := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	e.theirs("docs", "x", replace("/body", "theirs"))
	sent := edit(t, served.body, `"A"`, `"B"`)
	put := e.expect(e.do("PUT", "/docs/x.json", sent), 201, "PUT merged")
	if et := put.header.Get("ETag"); et != "" {
		t.Fatalf("a merged PUT has ETag %s", et)
	}
	// A client revalidating with the tag it had gets the merged document;
	// one that learned the head's tag from a listing gets a 304, which
	// records nothing. A save from the copy it sent keeps their edit.
	h, _ := e.load("docs", "x")
	e.expect(e.do("GET", "/docs/x.json", "", "If-None-Match", served.header.Get("ETag")), 200, "GET old tag")
	e.expect(e.do("GET", "/docs/x.json", "", "If-None-Match", `"`+h.ID+`"`), 304, "GET head's tag")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, sent, `"n": "0"`, `"n": "1"`)), 201, "PUT from the cached copy")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"title": "B", "body": "theirs", "n": "1"})

	// An unchanged save (autosave) over a moved head writes nothing, and
	// has no ETag either.
	e.create("docs", "y", map[string]any{"title": "A", "body": "x"})
	served = e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET")
	e.theirs("docs", "y", replace("/body", "theirs"))
	h, _ = e.load("docs", "y")
	put = e.expect(e.do("PUT", "/docs/y.json", served.body), 201, "PUT unchanged")
	if et := put.header.Get("ETag"); et != "" {
		t.Fatalf("an unchanged PUT over a moved head has ETag %s", et)
	}
	if h2, _ := e.load("docs", "y"); h2.ID != h.ID {
		t.Fatal("an unchanged save wrote")
	}
	e.expect(e.do("GET", "/docs/y.json", "", "If-None-Match", `"`+h.ID+`"`), 304, "revalidate")
	e.expect(e.do("PUT", "/docs/y.json", edit(t, served.body, `"A"`, `"B"`)), 201, "PUT an edit")
	_, doc = e.load("docs", "y")
	sameJSON(t, doc, map[string]any{"title": "B", "body": "theirs"})

	// A save that already reads so (the change someone else made too)
	// is stored as sent: its ETag is the head's, and the next edit from
	// it isn't a conflict with that change.
	e.create("docs", "z", map[string]any{"title": "T0", "body": "B0"})
	served = e.expect(e.do("GET", "/docs/z.json", ""), 200, "GET")
	e.theirs("docs", "z", replace("/title", "X"))
	h, _ = e.load("docs", "z")
	same := edit(t, served.body, `"T0"`, `"X"`)
	if r := e.expect(e.do("PUT", "/docs/z.json", same), 201, "PUT the same change"); r.header.Get("ETag") != `"`+h.ID+`"` {
		t.Fatalf("ETag %q, head %s", r.header.Get("ETag"), h.ID)
	}
	e.expect(e.do("PUT", "/docs/z.json", edit(t, same, `"B0"`, `"B1"`)), 201, "PUT a further edit")
	_, doc = e.load("docs", "z")
	sameJSON(t, doc, map[string]any{"title": "X", "body": "B1"})
}

// PUT preconditions, which x/net/webdav leaves alone: If-None-Match: *
// creates only (412 over a live document, as over a scratch file);
// If-Match: * edits only.
func TestSavePreconditions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "notes", map[string]any{"by": "alice", "text": "alice's notes"})
	e.expect(e.do("PUT", "/docs/notes.json", `{"by": "bob"}`, "If-None-Match", "*"), 412, "create-only over a live document")
	_, doc := e.load("docs", "notes")
	sameJSON(t, doc, map[string]any{"by": "alice", "text": "alice's notes"})
	e.expect(e.do("PUT", "/docs/fresh.json", `{"by": "bob"}`, "If-None-Match", "*"), 201, "create-only of a new name")
	e.expect(e.do("PUT", "/docs/.tmp", "x", "If-None-Match", "*"), 201, "create-only scratch")
	e.expect(e.do("PUT", "/docs/.tmp", "y", "If-None-Match", "*"), 412, "create-only over a scratch file")
	e.expect(e.do("PUT", "/docs/absent.json", `{}`, "If-Match", "*"), 412, "edit-only of a new name")
	if h, _ := e.load("docs", "absent"); h.State != client.NotFound {
		t.Fatal("an edit-only PUT created")
	}
}

// A save that deletes the original before writing the new version (an
// editor's, or a client's that creates only) restores it rebased on the
// last live document: edits others made since are kept.
func TestSaveDeleteThenWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/.x.json.tmp", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT temporary file")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE original")
	e.expect(e.do("MOVE", "/docs/.x.json.tmp", "", "Destination", "/docs/x.json"), 201, "MOVE onto it")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
	en := e.lastEntry("docs", "x")
	sameJSON(t, en.Patches, []any{replace("/a", "mine")})
}

// A gateway's records of what a user was served outlive the principal
// (dropped after an idle hour with its scratch files): an editor left
// open longer saves against its own version still.
func TestSaveRecordsOutliveSweep(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	later := e.s.Now().Add(3 * time.Hour)
	alice := k.Grant(t, later, "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	bob := k.Grant(t, later, "user:bob", []string{"docs"}, []string{"read"})
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	mu.Lock()
	now = now.Add(61 * time.Minute)
	mu.Unlock()
	e.expect(e.doAs(bob, "PROPFIND", "/docs/", "", "Depth", "1"), 207, "bob lists (sweeps alice)")
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "alice saves")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
}
