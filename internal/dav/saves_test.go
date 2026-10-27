package dav_test

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/jsonv"
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

	// Two clients of one principal edit from the same GET: the second
	// save reads as an edit of the GET's version (c1's change kept) as
	// well as an undo of c1's save with an edit (TestSaveOwnRevert), which
	// differ at /a, so it is a 409 rather than either; after a reload it
	// keeps c1's change.
	e.create("docs", "y", map[string]any{"a": "1", "b": "1"})
	c1 := e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET c1").body
	c2 := e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET c2").body
	e.expect(e.do("PUT", "/docs/y.json", edit(t, c1, `"a": "1"`, `"a": "c1"`)), 201, "PUT c1")
	e.expect(e.do("PUT", "/docs/y.json", edit(t, c2, `"b": "1"`, `"b": "c2"`)), 409, "PUT c2")
	c2 = e.expect(e.do("GET", "/docs/y.json", ""), 200, "reload c2").body
	e.expect(e.do("PUT", "/docs/y.json", edit(t, c2, `"b": "1"`, `"b": "c2"`)), 201, "PUT c2 after the reload")
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
	e.expect(e.do("PUT", "/docs/x.swp", "x", "If-None-Match", "*"), 201, "create-only scratch")
	e.expect(e.do("PUT", "/docs/x.swp", "y", "If-None-Match", "*"), 412, "create-only over a scratch file")
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
	e.expect(e.do("PUT", "/docs/.goutputstream-x", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT temporary file")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE original")
	e.expect(e.do("MOVE", "/docs/.goutputstream-x", "", "Destination", "/docs/x.json"), 201, "MOVE onto it")
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

// The base of a save isn't guessed between versions it can't tell apart:
// the version an editor opened and a newer one another program of the
// same user read (a preview, a second window, a sniffer's one-byte Range
// read) are as close to a save that changes what someone else changed in
// between, the same value or anywhere in the same array. Rebased on the
// newer one, their edit would be overwritten; the save is a 409 instead,
// and after a reload (its GET drops what was read before the 409) the
// same edit saves.
func TestSaveAmbiguousBase(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	for _, c := range []struct {
		name, old, now, new string
		doc                 map[string]any
		theirs              map[string]any
		preview             []string
	}{
		{"scalar", `"A"`, `"Theirs"`, `"Mine"`, map[string]any{"title": "A", "body": "b"}, replace("/title", "Theirs"), nil},
		{"array", `"a"`, `"a"`, `"mine"`, map[string]any{"items": []any{"a", "b"}}, map[string]any{"op": "add", "path": "/items/-", "value": "theirs"}, nil},
		{"sniff", `"A"`, `"Theirs"`, `"Mine"`, map[string]any{"title": "A", "body": "b"}, replace("/title", "Theirs"), []string{"Range", "bytes=0-0"}},
	} {
		e.create("docs", c.name, c.doc)
		p := "/docs/" + c.name + ".json"
		editor := e.expect(e.do("GET", p, ""), 200, c.name+": GET editor").body
		e.theirs("docs", c.name, c.theirs)
		h, theirs := e.load("docs", c.name)
		want := 200
		if c.preview != nil {
			want = 206
		}
		e.expect(e.do("GET", p, "", c.preview...), want, c.name+": GET preview")
		e.expect(e.do("PUT", p, edit(t, editor, c.old, c.new)), 409, c.name+": PUT the editor's buffer")
		if h2, _ := e.load("docs", c.name); h2.ID != h.ID {
			t.Fatalf("%s: a refused save wrote", c.name)
		}
		reloaded := e.expect(e.do("GET", p, ""), 200, c.name+": reload").body
		e.expect(e.do("PUT", p, edit(t, reloaded, c.now, c.new)), 201, c.name+": PUT after the reload")
		_, doc := e.load("docs", c.name)
		if jsonv.Equal(must(client.ToValue(doc)), must(client.ToValue(theirs))) {
			t.Fatalf("%s: the save after the reload wrote nothing", c.name)
		}
	}
	// The same refused PUT without a reload stays refused.
	e.create("docs", "again", map[string]any{"title": "A"})
	editor := e.expect(e.do("GET", "/docs/again.json", ""), 200, "GET editor").body
	e.theirs("docs", "again", replace("/title", "Theirs"))
	e.expect(e.do("GET", "/docs/again.json", ""), 200, "GET preview")
	for i := 0; i < 2; i++ {
		e.expect(e.do("PUT", "/docs/again.json", edit(t, editor, `"A"`, `"Mine"`)), 409, "PUT without a reload")
	}
	_, doc := e.load("docs", "again")
	sameJSON(t, doc, map[string]any{"title": "Theirs"})
}

// A conflict asks for a reload, and the reload is the base: the reloaded
// version is as close to the edit as the version it replaces, which the
// 409 makes the reload drop.
func TestSaveConflictThenReload(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"title": "A", "n": "1"})
	editor := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/title", "Theirs"))
	e.expect(e.do("PUT", "/docs/x.json", edit(t, editor, `"A"`, `"Mine"`)), 409, "PUT over their edit")
	// davfs2 revalidates the copy it has: a 304 would keep the old one.
	h, _ := e.load("docs", "x")
	reloaded := e.expect(e.do("GET", "/docs/x.json", "", "If-None-Match", `"`+h.ID+`"`), 200, "reload with the head's tag").body
	e.expect(e.do("PUT", "/docs/x.json", edit(t, reloaded, `"Theirs"`, `"Mine"`)), 201, "PUT after the reload")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"title": "Mine", "n": "1"})
}

// A candidate base that can't be read for a reason other than pruning (a
// 429, a 5xx) fails the save instead of being skipped: with no candidate
// left the head would be the base, and the file as written would revert
// others' edits. An If-Match naming a revision that can't be read at all
// is a 412.
func TestSaveBaseReadErrors(t *testing.T) {
	t.Parallel()
	var failRev atomic.Value
	failRev.Store("")
	e := newEnv(t, []string{"docs"}, nil, nil, func(c *clienttest.Options, o *dav.Options) {
		o.CacheBytes = 4096 // documents over 1 KiB aren't kept
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if rev := failRev.Load().(string); rev != "" && r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rev/"+rev) {
					w.Header().Set("Retry-After", "30")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte(`{"error": "rate_limited", "message": "slow down"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	pad := strings.Repeat("p", 2048)
	// If-Match, nothing served (a restart).
	r0 := e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	e.theirs("docs", "x", replace("/b", "theirs"))
	failRev.Store(r0)
	r := e.expect(e.do("PUT", "/docs/x.json", rendered(map[string]any{"a": "mine", "b": "1"}), "If-Match", `"`+r0+`"`), 503, "PUT If-Match, its base rate limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatalf("503 without Retry-After: %v", r.header)
	}
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "1", "b": "theirs"})
	failRev.Store("")
	e.expect(e.do("PUT", "/docs/x.json", rendered(map[string]any{"a": "mine", "b": "1"}), "If-Match", `"`+r0+`"`), 201, "PUT If-Match again")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})

	// The served version, evicted from the document cache.
	r0 = e.create("docs", "y", map[string]any{"a": "1", "b": "1", "pad": pad})
	buf := e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET").body
	e.theirs("docs", "y", replace("/b", "theirs"))
	failRev.Store(r0)
	e.expect(e.do("PUT", "/docs/y.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 503, "PUT, its base rate limited")
	failRev.Store("")
	e.expect(e.do("PUT", "/docs/y.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT again")
	_, doc = e.load("docs", "y")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs", "pad": pad})

	// An If-Match no revision of the document answers to.
	e.create("docs", "z", map[string]any{"a": "1"})
	e.expect(e.do("PUT", "/docs/z.json", rendered(map[string]any{"a": "2"}), "If-Match", `"`+r0+`"`), 412, "PUT If-Match another document's revision")
	_, doc = e.load("docs", "z")
	sameJSON(t, doc, map[string]any{"a": "1"})
}

// After a merged save, a client that reloads the merged revision and
// edits a value the merge brought in, sending If-Match with its ETag (as
// davfs2 does), isn't refused for good: the upload the merged revision
// holds and the revision itself are both what it may have had, so the
// first save may be a 409, but the reload it asks for settles it.
func TestSaveIfMatchAfterMerge(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "merged PUT")
	saved := false
	for i := 0; i < 3; i++ {
		g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "reload")
		var next string
		if saved {
			next = edit(t, g.body, `"a": "mine"`, `"a": "mine `+strconv.Itoa(i)+`"`)
		} else {
			next = edit(t, g.body, `"b": "theirs"`, `"b": "mine too"`)
		}
		r := e.do("PUT", "/docs/x.json", next, "If-Match", g.header.Get("ETag"))
		switch {
		case r.status == 201:
			saved = true
		case r.status == 409 && i == 0:
		default:
			t.Fatalf("attempt %d: %d %s", i, r.status, r.body)
		}
	}
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine 2", "b": "mine too"})
}

// A preview reading many revisions someone else makes doesn't push out
// the version the editor opened: the oldest record of a document stays.
func TestSaveRecordCap(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"title": "A", "n": 0.0})
	editor := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET editor").body
	for i := 1; i <= 18; i++ {
		e.theirs("docs", "x", replace("/n", float64(i)))
		e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET preview")
	}
	e.expect(e.do("PUT", "/docs/x.json", edit(t, editor, `"A"`, `"Mine"`)), 201, "PUT editor")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"title": "Mine", "n": 18.0})
}

// Records are kept per grant root: another user uploading more than the
// records' budget pushes out their own, not the version alice's editor
// opened; and a read-only grant's saves that write nothing, padded to
// the largest file, keep no bytes of it.
func TestSaveRecordsPerUser(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.MaxFileSize = 16 << 10
		o.RecordBytes = 64 << 10
	})
	now := e.s.Now()
	alice := k.Grant(t, now, "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	bob := k.Grant(t, now, "user:bob", []string{"docs"}, []string{"read", "create", "append"})
	reader := k.Grant(t, now, "user:mallory", []string{"docs"}, []string{"read"})
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	e.create("docs", "y", map[string]any{"a": "1", "b": "1"})
	for i := 0; i < 6; i++ {
		e.create("docs", "pad"+strconv.Itoa(i), map[string]any{"z": 1})
	}
	bufX := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice GETs x").body
	bufY := e.expect(e.doAs(alice, "GET", "/docs/y.json", ""), 200, "alice GETs y").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.theirs("docs", "y", replace("/b", "theirs"))
	big := `{"blob": "` + strings.Repeat("z", 14<<10) + `"}`
	for i := 0; i < 6; i++ {
		e.expect(e.doAs(bob, "PUT", "/docs/bob"+strconv.Itoa(i)+".json", big), 201, "bob uploads")
	}
	body := rendered(map[string]any{"z": 1})
	padded := body + strings.Repeat(" ", (16<<10)-len(body)-1)
	for i := 0; i < 6; i++ {
		e.expect(e.doAs(reader, "PUT", "/docs/pad"+strconv.Itoa(i)+".json", padded), 201, "a read-only save that writes nothing")
	}
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", edit(t, bufX, `"a": "1"`, `"a": "mine"`)), 201, "alice saves x")
	e.expect(e.doAs(alice, "PUT", "/docs/y.json", edit(t, bufY, `"a": "1"`, `"a": "mine"`)), 201, "alice saves y")
	for _, n := range []string{"x", "y"} {
		_, doc := e.load("docs", n)
		sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
	}
}

// When a user's own records of a document were pushed out (its uploads
// filled the budget), what is left isn't taken as the base: the save is
// a 409, never the file as written over others' edits; the reload saves.
func TestSaveRecordsLost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) {
		o.MaxFileSize = 16 << 10
		o.RecordBytes = 64 << 10
	})
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	big := `{"blob": "` + strings.Repeat("z", 14<<10) + `"}`
	for i := 0; i < 8; i++ {
		e.expect(e.do("PUT", "/docs/big"+strconv.Itoa(i)+".json", big), 201, "uploads")
	}
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT once its records are gone")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "1", "b": "theirs"})
	buf = e.expect(e.do("GET", "/docs/x.json", ""), 200, "reload").body
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT after the reload")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
}

// Records lost to the bounds are a 409 until the reload that refusal asks
// for (§H.4 "records evicted"), not until any read: in local mode every
// program is one login, and the editor that opened the version pushed
// out may still hold it after a preview read the file, its save then
// rebased on the preview's read and written over others' edits.
func TestSaveRecordsLostPreview(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) {
		o.MaxFileSize = 16 << 10
		o.RecordBytes = 64 << 10
	})
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "the editor's GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	big := `{"blob": "` + strings.Repeat("z", 14<<10) + `"}`
	for i := 0; i < 8; i++ {
		e.expect(e.do("PUT", "/docs/big"+strconv.Itoa(i)+".json", big), 201, "uploads")
	}
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "a preview's GET")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "the editor's save once its records are gone")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "1", "b": "theirs"})
}

// A save that writes nothing (the file already reads so) isn't a write:
// a later save of an older version unchanged isn't an undo of it, which
// would revert the edit of someone else's it reproduced.
func TestSaveNoopIsNoWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	editor1 := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET editor 1").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	window2 := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET window 2").body
	e.expect(e.do("PUT", "/docs/x.json", window2), 201, "window 2 saves unchanged (writes nothing)")
	e.expect(e.do("PUT", "/docs/x.json", editor1), 201, "editor 1 saves unchanged")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "1", "b": "theirs"})
}

// After a merged save, a conditional GET of the merged revision answers
// with its content, not a 304: the client may have filed what it sent
// under the merged revision's tag (davfs2 asks for it with a HEAD).
func TestSaveMergedRevalidates(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	body := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/x.json", edit(t, body, `"a": "1"`, `"a": "mine"`)), 201, "PUT merged")
	tag := e.expect(e.do("HEAD", "/docs/x.json", ""), 200, "HEAD").header.Get("ETag")
	g := e.expect(e.do("GET", "/docs/x.json", "", "If-None-Match", tag), 200, "GET If-None-Match the merged tag")
	if g.body != rendered(map[string]any{"a": "mine", "b": "theirs"}) {
		t.Fatalf("GET %q", g.body)
	}
	e.expect(e.do("GET", "/docs/x.json", "", "If-None-Match", tag), 304, "GET again")
}

// A delete-then-write save whose write is refused (a conflict) doesn't
// leave the document deleted: the user's own DELETE moments before is
// undone, as a plain PUT refused leaves the document as it was.
func TestSaveDeleteThenWriteRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/a", "theirs"))
	e.expect(e.do("PUT", "/docs/.goutputstream-x", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT temporary file")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE original")
	r := e.expect(e.do("MOVE", "/docs/.goutputstream-x", "", "Destination", "/docs/x.json"), 409, "MOVE onto it")
	if !strings.Contains(r.body, "restored") {
		t.Fatalf("409 %q", r.body)
	}
	h, doc := e.load("docs", "x")
	if h.State != client.Live {
		t.Fatalf("after a refused delete-then-write save the document is %v", h.State)
	}
	sameJSON(t, doc, map[string]any{"a": "theirs", "b": "1"})
	// Someone else's DELETE isn't undone.
	e.create("docs", "y", map[string]any{"a": "1", "b": "1"})
	buf = e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET").body
	e.theirs("docs", "y", replace("/a", "theirs"))
	h, _ = e.load("docs", "y")
	must(e.c.Delete(e.ctx, "docs", "y", h.ID))
	e.expect(e.do("PUT", "/docs/y.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT over someone else's DELETE")
	if h, _ := e.load("docs", "y"); h.State != client.Tombstoned {
		t.Fatalf("someone else's DELETE undone: %v", h.State)
	}
}

// DELETE honours If-Match (or an If header's entity tag): deleting the
// version a client saw doesn't tombstone one someone else changed since.
func TestDeleteIfMatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1"})
	g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	e.theirs("docs", "x", replace("/a", "theirs"))
	e.expect(e.do("DELETE", "/docs/x.json", "", "If-Match", g.header.Get("ETag")), 412, "DELETE If-Match an old revision")
	e.expect(e.do("DELETE", "/docs/x.json", "", "If", "(["+g.header.Get("ETag")+"])"), 412, "DELETE If an old revision")
	if h, _ := e.load("docs", "x"); h.State != client.Live {
		t.Fatalf("the document is %v", h.State)
	}
	h, _ := e.load("docs", "x")
	e.expect(e.do("DELETE", "/docs/x.json", "", "If-Match", `"`+h.ID+`"`), 204, "DELETE If-Match the head")
	if h, _ := e.load("docs", "x"); h.State != client.Tombstoned {
		t.Fatalf("the document is %v", h.State)
	}
	e.create("docs", "y", map[string]any{"a": "1"})
	e.expect(e.do("DELETE", "/docs/y.json", "", "If-Match", "*"), 204, "DELETE If-Match *")
}

// An If header that names only an entity tag (no lock token), or the
// always true Not <DAV:no-lock> with one, names the base as If-Match
// does: x/net/webdav would take it for a lock token and fail it (412).
func TestSaveIfHeaderETag(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	for i, f := range []string{"([%s])", "(Not <DAV:no-lock> [%s])"} {
		n := "x" + strconv.Itoa(i)
		r0 := e.create("docs", n, map[string]any{"a": "1", "b": "1"})
		e.theirs("docs", n, replace("/b", "theirs"))
		text := rendered(map[string]any{"a": "mine", "b": "1"})
		e.expect(e.do("PUT", "/docs/"+n+".json", text, "If", fmt.Sprintf(f, `"`+r0+`"`)), 201, "PUT If: "+f)
		_, doc := e.load("docs", n)
		sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
	}
	// With a lock token in another list, the lock is still checked.
	e.create("docs", "l", map[string]any{"a": "1"})
	lock := `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`
	tok := e.expect(e.do("LOCK", "/docs/l.json", lock, "Timeout", "Second-60"), 200, "LOCK").header.Get("Lock-Token")
	h, _ := e.load("docs", "l")
	e.expect(e.do("PUT", "/docs/l.json", `{"a": "2"}`, "If", `(["`+h.ID+`"])`), 423, "PUT of a locked file with an entity tag only")
	e.expect(e.do("PUT", "/docs/l.json", `{"a": "2"}`, "If", "("+tok+`) (["`+h.ID+`"])`), 201, "PUT with the token")
}

// If-Match: * and If-None-Match: * decide once whether the file exists:
// an empty placeholder (after a LOCK of a new name) exists for both, so
// If-Match: * writes over it, as over any file listed.
func TestSavePreconditionsPlaceholder(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	lock := `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`
	tok := e.expect(e.do("LOCK", "/docs/new.json", lock, "Timeout", "Second-60"), 201, "LOCK a new name").header.Get("Lock-Token")
	e.expect(e.do("PUT", "/docs/new.json", `{"v": 1}`, "If-None-Match", "*", "If", "("+tok+")"), 412, "create-only over the placeholder")
	e.expect(e.do("PUT", "/docs/new.json", `{"v": 1}`, "If-Match", "*", "If", "("+tok+")"), 201, "edit-only over the placeholder")
	_, doc := e.load("docs", "new")
	sameJSON(t, doc, map[string]any{"v": 1})
}

// A save that deletes the original before writing the new version gets
// it back whatever refuses the write that follows, not only a conflict: a
// body that isn't JSON (rclone's mount without a cache renames over a
// file as DELETE, then MOVE of a scratch file onto the name), one over
// -max-file-size, a failed precondition. A tree's file deleted by the
// user's DELETE before a write to its path is put back the same way: its
// placement, and its item.
func TestSaveDeleteThenWriteFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, []string{"cat"}, map[string]map[string]any{
		"cat": {"catalog": treeCatalog("files")},
	}, func(_ *clienttest.Options, o *dav.Options) { o.MaxFileSize = 1024 })
	must(e.c.CreateNamespace(e.ctx, "files", map[string]any{"read": "public"}))
	for i, c := range []struct {
		what   string
		status int
		write  func(p string) resp
	}{
		{"PUT of a body that isn't JSON", 400, func(p string) resp { return e.do("PUT", p, `{"v": 2`) }},
		{"MOVE of a scratch file that isn't JSON", 400, func(p string) resp {
			e.expect(e.do("PUT", "/docs/.goutputstream-XYZ", `{"v": 2`), 201, "PUT scratch")
			return e.do("MOVE", "/docs/.goutputstream-XYZ", "", "Destination", p, "Overwrite", "F")
		}},
		{"PUT over -max-file-size", 413, func(p string) resp { return e.do("PUT", p, `{"v": "`+strings.Repeat("x", 2000)+`"}`) }},
		{"PUT with If-Match: *", 412, func(p string) resp { return e.do("PUT", p, `{"v": 2}`, "If-Match", "*") }},
	} {
		name := "x" + strconv.Itoa(i)
		e.create("docs", name, map[string]any{"v": 1})
		e.expect(e.do("GET", "/docs/"+name+".json", ""), 200, "GET")
		e.expect(e.do("DELETE", "/docs/"+name+".json", ""), 204, "DELETE")
		r := e.expect(c.write("/docs/"+name+".json"), c.status, c.what)
		if !strings.Contains(r.body, "restored as it was") {
			t.Fatalf("%s: %q", c.what, r.body)
		}
		h, doc := e.load("docs", name)
		if h.State != client.Live {
			t.Fatalf("%s: the document is %v", c.what, h.State)
		}
		sameJSON(t, doc, map[string]any{"v": 1})
		if en := e.lastEntry("docs", name); en.Kind != "rev" || len(en.Patches.([]any)) != 0 {
			t.Fatalf("%s: restored with %+v", c.what, en)
		}
	}
	e.create("files", "p", map[string]any{"v": 1})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "files.p", map[string]any{"title": "p.json", "parents": parents("cat", "root")})
	e.expect(e.do("DELETE", "/cat/p.json", ""), 204, "DELETE a tree's file")
	e.expectTombstoned("files", "p", "the item")
	r := e.expect(e.do("PUT", "/cat/p.json", `{"v": 2`), 400, "PUT of a body that isn't JSON to its path")
	if !strings.Contains(r.body, "restored as it was") {
		t.Fatalf("400 %q", r.body)
	}
	sameJSON(t, e.parentsOf("files.p"), parents("cat", "root"))
	_, doc := e.load("files", "p")
	sameJSON(t, doc, map[string]any{"v": 1})
}

// A save that reads as an edit of more than one version the user had,
// with different results, isn't applied as either (§H.4): an undo of the
// user's own save combined with a new edit looks like a second program's
// edit from the version before that save. Taken as the latter, the undo
// was dropped, with a 2xx; it is a 409, and after a reload the save goes
// through as sent.
func TestSaveOwnRevert(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "orig", "b": "orig"})
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "changed", "b": "orig"}`), 201, "save")
	h, _ := e.load("docs", "x")
	r := e.expect(e.do("PUT", "/docs/x.json", `{"a": "orig", "b": "changed"}`), 409, "undo the save and edit")
	if !strings.Contains(r.body, "/a") {
		t.Fatalf("409 %q", r.body)
	}
	e.expectLive("docs", "x", h, "after the refused save")
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "reload")
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "orig", "b": "changed"}`), 201, "save after the reload")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "orig", "b": "changed"})
}

// Records are kept by document, and a path may come to name another: a
// save without a tag at a path that names another document than the one
// the user read or wrote under it, or none, is a 409 rather than a save
// over what is there (§H.4): a tree's title given to a new item after the
// old one was deleted, a raw x.json taking JSON document x's name. A
// reload (a GET of the path) settles it. A save naming a revision
// (If-Match) where the path holds no file is a 412, never a new file.
func TestSavePathReplaced(t *testing.T) {
	t.Parallel()
	e := treeEnv(t, func(_ *clienttest.Options, o *dav.Options) { o.CatalogTTL = time.Nanosecond })
	g := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET")
	hn, _ := e.load("cat", "matches.derby")
	must(e.c.Delete(e.ctx, "cat", "matches.derby", hn.ID))
	hi, _ := e.load("matches", "derby")
	must(e.c.Delete(e.ctx, "matches", "derby", hi.ID))
	e.create("matches", "newderby", map[string]any{"title": "Their new derby", "venue": "Theirs"})
	e.create("cat", "matches.newderby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
	h, _ := e.load("matches", "newderby")
	mine := edit(t, g.body, `"title": "Derby"`, `"title": "My derby"`)
	e.expect(e.do("PUT", "/cat/Season/derby.json", mine), 409, "PUT, the path naming a new item")
	e.expect(e.do("PUT", "/cat/Season/derby.json", mine, "If-Match", g.header.Get("ETag")), 412, "PUT If-Match, the path naming a new item")
	e.expectLive("matches", "newderby", h, "after the refused saves")
	r := e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "reload")
	e.expect(e.do("PUT", "/cat/Season/derby.json", edit(t, r.body, `"Theirs"`, `"Mine"`)), 201, "PUT after the reload")
	_, doc := e.load("matches", "newderby")
	sameJSON(t, doc, map[string]any{"title": "Their new derby", "venue": "Mine"})

	// Deleted by someone else, the tree read again since: no new file.
	g = e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET")
	o := e.another()
	o.expect(o.do("DELETE", "/cat/Season/derby.json", ""), 204, "another user's DELETE")
	before := e.liveNames("matches")
	e.expect(e.do("PUT", "/cat/Season/derby.json", `{"title": "Mine"}`), 409, "PUT over another user's delete")
	e.expect(e.do("PUT", "/cat/Season/derby.json", `{"title": "Mine"}`, "If-Match", g.header.Get("ETag")), 412, "PUT If-Match over another user's delete")
	sameStrings(t, "matches", e.liveNames("matches"), before)
	e.expect(e.do("GET", "/cat/Season/derby.json", ""), 404, "reload: gone")
	e.expect(e.do("PUT", "/cat/Season/derby.json", `{"title": "Mine"}`), 201, "PUT after the reload")
	if ns, item := e.itemOf("cat", "derby.json"); ns != "matches" || item == "newderby" {
		t.Fatalf("derby.json is %s/%s", ns, item)
	}

	// The flat view: a raw x.json takes JSON document x's name.
	f := newEnv(t, []string{"docs"}, nil, nil)
	f.create("docs", "x", map[string]any{"v": "1"})
	g = f.expect(f.do("GET", "/docs/x.json", ""), 200, "GET")
	f.rawDoc("docs", "x.json", "application/json", []byte("// someone's raw file\n"), nil)
	f.expect(f.do("PUT", "/docs/x.json", edit(t, g.body, `"v": "1"`, `"v": "2"`)), 409, "PUT, a raw x.json taking the name")
	if _, data := f.rawOf("docs", "x.json"); string(data) != "// someone's raw file\n" {
		t.Fatalf("raw x.json %q", data)
	}
	f.expect(f.do("GET", "/docs/x.json", ""), 200, "reload")
	f.expect(f.do("PUT", "/docs/x.json", "// mine\n"), 201, "PUT after the reload")
	if _, data := f.rawOf("docs", "x.json"); string(data) != "// mine\n" {
		t.Fatalf("raw x.json %q", data)
	}
	// If-Match naming a revision, where no file is.
	for _, p := range []string{"/docs/new.md", "/docs/new2.json"} {
		f.expect(f.do("PUT", p, `{}`, "If-Match", `"bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"`), 412, "PUT If-Match "+p)
	}
	f.expect(f.do("PUT", "/docs/.x.swp", `swap`, "If-Match", `"bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"`), 412, "PUT If-Match to a scratch name")
	sameStrings(t, "docs", f.liveNames("docs"), []string{"x", "x.json"})
}
