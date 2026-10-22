package dav_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// Spec v0.73, Addendum H (gateways): saves, deletes and moves.

// A gateway re-checks a grant at least every five minutes (§H.7
// "Re-checking"): VerifyEvery above that is refused (GW-32).
func TestV073VerifyEveryFiveMinutes(t *testing.T) {
	t.Parallel()
	c := must(client.New("http://127.0.0.1:1"))
	if _, err := dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true, VerifyEvery: 5*time.Minute + time.Second}); err == nil {
		t.Fatal("VerifyEvery of 5m1s taken")
	}
	must(dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true, VerifyEvery: 5 * time.Minute}))
}

// A DELETE without a tag deletes the head the gateway read, with If-Match
// on it (§H.5 "Delete a file"): an edit someone makes between that read
// and the delete is a 409, never tombstoned unseen; in a tree the
// placement is put back as it was (GW-34).
func TestV073DeleteWithoutTagHeadMoved(t *testing.T) {
	t.Parallel()
	h := &hook{}
	e := treeEnv(t, withHook(h))
	h.set(at("DELETE", "/r/matches/derby"), func() {
		e.theirs("matches", "derby", map[string]any{"op": "add", "path": "/theirs", "value": "important"})
	})
	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 409, "tree DELETE, the item edited after the gateway read it")
	if hn, _ := e.load("cat", "matches.derby"); hn.State != client.Live {
		t.Fatalf("placement %v", hn.State)
	}
	if hi, doc := e.load("matches", "derby"); hi.State != client.Live || doc.(map[string]any)["theirs"] != "important" {
		t.Fatalf("item %v %v", hi.State, doc)
	}
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})

	e.create("matches", "x", map[string]any{"a": "1"})
	h.set(at("DELETE", "/r/matches/x"), func() {
		e.theirs("matches", "x", replace("/a", "theirs"))
	})
	e.expect(e.do("DELETE", "/matches/x.json", ""), 409, "flat DELETE, edited after the gateway read it")
	if hx, doc := e.load("matches", "x"); hx.State != client.Live || doc.(map[string]any)["a"] != "theirs" {
		t.Fatalf("x %v %v", hx.State, doc)
	}
	e.expect(e.do("DELETE", "/matches/x.json", ""), 204, "DELETE again")
	e.expectTombstoned("matches", "x", "x")
	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "tree DELETE again")
	e.expectTombstoned("matches", "derby", "the item")
}

// Dangling placements aren't a folder's contents: those the grant can't
// delete (401, 403) are orphaned with it, and don't fail the folder's
// DELETE (§H.5 "Delete a folder", GW-35).
func TestV073DeleteFolderDanglingForbidden(t *testing.T) {
	t.Parallel()
	e := treeEnv(t, func(o *clienttest.Options, _ *dav.Options) {
		o.Wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" && r.URL.Path == "/r/cat/matches.ghost" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code":"forbidden","message":"this grant doesn't delete placements"}`))
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	})
	e.create("matches", "ghost", map[string]any{"t": 1})
	e.create("cat", "matches.ghost", map[string]any{"title": "ghost.json", "parents": parents("cat", "empty")})
	h, _ := e.load("matches", "ghost")
	must(e.c.Delete(e.ctx, "matches", "ghost", h.ID))
	e.expect(e.do("DELETE", "/cat/Empty", ""), 204, "DELETE of a folder holding a dangling placement the grant can't delete")
	e.expectTombstoned("cat", "empty", "the folder")
	if hn, _ := e.load("cat", "matches.ghost"); hn.State != client.Live {
		t.Fatalf("the dangling placement is %v, want live (orphaned)", hn.State)
	}
}

// A weak tag works as a DELETE's precondition (§H.1 "Writer's bytes",
// done GW-3): W/"{head}" deletes, an older one is 412, in the flat view
// and in a tree.
func TestV073DeleteWeakTag(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	r0 := e.create("matches", "x", map[string]any{"a": "1"})
	e.theirs("matches", "x", replace("/a", "2"))
	e.expect(e.do("DELETE", "/matches/x.json", "", "If-Match", `W/"`+r0+`"`), 412, "flat DELETE W/ an old revision")
	h, _ := e.load("matches", "x")
	e.expect(e.do("DELETE", "/matches/x.json", "", "If-Match", `W/"`+h.ID+`"`), 204, "flat DELETE W/ the head")
	e.expectTombstoned("matches", "x", "x")

	old := must(e.c.Head(e.ctx, "matches", "derby")).ID
	e.theirs("matches", "derby", replace("/title", "Derby 2"))
	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If", `([W/"`+old+`"])`), 412, "tree DELETE If W/ an old revision")
	e.nodeDoc("cat", "matches.derby")
	head := must(e.c.Head(e.ctx, "matches", "derby")).ID
	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If-Match", `W/"`+head+`"`), 204, "tree DELETE W/ the head")
	e.expectTombstoned("matches", "derby", "the item")
}

// A text/ type needs a body in UTF-8, a leading BOM allowed; any other
// body is application/octet-stream, whatever the name or the upload says
// (§H.1, GW-4): on a PUT, a rename that uploads again or copies, a move
// onto a file, and a copy, which keeps the source's blob only where the
// type comes out as the source's.
func TestV073RawTextNeedsUTF8(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("docs")}})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	bad := "\xff\xfe\x00abc"
	typeOf := func(name string) string {
		t.Helper()
		ref, _ := e.rawOf("docs", name)
		return ref["type"].(string)
	}
	for _, c := range []struct{ name, ctype, body, typ string }{
		{"bin.txt", "", bad, "application/octet-stream"},
		{"bin.md", "text/markdown", bad, "application/octet-stream"},
		{"bom.txt", "", "\xef\xbb\xbfhello", "text/plain"},
		{"plain.csv", "", "a,b\n", "text/csv"},
		{"x", "text/x-foo", bad, "application/octet-stream"},
		{"y", "text/x-foo; charset=utf-8", "héllo", "text/x-foo"},
		{"pic.png", "", bad, "image/png"},
	} {
		e.expect(e.do("PUT", "/docs/"+c.name, c.body, "Content-Type", c.ctype), 201, "PUT "+c.name)
		if got := typeOf(c.name); got != c.typ {
			t.Fatalf("%s as %q: %s, want %s", c.name, c.ctype, got, c.typ)
		}
	}
	e.expect(e.do("PUT", "/cat/notes.md", bad), 201, "PUT in a tree")
	if _, item := e.itemOf("cat", "notes.md"); typeOf(item) != "application/octet-stream" {
		t.Fatalf("a tree's notes.md of bytes that aren't UTF-8: %s", typeOf(item))
	}

	// Another tool's text/plain file of bytes that aren't UTF-8.
	e.rawDoc("docs", "data", "text/plain", []byte(bad), nil)
	e.expect(e.do("COPY", "/docs/data", "", "Destination", "/docs/copy"), 201, "COPY")
	ref, data := e.rawOf("docs", "copy")
	if ref["type"] != "application/octet-stream" || string(data) != bad {
		t.Fatalf("copy %v %q", ref, data)
	}
	if src, _ := e.rawOf("docs", "data"); src["$blob"] == ref["$blob"] {
		t.Fatalf("the copy kept the source's blob of another type: %v", ref)
	}
	e.expect(e.do("MOVE", "/docs/data", "", "Destination", "/docs/data.txt"), 201, "MOVE to a .txt name")
	if got := typeOf("data.txt"); got != "application/octet-stream" {
		t.Fatalf("data.txt after a rename: %s", got)
	}
	// From an octet stream to a .txt name, the blob stays (Blob-From).
	e.expect(e.do("MOVE", "/docs/data.txt", "", "Destination", "/docs/data2.txt"), 201, "MOVE to another .txt name")
	if got := typeOf("data2.txt"); got != "application/octet-stream" {
		t.Fatalf("data2.txt after a rename: %s", got)
	}
	e.expect(e.do("PUT", "/docs/target.md", "# text\n"), 201, "PUT target.md")
	e.expect(e.do("MOVE", "/docs/data2.txt", "", "Destination", "/docs/target.md"), 204, "MOVE onto target.md")
	ref, data = e.rawOf("docs", "target.md")
	if ref["type"] != "application/octet-stream" || string(data) != bad {
		t.Fatalf("target.md after a move onto it %v %q", ref, data)
	}
}

// A raw file's type is its name's, else the upload's Content-Type, else,
// for an existing file, the type it has, and only for a new one
// application/octet-stream (§H.1, GW-5): a re-save without a type, or
// with one that says nothing of the bytes, keeps the file's type, as
// does a restore after the user's own DELETE.
func TestV073RawTypeKept(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("docs")}})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	typeOf := func(name string) string {
		t.Helper()
		ref, _ := e.rawOf("docs", name)
		return ref["type"].(string)
	}
	e.expect(e.do("PUT", "/docs/x.foo", "one", "Content-Type", "image/x-foo"), 201, "PUT x.foo")
	for i, c := range []struct{ ctype, typ string }{
		{"", "image/x-foo"},
		{"application/octet-stream", "image/x-foo"},
		{"multipart/form-data; boundary=x", "image/x-foo"},
		{"image/x-bar", "image/x-bar"},
		{"", "image/x-bar"},
	} {
		e.expect(e.do("PUT", "/docs/x.foo", "v"+strconv.Itoa(i), "Content-Type", c.ctype), 201, "re-save x.foo as "+c.ctype)
		if got := typeOf("x.foo"); got != c.typ {
			t.Fatalf("x.foo re-saved as %q: %s, want %s", c.ctype, got, c.typ)
		}
	}
	e.expect(e.do("PUT", "/docs/n.md", "# one", "Content-Type", "image/x-foo"), 201, "PUT n.md")
	if got := typeOf("n.md"); got != "text/markdown" {
		t.Fatalf("n.md: %s", got)
	}
	e.expect(e.do("PUT", "/docs/new", "bytes"), 201, "PUT a new file without a type")
	if got := typeOf("new"); got != "application/octet-stream" {
		t.Fatalf("new: %s", got)
	}
	// Deleted, then written again: restored with its type.
	e.expect(e.do("PUT", "/docs/y", "one", "Content-Type", "image/x-foo"), 201, "PUT y")
	e.expect(e.do("DELETE", "/docs/y", ""), 204, "DELETE y")
	e.expect(e.do("PUT", "/docs/y", "two"), 201, "PUT y again")
	if got := typeOf("y"); got != "image/x-foo" {
		t.Fatalf("y restored: %s", got)
	}
	// A tree's file.
	e.expect(e.do("PUT", "/cat/pic", "one", "Content-Type", "image/x-foo"), 201, "PUT /cat/pic")
	e.expect(e.do("PUT", "/cat/pic", "two"), 201, "re-save /cat/pic without a type")
	if _, item := e.itemOf("cat", "pic"); typeOf(item) != "image/x-foo" {
		t.Fatalf("a tree's pic: %s", typeOf(item))
	}
}

// A successful raw save is always stored with the uploaded bytes and
// answered with the new revision as ETag (§H.1 "Identity", §H.4, GW-6):
// a version the user had, saved unchanged over someone else's bytes, is
// a 409 like any other save over them, nothing written, also where it
// would restore the user's own DELETE; a save of the bytes the head
// holds writes nothing and answers the head; a restore of the user's own
// DELETE with the bytes the file had is stored and answered with its
// revision.
func TestV073RawSaveAlwaysStored(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "priv"}, nil, map[string]map[string]any{"priv": {"nonce": "required"}})
	theirs := func(name string) {
		t.Helper()
		h, _ := e.load("docs", name)
		bid := must(e.c.UploadBlob(e.ctx, "docs", name, "text/plain", "", []byte("theirs")))
		must(e.c.Append(e.ctx, "docs", name, h.ID, []any{replace("/$blob", bid), replace("/size", 6)}))
	}
	e.rawDoc("docs", "c.txt", "text/plain", []byte("one"), nil)
	e.expect(e.do("GET", "/docs/c.txt", ""), 200, "GET")
	theirs("c.txt")
	h, _ := e.load("docs", "c.txt")
	e.expect(e.do("PUT", "/docs/c.txt", "one"), 409, "PUT the version read, unchanged, over theirs")
	e.expectLive("docs", "c.txt", h, "after the refused save")

	// After the user's own DELETE: the delete is undone, theirs kept.
	e.rawDoc("docs", "e.txt", "text/plain", []byte("one"), nil)
	e.expect(e.do("GET", "/docs/e.txt", ""), 200, "GET")
	theirs("e.txt")
	e.expect(e.do("DELETE", "/docs/e.txt", ""), 204, "DELETE")
	e.expect(e.do("PUT", "/docs/e.txt", "one"), 409, "PUT the version read, unchanged, after the user's DELETE of theirs")
	if hd, _ := e.load("docs", "e.txt"); hd.State != client.Live {
		t.Fatalf("e.txt %v", hd.State)
	}
	if _, data := e.rawOf("docs", "e.txt"); string(data) != "theirs" {
		t.Fatalf("e.txt %q", data)
	}

	for _, ns := range []string{"docs", "priv"} {
		p := "/" + ns + "/d.txt"
		r := e.expect(e.do("PUT", p, "same"), 201, "PUT "+p)
		h, _ := e.load(ns, "d.txt")
		if r.header.Get("ETag") != `"`+h.ID+`"` {
			t.Fatalf("%s: ETag %q, head %s", p, r.header.Get("ETag"), h.ID)
		}
		r = e.expect(e.do("PUT", p, "same"), 201, "PUT the head's bytes again "+p)
		if r.header.Get("ETag") != `"`+h.ID+`"` {
			t.Fatalf("%s: a save of the head's bytes: ETag %q, head %s", p, r.header.Get("ETag"), h.ID)
		}
		e.expectLive(ns, "d.txt", h, "after a save of the head's bytes")
		// Deleted by the user, then written again with the same bytes:
		// restored as it was, which holds them.
		e.expect(e.do("DELETE", p, ""), 204, "DELETE "+p)
		r = e.expect(e.do("PUT", p, "same"), 201, "PUT after the DELETE "+p)
		h, _ = e.load(ns, "d.txt")
		if h.State != client.Live || r.header.Get("ETag") != `"`+h.ID+`"` {
			t.Fatalf("%s restored: %v, ETag %q, head %s", p, h.State, r.header.Get("ETag"), h.ID)
		}
	}
}

// A new file over a tombstoned resource whose last revision has
// $successor (moved away) is 409 naming the new path, never made anew:
// its file in the same namespace's directory, else /r/{ns}/{name}; so is
// the save after a 409 for someone else's delete and its 404 reload, and
// a temporary file moved over the old name, a save too (§H.2 "Flat
// view", §H.4 "The reload", GW-23). A MOVE of a live file there is no
// save: a rename back makes the name anew.
func TestV073NewFileOverMovedAway(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "other"}, nil, nil)
	o := e.another()
	refused := func(r resp, to string) {
		t.Helper()
		if !strings.Contains(r.body, to) {
			t.Fatalf("409 naming %s: %q", to, r.body)
		}
	}
	e.create("docs", "x", map[string]any{"a": "1"})
	o.expect(o.do("MOVE", "/docs/x.json", "", "Destination", "/docs/y.json"), 201, "someone else's MOVE")
	refused(e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`), 409, "PUT the old name"), "/docs/y.json")
	e.expectTombstoned("docs", "x", "x")

	e.rawDoc("docs", "n.md", "text/markdown", []byte("one"), nil)
	e.expect(e.do("GET", "/docs/n.md", ""), 200, "GET n.md")
	o.expect(o.do("MOVE", "/docs/n.md", "", "Destination", "/docs/m.md"), 201, "someone else's MOVE of a raw file")
	e.expect(e.do("PUT", "/docs/n.md", "mine"), 409, "PUT over someone else's delete")
	e.expect(e.do("GET", "/docs/n.md", ""), 404, "the reload")
	refused(e.expect(e.do("PUT", "/docs/n.md", "mine"), 409, "PUT after the reload"), "/docs/m.md")
	e.expectTombstoned("docs", "n.md", "n.md")

	e.create("docs", "far", map[string]any{"a": "1"})
	o.expect(o.do("MOVE", "/docs/far.json", "", "Destination", "/other/far.json"), 201, "someone else's MOVE to another namespace")
	refused(e.expect(e.do("PUT", "/docs/far.json", `{"a": "mine"}`), 409, "PUT the old name"), "/r/other/far")

	e.expect(e.do("PUT", "/docs/.goutputstream-x", `{"a": "mine"}`), 201, "PUT a temporary file")
	refused(e.expect(e.do("MOVE", "/docs/.goutputstream-x", "", "Destination", "/docs/x.json"), 409, "a temporary file moved over the old name"), "/docs/y.json")
	e.expectTombstoned("docs", "x", "x")

	e.expect(e.do("MOVE", "/docs/y.json", "", "Destination", "/docs/x.json"), 201, "a rename back")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "1"})
	e.expect(e.do("MOVE", "/other/far.json", "", "Destination", "/docs/far.json"), 201, "a move back from another namespace")
	_, doc = e.load("docs", "far")
	sameJSON(t, doc, map[string]any{"a": "1"})
}

// Records last a day, and a path whose records expired counts as
// evicted (§H.4 "Records", GW-24): a save without a tag is then a 409
// asking for a reload, never one with no base that writes over what
// others changed; also once the idle user's records are swept, whose
// marks are kept; and a path record that expired still refuses a save
// of a path that now names another file. A document touched within the
// day keeps every record, the version an editor opened with them.
func TestV073ExpiredRecordsEvicted(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := treeEnv(t, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })

	// A document untouched for a day.
	e.create("matches", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/matches/x.json", ""), 200, "GET x").body
	e.theirs("matches", "x", replace("/b", "theirs"))
	e.rawDoc("matches", "r.txt", "text/plain", []byte("one"), nil)
	e.expect(e.do("GET", "/matches/r.txt", ""), 200, "GET r.txt")
	h, _ := e.load("matches", "r.txt")
	bid := must(e.c.UploadBlob(e.ctx, "matches", "r.txt", "text/plain", "", []byte("theirs")))
	must(e.c.Append(e.ctx, "matches", "r.txt", h.ID, []any{replace("/$blob", bid), replace("/size", 6)}))
	// A document read, then read again by another program 20 h later.
	e.create("matches", "w", map[string]any{"a": "1", "b": "1"})
	wbuf := e.expect(e.do("GET", "/matches/w.json", ""), 200, "GET w (the editor)").body
	e.theirs("matches", "w", replace("/b", "theirs"))
	// A tree's file read under its path.
	e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET derby.json")

	c.add(20 * time.Hour)
	e.expect(e.do("GET", "/matches/w.json", ""), 200, "GET w (a preview)")
	c.add(5 * time.Hour)
	e.expect(e.do("PUT", "/matches/w.json", edit(t, wbuf, `"a": "1"`, `"a": "mine"`)), 201, "PUT w, touched within the day")
	_, doc := e.load("matches", "w")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})

	hx, _ := e.load("matches", "x")
	e.expect(e.do("PUT", "/matches/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT x after 25 h")
	e.expectLive("matches", "x", hx, "x after the refusal")
	hr, _ := e.load("matches", "r.txt")
	e.expect(e.do("PUT", "/matches/r.txt", "mine"), 409, "PUT r.txt after 25 h")
	e.expectLive("matches", "r.txt", hr, "r.txt after the refusal")
	buf = e.expect(e.do("GET", "/matches/x.json", ""), 200, "the reload").body
	e.expect(e.do("PUT", "/matches/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT x after the reload")
	_, doc = e.load("matches", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})

	// The path's file replaced by another (deleted, a new item placed
	// under its title): the expired path record refuses the save.
	hd, _ := e.load("cat", "matches.derby")
	must(e.c.Delete(e.ctx, "cat", "matches.derby", hd.ID))
	e.create("matches", "derby2", map[string]any{"title": "Derby 2"})
	e.create("cat", "matches.derby2", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
	h2, _ := e.load("matches", "derby2")
	e.expect(e.do("PUT", "/cat/Season/derby.json", rendered(map[string]any{"title": "mine"})), 409, "PUT a path that names another file now")
	e.expectLive("matches", "derby2", h2, "derby2 after the refusal")

	// Swept, the idle user's records leave marks: still a 409.
	e.create("matches", "z", map[string]any{"a": "1", "b": "1"})
	buf = e.expect(e.do("GET", "/matches/z.json", ""), 200, "GET z").body
	e.theirs("matches", "z", replace("/b", "theirs"))
	c.add(25 * time.Hour)
	e.expect(e.do("PROPFIND", "/", "", "Depth", "0"), 207, "a request after a day (sweeps)")
	c.add(2 * time.Minute)
	hz, _ := e.load("matches", "z")
	e.expect(e.do("PUT", "/matches/z.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT z after the sweep")
	e.expectLive("matches", "z", hz, "z after the refusal")
}

// On any MOVE, the client's If-Match (its first value, W/ dropped), or
// an If header's entity tag, names the source, and one that isn't its
// head is 412 before anything is written (§H.5, GW-1): a rename in the
// flat view or in a tree, a move to another folder, onto an existing
// file, to another namespace, over a scratch file; a folder's names its
// node's head (F-H1); If-Match: * asks that the source exist. It is
// never the target's base.
func TestV073MoveSourceIfMatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"matches", "other"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}})
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
	e.create("cat", "empty", map[string]any{"title": "Empty", "parents": parents("cat", "root")})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
	q := func(rev string) string { return `"` + rev + `"` }
	stale := func(ns, name string) (string, *client.Head) {
		t.Helper()
		old := must(e.c.Head(e.ctx, ns, name)).ID
		e.theirs(ns, name, map[string]any{"op": "add", "path": "/theirs", "value": 1})
		h, _ := e.load(ns, name)
		return old, h
	}
	notMade := func(ns, name string) {
		t.Helper()
		if h, _ := e.load(ns, name); h.State != client.NotFound {
			t.Fatalf("%s/%s made by a refused MOVE: %v", ns, name, h.State)
		}
	}

	e.create("matches", "x", map[string]any{"a": "1"})
	old, h := stale("matches", "x")
	e.create("matches", "onto", map[string]any{"a": "onto"})
	ho, _ := e.load("matches", "onto")
	e.expect(e.do("PUT", "/matches/.x.swp", "swap"), 201, "a scratch file")
	for _, c := range []struct{ what, dst string }{
		{"a rename", "/matches/x2.json"},
		{"onto an existing file", "/matches/onto.json"},
		{"to another namespace", "/other/x.json"},
		{"over a scratch file", "/matches/.x.swp"},
	} {
		for _, hdr := range [][]string{{"If-Match", q(old)}, {"If-Match", "W/" + q(old)}, {"If", "([" + q(old) + "])"}, {"If-Match", q(old) + ", " + q(h.ID)}} {
			e.expect(e.do("MOVE", "/matches/x.json", "", append([]string{"Destination", c.dst}, hdr...)...), 412, "MOVE "+c.what+", "+hdr[0]+": "+hdr[1])
		}
	}
	e.expectLive("matches", "x", h, "x after refused moves")
	e.expectLive("matches", "onto", ho, "onto after refused moves")
	notMade("matches", "x2")
	notMade("other", "x")
	if g := e.expect(e.do("GET", "/matches/.x.swp", ""), 200, "GET the scratch file"); g.body != "swap" {
		t.Fatalf("the scratch file %q", g.body)
	}
	e.expect(e.do("MOVE", "/matches/nothing.json", "", "Destination", "/matches/n2.json", "If-Match", "*"), 412, "MOVE If-Match: * of nothing")
	e.expect(e.do("MOVE", "/matches/x.json", "", "Destination", "/matches/onto.json", "If-Match", "W/"+q(h.ID)), 204, "MOVE onto a file, W/ the head")
	e.expectTombstoned("matches", "x", "x")
	_, doc := e.load("matches", "onto")
	sameJSON(t, doc, map[string]any{"a": "1", "theirs": 1})
	e.expect(e.do("MOVE", "/matches/onto.json", "", "Destination", "/matches/y.json", "If-Match", "*"), 201, "MOVE If-Match: *")

	// In a tree: the item's head for a file, the node's for a folder.
	old, h = stale("matches", "derby")
	hn, _ := e.load("cat", "matches.derby")
	for _, dst := range []string{"/cat/Season/renamed.json", "/cat/Empty/derby.json", "/other/derby.json"} {
		e.expect(e.do("MOVE", "/cat/Season/derby.json", "", "Destination", dst, "If-Match", q(old)), 412, "tree MOVE to "+dst)
	}
	e.expectLive("cat", "matches.derby", hn, "the placement after refused moves")
	e.expectLive("matches", "derby", h, "the item after refused moves")
	notMade("other", "derby")
	e.expect(e.do("MOVE", "/cat/Season/derby.json", "", "Destination", "/cat/Empty/derby.json", "If-Match", q(h.ID)), 201, "tree MOVE, the head")
	folder := must(e.c.Head(e.ctx, "cat", "empty")).ID
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Full", "If-Match", q(hn.ID)), 412, "folder MOVE naming another revision")
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Full", "If-Match", q(folder)), 201, "folder MOVE naming its node's head")
	if e.nodeDoc("cat", "empty")["title"] != "Full" {
		t.Fatalf("folder %v", e.nodeDoc("cat", "empty"))
	}
}

// Where the gateway serves a writer its own uploaded bytes, which the
// revision holds exactly though its rendering differs, GET, HEAD and
// PROPFIND carry W/"{id}"; everyone else reads the rendering under
// "{id}"; the PUT's answer stays strong, and the weak tag works in any
// If-Match, a GET's included, and as a save's base (§H.1 "Writer's
// bytes", GW-2).
func TestV073WriterBytesWeakETag(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	o := e.another()
	upload := `{"b": 1,   "a": 2}`
	r := e.expect(e.do("PUT", "/docs/w.json", upload), 201, "PUT")
	h, _ := e.load("docs", "w")
	strong, weak := `"`+h.ID+`"`, `W/"`+h.ID+`"`
	if r.header.Get("ETag") != strong {
		t.Fatalf("PUT ETag %q, want %s", r.header.Get("ETag"), strong)
	}
	if g := e.expect(e.do("GET", "/docs/w.json", ""), 200, "the writer's GET"); g.body != upload || g.header.Get("ETag") != weak {
		t.Fatalf("the writer's GET: %q under %q", g.body, g.header.Get("ETag"))
	}
	if g := e.expect(e.do("HEAD", "/docs/w.json", ""), 200, "the writer's HEAD"); g.header.Get("ETag") != weak {
		t.Fatalf("the writer's HEAD: %q", g.header.Get("ETag"))
	}
	if l := e.propfind("/docs/"); l["/docs/w.json"].etag != weak {
		t.Fatalf("the writer's listing: %+v", l["/docs/w.json"])
	}
	if l := e.propfind("/docs/w.json", "0"); l["/docs/w.json"].etag != weak {
		t.Fatalf("the writer's PROPFIND: %+v", l["/docs/w.json"])
	}
	if g := o.expect(o.do("GET", "/docs/w.json", ""), 200, "another user's GET"); g.body != rendered(map[string]any{"a": 2, "b": 1}) || g.header.Get("ETag") != strong {
		t.Fatalf("another user's GET: %q under %q", g.body, g.header.Get("ETag"))
	}
	if l := o.propfind("/docs/"); l["/docs/w.json"].etag != strong {
		t.Fatalf("another user's listing: %+v", l["/docs/w.json"])
	}
	for _, tag := range []string{strong, weak} {
		e.expect(e.do("GET", "/docs/w.json", "", "If-None-Match", tag), 304, "the writer's GET If-None-Match "+tag)
		e.expect(e.do("GET", "/docs/w.json", "", "If-Match", tag), 200, "the writer's GET If-Match "+tag)
		o.expect(o.do("GET", "/docs/w.json", "", "If-Match", tag), 200, "another user's GET If-Match "+tag)
		e.expect(e.do("HEAD", "/docs/w.json", "", "If-Match", tag), 200, "the writer's HEAD If-Match "+tag)
	}
	e.expect(e.do("GET", "/docs/w.json", "", "If-Match", `"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), 412, "GET If-Match another revision")
	e.theirs("docs", "w", map[string]any{"op": "add", "path": "/c", "value": 3})
	e.expect(e.do("PUT", "/docs/w.json", `{"b": 1, "a": 5}`, "If-Match", weak), 201, "PUT with the weak tag as its base")
	_, doc := e.load("docs", "w")
	sameJSON(t, doc, map[string]any{"a": 5, "b": 1, "c": 3})
}

// The user's own DELETE forgets the path (§H.4 "Records"), also once
// its records expired (GW-24), and once the idle user's records are
// retired past the sweep: a new file over that delete, JSON or raw, is
// made anew a day later, and saved again after that, where the lost
// marks would have refused it as a save over someone else's delete (and
// refused every save after it from a mount, which never reads a name its
// listing lacks), or refused the save after it. A file someone else
// deleted after the user read it is still refused.
func TestV073OwnDeleteAfterRetire(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })
	o := e.another()
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "1"}`), 201, "PUT x.json")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "the user's own DELETE of x.json")
	e.expect(e.do("PUT", "/docs/r.txt", "one"), 201, "PUT r.txt")
	e.expect(e.do("DELETE", "/docs/r.txt", ""), 204, "the user's own DELETE of r.txt")
	e.expect(e.do("PUT", "/docs/w.json", `{"a": "1"}`), 201, "PUT w.json")
	e.expect(e.do("DELETE", "/docs/w.json", ""), 204, "the user's own DELETE of w.json")
	e.create("docs", "z", map[string]any{"a": "1"})
	e.expect(e.do("GET", "/docs/z.json", ""), 200, "GET z.json")
	o.expect(o.do("DELETE", "/docs/z.json", ""), 204, "someone else's DELETE of z.json")

	// Expired, the user still active: not swept.
	c.add(20 * time.Hour)
	e.create("docs", "a", map[string]any{"a": "1"})
	e.expect(e.do("GET", "/docs/a.json", ""), 200, "the user reads another file")
	c.add(5 * time.Hour)
	e.expect(e.do("PUT", "/docs/w.json", `{"a": "new"}`), 201, "PUT a new w.json over the user's own delete, a day later")
	e.expect(e.do("PUT", "/docs/w.json", `{"a": "newer"}`), 201, "PUT w.json again")
	_, doc := e.load("docs", "w")
	sameJSON(t, doc, map[string]any{"a": "newer"})

	// Retired.
	c.add(25 * time.Hour)
	e.expect(e.do("PROPFIND", "/", "", "Depth", "0"), 207, "a request after a day (sweeps)")
	c.add(2 * time.Minute)
	e.expectTombstoned("docs", "x", "x before the new file")
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "new"}`), 201, "PUT a new x.json over the user's own delete, after the sweep")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "new"})
	e.expect(e.do("PUT", "/docs/r.txt", "new"), 201, "PUT a new r.txt over the user's own delete, after the sweep")
	c.add(time.Minute)
	e.expect(e.do("PUT", "/docs/r.txt", "newer"), 201, "PUT r.txt again, without a GET")
	if _, data := e.rawOf("docs", "r.txt"); string(data) != "newer" {
		t.Fatalf("r.txt reads %q", data)
	}
	e.expect(e.do("PUT", "/docs/z.json", `{"a": "mine"}`), 409, "PUT z.json over someone else's delete, after the sweep")
	e.expectTombstoned("docs", "z", "z after the refusal")
}

// A save from a version the user had (records, or If-Match) of a file
// someone else then moved away is 409 naming the new path, the first
// refusal too, not one for someone else's delete asking for a reload
// after which a save would make it anew: no save does (§H.4 "Answers",
// "The reload", GW-23); the refusals after it, with or without that
// reload, name it as well.
func TestV073MovedAwayFromRecords(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "other"}, nil, nil)
	o := e.another()
	refused := func(r resp, to string) {
		t.Helper()
		if !strings.Contains(r.body, to) || strings.Contains(r.body, "deleted by someone else") {
			t.Fatalf("409 naming %s: %q", to, r.body)
		}
	}
	e.create("docs", "x", map[string]any{"a": "1"})
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET x.json")
	o.expect(o.do("MOVE", "/docs/x.json", "", "Destination", "/docs/y.json"), 201, "someone else's MOVE")
	refused(e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`), 409, "PUT the version read"), "/docs/y.json")
	refused(e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`), 409, "PUT again, without a GET"), "/docs/y.json")
	e.expect(e.do("GET", "/docs/x.json", ""), 404, "the reload")
	refused(e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`), 409, "PUT after the reload"), "/docs/y.json")
	e.expectTombstoned("docs", "x", "x")

	e.rawDoc("docs", "n.md", "text/markdown", []byte("one"), nil)
	e.expect(e.do("GET", "/docs/n.md", ""), 200, "GET n.md")
	o.expect(o.do("MOVE", "/docs/n.md", "", "Destination", "/docs/m.md"), 201, "someone else's MOVE of a raw file")
	refused(e.expect(e.do("PUT", "/docs/n.md", "mine"), 409, "PUT the raw file read"), "/docs/m.md")
	e.expectTombstoned("docs", "n.md", "n.md")

	old := e.create("docs", "far", map[string]any{"a": "1"})
	o.expect(o.do("MOVE", "/docs/far.json", "", "Destination", "/other/far.json"), 201, "someone else's MOVE to another namespace")
	refused(e.expect(e.do("PUT", "/docs/far.json", `{"a": "mine"}`, "If-Match", `"`+old+`"`), 409, "PUT naming the version moved"), "/r/other/far")
	e.expectTombstoned("docs", "far", "far")
}
