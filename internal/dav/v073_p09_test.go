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
// a move onto the old name (§H.2 "Flat view", §H.4 "The reload", GW-23).
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

	e.create("docs", "z", map[string]any{"a": "z"})
	refused(e.expect(e.do("MOVE", "/docs/z.json", "", "Destination", "/docs/x.json"), 409, "MOVE onto the old name"), "/docs/y.json")
	e.create("other", "q", map[string]any{"a": "q"})
	refused(e.expect(e.do("MOVE", "/other/q.json", "", "Destination", "/docs/x.json"), 409, "MOVE from another namespace onto the old name"), "/docs/y.json")
	e.expectTombstoned("docs", "x", "x")
	if h, _ := e.load("docs", "z"); h.State != client.Live {
		t.Fatalf("z %v", h.State)
	}
	if h, _ := e.load("other", "q"); h.State != client.Live {
		t.Fatalf("q %v", h.State)
	}
}
