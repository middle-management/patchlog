package dav_test

import (
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
	e := newEnv(t, []string{"docs", "priv"}, map[string]map[string]any{"priv": {"nonce": "required"}})
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
	e := newEnv(t, []string{"docs", "other"}, nil)
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

// Where the gateway serves a writer its own uploaded bytes, which the
// revision holds exactly though its rendering differs, GET, HEAD and
// PROPFIND carry W/"{id}"; everyone else reads the rendering under
// "{id}"; the PUT's answer stays strong, and the weak tag works in any
// If-Match, a GET's included, and as a save's base (§H.1 "Writer's
// bytes", GW-2).
func TestV073WriterBytesWeakETag(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil)
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
	e := newEnv(t, []string{"docs"}, nil, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })
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
	e := newEnv(t, []string{"docs", "other"}, nil)
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

// An If-Match whose first value isn't an entity tag (unquoted, say)
// names no revision: the condition is false, 412 and nothing done, on a
// MOVE as on a PUT or a DELETE, never the request done as if it had no
// precondition (RFC 9110 §13.1.1; §H.4 "The base", §H.5, GW-1). Empty
// list elements are skipped (RFC 9110 §5.6.1).
func TestV073MalformedIfMatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil)
	old := e.create("docs", "x", map[string]any{"a": "1"})
	e.theirs("docs", "x", replace("/a", "2"))
	h, _ := e.load("docs", "x")
	for _, tag := range []string{old, h.ID, "W/" + h.ID, `"` + h.ID, `""`, ","} {
		e.expect(e.do("MOVE", "/docs/x.json", "", "Destination", "/docs/y.json", "If-Match", tag), 412, "MOVE If-Match: "+tag)
		e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`, "If-Match", tag), 412, "PUT If-Match: "+tag)
		e.expect(e.do("DELETE", "/docs/x.json", "", "If-Match", tag), 412, "DELETE If-Match: "+tag)
	}
	e.expectLive("docs", "x", h, "x after the refusals")
	if g, _ := e.load("docs", "y"); g.State != client.NotFound {
		t.Fatalf("y made by a refused MOVE: %v", g.State)
	}
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`, "If-Match", `, "`+h.ID+`"`), 201, "PUT If-Match: an empty element, then the head")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine"})
}
