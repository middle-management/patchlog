package dav_test

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// TOOLS-6 (§H.2, §H.4, §H.6, Open 130): the next save over a tombstoned
// file whose last revision has $successor is 409, naming the new path,
// with no exception where the gateway can't read that revision (served
// sealed): a successor the head names is named, and where none is known
// the save is 409 all the same, saying the last revision can't be read to
// find out where the file went. No new file is made over it.
func TestV074SealedMovedAway(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	srv := must(dav.New(e.opt))
	g := *e
	g.dav = newTestServer(t, srv)

	// Moved away by someone else; its last revision, with $successor, is
	// served sealed to g.
	e.create("docs", "x", map[string]any{"a": "1"})
	e.another().expect(e.another().do("MOVE", "/docs/x.json", "", "Destination", "/docs/y.json"), 201, "someone else's MOVE")
	h, _ := e.load("docs", "x")
	dav.ServeSealed(srv, "docs", "x", h.Last)
	r := g.expect(g.do("PUT", "/docs/x.json", `{"a": "mine"}`), 409, "PUT the old name of a file moved away, its last revision sealed")
	if h.Successor == "" || !strings.Contains(r.body, "/docs/y.json") {
		t.Fatalf("409 naming /docs/y.json: %q", r.body)
	}
	e.expectTombstoned("docs", "x", "x")

	// Deleted by someone else, its last revision sealed: whether it moved
	// can't be told, so no save makes it anew.
	id := e.create("docs", "z", map[string]any{"a": "1"})
	must(e.c.Delete(e.ctx, "docs", "z", id))
	h, _ = e.load("docs", "z")
	dav.ServeSealed(srv, "docs", "z", h.Last)
	r = g.expect(g.do("PUT", "/docs/z.json", `{"a": "mine"}`), 409, "PUT over a deleted file whose last revision is sealed")
	if !strings.Contains(r.body, "can't be read") {
		t.Fatalf("409 saying the last revision can't be read: %q", r.body)
	}
	e.expectTombstoned("docs", "z", "z")
}

// TOOLS-7 (§H.7 "Users", §C.4, Open 134): a user's own entries are those
// whose grant has its sub and a kid that named, when written, its key. sam
// on key B reads x; sam on key A, the same sub, edits it under kid u, A's
// then; the namespace then gives kid u to B. sam-on-B's save from before,
// under a grant of kid u, overlaps sam-on-A's edit: that edit is someone
// else's (kid u named A when it was written), so the save is 409, not a
// rebase that takes it for the user's own and writes over it.
func TestV074OwnEntriesByKeyWhenWritten(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	writer := []string{"read", "create", "append", "restore", "delete"}
	keyA := clienttest.NewKey("u")
	keyB := clienttest.NewKey("b")
	setKeys := func(keys ...map[string]any) {
		t.Helper()
		admin := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"docs"}, []string{"read", "config"})))
		all := []any{k.Entry("*")}
		for _, x := range keys {
			all = append(all, x)
		}
		must(admin.PatchConfig(e.ctx, "docs", must(admin.NSHead(e.ctx, "docs")).Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": all}}))
	}
	setKeys(keyA.Entry(writer...), keyB.Entry(writer...))
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	onB := keyB.Grant(t, e.s.Now(), "user:sam", []string{"docs"}, writer)
	buf := e.expect(e.doAs(onB, "GET", "/docs/x.json", ""), 200, "sam-on-B's GET").body
	onA := e.s.Client(t, client.WithBearer(keyA.Grant(t, e.s.Now(), "user:sam", []string{"docs"}, writer)))
	h, _ := e.load("docs", "x")
	must(onA.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/v", "value": 2}}))
	// Kid u now names B.
	bAsU := keyB
	bAsU.Kid = "u"
	setKeys(bAsU.Entry(writer...), keyB.Entry(writer...))
	onBu := bAsU.Grant(t, e.s.Now(), "user:sam", []string{"docs"}, writer)
	e.expect(e.doAs(onBu, "PROPFIND", "/docs/", "", "Depth", "1"), 207, "sam-on-B's listing under kid u")
	e.expect(e.doAs(onBu, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 3`, 1)), 409, "sam-on-B's save from before, over sam-on-A's edit")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 2, "w": 1})
}
