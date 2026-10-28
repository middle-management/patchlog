package dav_test

import (
	"strings"
	"testing"

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
