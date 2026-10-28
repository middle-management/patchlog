package dav_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// TOOLS-7 (§H.7 "Users", §2.1, §7.7): the namespace log a token reads to
// judge the user's entries by the keys their kids named when written is
// the same for every grant that may read it, so a gateway reads it whole
// once, not again for each token: a second token reads the one entry the
// kept history names, showing it may read the log, and what came after.
func TestV074KeyHistorySharedAcrossTokens(t *testing.T) {
	t.Parallel()
	var whole atomic.Int64 // namespace log reads from its first entry
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/ns/docs/rev/") && strings.HasSuffix(r.URL.Path, "/log") && r.URL.Query().Get("since") == "" {
				whole.Add(1)
			}
			h.ServeHTTP(w, r)
		})
	}})
	k := clienttest.NewKey("k")
	writer := []string{"read", "create", "append", "restore", "delete"}
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, writer)))}
	srv, err := dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	e.dav = httptest.NewServer(srv)
	t.Cleanup(e.dav.Close)
	e.create("docs", "x", map[string]any{"v": 0, "w": 0})

	// Each user reads x, edits it elsewhere under the same grant, and
	// saves a change beside that edit: the save judges the edit theirs.
	save := func(sub string, v int) int64 {
		t.Helper()
		g := k.Grant(t, s.Now(), "user:"+sub, []string{"docs"}, writer)
		buf := e.expect(e.doAs(g, "GET", "/docs/x.json", ""), 200, sub+"'s GET").body
		h, _ := e.load("docs", "x")
		must(s.Client(t, client.WithBearer(g)).Append(ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/v", "value": v}}))
		before := whole.Load()
		var m map[string]any
		if err := json.Unmarshal([]byte(buf), &m); err != nil {
			t.Fatal(err)
		}
		m["w"] = sub
		r := e.doAs(g, "PUT", "/docs/x.json", string(must(json.Marshal(m))))
		if r.status/100 != 2 {
			t.Fatalf("%s's save: %d %s", sub, r.status, r.body)
		}
		_, doc := e.load("docs", "x")
		if m := doc.(map[string]any); m["v"] != float64(v) || m["w"] != sub {
			t.Fatalf("%s's save left %v", sub, m)
		}
		return whole.Load() - before
	}
	if n := save("sam", 1); n == 0 {
		t.Fatal("sam's save read no namespace log from its first entry")
	}
	if n := save("kim", 2); n != 0 {
		t.Fatalf("kim's save read the namespace log from its first entry %d times, after sam's token read it", n)
	}
}

// A token that may not read the namespace log (a grant limited to some
// resources, §2.1) doesn't take the key history another token read: its
// user's entries are judged as the kid names the key now, as before
// (§H.7 "Users"). As in TestV074OwnEntriesByKeyWhenWritten, sam-on-B
// under kid u saves over sam-on-A's edit: with the whole grant, after
// which the gateway keeps the history, that is 409; with one limited to
// x, the edit counts as sam's own, and the save writes over it.
func TestV074KeyHistoryNotSharedWithoutLogRead(t *testing.T) {
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
	bAsU := keyB
	bAsU.Kid = "u"
	setKeys(bAsU.Entry(writer...), keyB.Entry(writer...))
	save := strings.Replace(buf, `"v": 1`, `"v": 3`, 1)
	whole := bAsU.Grant(t, e.s.Now(), "user:sam", []string{"docs"}, writer)
	e.expect(e.doAs(whole, "PUT", "/docs/x.json", save), 409, "sam-on-B's save under kid u, with the whole grant")
	limited := bAsU.Grant(t, e.s.Now(), "user:sam", []string{"docs"}, writer, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"x"}}}}})
	r := e.doAs(limited, "PUT", "/docs/x.json", save)
	if r.status/100 != 2 {
		t.Fatalf("sam-on-B's save under kid u, limited to x: %d %s, want it judged by the key kid u names now", r.status, r.body)
	}
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 3, "w": 1})
}
