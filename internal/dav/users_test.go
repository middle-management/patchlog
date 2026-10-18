package dav_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/grant"
)

// narrowed is tok attenuated offline with a narrowing block (Addendum C):
// another token, of the same root.
func narrowed(t *testing.T, tok string, block map[string]any) string {
	t.Helper()
	g := must(grant.Decode(tok, 64<<10))
	return must(g.Narrow(block)).Encode()
}

// Users (§H.7): a gateway keeps state per user, the root sub and kid GET
// /ns/{ns}/principal names, never per token. So one person's tokens,
// minted again or attenuated offline, are one user: a save by one within
// 30 s of another's DELETE restores the file (§H.6), rebased on what the
// saver read, rather than being a 409 over "someone else's" delete; and
// records, guards, scratch files and locks are shared. Another sub is
// another user, for whom that delete is someone else's.
func TestGatewayUserTokens(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	now := e.s.Now()
	writer := []string{"read", "create", "append", "restore", "delete"}
	a1 := k.Grant(t, now, "user:alice", []string{"docs"}, writer)
	a2 := k.Grant(t, now.Add(time.Second), "user:alice", []string{"docs"}, writer)
	a3 := narrowed(t, a1, map[string]any{"via": "laptop", "exp": now.Add(30 * time.Minute).Format(time.RFC3339)})
	bob := k.Grant(t, now, "user:bob", []string{"docs"}, writer)

	for _, c := range []struct{ name, what, reader, deleter string }{
		{"x", "minted again", a2, a1},
		{"y", "attenuated", a3, a1},
		{"z", "attenuated, the other way", a1, a3},
	} {
		e.create("docs", c.name, map[string]any{"v": 1, "w": 1})
		buf := e.expect(e.doAs(c.reader, "GET", "/docs/"+c.name+".json", ""), 200, c.what+": GET").body
		e.expect(e.doAs(c.deleter, "DELETE", "/docs/"+c.name+".json", ""), 204, c.what+": DELETE by another token of the user")
		e.expect(e.doAs(c.reader, "PUT", "/docs/"+c.name+".json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, c.what+": PUT within 30 s")
		h, doc := e.load("docs", c.name)
		if h.State != client.Live {
			t.Fatalf("%s: %s is %v", c.what, c.name, h.State)
		}
		sameJSON(t, doc, map[string]any{"v": 2, "w": 1})
		// A restore rebased on the last live document: the edit alone,
		// not a new file's root replace.
		if p := patchPaths(t, e.lastEntry("docs", c.name).Patches); strings.Join(p, " ") != "/v" {
			t.Fatalf("%s: the restore writes %q", c.what, p)
		}
	}

	// A refused save's guard holds for every token of the user: the
	// cleanup DELETE of another is refused (§H.6).
	h, _ := e.load("docs", "x")
	e.expect(e.doAs(a1, "PUT", "/docs/x.json", `{"v": `), 400, "a refused save")
	e.expect(e.doAs(a3, "DELETE", "/docs/x.json", ""), 409, "a DELETE by another token of the user, guarded")
	e.expectLive("docs", "x", h, "after the guarded DELETE")
	// Not for another user's.
	e.expect(e.doAs(a1, "PUT", "/docs/x.json", `{"v": `), 400, "a refused save")
	e.expect(e.doAs(bob, "DELETE", "/docs/x.json", ""), 204, "bob's DELETE, not guarded by alice's refusal")

	// Another sub: alice's delete is someone else's for bob, whose save
	// from before it is a 409.
	e.create("docs", "b", map[string]any{"v": 1})
	e.expect(e.doAs(bob, "GET", "/docs/b.json", ""), 200, "bob's GET")
	e.expect(e.doAs(a2, "DELETE", "/docs/b.json", ""), 204, "alice's DELETE")
	e.expect(e.doAs(bob, "PUT", "/docs/b.json", `{"v": 2}`), 409, "bob's save over alice's delete")

	// Scratch files and locks are the user's.
	e.expect(e.doAs(a1, "PUT", "/docs/.notes.swp", "alice's swap"), 201, "alice's swap file")
	if r := e.expect(e.doAs(a3, "GET", "/docs/.notes.swp", ""), 200, "by another token of alice's"); r.body != "alice's swap" {
		t.Fatalf("alice's swap file %q", r.body)
	}
	e.expect(e.doAs(bob, "GET", "/docs/.notes.swp", ""), 404, "bob's GET of alice's swap file")
	lock := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`
	r := e.expect(e.doAs(a1, "LOCK", "/docs/y.json", lock, "Depth", "0"), 200, "alice's LOCK")
	e.expect(e.doAs(bob, "UNLOCK", "/docs/y.json", "", "Lock-Token", r.header.Get("Lock-Token")), 409, "bob's UNLOCK of alice's lock")
	e.expect(e.doAs(a2, "UNLOCK", "/docs/y.json", "", "Lock-Token", r.header.Get("Lock-Token")), 204, "UNLOCK by another token of alice's")
}

// A grant revoked (§C.4) is refused at its next check, VerifyEvery after
// the one before (§H.7), or at its next request after the core refused it
// in between; that refusal has its user's other tokens asked again at
// their next request. Those the core still accepts keep the user's state:
// one token's revocation doesn't wipe what the person has.
func TestGatewayRevokedToken(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, []string{"read", "create", "append", "config"})))
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf, Now: clock, VerifyEvery: time.Minute}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, c: admin, dav: hs}
	var revoked []any
	revoke := func(tok string) {
		t.Helper()
		revoked = append(revoked, must(grant.Decode(tok, 64<<10)).RevocationIDs()[0])
		h := must(admin.NSHead(ctx, "docs"))
		must(admin.PatchConfig(ctx, "docs", h.Config, []any{map[string]any{"op": "add", "path": "/revoked", "value": revoked}}))
	}
	read := []string{"read"}
	a1 := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, read)
	a1n := narrowed(t, a1, map[string]any{"via": "phone"})
	a2 := k.Grant(t, s.Now().Add(time.Second), "user:alice", []string{"docs"}, read)
	e.expect(e.doAs(a1, "PUT", "/docs/.swp", "alice"), 201, "alice's scratch file")
	for _, tok := range []string{a1n, a2} {
		if r := e.expect(e.doAs(tok, "GET", "/docs/.swp", ""), 200, "alice's other tokens"); r.body != "alice" {
			t.Fatalf("alice's scratch file %q", r.body)
		}
	}

	// a1's root block revoked: the core refuses a1n's next read, and the
	// gateway a1n's next request; then alice's other tokens are asked
	// again before VerifyEvery is over: a1, of the same root, is refused,
	// a2 isn't, and finds alice's scratch file.
	revoke(a1)
	e.expect(e.doAs(a1n, "PROPFIND", "/docs/", "", "Depth", "1"), 401, "a1n's read, revoked")
	e.expect(e.doAs(a1n, "GET", "/docs/.swp", ""), 401, "a1n's next request")
	e.expect(e.doAs(a1, "GET", "/docs/.swp", ""), 401, "a1, asked again")
	if r := e.expect(e.doAs(a2, "GET", "/docs/.swp", ""), 200, "a2, asked again"); r.body != "alice" {
		t.Fatalf("alice's scratch file after a1's revocation %q", r.body)
	}

	// Revoked without a read in between: refused at its check, VerifyEvery
	// after the last.
	a3 := k.Grant(t, s.Now().Add(2*time.Second), "user:alice", []string{"docs"}, read)
	e.expect(e.doAs(a3, "GET", "/docs/.swp", ""), 200, "a3")
	revoke(a3)
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	e.expect(e.doAs(a3, "GET", "/docs/.swp", ""), 401, "a3 at its next check")
	if r := e.expect(e.doAs(a2, "GET", "/docs/.swp", ""), 200, "a2 at its next check"); r.body != "alice" {
		t.Fatalf("alice's scratch file after a3's revocation %q", r.body)
	}
}

// A grant limited to some resources (rules on /resource) can't read the
// namespace document, but learns what a writer needs from GET
// /ns/{ns}/principal (§7.4, §H.7 "Limited grants"): the gateway accepts
// it, its writes carry a fresh $nonce where the namespace requires one
// and none where it doesn't, and a limit the namespace sets refuses a
// file before anything is uploaded.
func TestGatewayLimitedGrant(t *testing.T) {
	t.Parallel()
	var uploads atomic.Int32
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" && strings.Contains(r.URL.Path, "/blob/") {
				uploads.Add(1)
			}
			h.ServeHTTP(w, r)
		})
	}})
	k := clienttest.NewKey("k")
	for ns, extra := range map[string]map[string]any{
		"lim":  {"nonce": "required", "limits": map[string]any{"blobSize": 8}},
		"open": {},
	} {
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
		for k, v := range extra {
			doc[k] = v
		}
		op := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
		must(op.CreateNamespace(ctx, ns, doc))
	}
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"lim", "open"}, []string{"read"})))
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"lim", "open"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, c: admin, dav: hs}
	li := k.Grant(t, s.Now(), "user:li", []string{"lim", "open"}, []string{"read", "create", "append"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"x", "x.md"}}}}})
	lc := s.Client(t, client.WithBearer(li))
	if h, err := lc.NSHead(ctx, "lim"); err == nil {
		if _, err := lc.NSDoc(ctx, "lim", h.ID); err == nil {
			t.Fatal("the limited grant reads the namespace document")
		}
	}

	e.expect(e.doAs(li, "PUT", "/lim/x.json", `{"v": 1}`), 201, "a create where nonces are required")
	if _, doc := e.load("lim", "x"); doc.(map[string]any)["$nonce"] == nil {
		t.Fatalf("lim/x without a $nonce: %v", doc)
	}
	e.expect(e.doAs(li, "PUT", "/lim/x.json", `{"v": 2}`), 201, "an edit where nonces are required")
	if p := patchPaths(t, e.lastEntry("lim", "x").Patches); !strings.Contains(strings.Join(p, " "), "/$nonce") {
		t.Fatalf("lim/x's edit without a fresh $nonce: %q", p)
	}
	e.expect(e.doAs(li, "PUT", "/open/x.json", `{"v": 1}`), 201, "a create where they aren't")
	if _, doc := e.load("open", "x"); doc.(map[string]any)["$nonce"] != nil {
		t.Fatalf("open/x with a $nonce: %v", doc)
	}
	r := e.expect(e.doAs(li, "PUT", "/lim/x.md", "123456789"), 413, "a raw file over the namespace's blobSize")
	if !strings.HasPrefix(r.body, "too large: blobSize 9 > 8") || !strings.Contains(r.body, "nothing was uploaded") || uploads.Load() != 0 {
		t.Fatalf("413 %q after %d uploads", r.body, uploads.Load())
	}
	e.expect(e.doAs(li, "PUT", "/open/y.json", `{"v": 1}`), 403, "a resource the grant's rules don't allow")
}

// A grant the core verifies in no served namespace but a purged one is
// 410 there (§8.5, §H.4 "Answers"), and an operator grant for a namespace
// that doesn't exist is 404 (§7.4, §C.4): neither is "no usable grant"
// (401), nor is anything kept for them.
func TestGatewayVerifyAnswers(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.Namespaces = []string{"absent", "docs", "gone"} })
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "gone")))
	must(op.CreateNamespace(e.ctx, "gone", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	pc := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:ops", []string{"gone"}, []string{"read", "config", "purge-ns"})))
	must(pc.PatchConfig(e.ctx, "gone", must(pc.NSHead(e.ctx, "gone")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(pc.PurgeNamespace(e.ctx, "gone", must(pc.NSHead(e.ctx, "gone")).ID))

	gone := k.Grant(t, e.s.Now(), "user:alice", []string{"gone"}, []string{"read"})
	r := e.expect(e.doAs(gone, "PROPFIND", "/", "", "Depth", "1"), 410, "a grant for a purged namespace")
	if r.header.Get("WWW-Authenticate") != "" || !strings.Contains(r.body, "purged") {
		t.Fatalf("410 %v %q", r.header, r.body)
	}
	absent := e.s.OperatorGrant(t, "absent")
	r = e.expect(e.doAs(absent, "PROPFIND", "/", "", "Depth", "1"), 404, "an operator grant for a namespace that doesn't exist")
	if r.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("404 %v %q", r.header, r.body)
	}
	// A grant that also names a namespace that accepts it is that one's.
	both := k.Grant(t, e.s.Now(), "user:alice", []string{"docs", "gone"}, []string{"read"})
	e.expect(e.doAs(both, "PUT", "/docs/.swp", "x"), 201, "a grant docs accepts")
	e.expect(e.doAs(both, "PROPFIND", "/gone/", "", "Depth", "1"), 410, "its read of the purged namespace")
}

// Writers' settings come from GET /ns/{ns}/principal (§7.4), kept a short
// while (it is no-store): a write the core refuses over one that changed
// since (a nonce now required, §C.7) gets the core's answer, and the next
// write asks again, so it carries a fresh $nonce.
func TestWriterSettingsRefresh(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.expect(e.do("PUT", "/docs/x.json", `{"v": 1}`), 201, "PUT")
	if _, doc := e.load("docs", "x"); doc.(map[string]any)["$nonce"] != nil {
		t.Fatalf("x with a $nonce: %v", doc)
	}
	nh := must(e.c.NSHead(e.ctx, "docs"))
	must(e.c.PatchConfig(e.ctx, "docs", nh.Config, []any{map[string]any{"op": "add", "path": "/nonce", "value": "required"}}))
	r := e.expect(e.do("PUT", "/docs/x.json", `{"v": 2}`), 422, "PUT with the settings kept")
	if !strings.Contains(r.body, "nonce") {
		t.Fatalf("422 %q", r.body)
	}
	e.expect(e.do("PUT", "/docs/x.json", `{"v": 2}`), 201, "the next PUT, which asks again")
	if _, doc := e.load("docs", "x"); doc.(map[string]any)["$nonce"] == nil || doc.(map[string]any)["v"] != 2.0 {
		t.Fatalf("x after the nonce became required: %v", doc)
	}
}

// A gateway re-checks a grant at least as often as edge grants expire
// (§H.7, §C.5.2): VerifyEvery is at most their longest lifetime.
func TestVerifyEveryBound(t *testing.T) {
	t.Parallel()
	c := must(client.New("http://127.0.0.1:1"))
	if _, err := dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true, VerifyEvery: 16 * time.Minute}); err == nil {
		t.Fatal("VerifyEvery of 16 minutes taken")
	}
	must(dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true, VerifyEvery: 15 * time.Minute}))
	must(dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true}))
}
