package dav_test

import (
	"context"
	"fmt"
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
// records and guards are shared. Scratch files and locks, which may hold
// what one token read, are shared by the tokens the issuer minted, not
// with one attenuated offline (a via: a delegate), which may read less.
// Another sub is another user, for whom that delete is someone else's.
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

	// Scratch files and locks are the user's, for the tokens the issuer
	// minted; a token attenuated offline has its own.
	e.expect(e.doAs(a1, "PUT", "/docs/.notes.swp", "alice's swap"), 201, "alice's swap file")
	if r := e.expect(e.doAs(a2, "GET", "/docs/.notes.swp", ""), 200, "by another token of alice's"); r.body != "alice's swap" {
		t.Fatalf("alice's swap file %q", r.body)
	}
	e.expect(e.doAs(a3, "GET", "/docs/.notes.swp", ""), 404, "by a token of alice's attenuated offline")
	e.expect(e.doAs(bob, "GET", "/docs/.notes.swp", ""), 404, "bob's GET of alice's swap file")
	lock := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`
	r := e.expect(e.doAs(a1, "LOCK", "/docs/y.json", lock, "Depth", "0"), 200, "alice's LOCK")
	e.expect(e.doAs(bob, "UNLOCK", "/docs/y.json", "", "Lock-Token", r.header.Get("Lock-Token")), 409, "bob's UNLOCK of alice's lock")
	e.expect(e.doAs(a3, "UNLOCK", "/docs/y.json", "", "Lock-Token", r.header.Get("Lock-Token")), 409, "UNLOCK by a token of alice's attenuated offline")
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
	if r := e.expect(e.doAs(a2, "GET", "/docs/.swp", ""), 200, "alice's other token"); r.body != "alice" {
		t.Fatalf("alice's scratch file %q", r.body)
	}
	// a1n, attenuated offline, is alice too, with scratch files of its
	// own (scope).
	e.expect(e.doAs(a1n, "GET", "/docs/.swp", ""), 404, "alice's token attenuated offline")

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

// A scratch file is reached only by a token whose grant names its
// namespace (§C.2): one of the user's tokens that doesn't name it,
// whether the issuer minted it so (the same scope as the user's others)
// or it was attenuated offline, neither keeps one there nor reads or
// moves out one another token kept, which may hold the text of a
// document the core refuses it (an editor's swap file).
func TestGatewayScratchNamedNS(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.Namespaces = []string{"docs", "priv"} })
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "priv")))
	must(op.CreateNamespace(e.ctx, "priv", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	now := e.s.Now()
	writer := []string{"read", "create", "append"}
	full := k.Grant(t, now, "user:alice", []string{"docs", "priv"}, writer)
	docsOnly := k.Grant(t, now.Add(time.Second), "user:alice", []string{"docs"}, writer)
	attenuated := narrowed(t, full, map[string]any{"ns": []any{"docs"}, "via": "svc:helper"})
	e.expect(e.doAs(full, "PUT", "/priv/.plan.md.swp", "private draft"), 201, "alice's swap file in priv")
	e.expect(e.doAs(docsOnly, "PUT", "/docs/.notes.swp", "notes"), 201, "a swap file in docs through the token for docs")
	for _, c := range []struct{ what, tok string }{{"minted for docs only", docsOnly}, {"attenuated to docs", attenuated}} {
		e.expect(e.doAs(c.tok, "PUT", "/priv/.x.swp", "x"), 403, c.what+": PUT of a scratch file in priv")
		if r := e.doAs(c.tok, "GET", "/priv/.plan.md.swp", ""); r.status == 200 {
			t.Fatalf("%s: read alice's swap file in priv: %q", c.what, r.body)
		}
		if r := e.doAs(c.tok, "MOVE", "/priv/.plan.md.swp", "", "Destination", "/docs/.plan.md.swp"); r.status < 300 {
			t.Fatalf("%s: moved alice's swap file out of priv: %d", c.what, r.status)
		}
	}
	if r := e.expect(e.doAs(full, "GET", "/priv/.plan.md.swp", ""), 200, "the token that kept it"); r.body != "private draft" {
		t.Fatalf("alice's swap file %q", r.body)
	}
	if r := e.expect(e.doAs(full, "GET", "/docs/.notes.swp", ""), 200, "a swap file in docs, by another token of alice's"); r.body != "notes" {
		t.Fatalf("alice's swap file in docs %q", r.body)
	}
}

// A document moved aside to a backup name (§H.5, vim's x~) is copied into
// scratch whole; a token of the user's attenuated offline to read less
// (rules, can, a via) has scratch files of its own (scope), so it isn't
// served that copy, which the core would refuse it, while the user's
// token that moved it is.
func TestGatewayNarrowedScratch(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	now := e.s.Now()
	alice := k.Grant(t, now, "user:alice", []string{"docs"}, []string{"read", "create", "append", "restore", "delete"})
	helper := narrowed(t, alice, map[string]any{"via": "svc:helper", "can": []any{"read"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "public"}}})
	e.create("docs", "secret", map[string]any{"salary": 123456})
	e.create("docs", "public", map[string]any{"v": 1})
	if r := e.doAs(helper, "GET", "/docs/secret.json", ""); r.status == 200 {
		t.Fatalf("the narrowed token read secret.json: %q", r.body)
	}
	e.expect(e.doAs(helper, "GET", "/docs/public.json", ""), 200, "the narrowed token's GET of public.json")
	e.expect(e.doAs(alice, "MOVE", "/docs/secret.json", "", "Destination", "/docs/secret.json~"), 201, "alice's backup move")
	if r := e.doAs(helper, "GET", "/docs/secret.json~", ""); r.status == 200 {
		t.Fatalf("the narrowed token read secret's backup copy: %q", r.body)
	}
	if r := e.expect(e.doAs(alice, "GET", "/docs/secret.json~", ""), 200, "alice's GET of the backup"); !strings.Contains(r.body, "123456") {
		t.Fatalf("alice's backup %q", r.body)
	}
}

// The namespace that verifies a grant is part of its user (§H.7, kids
// are per namespace), and stays the same for one person: a namespace
// created later, or given the key later, that sorts first, makes neither
// the token verified again nor the person's next one someone else, with
// none of their records or scratch files, whose save without If-Match
// would then take the head as its base and revert another's edit
// (§H.4). A token verified again as someone else, the namespace that
// accepted it refusing it now, has its saves without a base refused until
// it reloads.
func TestGatewayStableUser(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	later := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.Namespaces = []string{"alpha", "docs"}
		o.Now, o.VerifyEvery = clock, time.Minute
	})
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET").body
	e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "swap"), 201, "alice's swap file")
	h, _ := e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))

	// alpha is created, the issuer's key listed there too; the token's
	// next check comes due, and alice logs in with a token minted again.
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	later(2 * time.Minute)
	again := k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"alpha", "docs"}, writer)
	for _, tok := range []string{alice, again} {
		if r := e.expect(e.doAs(tok, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file once alpha exists"); r.body != "swap" {
			t.Fatalf("alice's swap file %q", r.body)
		}
	}
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "alice's save, no If-Match")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 2, "w": 2})

	// A token verified first by alpha, which drops the key that docs
	// still lists: verified again by docs, it is another user, whose
	// records hold nothing of what it read; its save from before is
	// refused, not rebased on the head.
	e, k = authEnv(t, true, func(o *dav.Options) {
		o.Namespaces = []string{"alpha", "docs"}
		o.Now, o.VerifyEvery = clock, time.Minute
	})
	op = e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	alice = k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf = e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha").body
	h, _ = e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))
	ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
	nh := must(ac.NSHead(e.ctx, "alpha"))
	must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
	later(2 * time.Minute)
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "alice's save, verified again as another user")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 1, "w": 2})
	e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "the reload")
}

// A grant an operator key signed (§C.4) authorizes nothing a gateway
// does: refused (401), though GET /ns/{ns}/principal accepts it, and
// never taken for the user of a namespace key that carries its kid, whose
// scratch files it would read.
func TestGatewayOperatorGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	// docs' own key carries the kid of the deployment's operator key
	// ("operator" in clienttest).
	k := clienttest.NewKey("operator")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, dav: hs}

	alice := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	e.expect(e.doAs(alice, "PUT", "/docs/.notes.md.swp", "alice's unsaved draft"), 201, "alice's swap file")
	opAlice := clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "user:alice", "ns": []any{"docs"},
		"can": []any{"read"}, "exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
	if _, err := s.Client(t, client.WithBearer(opAlice)).NSPrincipal(ctx, "docs"); err != nil {
		t.Fatalf("/principal refused the operator grant: %v", err)
	}
	for _, req := range []struct{ method, path string }{{"GET", "/docs/.notes.md.swp"}, {"PROPFIND", "/docs/"}} {
		r := e.expect(e.doAs(opAlice, req.method, req.path, "", "Depth", "1"), 401, "the operator grant's "+req.method)
		if !strings.Contains(r.body, "operator key") {
			t.Fatalf("401 %q", r.body)
		}
	}
	if r := e.expect(e.doAs(alice, "GET", "/docs/.notes.md.swp", ""), 200, "alice's own GET"); r.body != "alice's unsaved draft" {
		t.Fatalf("alice's swap file %q", r.body)
	}
}

// What each token read of a catalog (its graph, its folders as a tree
// service listed them) is kept for it alone (§H.7), so it is bounded over
// every token by CacheBytes, the least recently used going first, not
// per token: a gateway keeps up to MaxPrincipals times
// MaxTokensPerPrincipal tokens, and a graph holds every node.
func TestGatewayViewsBounded(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	const bound = 16 << 10
	for _, treeURL := range []string{"", a.tr.http.URL} {
		srv := must(dav.New(dav.Options{Client: a.s.Client(t), Catalogs: []string{"cat"}, Gateway: true, TreeService: treeURL,
			CacheBytes: bound, CatalogTTL: time.Minute, Logf: t.Logf}))
		g := &env{t: t, ctx: a.ctx, s: a.s, c: a.w, dav: newTestServer(t, srv)}
		for i := 0; i < 40; i++ {
			tok := a.k.Grant(t, a.s.Now(), fmt.Sprintf("user:u%d", i), a.both, []string{"read"})
			sameStrings(t, "the top level", names(g.propfindAs(tok, "/cat/"), "/cat/"), []string{"Hidden/", "Season/"})
			sameStrings(t, "Season", names(g.propfindAs(tok, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
		}
		n, b := dav.Views(srv)
		if b > bound || n == 0 || n >= 40 {
			t.Fatalf("tree service %q: %d views kept, costing %d, over 40 tokens (bound %d)", treeURL, n, b, bound)
		}
	}
}
