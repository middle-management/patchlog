package dav_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
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
// what one token read, are shared by the tokens the issuer minted with
// the same rights, not with one attenuated offline (a via: a delegate),
// which may read less.
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
	// minted with the same rights; a token attenuated offline has its own.
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
	// The token for docs reads its own; the full token, minted with other
	// rights (ns), keeps its own scratch files (scope).
	if r := e.expect(e.doAs(docsOnly, "GET", "/docs/.notes.swp", ""), 200, "a swap file in docs, by the token that kept it"); r.body != "notes" {
		t.Fatalf("alice's swap file in docs %q", r.body)
	}
	e.expect(e.doAs(full, "GET", "/docs/.notes.swp", ""), 404, "the docs token's swap file, by the token minted for docs and priv")
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

// A grant the issuer minted limited to some resources (rules on /resource
// in its root block, §C.5.1), for the same sub and kid, is the same user
// but has scratch files of its own (scope): it isn't served the backup
// copy a move aside made of a document the core refuses it. Minted again
// with the same rights (other times), a token shares the user's.
func TestGatewayIssuedLimitedScratch(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	now := e.s.Now()
	writer := []string{"read", "create", "append", "restore", "delete"}
	alice := k.Grant(t, now, "user:alice", []string{"docs"}, writer)
	again := k.Grant(t, now.Add(time.Minute), "user:alice", []string{"docs"}, writer)
	limited := k.Grant(t, now.Add(time.Second), "user:alice", []string{"docs"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "public"}}})
	e.create("docs", "secret", map[string]any{"salary": 123456})
	e.create("docs", "public", map[string]any{"v": 1})
	if r := e.doAs(limited, "GET", "/docs/secret.json", ""); r.status == 200 {
		t.Fatalf("the limited grant read secret.json: %q", r.body)
	}
	e.expect(e.doAs(limited, "GET", "/docs/public.json", ""), 200, "the limited grant's GET of public.json")
	e.expect(e.doAs(alice, "MOVE", "/docs/secret.json", "", "Destination", "/docs/secret.json~"), 201, "alice's backup move")
	if r := e.doAs(limited, "GET", "/docs/secret.json~", ""); r.status == 200 {
		t.Fatalf("the grant limited to public read secret's backup copy: %q", r.body)
	}
	if r := e.expect(e.doAs(again, "GET", "/docs/secret.json~", ""), 200, "the copy, by alice's token minted again"); !strings.Contains(r.body, "123456") {
		t.Fatalf("the copy %q", r.body)
	}
}

// kids are free-form and per namespace document (§C.1): bob's own key in
// zeta also has kid "k", and a grant of it for sub user:alice (zeta's key
// may mint any sub) logs in first. Neither takes the record of where
// alice's grants verify (kidNS, by kid and sub, a few namespaces kept):
// once alpha, which sorts first, is given her key, her token minted again
// is still the user docs verified, with her swap file, and her save
// without If-Match is rebased on what she read, not on the head.
func TestGatewayStableUserKidSub(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.Namespaces = []string{"alpha", "docs", "zeta"} })
	bobKey := clienttest.NewKey("k")
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "zeta")))
	must(op.CreateNamespace(e.ctx, "zeta", map[string]any{"read": "grant", "keys": []any{bobKey.Entry("*")}}))
	for _, sub := range []string{"user:bob", "user:alice"} {
		tok := bobKey.Grant(t, e.s.Now(), sub, []string{"zeta"}, []string{"read", "create", "append"})
		e.expect(e.doAs(tok, "PROPFIND", "/zeta/", "", "Depth", "1"), 207, "zeta's listing for "+sub+", before alice's")
	}
	writer := []string{"read", "create", "append", "restore", "delete"}
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET (verified by docs)").body
	e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "swap"), 201, "alice's swap file")
	h, _ := e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))
	op = e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	again := k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"alpha", "docs"}, writer)
	if r := e.expect(e.doAs(again, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file by her token minted again"); r.body != "swap" {
		t.Fatalf("alice's swap file %q", r.body)
	}
	e.expect(e.doAs(again, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "alice's save, no If-Match")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 2, "w": 2})
}

// A token dropped while idle (unused for VerifyEvery, sweep) and verified
// again as another user (alpha, which verified it, dropped the key) has
// the documents its old user had records of marked lost for the new one,
// as one still kept does (TestGatewayStableUser): who each token was
// verified as is kept past the token (idUsers), so its save from before
// is a 409, not a rebase on the head.
func TestGatewaySwitchAfterSweep(t *testing.T) {
	t.Parallel()
	clk := &testClock{t: time.Now()}
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.Namespaces = []string{"alpha", "docs"}
		o.Now, o.VerifyEvery = clk.now, time.Minute
	})
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	bob := k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha").body
	h, _ := e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))
	ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
	nh := must(ac.NSHead(e.ctx, "alpha"))
	must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
	clk.add(2 * time.Minute)
	e.expect(e.doAs(bob, "PROPFIND", "/docs/", "", "Depth", "1"), 207, "bob's listing, which sweeps alice's idle token")
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "alice's save from before, verified again as another user")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 1, "w": 2})
}

// A token verified again as another user must read every document its
// old user had records of before saving it without a base, those the new
// user has records of too: here alice's token for docs only, a user apart
// since alpha verified her full token first, read the head. The full
// token's save from before, verified again by docs as that user, is a
// 409, not a rebase from the version the other token read, and so is its
// save after the other token reads the file again: that read isn't the
// full token's reload. The docs-only token's own saves go through.
func TestGatewayLoseRecordsKnown(t *testing.T) {
	t.Parallel()
	clk := &testClock{t: time.Now()}
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.Namespaces = []string{"alpha", "docs"}
		o.Now, o.VerifyEvery = clk.now, time.Minute
	})
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	aliceDocs := k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha").body
	h, _ := e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))
	e.expect(e.doAs(aliceDocs, "GET", "/docs/x.json", ""), 200, "alice's docs-only token reads the head")
	ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
	nh := must(ac.NSHead(e.ctx, "alpha"))
	must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
	clk.add(2 * time.Minute)
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "the full token's save from before")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 1, "w": 2})
	// The docs-only token reads, and saves.
	docsBuf := e.expect(e.doAs(aliceDocs, "GET", "/docs/x.json", ""), 200, "the docs token's GET").body
	e.expect(e.doAs(aliceDocs, "PUT", "/docs/x.json", strings.Replace(docsBuf, `"v": 1`, `"v": 3`, 1)), 201, "the docs token's save from its GET")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 3, "w": 2})
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "the full token's save from before, after the docs token's reads")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 3, "w": 2})
	// The full token reloads, and saves.
	buf = e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "the full token's reload").body
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 3`, `"v": 4`, 1)), 201, "the full token's save after its reload")
	_, doc = e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 4, "w": 2})
}

// Narrowing is offline and free, so making room among a user's scopes
// (MaxTokensPerPrincipal) never drops one that keeps scratch files or
// locks, and narrowed tokens make room only among their own kind: eight
// narrowings of a delegate's token leave alice's swap file and lock
// alone; a ninth drops the least recently used narrowed scope that keeps
// nothing; once every narrowed scope keeps a file, another narrowing is
// a 503, and alice's files stay.
func TestGatewayScopeChurn(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append", "restore", "delete"})
	e.create("docs", "x", map[string]any{"v": 1})
	e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "unsaved edits"), 201, "alice's swap file")
	lock := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`
	lt := e.expect(e.doAs(alice, "LOCK", "/docs/x.json", lock, "Depth", "0"), 200, "alice's LOCK").header.Get("Lock-Token")
	helper := narrowed(t, alice, map[string]any{"via": "svc:helper"})
	var toks []string
	for i := 0; i < 9; i++ {
		tok := narrowed(t, helper, map[string]any{"via": fmt.Sprintf("svc:helper/%d", i)})
		toks = append(toks, tok)
		e.expect(e.doAs(tok, "GET", "/docs/x.json", ""), 200, "a further narrowing's GET")
	}
	if r := e.expect(e.doAs(alice, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file after 9 narrowings"); r.body != "unsaved edits" {
		t.Fatalf("alice's swap file %q", r.body)
	}
	// Each narrowed scope kept (the last 8) keeps a file.
	for i, tok := range toks[1:] {
		e.expect(e.doAs(tok, "PUT", fmt.Sprintf("/docs/.n%d.swp", i), "n"), 201, "a narrowing's swap file")
	}
	r := e.expect(e.doAs(narrowed(t, helper, map[string]any{"via": "svc:helper/new"}), "GET", "/docs/x.json", ""), 503, "another narrowing, every narrowed scope keeping a file")
	if r.header.Get("Retry-After") == "" {
		t.Fatalf("503 without Retry-After: %v", r.header)
	}
	e.expect(e.doAs(toks[1], "GET", "/docs/.n0.swp", ""), 200, "a narrowing's swap file, kept")
	if r := e.expect(e.doAs(alice, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file"); r.body != "unsaved edits" {
		t.Fatalf("alice's swap file %q", r.body)
	}
	e.expect(e.doAs(alice, "UNLOCK", "/docs/x.json", "", "Lock-Token", lt), 204, "alice's UNLOCK of her lock")
}

// Dead properties are bounded per user over the user's scopes (1 MiB),
// as scratch files and locks are, not per scope: four narrowings of one
// token, each setting 900 kB, keep at most 1 MiB in all.
func TestGatewayDeadPropsPerUser(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, []string{"read"})
	toks := []string{alice}
	for i := 0; i < 3; i++ {
		toks = append(toks, narrowed(t, alice, map[string]any{"via": fmt.Sprintf("dev%d", i)}))
	}
	value := strings.Repeat("v", 60000)
	for j, tok := range toks {
		e.create("docs", fmt.Sprintf("a%d", j), map[string]any{"v": j})
		for i := 0; i < 15; i++ {
			pp := fmt.Sprintf(`<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x"><D:set><D:prop><Z:p%d>%s</Z:p%d></D:prop></D:set></D:propertyupdate>`, i, value, i)
			e.expect(e.doAs(tok, "PROPPATCH", fmt.Sprintf("/docs/a%d.json", j), pp), 207, "PROPPATCH")
		}
	}
	total := 0
	for j, tok := range toks {
		for i := 0; i < 15; i++ {
			body := fmt.Sprintf(`<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:Z="urn:x"><D:prop><Z:p%d/></D:prop></D:propfind>`, i)
			if r := e.expect(e.doAs(tok, "PROPFIND", fmt.Sprintf("/docs/a%d.json", j), body, "Depth", "0"), 207, "PROPFIND"); strings.Contains(r.body, value) {
				total += len(value)
			}
		}
	}
	if total > 1<<20 || total == 0 {
		t.Fatalf("one user keeps %d bytes of dead properties over 4 narrowings of one token", total)
	}
	// The last token's own, set last, are kept.
	body := `<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:Z="urn:x"><D:prop><Z:p14/></D:prop></D:propfind>`
	if r := e.expect(e.doAs(toks[3], "PROPFIND", "/docs/a3.json", body, "Depth", "0"), 207, "PROPFIND"); !strings.Contains(r.body, value) {
		t.Fatalf("the last set property is gone")
	}
}

// opKeysFront is a core behind a proxy that rewrites the root document's
// jwks_uri to keys, a key set host the test controls.
func opKeysFront(t *testing.T, s *clienttest.Server, keys http.Handler) string {
	t.Helper()
	jwks := newTestServer(t, keys)
	rp := httputil.NewSingleHostReverseProxy(must(url.Parse(s.URL)))
	rp.Transport = s.HTTP.Client().Transport
	rp.ModifyResponse = func(r *http.Response) error {
		if r.Request.URL.Path != "/" || r.StatusCode != 200 {
			return nil
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		b = []byte(strings.Replace(string(b), `"jwks_uri":`, `"jwks_uri":"`+jwks.URL+`/keys","was":`, 1))
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", fmt.Sprint(len(b)))
		return nil
	}
	return newTestServer(t, rp).URL
}

// The deployment's operator keys (§C.4) are read again once they are 5
// minutes old: once for every verification asking meanwhile, which use
// those read before until it is done, and, failed, not again for 30
// seconds (logins don't each wait for a key set host that is down).
func TestGatewayOperatorKeysRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	var fetches atomic.Int64
	var failing atomic.Bool
	release := make(chan struct{})
	var hold atomic.Bool
	front := opKeysFront(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if hold.Load() {
			<-release
		}
		if failing.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		io.WriteString(w, `{"keys":[]}`)
	}))
	clk := &testClock{t: time.Now()}
	srv := must(dav.New(dav.Options{Client: must(client.New(front)), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf, Now: clk.now}))
	e := &env{t: t, ctx: ctx, s: s, dav: newTestServer(t, srv)}
	login := func(i int) resp {
		return e.doAs(k.Grant(t, s.Now(), fmt.Sprintf("user:u%d", i), []string{"docs"}, []string{"read"}), "PROPFIND", "/docs/", "", "Depth", "1")
	}
	e.expect(login(0), 207, "the first login")
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d reads of the key set", n)
	}
	// 6 minutes on, the host down: one read, then none for 30 s.
	clk.add(6 * time.Minute)
	failing.Store(true)
	for i := 1; i <= 5; i++ {
		e.expect(login(i), 207, "a login with the key set down")
	}
	for deadline := time.Now().Add(10 * time.Second); fetches.Load() < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the key set wasn't read again")
		}
	}
	for i := 6; i <= 8; i++ {
		e.expect(login(i), 207, "a login with the key set down")
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("%d reads of the key set, 8 logins with it down within 30 s of a failed read", n)
	}
	// 31 s on, the host hangs: logins don't wait for it, and it is read once.
	clk.add(31 * time.Second)
	hold.Store(true)
	var wg sync.WaitGroup
	for i := 10; i < 14; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := login(i); r.status != 207 {
				t.Errorf("a login while the key set is read: %d %q", r.status, r.body)
			}
		}()
	}
	wg.Wait()
	close(release)
	for deadline := time.Now().Add(10 * time.Second); fetches.Load() < 3; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the key set wasn't read again")
		}
	}
	e.expect(login(20), 207, "a login after the read")
	if n := fetches.Load(); n != 3 {
		t.Fatalf("%d reads of the key set, 5 logins while one hangs or just failed", n)
	}
}

// A key set the core's jwks_uri doesn't serve (a 404: a proxy in front of
// the core that doesn't route /.well-known) is a failed read, not "no
// operator keys": with none read, the core is asked whether a namespace's
// own keys verify each grant, so alice's grant (docs' key, whose kid is
// the operator key's) is served, and an operator grant for her sub isn't.
func TestGatewayOperatorKeys404(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("operator")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	rp := httputil.NewSingleHostReverseProxy(must(url.Parse(s.URL)))
	rp.Transport = s.HTTP.Client().Transport
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			http.NotFound(w, r)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	srv := must(dav.New(dav.Options{Client: must(client.New(front.URL)), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf}))
	e := &env{t: t, ctx: ctx, s: s, dav: newTestServer(t, srv)}
	alice := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	e.expect(e.doAs(alice, "PUT", "/docs/.notes.md.swp", "alice's unsaved draft"), 201, "alice's swap file")
	opAlice := clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "user:alice", "ns": []any{"docs"},
		"can": []any{"read"}, "exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
	e.expect(e.doAs(opAlice, "GET", "/docs/.notes.md.swp", ""), 401, "the operator grant, the key set answered 404")
}

// An operator who lists its own key in a namespace document under the
// same kid (§C.4) mints grants the core serves as that namespace's (it
// verifies namespace keys first): the gateway serves them too. In a
// public namespace, whose reads ignore a grant, the document says which
// key signed it: an operator grant there whose kid a different key of the
// namespace carries is refused.
func TestGatewayOperatorKeyInNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	opKey := clienttest.Key{Kid: "operator", Priv: s.OperatorKey, Pub: base64.RawURLEncoding.EncodeToString(s.OperatorKey.Public().(ed25519.PublicKey))}
	other := clienttest.NewKey("operator")
	for ns, doc := range map[string]map[string]any{
		"docs":  {"read": "grant", "keys": []any{opKey.Entry("*")}},
		"pub":   {"read": "public", "keys": []any{opKey.Entry("*")}},
		"pub2":  {"read": "public", "keys": []any{other.Entry("*")}},
		"other": {"read": "grant", "keys": []any{other.Entry("*")}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs", "other", "pub", "pub2"}, Gateway: true, Logf: t.Logf}))
	e := &env{t: t, ctx: ctx, s: s, dav: newTestServer(t, srv)}
	for _, ns := range []string{"docs", "pub"} {
		tok := opKey.Grant(t, s.Now(), "user:ops", []string{ns}, []string{"read", "create", "append"})
		must(s.Client(t, client.WithBearer(tok)).CreateDoc(ctx, ns, "x", map[string]any{"v": 1}))
		e.expect(e.doAs(tok, "GET", "/"+ns+"/x.json", ""), 200, "a grant of the operator's key "+ns+" lists")
	}
	for _, ns := range []string{"other", "pub2"} {
		tok := opKey.Grant(t, s.Now(), "user:ops", []string{ns}, []string{"read"})
		if r := e.expect(e.doAs(tok, "PROPFIND", "/"+ns+"/", "", "Depth", "1"), 401, "an operator grant in "+ns+", whose key named operator is another"); !strings.Contains(r.body, "operator key") {
			t.Fatalf("401 %q", r.body)
		}
	}
}

// A refused save asks for a reload (§H.4), and the user's records are
// their tokens': any program's read drops what was recorded before the
// refusal. But the program refused keeps what it had and may retry the
// refused upload on its own (an rclone mount's write-back, 10 s, 20 s, 40 s
// later), the same bytes: until that token reads the file itself, its
// saves without a base are refused again, not rebased on what another
// token of the user read, which would overwrite the edit the refusal was
// about. Once it reloads, its save goes through.
func TestGatewayRetryAfterOtherRead(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	writer := []string{"read", "create", "append", "restore", "delete"}
	mount := k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)
	other := k.Grant(t, e.s.Now().Add(time.Second), "user:bob", []string{"docs"}, writer)
	e.create("docs", "a", map[string]any{"score": "0-0", "title": "T"})
	e.expect(e.doAs(mount, "GET", "/docs/a.json", ""), 200, "bob's mount opens a.json")
	h, _ := e.load("docs", "a")
	must(e.c.Append(e.ctx, "docs", "a", h.ID, []any{replace("/score", "1-0")}))
	refused := rendered(map[string]any{"score": "8-8", "title": "T"})
	e.expect(e.doAs(mount, "PUT", "/docs/a.json", refused), 409, "the mount's upload, from 0-0")
	e.expect(e.doAs(other, "GET", "/docs/a.json", ""), 200, "another program of bob's reads a.json")
	e.expect(e.doAs(mount, "PUT", "/docs/a.json", refused), 409, "the mount's retry of the bytes refused")
	_, doc := e.load("docs", "a")
	sameJSON(t, doc, map[string]any{"score": "1-0", "title": "T"})
	// The other program's own save, from what it read, goes through.
	e.expect(e.doAs(other, "PUT", "/docs/a.json", rendered(map[string]any{"score": "1-0", "title": "T2"})), 201, "the other program's save")
	// The mount reloads, and saves.
	buf := e.expect(e.doAs(mount, "GET", "/docs/a.json", ""), 200, "the mount reloads").body
	e.expect(e.doAs(mount, "PUT", "/docs/a.json", strings.Replace(buf, `"1-0"`, `"8-8"`, 1)), 201, "the mount's save after its reload")
	_, doc = e.load("docs", "a")
	sameJSON(t, doc, map[string]any{"score": "8-8", "title": "T2"})
}

// A retry refused (refusedSave) asks the user for no reload: re-arming
// the user's would make another program's next read of the file drop
// the records older than the retry, the version that program has open
// among them, and its next save without If-Match would be rebased on
// that read alone, writing back what a third party changed since its
// version (§H.4). Here the editor opens R2 after the mount's refusal and
// edits the title; a third party sets note; the mount retries (409); the
// editor's program reads the file again (a preview); the editor's save
// from R2 keeps the third party's note, with or without the retry.
func TestGatewayRetryKeepsOthersBase(t *testing.T) {
	t.Parallel()
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%v", retry), func(t *testing.T) {
			e, k := authEnv(t, true)
			writer := []string{"read", "create", "append", "restore", "delete"}
			mount := k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)
			editor := k.Grant(t, e.s.Now().Add(time.Second), "user:bob", []string{"docs"}, writer)
			e.create("docs", "a", map[string]any{"score": "0-0", "title": "T", "note": "n"})
			e.expect(e.doAs(mount, "GET", "/docs/a.json", ""), 200, "the mount opens a.json (R1)")
			h, _ := e.load("docs", "a")
			must(e.c.Append(e.ctx, "docs", "a", h.ID, []any{replace("/score", "1-0")}))
			refused := rendered(map[string]any{"score": "8-8", "title": "T", "note": "n"})
			e.expect(e.doAs(mount, "PUT", "/docs/a.json", refused), 409, "the mount's upload, from R1")
			buf := e.expect(e.doAs(editor, "GET", "/docs/a.json", ""), 200, "the editor opens a.json (R2)").body
			h, _ = e.load("docs", "a")
			must(e.c.Append(e.ctx, "docs", "a", h.ID, []any{replace("/note", "n2")}))
			if retry {
				e.expect(e.doAs(mount, "PUT", "/docs/a.json", refused), 409, "the mount's retry")
			}
			e.expect(e.doAs(editor, "GET", "/docs/a.json", ""), 200, "the editor's program reads a.json again (R3)")
			e.expect(e.doAs(editor, "PUT", "/docs/a.json", strings.Replace(buf, `"T"`, `"T2"`, 1)), 201, "the editor's save of its title edit from R2")
			_, doc := e.load("docs", "a")
			sameJSON(t, doc, map[string]any{"score": "1-0", "title": "T2", "note": "n2"})
		})
	}
}

// A retry refused by its own rebase asks the user for no reload either
// (refuse): the token is already to read the file itself, so the reload
// its first refusal asked for is the editor's read, R2, which a re-armed
// reload would drop at the editor's program's next read (R3), and the
// editor's save from R2 would be rebased on R3 alone, writing back the
// score and note the third party changed after R2 (§H.4). The third
// party's second change makes the mount's retry clash, a JSON file's
// (with If-Match R1 or without) or a raw file's (any change of its
// bytes): the editor's save keeps it, or, a raw file's, is 409 as
// without the retry.
func TestGatewayRetryClashKeepsOthersBase(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"json", "if-match", "raw"} {
		for _, retry := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/retry=%v", kind, retry), func(t *testing.T) {
				e, k := authEnv(t, true)
				writer := []string{"read", "create", "append", "restore", "delete"}
				mount := k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)
				editor := k.Grant(t, e.s.Now().Add(time.Second), "user:bob", []string{"docs"}, writer)
				if kind == "raw" {
					e.rawDoc("docs", "a.txt", "text/plain", []byte("one"), nil)
					set := func(b string) {
						h, _ := e.load("docs", "a.txt")
						bid := must(e.c.UploadBlob(e.ctx, "docs", "a.txt", "text/plain", "", []byte(b)))
						must(e.c.Append(e.ctx, "docs", "a.txt", h.ID, []any{replace("/$blob", bid), replace("/size", len(b))}))
					}
					e.expect(e.doAs(mount, "GET", "/docs/a.txt", ""), 200, "the mount opens a.txt (R1)")
					set("theirs")
					e.expect(e.doAs(mount, "PUT", "/docs/a.txt", "mine"), 409, "the mount's upload, from R1")
					e.expect(e.doAs(editor, "GET", "/docs/a.txt", ""), 200, "the editor opens a.txt (R2)")
					set("theirs2")
					if retry {
						e.expect(e.doAs(mount, "PUT", "/docs/a.txt", "mine"), 409, "the mount's retry")
					}
					e.expect(e.doAs(editor, "GET", "/docs/a.txt", ""), 200, "the editor's program reads a.txt again (R3)")
					e.expect(e.doAs(editor, "PUT", "/docs/a.txt", "theirs, edited"), 409, "the editor's save from R2, whose bytes changed since")
					if _, data := e.rawOf("docs", "a.txt"); string(data) != "theirs2" {
						t.Fatalf("a.txt reads %q", data)
					}
					return
				}
				e.create("docs", "a", map[string]any{"score": "0-0", "title": "T", "note": "n"})
				r1 := e.expect(e.doAs(mount, "GET", "/docs/a.json", ""), 200, "the mount opens a.json (R1)").header.Get("ETag")
				var tag []string
				if kind == "if-match" {
					tag = []string{"If-Match", r1}
				}
				h, _ := e.load("docs", "a")
				must(e.c.Append(e.ctx, "docs", "a", h.ID, []any{replace("/score", "1-0")}))
				refused := rendered(map[string]any{"score": "8-8", "title": "T", "note": "n"})
				e.expect(e.doAs(mount, "PUT", "/docs/a.json", refused, tag...), 409, "the mount's upload, from R1")
				buf := e.expect(e.doAs(editor, "GET", "/docs/a.json", ""), 200, "the editor opens a.json (R2)").body
				h, _ = e.load("docs", "a")
				must(e.c.Append(e.ctx, "docs", "a", h.ID, []any{replace("/score", "2-0"), replace("/note", "n2")}))
				if retry {
					e.expect(e.doAs(mount, "PUT", "/docs/a.json", refused, tag...), 409, "the mount's retry, which clashes on /score")
				}
				e.expect(e.doAs(editor, "GET", "/docs/a.json", ""), 200, "the editor's program reads a.json again (R3)")
				e.expect(e.doAs(editor, "PUT", "/docs/a.json", strings.Replace(buf, `"T"`, `"T2"`, 1)), 201, "the editor's save of its title edit from R2")
				_, doc := e.load("docs", "a")
				sameJSON(t, doc, map[string]any{"score": "2-0", "title": "T2", "note": "n2"})
			})
		}
	}
}

// A token refused a save, which must read the file itself before its
// next save without a base (refusedSave), gets it in full from a
// conditional GET, whatever its validators say (§H.1, §H.4), after
// another token of the user read it too: that GET is its reload, and its
// save of the head it read goes through.
func TestGatewayRefusedConditionalGET(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	writer := []string{"read", "create", "append", "restore", "delete"}
	mount := k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)
	other := k.Grant(t, e.s.Now().Add(time.Second), "user:bob", []string{"docs"}, writer)
	e.create("docs", "a", map[string]any{"score": "0-0", "title": "T"})
	e.expect(e.doAs(mount, "GET", "/docs/a.json", ""), 200, "the mount opens a.json")
	h, _ := e.load("docs", "a")
	must(e.c.Append(e.ctx, "docs", "a", h.ID, []any{replace("/score", "1-0")}))
	e.expect(e.doAs(mount, "PUT", "/docs/a.json", rendered(map[string]any{"score": "8-8", "title": "T"})), 409, "the mount's upload, from 0-0")
	etag := e.expect(e.doAs(other, "GET", "/docs/a.json", ""), 200, "another program of bob's reads a.json").header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	r := e.expect(e.doAs(mount, "GET", "/docs/a.json", "", "If-None-Match", etag), 200, "the refused mount's conditional GET")
	if r.body != rendered(map[string]any{"score": "1-0", "title": "T"}) {
		t.Fatalf("the mount's GET %q", r.body)
	}
	e.expect(e.doAs(mount, "PUT", "/docs/a.json", rendered(map[string]any{"score": "1-0", "title": "T2"})), 201, "the mount's save of the head it read")
	_, doc := e.load("docs", "a")
	sameJSON(t, doc, map[string]any{"score": "1-0", "title": "T2"})
}

// A token verified again as another user must read each document its
// old user had records of before saving it without a base (loseRecords),
// but only that token: the new user's other tokens, which never were
// someone else, save from what they read as the new user, a GET made
// after the switch or before it, with no refusal (§H.4, §H.7).
func TestGatewaySwitchOthersSave(t *testing.T) {
	t.Parallel()
	for _, before := range []bool{false, true} {
		t.Run(fmt.Sprintf("read before the switch=%v", before), func(t *testing.T) {
			clk := &testClock{t: time.Now()}
			e, k := authEnv(t, true, func(o *dav.Options) {
				o.Namespaces = []string{"alpha", "docs"}
				o.Now, o.VerifyEvery = clk.now, time.Minute
			})
			writer := []string{"read", "create", "append", "restore", "delete", "config"}
			op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
			must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
			alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
			aliceDocs := k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"docs"}, writer)
			e.create("docs", "x", map[string]any{"v": 1, "w": 1})
			e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha")
			var buf string
			if before {
				buf = e.expect(e.doAs(aliceDocs, "GET", "/docs/x.json", ""), 200, "the docs token reads x before the switch").body
			}
			ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
			nh := must(ac.NSHead(e.ctx, "alpha"))
			must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
			clk.add(2 * time.Minute)
			e.expect(e.doAs(alice, "PROPFIND", "/docs/", "", "Depth", "1"), 207, "alice's full token, verified again by docs (a switch)")
			if !before {
				buf = e.expect(e.doAs(aliceDocs, "GET", "/docs/x.json", ""), 200, "the docs token opens x after the switch").body
			}
			e.expect(e.doAs(aliceDocs, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 3`, 1)), 201, "the docs token's save from what it read")
			_, doc := e.load("docs", "x")
			sameJSON(t, doc, map[string]any{"v": 3, "w": 1})
		})
	}
}

// A switched token refused room as its new user (503: here the new
// user's 8 scopes of tokens as issued each keep a swap file) is admitted
// as nobody, and marks nothing: its retries (Retry-After) don't undo
// what the new user's other tokens read meanwhile, whose saves from it
// go through (§H.4, §H.7).
func TestGatewaySwitchRefusedRoom(t *testing.T) {
	t.Parallel()
	clk := &testClock{t: time.Now()}
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.Namespaces = []string{"alpha", "docs"}
		o.Now, o.VerifyEvery = clk.now, time.Minute
	})
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha")
	var docsToks []string
	for i := 0; i < 8; i++ {
		tok := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer, map[string]any{"attrs": map[string]any{"n": i}})
		e.expect(e.doAs(tok, "PUT", fmt.Sprintf("/docs/.s%d.swp", i), "swap"), 201, "a docs-only token's swap file")
		docsToks = append(docsToks, tok)
	}
	ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
	nh := must(ac.NSHead(e.ctx, "alpha"))
	must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
	clk.add(2 * time.Minute)
	e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 503, "alice's full token, verified again by docs: no scope for it")
	d := docsToks[0]
	buf := e.expect(e.doAs(d, "GET", "/docs/x.json", ""), 200, "a docs token reads x").body
	e.expect(e.doAs(d, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "its save")
	buf = e.expect(e.doAs(d, "GET", "/docs/x.json", ""), 200, "it reads its save").body
	e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 503, "the full token's retry")
	e.expect(e.doAs(d, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 2`, `"v": 3`, 1)), 201, "the docs token's save from what it read, after the retry")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 3, "w": 1})
}

// A document's tokens to read it themselves (unread) are bounded (8):
// one pushed out by a ninth leaves the document lost, so its save from
// before is refused, not rebased on the new user's records (§H.4, §H.7).
// Here alice's 9 tokens, all verified by alpha, are verified again by
// docs (a switch each); T1, whose client holds x as read before a third
// party's edit, switched first, and its save from before is a 409 with 7
// or 8 switched after it, never written whole over the edit (the new
// user has no record of x, so the head would be the base). Its reloads
// then let it save.
func TestGatewaySwitchMarkPushedOut(t *testing.T) {
	t.Parallel()
	for _, others := range []int{7, 8} {
		t.Run(fmt.Sprintf("others=%d", others), func(t *testing.T) {
			clk := &testClock{t: time.Now()}
			e, k := authEnv(t, true, func(o *dav.Options) {
				o.Namespaces = []string{"alpha", "docs"}
				o.Now, o.VerifyEvery = clk.now, time.Minute
			})
			writer := []string{"read", "create", "append", "restore", "delete", "config"}
			op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
			must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
			var toks []string
			for i := 0; i <= others; i++ {
				toks = append(toks, k.Grant(t, e.s.Now().Add(time.Duration(i)*time.Second), "user:alice", []string{"alpha", "docs"}, writer))
			}
			e.create("docs", "x", map[string]any{"v": 1, "w": 1})
			buf := e.expect(e.doAs(toks[0], "GET", "/docs/x.json", ""), 200, "T1's GET, verified by alpha").body
			for i, tok := range toks[1:] {
				e.expect(e.doAs(tok, "PROPFIND", "/docs/", "", "Depth", "1"), 207, fmt.Sprintf("T%d, verified by alpha", i+2))
			}
			h, _ := e.load("docs", "x")
			must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{replace("/w", 2)}))
			ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
			nh := must(ac.NSHead(e.ctx, "alpha"))
			must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
			clk.add(2 * time.Minute)
			for i, tok := range toks {
				e.expect(e.doAs(tok, "PROPFIND", "/docs/", "", "Depth", "1"), 207, fmt.Sprintf("T%d, verified again by docs (a switch)", i+1))
			}
			e.expect(e.doAs(toks[0], "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "T1's save from before the switch")
			_, doc := e.load("docs", "x")
			sameJSON(t, doc, map[string]any{"v": 1, "w": 2})
			saved := false
			for try := 0; try < 3 && !saved; try++ {
				buf = e.expect(e.doAs(toks[0], "GET", "/docs/x.json", ""), 200, "T1 reloads").body
				r := e.doAs(toks[0], "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1))
				saved = r.status == 201
			}
			if !saved {
				t.Fatal("T1's save after three reloads is still refused")
			}
			_, doc = e.load("docs", "x")
			sameJSON(t, doc, map[string]any{"v": 2, "w": 2})
		})
	}
}

// The record of where a person's grants verify (kidNS, by kid and sub)
// keeps every served namespace that accepted one, the first never pushed
// out by later ones (§H.7 "a reminted token is the same person"): four
// more namespaces accepting a grant of the same kid and sub (a
// stranger's, whose key is named "k" too and mints sub user:alice, or
// alice's own single-namespace grants) don't make docs, which verified
// her first, lose its place to alpha, which sorts first and is given her
// key later: her token minted again is still docs' user, with her swap
// file, and her save without If-Match is rebased on what she read.
func TestGatewayStableUserManyNamespaces(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"a stranger's", "alice's own"} {
		t.Run(variant, func(t *testing.T) {
			e, k := authEnv(t, true, func(o *dav.Options) { o.Namespaces = []string{"alpha", "docs", "z1", "z2", "z3", "z4"} })
			key := clienttest.NewKey("k")
			if variant == "alice's own" {
				key = k
			}
			writer := []string{"read", "create", "append", "restore", "delete"}
			alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
			e.create("docs", "x", map[string]any{"v": 1, "w": 1})
			buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET (verified by docs)").body
			e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "swap"), 201, "alice's swap file")
			h, _ := e.load("docs", "x")
			must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))
			for i := 1; i <= 4; i++ {
				ns := fmt.Sprintf("z%d", i)
				op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, ns)))
				must(op.CreateNamespace(e.ctx, ns, map[string]any{"read": "grant", "keys": []any{key.Entry("*")}}))
				tok := key.Grant(t, e.s.Now(), "user:alice", []string{ns}, []string{"read"})
				e.expect(e.doAs(tok, "PROPFIND", "/"+ns+"/", "", "Depth", "1"), 207, ns+"'s listing for (k, user:alice)")
			}
			op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
			must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
			again := k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"alpha", "docs"}, writer)
			if r := e.expect(e.doAs(again, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file by her token minted again"); r.body != "swap" {
				t.Fatalf("alice's swap file %q", r.body)
			}
			e.expect(e.doAs(again, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "alice's save, no If-Match")
			_, doc := e.load("docs", "x")
			sameJSON(t, doc, map[string]any{"v": 2, "w": 2})
		})
	}
}

// Who each token was verified as (idUsers), what lets a token dropped
// while idle be seen to come back as another user (TestGatewaySwitchAfterSweep),
// is bounded per user, not only over all users: narrowing is offline and
// free, so mallory logging in with more narrowings of her one grant than
// the gateway keeps ids for at all pushes out only her own. alice's token,
// swept meanwhile and verified again as another user, is still seen to
// switch, and her save from before is a 409, not rebased on the head.
// The bounds are made small here (16384 and 256 in use).
func TestGatewayIDUsersFlood(t *testing.T) {
	t.Parallel()
	clk := &testClock{t: time.Now()}
	e, k := authEnv(t, true)
	srv := must(dav.New(dav.Options{Client: e.s.Client(t), Namespaces: []string{"alpha", "docs"}, Gateway: true,
		Now: clk.now, VerifyEvery: time.Minute, Logf: t.Logf}))
	const all, perUser = 256, 16
	dav.SetIDUsers(srv, all, perUser)
	e.dav = newTestServer(t, srv)
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
	must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
	mallory := k.Grant(t, e.s.Now(), "user:mallory", []string{"docs"}, []string{"read"})
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha").body
	h, _ := e.load("docs", "x")
	must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{map[string]any{"op": "replace", "path": "/w", "value": 2}}))
	ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
	nh := must(ac.NSHead(e.ctx, "alpha"))
	must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{clienttest.NewKey("k2").Entry("*")}}}))
	clk.add(2 * time.Minute)
	// mallory's logins (the first sweeps alice's idle token), fewer at once
	// than her tokens kept, so each is admitted.
	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				tok := narrowed(t, mallory, map[string]any{"via": fmt.Sprintf("m%d", i)})
				if r := e.doAs(tok, "GET", "/docs/.nothing", ""); r.status != 404 {
					t.Errorf("mallory's login %d: %d %s", i, r.status, r.body)
				}
			}
		}()
	}
	for i := 0; i < all+perUser; i++ {
		ch <- i
	}
	close(ch)
	wg.Wait()
	e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "alice's save from before, verified again as another user after mallory's logins")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 1, "w": 2})
}

// Who each token was verified as (idUsers) is bounded per user, but the
// holder of a served namespace's key mints grants for any sub, each
// another user, and adds keys (kids) to its namespace: mallory, holding
// the key of a served namespace of her own (mal), as the strangers of
// TestGatewayStableUserManyNamespaces do, or a second key alpha lists,
// logs in with more grants than the gateway keeps ids for at all, 8 per
// user, for 34 subs, or 34 kids of mal's. Over the bound, the verifying
// namespace keeping the most ids gives way, then its issuer keeping the
// most: hers. alice's token, swept meanwhile and verified again as
// another user, is still seen to switch, and her save from before is a
// 409, not rebased on the head. The bounds are made small here (16384 and
// 256 in use).
func TestGatewayIDUsersFloodManySubs(t *testing.T) {
	t.Parallel()
	for _, flood := range []string{"one login", "subs of mal's key", "kids of mal's", "subs of a key of alpha's"} {
		t.Run(flood, func(t *testing.T) {
			clk := &testClock{t: time.Now()}
			e, k := authEnv(t, true)
			srv := must(dav.New(dav.Options{Client: e.s.Client(t), Namespaces: []string{"alpha", "docs", "mal"}, Gateway: true,
				Now: clk.now, VerifyEvery: time.Minute, Logf: t.Logf}))
			const all, perUser, per = 256, 16, 8
			dav.SetIDUsers(srv, all, perUser)
			e.dav = newTestServer(t, srv)
			writer := []string{"read", "create", "append", "restore", "delete", "config"}
			mk := clienttest.NewKey("mk")
			mks := []clienttest.Key{mk}
			if flood == "kids of mal's" {
				for i := 1; i <= all/per+2; i++ {
					mks = append(mks, clienttest.NewKey(fmt.Sprintf("mk%d", i)))
				}
			}
			var malKeys []any
			for _, key := range mks {
				malKeys = append(malKeys, key.Entry("*"))
			}
			alphaKeys := []any{k.Entry("*")}
			ns := "mal"
			if flood == "subs of a key of alpha's" {
				alphaKeys, ns = append(alphaKeys, mk.Entry("*")), "alpha"
			}
			op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "alpha")))
			must(op.CreateNamespace(e.ctx, "alpha", map[string]any{"read": "grant", "keys": alphaKeys}))
			opm := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "mal")))
			must(opm.CreateNamespace(e.ctx, "mal", map[string]any{"read": "grant", "keys": malKeys}))
			alice := k.Grant(t, e.s.Now(), "user:alice", []string{"alpha", "docs"}, writer)
			e.create("docs", "x", map[string]any{"v": 1, "w": 1})
			buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET, verified by alpha").body
			h, _ := e.load("docs", "x")
			must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{replace("/w", 2)}))
			ac := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"alpha"}, writer)))
			nh := must(ac.NSHead(e.ctx, "alpha"))
			must(ac.PatchConfig(e.ctx, "alpha", nh.Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": append([]any{clienttest.NewKey("k2").Entry("*")}, alphaKeys[1:]...)}}))
			clk.add(2 * time.Minute)
			// mallory's logins (the first sweeps alice's idle token), per
			// tokens of each sub, or of each kid, within the per-user bound.
			var wg sync.WaitGroup
			ch := make(chan int)
			for w := 0; w < 4; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range ch {
						key, sub := mk, fmt.Sprintf("user:m%d", i/per)
						if flood == "kids of mal's" {
							key, sub = mks[i/per], "user:m"
						}
						tok := key.Grant(t, e.s.Now().Add(time.Duration(i)*time.Second), sub, []string{ns}, []string{"read"})
						if r := e.doAs(tok, "GET", "/"+ns+"/.nothing", ""); r.status != 404 {
							t.Errorf("mallory's login %d: %d %s", i, r.status, r.body)
						}
					}
				}()
			}
			n := 1
			if flood != "one login" {
				n = all + 2*per
			}
			for i := 0; i < n; i++ {
				ch <- i
			}
			close(ch)
			wg.Wait()
			e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 409, "alice's save from before, verified again as another user after mallory's logins")
			_, doc := e.load("docs", "x")
			sameJSON(t, doc, map[string]any{"v": 1, "w": 2})
		})
	}
}

// A key set the core's jwks_uri answers 200 with a body that isn't a JWK
// Set (`{}`, a proxy's JSON error page for an unrouted /.well-known) is a
// failed read, as a 404 is (TestGatewayOperatorKeys404), not an empty
// set: an operator grant for alice's sub, whose kid docs' key carries,
// isn't taken for alice and doesn't read her swap file.
func TestGatewayOperatorKeysNotASet(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{"error":"no route"}`, `{}`} {
		t.Run(body, func(t *testing.T) {
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
			k := clienttest.NewKey("operator")
			op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
			must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
			rp := httputil.NewSingleHostReverseProxy(must(url.Parse(s.URL)))
			rp.Transport = s.HTTP.Client().Transport
			front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/") {
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, body)
					return
				}
				rp.ServeHTTP(w, r)
			}))
			srv := must(dav.New(dav.Options{Client: must(client.New(front.URL)), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf}))
			e := &env{t: t, ctx: ctx, s: s, dav: newTestServer(t, srv)}
			alice := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append"})
			e.expect(e.doAs(alice, "PUT", "/docs/.notes.md.swp", "alice's unsaved draft"), 201, "alice's swap file")
			opAlice := clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "user:alice", "ns": []any{"docs"},
				"can": []any{"read"}, "exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
			e.expect(e.doAs(opAlice, "GET", "/docs/.notes.md.swp", ""), 401, "the operator grant, the key set answered 200 "+body)
		})
	}
}

// ns, can, roles and groups are sets (§C.1, §C.2): alice's token minted
// again with the same rights listed in another order (or one listed
// twice) is in the same scope (§H.7 "a reminted token is the same
// person"), and reads her swap file.
func TestGatewayScopeListOrder(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.Namespaces = []string{"docs", "notes"} })
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs", "notes"}, []string{"read", "create", "append"},
		map[string]any{"groups": []any{"eng", "ops"}, "roles": []any{"editor", "viewer"}})
	again := k.Grant(t, e.s.Now().Add(time.Minute), "user:alice", []string{"notes", "docs"}, []string{"append", "create", "read", "read"},
		map[string]any{"groups": []any{"ops", "eng"}, "roles": []any{"viewer", "editor"}})
	e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "swap"), 201, "alice's swap file")
	if r := e.expect(e.doAs(again, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file by her token minted again, the same rights in another order"); r.body != "swap" {
		t.Fatalf("alice's swap file %q", r.body)
	}
}

// Tokens narrowed offline keep scopes per chain, the token their
// narrowing started from: a delegate holding one narrowed token of
// alice's narrows it 8 times and keeps a scratch file in each scope,
// which fills only its chain's pool (its next narrowing is 503), not that
// of alice's own read-only narrowing for her phone or another delegate's.
// Chains are bounded too, a new one making room among the others' idle
// scopes: once 8 other chains each keep a file, a new one is 503, and
// alice's tokens as issued are untouched (§H.6, §H.7).
func TestGatewayNarrowedChains(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append", "restore", "delete"})
	e.create("docs", "x", map[string]any{"v": 1})
	e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "unsaved edits"), 201, "alice's swap file")
	mallory := narrowed(t, alice, map[string]any{"via": "user:mallory"})
	for i := 0; i < 8; i++ {
		tok := narrowed(t, mallory, map[string]any{"via": fmt.Sprintf("m%d", i)})
		e.expect(e.doAs(tok, "PUT", fmt.Sprintf("/docs/.m%d.swp", i), "m"), 201, "the delegate's scratch file")
	}
	e.expect(e.doAs(narrowed(t, mallory, map[string]any{"via": "m8"}), "GET", "/docs/x.json", ""), 503, "the delegate's ninth narrowing, its 8 scopes each keeping a file")
	phone := narrowed(t, alice, map[string]any{"can": []any{"read"}})
	e.expect(e.doAs(phone, "GET", "/docs/x.json", ""), 200, "alice's own read-only narrowing for her phone")
	carol := narrowed(t, alice, map[string]any{"via": "user:carol"})
	e.expect(e.doAs(carol, "GET", "/docs/x.json", ""), 200, "another delegate's token")
	// Seven more chains, each keeping a file: the phone's and carol's
	// idle scopes make room.
	for i := 0; i < 7; i++ {
		tok := narrowed(t, alice, map[string]any{"via": fmt.Sprintf("svc:%d", i)})
		e.expect(e.doAs(tok, "PUT", fmt.Sprintf("/docs/.c%d.swp", i), "c"), 201, "a chain's scratch file")
	}
	r := e.expect(e.doAs(narrowed(t, alice, map[string]any{"via": "svc:new"}), "GET", "/docs/x.json", ""), 503, "a new chain, 8 others each keeping a file")
	if r.header.Get("Retry-After") == "" {
		t.Fatalf("503 without Retry-After: %v", r.header)
	}
	e.expect(e.doAs(narrowed(t, mallory, map[string]any{"via": "m0"}), "GET", "/docs/.m0.swp", ""), 200, "the delegate's scratch file, kept")
	if r := e.expect(e.doAs(alice, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file"); r.body != "unsaved edits" {
		t.Fatalf("alice's swap file %q", r.body)
	}
}
