package dav_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// authEnv: a core with authentication, namespace docs readable with a
// grant of key k, and a WebDAV server in gateway mode, or in local mode
// with user:svc's grant and the password "s3cret".
func authEnv(t *testing.T, gateway bool, with ...func(*dav.Options)) (*env, clienttest.Key) {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	writer := []string{"read", "create", "append", "restore", "delete"}
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, writer)))}
	opt := dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: gateway, Logf: t.Logf}
	if !gateway {
		opt.Client = s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:svc", []string{"docs"}, writer)))
		opt.Password, e.pw = "s3cret", "s3cret"
	}
	for _, f := range with {
		f(&opt)
	}
	srv, err := dav.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	e.dav = httptest.NewServer(srv)
	t.Cleanup(e.dav.Close)
	return e, k
}

// Gateway mode: the Basic password is the grant, sent upstream, so the
// revision is the grant's subject's; no grant, one that isn't, or one the
// core refuses is 401 with a Basic challenge; one without write is 403.
// Scratch files are per user (§H.7).
func TestGateway(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	now := e.s.Now()
	alice := k.Grant(t, now, "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	bob := k.Grant(t, now, "user:bob", []string{"docs"}, []string{"read"})

	for what, pw := range map[string]string{
		"no password":     "",
		"not a grant":     "hunter2",
		"expired":         k.Grant(t, now.Add(-2*time.Hour), "user:alice", []string{"docs"}, []string{"read"}),
		"an unknown key":  clienttest.NewKey("k").Grant(t, now, "user:mallory", []string{"docs"}, []string{"read"}),
		"another's grant": clienttest.NewKey("x").Grant(t, now, "user:mallory", []string{"docs"}, []string{"read"}),
	} {
		r := e.doAs(pw, "PROPFIND", "/docs/", "", "Depth", "1")
		if r.status != 401 || !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Basic realm=") {
			t.Errorf("%s: %d %v %s", what, r.status, r.header, r.body)
		}
	}

	e.expect(e.doAs(alice, "PUT", "/docs/a.json", `{"by": "alice"}`), 201, "alice's PUT")
	en := e.lastEntry("docs", "a")
	if en.Grant == nil || en.Grant.Sub != "user:alice" || !strings.Contains(en.Author, "alice") {
		t.Fatalf("entry %+v %+v", en, en.Grant)
	}
	r := e.expect(e.doAs(bob, "PUT", "/docs/b.json", `{"by": "bob"}`), 403, "bob's PUT")
	if !strings.Contains(r.body, "forbidden") || !strings.Contains(r.body, "create") || strings.Contains(r.body, "403") {
		t.Fatalf("403 text %q: the core's code and message, not its status again", r.body)
	}
	sameStrings(t, "bob's listing", names(e.propfindAs(bob, "/docs/"), "/docs/"), []string{"a.json"})

	// Scratch files are each user's own.
	e.expect(e.doAs(alice, "PUT", "/docs/.a.json.swp", "alice's swap"), 201, "alice's scratch")
	sameStrings(t, "alice's listing", names(e.propfindAs(alice, "/docs/"), "/docs/"), []string{".a.json.swp", "a.json"})
	sameStrings(t, "bob's listing", names(e.propfindAs(bob, "/docs/"), "/docs/"), []string{"a.json"})
	e.expect(e.doAs(bob, "GET", "/docs/.a.json.swp", ""), 404, "bob's GET of alice's scratch")
	e.expect(e.doAs(bob, "PUT", "/docs/.a.json.swp", "bob's swap"), 201, "bob's scratch")
	if b := e.expect(e.doAs(alice, "GET", "/docs/.a.json.swp", ""), 200, "alice's GET").body; b != "alice's swap" {
		t.Fatalf("alice's scratch %q", b)
	}
	e.expect(e.doAs(bob, "DELETE", "/docs/.a.json.swp", ""), 204, "bob's DELETE")
	e.expect(e.doAs(alice, "GET", "/docs/.a.json.swp", ""), 200, "alice's after bob's DELETE")
}

func (e *env) propfindAs(pw, p string) map[string]entry {
	e.t.Helper()
	keep := e.pw
	e.pw = pw
	defer func() { e.pw = keep }()
	return e.propfind(p)
}

// Local mode: one grant for every request, behind the server's password.
func TestLocalMode(t *testing.T) {
	t.Parallel()
	e, _ := authEnv(t, false)
	for what, pw := range map[string]string{"no password": "", "a wrong one": "s3cret!"} {
		if r := e.doAs(pw, "PROPFIND", "/docs/", "", "Depth", "1"); r.status != 401 || r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d %v", what, r.status, r.header)
		}
	}
	e.expect(e.do("PUT", "/docs/a.json", `{"v": 1}`), 201, "PUT")
	if en := e.lastEntry("docs", "a"); en.Grant == nil || en.Grant.Sub != "user:svc" {
		t.Fatalf("entry %+v", en)
	}
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{"a.json"})

	// The core refusing the server's grant isn't the user's password: 502.
	bad := clienttest.NewKey("k").Grant(t, e.s.Now(), "user:svc", []string{"docs"}, []string{"read"})
	srv := must(dav.New(dav.Options{Client: e.s.Client(t, client.WithBearer(bad)), Namespaces: []string{"docs"}, Password: "s3cret", Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e2 := &env{t: t, ctx: e.ctx, s: e.s, c: e.c, dav: hs, pw: "s3cret"}
	r := e2.expect(e2.do("PROPFIND", "/docs/", "", "Depth", "1"), 502, "PROPFIND with a refused grant")
	if r.header.Get("WWW-Authenticate") != "" || !strings.Contains(r.body, "-bearer") {
		t.Fatalf("502 %v %q", r.header, r.body)
	}
}

// A gateway keeps MaxPrincipals users, dropping the least recently seen
// with its scratch files.
func TestGatewayEviction(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.MaxPrincipals = 2
		// Every reading a millisecond later: no two requests tie.
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); now = now.Add(time.Millisecond); return now }
	})
	g := map[string]string{}
	for _, u := range []string{"a", "b", "c"} {
		g[u] = k.Grant(t, e.s.Now(), "user:"+u, []string{"docs"}, []string{"read"})
	}
	e.expect(e.doAs(g["a"], "PUT", "/docs/scratch.swp", "a"), 201, "a's scratch")
	e.expect(e.doAs(g["b"], "PUT", "/docs/scratch.swp", "b"), 201, "b's scratch")
	e.expect(e.doAs(g["a"], "GET", "/docs/scratch.swp", ""), 200, "a again")
	e.expect(e.doAs(g["c"], "PUT", "/docs/scratch.swp", "c"), 201, "c's scratch")
	for _, u := range []string{"a", "c"} {
		if r := e.expect(e.doAs(g[u], "GET", "/docs/scratch.swp", ""), 200, u+" kept"); r.body != u {
			t.Fatalf("%s's scratch %q", u, r.body)
		}
	}
	// b comes back as a new user, without its scratch file (and a, now
	// the least recently seen, goes).
	e.expect(e.doAs(g["b"], "GET", "/docs/scratch.swp", ""), 404, "b, dropped")
}

// A gateway keeps nothing for a grant before the core accepts it: a grant
// signed by a key no namespace trusts gets no scratch file and pushes no
// one's state out. In a public namespace, whose reads ignore a bad grant,
// the grant is verified against the namespace's keys.
func TestGatewayVerifies(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.MaxPrincipals = 2 })
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	e.expect(e.doAs(alice, "PUT", "/docs/.x.json.swp", "swap"), 201, "alice's swap file")
	for i := 0; i < 4; i++ {
		forged := clienttest.NewKey("x"+strconv.Itoa(i)).Grant(t, e.s.Now(), "user:mallory", []string{"docs"}, []string{"read"})
		r := e.doAs(forged, "PUT", "/.junk", "x")
		if r.status != 401 || !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("forged grant %d: %d %s", i, r.status, r.body)
		}
	}
	e.expect(e.doAs(alice, "GET", "/docs/.x.json.swp", ""), 200, "alice's swap file, kept")
	e.expect(e.doAs(k.Grant(t, e.s.Now(), "user:bob", []string{"other"}, []string{"read"}), "GET", "/", ""), 401, "a grant naming no served namespace")

	// A public namespace.
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "pub")))
	must(op.CreateNamespace(e.ctx, "pub", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	srv := must(dav.New(dav.Options{Client: e.s.Client(t), Namespaces: []string{"pub"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	g := &env{t: t, ctx: e.ctx, s: e.s, c: e.c, dav: hs}
	forged := clienttest.NewKey("k").Grant(t, e.s.Now(), "user:mallory", []string{"pub"}, []string{"read"})
	g.expect(g.doAs(forged, "PUT", "/pub/junk.swp", "x"), 401, "a forged grant for a public namespace")
	carol := k.Grant(t, e.s.Now(), "user:carol", []string{"pub"}, []string{"read", "create"})
	g.expect(g.doAs(carol, "PUT", "/pub/.swp", "x"), 201, "a valid one")
	g.expect(g.doAs(carol, "PUT", "/pub/a.json", `{"by": "carol"}`), 201, "and its write")
}

// Tokens of one person (attenuated offline, or minted again) are one user,
// with one scratch store, and at most MaxTokensPerPrincipal of them are
// kept: more push out only that user's tokens, never another user's
// state, and one pushed out is verified again when it comes back, to the
// same state. A user with a request in flight isn't pushed out, nor its
// scratch bytes lost to the server's budget.
func TestGatewayBounds(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.MaxPrincipals, o.MaxTokensPerPrincipal = 3, 2
		o.ScratchTotal, o.ScratchBytes, o.MaxFileSize = 3<<20, 2<<20, 2<<20
	})
	now := e.s.Now()
	bob := k.Grant(t, now, "user:bob", []string{"docs"}, []string{"read"})
	e.expect(e.doAs(bob, "PUT", "/docs/bob.swp", "b"), 201, "bob's scratch")
	var alices []string
	for i := 0; i < 3; i++ {
		a := k.Grant(t, now.Add(time.Duration(i)*time.Second), "user:alice", []string{"docs"}, []string{"read"})
		alices = append(alices, a)
		e.expect(e.doAs(a, "PUT", "/docs/alice.swp", "a"+strconv.Itoa(i)), 201, "alice's scratch")
	}
	e.expect(e.doAs(bob, "GET", "/docs/bob.swp", ""), 200, "bob's, kept")
	for i := range alices {
		if r := e.expect(e.doAs(alices[i], "GET", "/docs/alice.swp", ""), 200, "alice's"); r.body != "a2" {
			t.Fatalf("alice's scratch file through token %d: %q", i, r.body)
		}
	}

	// p's PUT is in flight while two others come and go.
	p := k.Grant(t, now, "user:p", []string{"docs"}, []string{"read"})
	pr, pw := io.Pipe()
	req := must(http.NewRequest("PUT", e.dav.URL+"/docs/big.swp", pr))
	req.SetBasicAuth("u", p)
	done := make(chan int)
	go func() {
		res, err := testHTTP.Do(req)
		if err != nil {
			done <- -1
			return
		}
		res.Body.Close()
		done <- res.StatusCode
	}()
	pw.Write([]byte(strings.Repeat("A", 1000)))
	for _, u := range []string{"user:q", "user:r", "user:s"} {
		e.doAs(k.Grant(t, now, u, []string{"docs"}, []string{"read"}), "GET", "/docs/none.swp", "")
	}
	pw.Write([]byte(strings.Repeat("A", 2<<20-1000)))
	pw.Close()
	if st := <-done; st != 201 {
		t.Fatalf("p's PUT: %d", st)
	}
	e.expect(e.doAs(p, "GET", "/docs/big.swp", ""), 200, "p's file")
	e.expect(e.doAs(p, "DELETE", "/docs/big.swp", ""), 204, "p's file deleted")
	e.expect(e.doAs(k.Grant(t, now, "user:t", []string{"docs"}, []string{"read"}), "PUT", "/docs/x.swp", strings.Repeat("B", 2<<20)), 201, "the budget is whole")
}

// A root listing names the served namespaces without reading them, so a
// grant that reads only some of them still mounts; the others refuse when
// opened. A tree's folder leaves out the files whose items the grant
// doesn't read (§B.11.5: nothing hidden shows).
func TestGatewayPartialGrant(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	for _, ns := range []string{"secret", "cat"} {
		op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, ns)))
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["catalog"] = treeCatalog("docs", "secret")
		}
		must(op.CreateNamespace(e.ctx, ns, doc))
	}
	w := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:admin", []string{"secret", "cat"}, []string{"read", "create"})))
	e.create("docs", "a", map[string]any{"v": 1})
	must(w.CreateDoc(e.ctx, "secret", "s", map[string]any{"v": 2}))
	must(w.CreateDoc(e.ctx, "cat", "root", map[string]any{"parents": []any{}}))
	for _, n := range []string{"docs.a", "secret.s"} {
		must(w.CreateDoc(e.ctx, "cat", n, map[string]any{"title": n + ".json", "parents": parents("cat", "root")}))
	}
	srv := must(dav.New(dav.Options{Client: e.s.Client(t), Namespaces: []string{"docs", "secret"}, Catalogs: []string{"cat"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	g := &env{t: t, ctx: e.ctx, s: e.s, c: e.c, dav: hs, pw: k.Grant(t, e.s.Now(), "user:alice", []string{"docs", "cat"}, []string{"read"})}
	sameStrings(t, "root", names(g.propfind("/"), "/"), []string{"cat/", "docs/", "secret/"})
	sameStrings(t, "docs", names(g.propfind("/docs/"), "/docs/"), []string{"a.json"})
	if r := g.do("PROPFIND", "/secret/", "", "Depth", "1"); r.status != 403 {
		t.Fatalf("PROPFIND /secret/: %d %s", r.status, r.body)
	}
	sameStrings(t, "cat", names(g.propfind("/cat/"), "/cat/"), []string{"docs.a.json"})
}

// A grant the core refuses for its key's scope (a lifetime over the
// key's maxTtl, a sub outside its pattern) reads as 404 there, as a
// namespace the grant can't see: that isn't an acceptance. Nothing is
// kept for it, in a namespace that isn't public or one that is.
func TestGatewayScopeRefused(t *testing.T) {
	t.Parallel()
	e, _ := authEnv(t, true)
	k2, k3 := clienttest.NewKey("k2"), clienttest.NewKey("k3")
	for _, ns := range []string{"scoped", "pub"} {
		ttl := k2.Entry("read", "create", "append")
		ttl["maxTtl"] = "PT15M"
		subs := k3.Entry("read", "create", "append")
		subs["sub"] = "partner:.*"
		read := "grant"
		if ns == "pub" {
			read = "public"
		}
		op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, ns)))
		must(op.CreateNamespace(e.ctx, ns, map[string]any{"read": read, "keys": []any{ttl, subs}}))
	}
	srv := must(dav.New(dav.Options{Client: e.s.Client(t), Namespaces: []string{"scoped", "pub"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	g := &env{t: t, ctx: e.ctx, s: e.s, c: e.c, dav: hs}
	for _, ns := range []string{"scoped", "pub"} {
		for what, tok := range map[string]string{
			"over maxTtl":          k2.Grant(t, e.s.Now(), "user:mallory", []string{ns}, []string{"read"}),
			"outside the sub rule": k3.Grant(t, e.s.Now(), "user:mallory", []string{ns}, []string{"read"}),
		} {
			r := g.doAs(tok, "PUT", "/"+ns+"/.junk", "x")
			if r.status != 401 || !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Basic") {
				t.Errorf("%s, %s: %d %s", ns, what, r.status, r.body)
			}
		}
	}
	// Within the key's scope, it is accepted.
	ok := k2.Grant(t, e.s.Now(), "user:alice", []string{"scoped"}, []string{"read"}, map[string]any{"exp": e.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	g.expect(g.doAs(ok, "PUT", "/scoped/.swp", "x"), 201, "a grant within the key's scope")
}

// Asked again, a grant the key's scope no longer covers is refused, as a
// revoked one is (TestGatewayRevokedToken).
func TestGatewayReverify(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	cr := must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, []string{"read", "create", "append", "config"})))
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf, Now: clock, VerifyEvery: time.Minute}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, c: admin, dav: hs}
	alice := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, []string{"read"})
	bob := k.Grant(t, s.Now(), "user:bob", []string{"docs"}, []string{"read"})
	e.expect(e.doAs(alice, "PUT", "/docs/.swp", "alice"), 201, "alice's scratch")
	e.expect(e.doAs(bob, "PUT", "/docs/.swp", "bob"), 201, "bob's scratch")
	ent := k.Entry("*")
	ent["sub"] = "user:(admin|bob)"
	must(admin.PatchConfig(ctx, "docs", cr.Config, []any{map[string]any{"op": "replace", "path": "/keys/0", "value": ent}}))
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	e.expect(e.doAs(alice, "GET", "/docs/.swp", ""), 401, "alice, out of the key's scope")
	if r := e.expect(e.doAs(bob, "GET", "/docs/.swp", ""), 200, "bob, in it"); r.body != "bob" {
		t.Fatalf("bob's scratch %q", r.body)
	}
}

// A namespace made public is public at once to verification: a forged
// grant, which its reads ignore, isn't taken as accepted for the minute
// the gateway took it for private.
func TestGatewayPublicityChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	cr := must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, []string{"read", "config"})))
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, c: admin, dav: hs}
	alice := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, []string{"read"})
	e.expect(e.doAs(alice, "PROPFIND", "/", "", "Depth", "0"), 207, "alice")
	must(admin.PatchConfig(ctx, "docs", cr.Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "public"}}))
	for i := 0; i < 3; i++ {
		forged := clienttest.NewKey("x").Grant(t, s.Now(), "user:mallory"+strconv.Itoa(i), []string{"docs"}, []string{"read"})
		e.expect(e.doAs(forged, "PUT", "/docs/junk.swp", "x"), 401, "a forged grant after the namespace turned public")
	}
	carol := k.Grant(t, s.Now(), "user:carol", []string{"docs"}, []string{"read"})
	e.expect(e.doAs(carol, "PUT", "/docs/.swp", "x"), 201, "a valid one")
}

// A user is the sub and kid GET /ns/{ns}/principal names, with the
// namespace whose key verified the grant (a kid names a key of one
// namespace's document): a key of the same kid in another served
// namespace mints grants for the same sub that are another user's, which
// share none of the first one's state, push out none of its tokens, nor
// fill its scratch quota.
func TestGatewayRootPerNamespace(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	evil := clienttest.NewKey("k")
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "other")))
	must(op.CreateNamespace(e.ctx, "other", map[string]any{"read": "grant", "keys": []any{evil.Entry("*")}}))
	srv := must(dav.New(dav.Options{Client: e.s.Client(t), Namespaces: []string{"docs", "other"}, Gateway: true, Logf: t.Logf,
		MaxTokensPerPrincipal: 2, ScratchBytes: 1 << 20, MaxFileSize: 1 << 20}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	g := &env{t: t, ctx: e.ctx, s: e.s, c: e.c, dav: hs}
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	g.expect(g.doAs(alice, "PUT", "/docs/.a.json.swp", "alice's unsaved work"), 201, "alice's swap")
	for i := 0; i < 3; i++ {
		tok := evil.Grant(t, e.s.Now().Add(time.Duration(i)*time.Second), "user:alice", []string{"other"}, []string{"read"})
		g.expect(g.doAs(tok, "PUT", "/other/fill.swp", strings.Repeat("F", 400<<10)), 201, "the other namespace's alice")
	}
	if r := g.expect(g.doAs(alice, "GET", "/docs/.a.json.swp", ""), 200, "alice's swap, kept"); r.body != "alice's unsaved work" {
		t.Fatalf("alice's swap %q", r.body)
	}
}

// Before a grant is verified, the gateway says nothing of what it serves,
// and a self-signed grant naming every namespace costs the core a few
// requests, not one per namespace served; a refused grant presented again
// soon costs none.
func TestGatewayPreauth(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			h.ServeHTTP(w, r)
		})
	}})
	ctx := context.Background()
	k := clienttest.NewKey("k")
	var nss []string
	for i := 0; i < 6; i++ {
		ns := "ns" + strconv.Itoa(i)
		nss = append(nss, ns)
		op := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
		must(op.CreateNamespace(ctx, ns, map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	}
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: nss, Catalogs: []string{"secret-cat"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, dav: hs}
	self := clienttest.NewKey("x").Grant(t, s.Now(), "x", []string{"nope"}, []string{"read"})
	r := e.expect(e.doAs(self, "GET", "/", ""), 401, "a self-signed grant naming nothing served")
	if strings.Contains(r.body, "ns0") || strings.Contains(r.body, "secret-cat") {
		t.Fatalf("401 %q", r.body)
	}
	star := func(i int) string {
		return clienttest.NewKey("x").Grant(t, s.Now(), "x"+strconv.Itoa(i), []string{"*"}, []string{"read"})
	}
	e.expect(e.doAs(star(-1), "GET", "/", ""), 401, "warm the publicity cache")
	calls.Store(0)
	for i := 0; i < 10; i++ {
		e.expect(e.doAs(star(i), "GET", "/", ""), 401, "a forged grant naming everything")
	}
	if n := calls.Load(); n > 30 {
		t.Fatalf("10 forged grants: %d requests to the core", n)
	}
	again := star(99)
	e.expect(e.doAs(again, "GET", "/", ""), 401, "a forged grant")
	calls.Store(0)
	for i := 0; i < 5; i++ {
		e.expect(e.doAs(again, "GET", "/", ""), 401, "the same forged grant again")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("a refused grant again: %d requests to the core", n)
	}
}

// Locks are bounded: an owner is at most 1 KiB, a lock's timeout at most
// the scratch idle time (Infinite too), and a principal holds at most
// MaxLocks of them, so a read-only grant can't pin memory with them.
func TestGatewayLockBounds(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.MaxLocks = 3 })
	reader := k.Grant(t, e.s.Now(), "user:mallory", []string{"docs"}, []string{"read"})
	for i := 0; i < 5; i++ {
		e.create("docs", "f"+strconv.Itoa(i), map[string]any{"v": i})
	}
	lock := func(owner string) string {
		return `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>` + owner + `</D:owner></D:lockinfo>`
	}
	e.expect(e.doAs(reader, "LOCK", "/docs/f0.json", lock(strings.Repeat("A", 2048)), "Timeout", "Infinite", "Depth", "0"), 400, "LOCK with a 2 KiB owner")
	r := e.expect(e.doAs(reader, "LOCK", "/docs/f0.json", lock("me"), "Timeout", "Infinite", "Depth", "0"), 200, "LOCK")
	if !strings.Contains(r.body, "Second-3600") {
		t.Fatalf("LOCK Infinite: %s", r.body)
	}
	tok := r.header.Get("Lock-Token")
	for i := 1; i < 3; i++ {
		e.expect(e.doAs(reader, "LOCK", "/docs/f"+strconv.Itoa(i)+".json", lock("me"), "Depth", "0"), 200, "LOCK")
	}
	e.expect(e.doAs(reader, "LOCK", "/docs/f3.json", lock("me"), "Depth", "0"), 507, "a lock over MaxLocks")
	e.expect(e.doAs(reader, "UNLOCK", "/docs/f0.json", "", "Lock-Token", tok), 204, "UNLOCK")
	e.expect(e.doAs(reader, "LOCK", "/docs/f3.json", lock("me"), "Depth", "0"), 200, "LOCK after an UNLOCK")
}

// One grant root holds at most a share of the bytes buffered for writes
// at once: stalled uploads of one user don't make every other user's
// saves a 503.
func TestGatewayInflightShare(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) {
		o.MaxFileSize, o.MaxRawSize = 1<<20, 1<<20
		o.InflightBytes = 2 << 20
	})
	now := e.s.Now()
	mallory := k.Grant(t, now, "user:mallory", []string{"docs"}, []string{"read"})
	alice := k.Grant(t, now, "user:alice", []string{"docs"}, []string{"read", "create", "append"})
	var pws []*io.PipeWriter
	done := make(chan struct{}, 2)
	defer func() {
		for _, pw := range pws {
			pw.CloseWithError(io.ErrUnexpectedEOF)
		}
		for range pws {
			<-done
		}
	}()
	for i := 0; i < 2; i++ {
		pr, pw := io.Pipe()
		pws = append(pws, pw)
		req := must(http.NewRequest("PUT", e.dav.URL+"/docs/slow"+strconv.Itoa(i)+".swp", pr))
		req.SetBasicAuth("u", mallory)
		go func() {
			defer func() { done <- struct{}{} }()
			if res, err := testHTTP.Do(req); err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
		go pw.Write([]byte(strings.Repeat("A", 1<<20-1)))
	}
	time.Sleep(300 * time.Millisecond)
	e.expect(e.doAs(alice, "PUT", "/docs/n.json", `{"pad": "`+strings.Repeat("x", 40000)+`"}`), 201, "alice's PUT while mallory stalls")
}

// Request bodies other than a PUT's are at most 64 KiB: x/net/webdav
// decodes them whole, a property at a time, and a PROPPATCH of 1 MiB of
// empty properties took gigabytes to answer.
func TestXMLBodyBound(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	reader := k.Grant(t, e.s.Now(), "user:mallory", []string{"docs"}, []string{"read"})
	e.expect(e.doAs(reader, "PUT", "/docs/x.swp", "x"), 201, "scratch")
	pp := func(n int) string {
		var b strings.Builder
		b.WriteString(`<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>`)
		for b.Len() < n {
			b.WriteString("<a/>")
		}
		b.WriteString(`</D:prop></D:set></D:propertyupdate>`)
		return b.String()
	}
	e.expect(e.doAs(reader, "PROPPATCH", "/docs/x.swp", pp(100<<10)), 413, "PROPPATCH of 100 KiB")
	e.expect(e.doAs(reader, "PROPPATCH", "/docs/x.swp", pp(32<<10)), 207, "PROPPATCH of 32 KiB")
}

// In a gateway, nothing is kept for a user in a served namespace their
// grant doesn't name, which they can't list: scratch files and
// directories there are refused, as in a catalog the core's refusal of
// its tree refuses them.
func TestGatewayScratchUnnamed(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true, func(o *dav.Options) { o.Namespaces = []string{"docs", "secret"} })
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "secret")))
	must(op.CreateNamespace(e.ctx, "secret", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	carol := k.Grant(t, e.s.Now(), "user:carol", []string{"secret"}, []string{"read", "create", "append"})
	e.expect(e.doAs(carol, "PROPFIND", "/docs/", "", "Depth", "1"), 403, "carol lists docs")
	e.expect(e.doAs(carol, "PUT", "/docs/.scratch.swp", "x"), 403, "carol's scratch file in docs")
	e.expect(e.doAs(carol, "MKCOL", "/docs/.TemporaryItems", ""), 403, "carol's scratch directory in docs")
	e.expect(e.doAs(carol, "GET", "/docs/.scratch.swp", ""), 404, "carol's scratch file in docs, kept")
	e.expect(e.doAs(carol, "PUT", "/secret/.scratch.swp", "x"), 201, "carol's scratch file in secret")
	e.expect(e.doAs(carol, "MOVE", "/secret/.scratch.swp", "", "Destination", "/docs/.moved"), 403, "carol's scratch file moved to docs")
	e.expect(e.doAs(carol, "PUT", "/.DS_Store", "x"), 201, "carol's scratch file at the root")
}

// In a gateway, a PUT of a new file in a tree is checked by a dry run of
// its placement with the user's grant (§7.5) before its item is created:
// a catalog the grant reads but can't write (its role there allows only
// read) refuses it, and nothing is written; one it writes takes it. A
// DELETE whose grant doesn't delete in files.ns deletes the placement and
// leaves the item (§H.5).
func TestGatewayPlacementRefusedByGrant(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	ctx := context.Background()
	k := clienttest.NewKey("k")
	member := func(can ...any) map[string]any { return map[string]any{"member": map[string]any{"can": can}} }
	for ns, doc := range map[string]map[string]any{
		"matches": {"read": "grant", "keys": []any{k.Entry("*")}, "roles": member("read", "create", "append")},
		"cat":     {"read": "grant", "keys": []any{k.Entry("*")}, "roles": member("read", "create", "append", "delete"), "catalog": treeCatalog("matches")},
		"ro":      {"read": "grant", "keys": []any{k.Entry("*")}, "roles": member("read"), "catalog": treeCatalog("matches")},
	} {
		op := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
		must(op.CreateNamespace(ctx, ns, doc))
	}
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"matches", "cat", "ro"}, []string{"read", "create", "append"})))
	for _, cat := range []string{"cat", "ro"} {
		must(admin.CreateDoc(ctx, cat, "root", map[string]any{"parents": []any{}}))
	}
	srv := must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"matches"}, Catalogs: []string{"cat", "ro"}, Gateway: true, Logf: t.Logf}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, c: admin, dav: hs}
	alice := k.Grant(t, s.Now(), "user:alice", []string{"matches", "cat", "ro"}, nil, map[string]any{"roles": []any{"member"}})
	sameStrings(t, "ro", names(e.propfindAs(alice, "/ro/"), "/ro/"), nil)
	e.expect(e.doAs(alice, "PUT", "/ro/refused.json", `{"title": "Refused"}`), 403, "PUT of a file in a tree the grant only reads")
	sameStrings(t, "matches", e.liveNames("matches"), nil)
	e.expect(e.doAs(alice, "PUT", "/cat/taken.json", `{"title": "Taken"}`), 201, "PUT of a file in a tree the grant writes")
	node, _ := e.titled("cat", "taken.json")
	_, item, _ := strings.Cut(node, ".")
	_, doc := e.load("matches", item)
	sameJSON(t, doc, map[string]any{"title": "Taken"})
	if en := e.lastEntry("cat", node); en.Grant == nil || en.Grant.Sub != "user:alice" {
		t.Fatalf("placement entry %+v", en)
	}
	e.expect(e.doAs(alice, "DELETE", "/cat/taken.json", ""), 204, "DELETE without delete in files.ns")
	e.expectTombstoned("cat", node, "the placement")
	if h, _ := e.load("matches", item); h.State != client.Live {
		t.Fatalf("an item the grant can't delete is %v", h.State)
	}
}
