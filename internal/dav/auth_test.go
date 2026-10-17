package dav_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
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
// Scratch files are per grant.
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
	if !strings.Contains(r.body, "403") {
		t.Fatalf("403 text %q", r.body)
	}
	sameStrings(t, "bob's listing", names(e.propfindAs(bob, "/docs/"), "/docs/"), []string{"a.json"})

	// Scratch files are each grant's own.
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

// A gateway keeps MaxPrincipals principals, dropping the least recently
// seen with its scratch files.
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
	e.expect(e.doAs(g["a"], "PUT", "/docs/.scratch", "a"), 201, "a's scratch")
	e.expect(e.doAs(g["b"], "PUT", "/docs/.scratch", "b"), 201, "b's scratch")
	e.expect(e.doAs(g["a"], "GET", "/docs/.scratch", ""), 200, "a again")
	e.expect(e.doAs(g["c"], "PUT", "/docs/.scratch", "c"), 201, "c's scratch")
	for _, u := range []string{"a", "c"} {
		if r := e.expect(e.doAs(g[u], "GET", "/docs/.scratch", ""), 200, u+" kept"); r.body != u {
			t.Fatalf("%s's scratch %q", u, r.body)
		}
	}
	// b comes back as a new principal, without its scratch file (and a,
	// now the least recently seen, goes).
	e.expect(e.doAs(g["b"], "GET", "/docs/.scratch", ""), 404, "b, dropped")
}
