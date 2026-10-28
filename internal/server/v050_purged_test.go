package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// expectPurgedBase expects the 410 "purged" of a remote branch whose base,
// or a base in its chain, is purged at A: origin, ns and head name the
// purged namespace and its purge-ns entry there (§G.3, §12).
func expectPurgedBase(t *testing.T, r *resp, ns, head string) {
	t.Helper()
	expectPurged(t, r, head)
	if r.Str("origin") != originA || r.Str("ns") != ns {
		t.Fatalf("origin and ns of %s, want %s and %s", r.Body, originA, ns)
	}
}

// purgeNSAs freezes ns and purges it under bearer, returning the purge-ns
// entry's ns_id.
func (e *tenv) purgeNSAs(ns, bearer string) string {
	e.t.Helper()
	expect(e.t, e.patchNS(ns, ops(op("add", "/frozen", true)), bearer), 201)
	expect(e.t, e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns, bearer), bearer: bearer}), 204)
	return e.nsHead(ns, bearer)
}

// v0.50 §G.3, §12: a remote branch of a purged base is 410 "purged", with
// origin, ns and head naming the purged namespace at A and its purge-ns
// entry, for any at, as for a local branch of it (§7.6): the purge itself,
// one before it, and one A doesn't know or that isn't in its chain (A's
// /heads is 410 at any revision, §8.5). Nothing is written on B, and a
// name taken on B is still 412 before anything is fetched.
func TestV050RemoteBranchOfPurgedBase(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateA(t, a)
	notInChain := a.nsHead("schemas")
	head := a.nsPurge("main")
	for _, c := range []struct{ name, at string }{
		{"at the purge", head},
		{"before the purge", f.at},
		{"unknown", hashID(t, "", nil)},
		{"not in its chain", notInChain},
	} {
		// The local branch answers the same.
		expectPurged(t, a.branch("main", map[string]any{"name": "loc", "at": c.at, "patches": []any{}}, "admin"), head)
		r := b.mkRemote("rel", remoteGenesis("main", c.at, nil))
		if r.Code != 410 {
			t.Fatalf("%s: %d %s", c.name, r.Code, r.Body)
		}
		expectPurgedBase(t, r, "main", head)
		if b.get("/ns/rel").Code != 404 || b.get("/ns/schemas").Code != 404 {
			t.Fatalf("%s: written on B", c.name)
		}
	}
	b.mkNS("taken", map[string]any{"read": "public"})
	rt.set("http://127.0.0.1:1", "") // A unreachable: nothing may be fetched
	expectCode(t, b.mkRemote("taken", remoteGenesis("main", f.at, nil)), 412, "stale")
}

// v0.50 §G.3: in a chain, the purged namespace found first is named, A
// before its bases: a base can't be purged while A lives (§8.5), so A's
// /heads answers first. A base further up that answers 410 purged is named
// by its own URLs.
func TestV050RemoteBranchOfPurgedChain(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateChain(t, a)

	// A 410 purged for /r/matches/… names matches, with its head.
	rt.set(purging(t, a, "/r/matches/", "1abc"), "")
	expectPurgedBase(t, b.mkRemote("rel", remoteGenesisChain(r7Chain, f.atA, nil)), "matches", "1abc")
	expect(t, b.get("/ns/rel"), 404)

	rt.set(a.srv.URL, "")
	h7 := a.nsPurge("r7")
	a.nsPurge("matches")
	expectPurgedBase(t, b.mkRemote("rel", remoteGenesisChain(r7Chain, f.atA, nil)), "r7", h7)
	expect(t, b.get("/ns/rel"), 404)
}

// purging serves A through a proxy that answers 410 purged, with head, for
// paths containing match.
func purging(t *testing.T, a *tenv, match, head string) string {
	t.Helper()
	u, err := url.Parse(a.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, match) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(410)
			w.Write([]byte(`{"code":"purged","head":"` + head + `"}`))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	return p.URL
}

// v0.50 §G.3, §8.5: the 410 shows only to an endpoint grant that passes
// A's read check; one that can't read the purged namespace gets the 422 of
// a base B can't read.
func TestV050RemoteBranchOfPurgedBaseReadCheck(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv))
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("p", map[string]any{"read": "grant", "keys": []any{kA.entry("*")}})
	root := a.grant(kA, "user:root", []string{"p"}, allVerbs)
	a.create("p", "d", map[string]any{"v": 1.0}, root)
	at := a.nsHead("p", root)
	head := a.purgeNSAs("p", root)

	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"p"}, []string{"append"})}
	b := newEnv(t, withOrigin(originB), withRemote(rt))
	genesis := remoteGenesis("p", at, map[string]any{"read": "grant"})
	expectCode(t, b.mkRemote("rel", genesis), 422, "invalid")
	rt.set(a.srv.URL, a.grant(kA, "svc:b", []string{"p"}, []string{"read"}))
	expectPurgedBase(t, b.mkRemote("rel", genesis), "p", head)
	expect(t, b.get("/ns/rel"), 404)
}

// v0.50 §G.3: a purged sealed base is 410 purged too, from A's /heads,
// which B reads before the logs it would need A's keys for.
func TestV050RemoteBranchOfPurgedSealedBase(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := a.grant(kA, "user:root", []string{"s"}, allVerbs)
	a.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": encMarker})), root)
	at := a.nsHead("s", root)
	head := a.purgeNSAs("s", root)

	bJWK, bPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bPriv
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"s"}, []string{"read", "export"}, map[string]any{"enc": bJWK})}
	b := newEnv(t, withOrigin(originB), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning)
	sealed := map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}}
	for name, at := range map[string]string{"at the purge": head, "before the purge": at} {
		r := b.mkRemote("rel", remoteGenesis("s", at, sealed))
		if r.Code != 410 {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body)
		}
		expectPurgedBase(t, r, "s", head)
	}
	expect(t, b.get("/ns/rel"), 404)
}

// v0.50 §G.3, §6.1: a schema namespace B would mirror isn't in the base's
// chain: if it is purged at A (forced past in_use), creation is 422
// schema_unavailable naming the revision, not 410, and nothing is written.
func TestV050RemoteBranchPurgedSchemaNamespace(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	f := populateA(t, a)
	expect(t, a.patchNS("schemas", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, a.do(req{method: "POST", path: "/ns/schemas/purge?force=1", ifMatch: a.nsHead("schemas"), author: "admin"}), 204)
	r := b.mkRemote("rel", remoteGenesis("main", f.at, nil))
	expectCode(t, r, 422, "schema_unavailable")
	if ref := r.Str("ref"); ref != "/r/schemas/match/rev/"+f.s2 && ref != "/r/schemas/match/rev/"+f.s1 {
		t.Fatalf("ref of %s", r.Body)
	}
	if b.get("/ns/rel").Code != 404 || b.get("/ns/schemas").Code != 404 {
		t.Fatal("written on B")
	}
}

// v0.50 §8.5: a purged namespace's URLs answer 410 as soon as the full read
// check passes, the grant's rules included, and before any other answer to
// a well-formed request: 404 for an unknown id, not_offered for the
// gestures listing of a sealed namespace. A grant whose rules refuse the
// read still gets its refusal, and a malformed request its 400.
func TestV050PurgedReadCheck(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a0 := e.create("sec", "a", map[string]any{}, f.adminG)
	e.create("sec", "b", map[string]any{}, f.adminG)
	gid := grantIDOf(t, f.adminG)
	at := e.nsHead("sec", f.adminG)
	head := e.purgeNSAs("sec", f.adminG)
	unknown := hashID(t, "", nil)
	readOnly := func(name string) string {
		return e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{
			map[string]any{"op": "test", "path": "/resource", "value": name}}})
	}
	onlyA, onlyB := readOnly("a"), readOnly("b")
	appendOnly := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"})

	for _, c := range []struct {
		path, bearer string
		code         int // 0: 410 purged
	}{
		// Resource URLs: read on that resource.
		{"/r/sec/a", onlyB, 404},
		{"/r/sec/a", onlyA, 0},
		{"/r/sec/a/rev/" + a0, onlyB, 404},
		{"/r/sec/a/rev/" + a0, onlyA, 0},
		{"/r/sec/a/rev/" + unknown, onlyA, 0},
		{"/r/sec/a/rev/" + a0 + "/log", onlyA, 0},
		// /heads and grants: unrestricted read (403 otherwise, v0.74), then
		// 410 for unknown ids too.
		{"/ns/sec/rev/" + at + "/heads", onlyA, 403},
		{"/ns/sec/rev/" + at + "/heads", f.adminG, 0},
		{"/ns/sec/rev/" + unknown + "/heads", f.adminG, 0},
		{"/ns/sec/grants/" + gid, onlyA, 403},
		{"/ns/sec/grants/" + gid, f.adminG, 0},
		{"/ns/sec/grants/" + grantIDOf(t, appendOnly), f.adminG, 0},
		// The gestures listing: any read.
		{"/ns/sec/gestures/" + gA, "", 401},
		{"/ns/sec/gestures/" + gA, appendOnly, 403},
		{"/ns/sec/gestures/" + gA, onlyA, 0},
		// Not well-formed: the request's shape comes first.
		{"/r/sec/a?bogus=1", onlyA, 400},
	} {
		r := e.get(c.path, c.bearer)
		if c.code == 0 {
			if r.Code != 410 || r.Str("code") != "purged" || r.Str("head") != head || r.Obj()["ns"] != nil {
				t.Errorf("%s: %d %s, want 410 purged with head %s", c.path, r.Code, r.Body, head)
			}
		} else if r.Code != c.code {
			t.Errorf("%s: %d %s, want %d", c.path, r.Code, r.Body, c.code)
		}
	}

	// A sealed namespace's gestures listing, which a live one doesn't
	// offer: 410 for a grant whose rules read one resource only.
	s := newSealedAuthEnv(t)
	k := newKey("admin")
	s.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	admin := s.grant(k, "user:root", []string{"s"}, allVerbs)
	one := s.grant(k, "user:r", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	expectCode(t, s.get("/ns/s/gestures/"+gA, one), 404, "not_offered")
	sh := s.purgeNSAs("s", admin)
	expectPurged(t, s.get("/ns/s/gestures/"+gA, one), sh)
}
