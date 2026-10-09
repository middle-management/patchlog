package server

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// v0.47 §C.5 "The stream is metadata": /ns/{ns} and everything under it
// but the gestures listing need unrestricted read, while a resource's own
// URLs, its events included, need read on that resource only. Roles are
// alternatives: one read role without /resource rules is enough, for
// branching (§7.6) and remote registration (§G.3) too.
func TestV047UnrestrictedRead(t *testing.T) {
	t.Parallel()
	onlyA := []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}
	f := newAuthFixture(t, map[string]any{"roles": map[string]any{
		"one":      map[string]any{"can": []any{"read"}, "rules": onlyA},
		"all":      map[string]any{"can": []any{"read", "branch", "export"}},
		"brancher": map[string]any{"can": []any{"branch", "export"}},
	}})
	e := f.tenv
	hdr := map[string]string{"Gesture": gA}
	a0 := etagOf(e.do(req{method: "PATCH", path: "/r/sec/a", ifNoneMatch: "*", body: addRoot(map[string]any{"n": 0.0}), bearer: f.adminG, hdr: hdr}))
	e.do(req{method: "PATCH", path: "/r/sec/b", ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: f.adminG, hdr: hdr})
	head := e.nsHead("sec", f.adminG)
	nsURLs := []string{"/ns/sec", "/ns/sec/rev/" + head, "/ns/sec/rev/" + head + "/log", "/ns/sec/rev/" + head + "/heads",
		"/ns/sec/log", "/ns/sec/log?live=long-poll", "/ns/sec/events", "/ns/sec/branches", "/ns/sec/grants/" + grantIDOf(t, f.adminG)}

	// A rule that hides b without fixing a used to pass on /ns/sec, which
	// would list b; such a grant, and one fixed to a, read a alone.
	hideB := e.grant(f.issuer, "user:h", []string{"sec"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "b"}}}})
	fixed := e.grant(f.issuer, "user:x", []string{"sec"}, []string{"read"}, map[string]any{"rules": onlyA})
	oneRole := e.grant(f.admin, "user:o", []string{"sec"}, nil, map[string]any{"roles": []any{"one", "brancher"}})
	status := func(p, g string) int {
		if p != "/ns/sec/events" {
			return e.get(p, g).Code
		}
		// A stream that stays open once admitted.
		_, resp, cancel := e.openSSE(p, map[string]string{"Authorization": "Bearer " + g})
		cancel()
		return resp.StatusCode
	}
	for _, g := range []string{hideB, fixed, oneRole} {
		expect(t, e.get("/r/sec/a", g), 302)
		expect(t, e.get("/r/sec/b", g), 404)
		for _, p := range nsURLs {
			// The answer of any other read it may not make.
			if c := status(p, g); c != 404 {
				t.Errorf("%s: %d", p, c)
			}
		}
		// The gestures listing answers it, filtered to what it reads.
		if r := e.get("/ns/sec/gestures/"+gA, g); r.Code != 200 || len(r.Arr()) != 1 {
			t.Fatalf("gestures: %d %s", r.Code, r.Body)
		}
	}
	for _, p := range nsURLs {
		expect(t, e.get(p), 401)
	}

	// The resource's own URLs, its events and long-poll included.
	a1 := e.appendRev("sec", "a", a0, ops(op("replace", "/n", 1.0)), f.adminG)
	expect(t, e.get("/r/sec/a/log?live=long-poll&since="+a0, fixed), 200)
	ch, resp, _ := e.openSSE("/r/sec/a/events?since="+a0, map[string]string{"Authorization": "Bearer " + fixed})
	if resp.StatusCode != 200 {
		t.Fatalf("resource events %d", resp.StatusCode)
	}
	if ev := next(t, ch); ev.event != "revision" || ev.id != a1 {
		t.Fatalf("event %v", ev)
	}
	expect(t, e.get("/r/sec/b/events", fixed), 404)

	// Branching and registration: refused without unrestricted read…
	at := e.nsHead("sec", f.adminG)
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-o"}, oneRole), 403, "forbidden")
	expectCode(t, e.register("sec", "rel-o", at, "", oneRole), 403, "forbidden")
	// …which one role listing read without /resource rules gives.
	roles := e.grant(f.admin, "user:r", []string{"sec", "sec-r"}, nil, map[string]any{"roles": []any{"one", "all"}})
	for _, p := range nsURLs {
		if c := status(p, roles); c >= 400 {
			t.Errorf("%s with a read role: %d", p, c)
		}
	}
	expect(t, e.branch("sec", map[string]any{"name": "sec-r"}, roles), 201)
	expect(t, e.register("sec", "rel-r", at, "", roles), 201)
}

// v0.47 §C.5, §E.2.3: only a grant that reads the namespace unrestricted
// gets epoch keys. A read role whose rule refers to /resource but passes
// without it (hiding b) doesn't count, even beside an unrestricted role
// that fails for the principal; such a grant gets per-resource keys.
func TestV047SealedKeysRoles(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("*")}, "roles": map[string]any{
		"notB":  map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "b"}}}},
		"staff": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/principal/id", "value": "user:staff"}}},
	}}))
	star := e.grant(k, "user:admin", []string{"s"}, []string{"create", "read"})
	e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": "a"})), star)
	b := e.wr("s", "b", "", withNonce(addRoot(map[string]any{"v": "b"})), star)
	docB := string(e.get("/r/s/b/rev/" + b).Body)

	roles := map[string]any{"roles": []any{"notB", "staff"}}
	x := e.grant(k, "user:x", []string{"s"}, nil, roles)
	keys, r := e.keysOf("s", map[string]any{"resources": []any{"a", "b"}}, x)
	expect(t, r, 200)
	if len(keys) != 1 || keys["s#1 a"] == nil {
		t.Fatalf("restricted role: %s", r.Body)
	}
	if _, err := seal.OpenExpect(docB, keys["s#1 a"], "s#1", seal.ResourcePL("s", "b", b, "doc")); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("K_a opened b: %v", err)
	}
	// Roles are alternatives: staff's passes, so it reads unrestricted.
	keys, r = e.keysOf("s", nil, e.grant(k, "user:staff", []string{"s"}, nil, roles))
	expect(t, r, 200)
	if len(keys) != 1 || keys["s#1"] == nil {
		t.Fatalf("unrestricted role: %s", r.Body)
	}
	open(t, docB, resKey(t, keys["s#1"], "s", "b"), "s#1", seal.ResourcePL("s", "b", b, "doc"))
	// Without a role that may pass per resource, it doesn't read the
	// namespace unrestricted: 403 (v0.49 §E.2.3).
	_, r = e.keysOf("s", nil, e.grant(k, "user:x", []string{"s"}, nil, map[string]any{"roles": []any{"staff"}}))
	expectCode(t, r, 403, "forbidden")
}

// v0.47 §7.6: branching needs unrestricted read on the base (§C.5) even
// when the base is public, so a grant limited to some resources, by a
// role or its key's readScope, may not branch it.
func TestV047BranchPublicBase(t *testing.T) {
	t.Parallel()
	rk := newKey("rk")
	rkEntry := rk.entry("read", "branch")
	rkEntry["readScope"] = "resource"
	f := newAuthFixture(t, map[string]any{"read": "public", "roles": map[string]any{
		"one":      map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}},
		"all":      map[string]any{"can": []any{"read"}},
		"brancher": map[string]any{"can": []any{"branch"}},
	}})
	e := f.tenv
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", rkEntry)), f.adminG), 201)
	oneRole := e.grant(f.admin, "user:o", []string{"sec"}, nil, map[string]any{"roles": []any{"one", "brancher"}})
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-o"}, oneRole), 403, "forbidden")
	scoped := e.grant(rk, "user:s", []string{"sec"}, []string{"read", "branch"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-s"}, scoped), 403, "forbidden")
	allRole := e.grant(f.admin, "user:a", []string{"sec", "sec-a"}, nil, map[string]any{"roles": []any{"one", "all", "brancher"}})
	expect(t, e.branch("sec", map[string]any{"name": "sec-a"}, allRole), 201)
}

// v0.47 §8.5: once a namespace is purged, every /r/{ns}/… URL,
// /ns/{ns}/grants/…, /ns/{ns}/gestures/… and /heads at any revision answer
// 410 "purged", reads with the long cache class (§9) but the no-store
// ones; /ns/{ns} and its log stay readable.
func TestV047PurgedNamespace(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	a0 := etagOf(e.gw("PATCH", "p", "a", "", addRoot(map[string]any{"n": 0.0}), map[string]string{"Gesture": gA}))
	bid := e.upload("p", "a", "text/plain", []byte("x"))
	old := e.nsHead("p")
	expect(t, e.patchNS("p", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/p/purge", ifMatch: e.nsHead("p"), author: "admin"}), 204)
	head := e.nsHead("p")
	for _, p := range []string{"/r/p/a", "/r/p/missing", "/r/p/a/rev/" + a0, "/r/p/a/rev/" + a0 + "/log", "/r/p/a/log",
		"/r/p/a/log?live=long-poll", "/r/p/a/blob/" + bid, "/ns/p/rev/" + head + "/heads", "/ns/p/rev/" + old + "/heads?after=a",
		"/ns/p/grants/" + a0} {
		r := e.get(p)
		expectCode(t, r, 410, "purged")
		if cc := r.H.Get("Cache-Control"); cc != ccLong {
			t.Errorf("%s: Cache-Control %q", p, cc)
		}
	}
	for _, p := range []string{"/r/p/a/events", "/ns/p/gestures/" + gA} {
		r := e.get(p)
		expectCode(t, r, 410, "purged")
		if cc := r.H.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", p, cc)
		}
	}
	expectCode(t, e.write("PATCH", "p", "a", a0, ops(op("add", "/x", 1.0))), 410, "purged")
	expectCode(t, e.putBlobAs("p", "a", bid, "text/plain", "", []byte("x")), 410, "purged")
	lg := e.get("/ns/p/rev/" + head + "/log").Arr()
	if k := lg[len(lg)-1].(map[string]any)["kind"]; k != "purge-ns" {
		t.Fatalf("last entry %v", k)
	}

	// /heads answers 410 after the read check.
	f := newAuthFixture(t, nil)
	ae := f.tenv
	ae.create("sec", "a", map[string]any{}, f.adminG)
	expect(t, ae.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG), 201)
	expect(t, ae.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: ae.nsHead("sec", f.adminG), bearer: f.adminG}), 204)
	heads := "/ns/sec/rev/" + ae.nsHead("sec", f.adminG) + "/heads"
	fixed := ae.grant(f.issuer, "user:x", []string{"sec"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	expect(t, ae.get(heads), 401)
	expect(t, ae.get(heads, fixed), 404)
	expectCode(t, ae.get(heads, f.adminG), 410, "purged")
	expectCode(t, ae.get("/r/sec/a", fixed), 410, "purged")
}

// v0.47 §6.6: a 429 carries retryAfter, the wait in seconds as a decimal,
// beside Retry-After in whole seconds rounded up; dry runs draw tokens as
// the submit would. Without authentication buckets are keyed by the
// author, and an allowance matches its sub alone, the first entry applying.
func TestV047RateLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public", "limits": map[string]any{
		"ratePerResource":  map[string]any{"rate": 4.0, "burst": 1.0},
		"ratePerPrincipal": map[string]any{"rate": 1.0, "burst": 3.0},
	}, "allowances": []any{
		map[string]any{"sub": "svc:imp", "kid": "k1", "bucket": map[string]any{"rate": 1.0, "burst": 5.0}},
		map[string]any{"sub": "svc:imp", "kid": "k2", "bucket": map[string]any{"rate": 1.0, "burst": 1.0}},
	}})
	h := e.create("docs", "a", map[string]any{"n": 0.0})
	r := e.write("PATCH", "docs", "a", h, ops(op("replace", "/n", 1.0)))
	expectCode(t, r, 429, "rate")
	if r.Str("limit") != "ratePerResource" || r.Obj()["retryAfter"] != 0.25 || r.H.Get("Retry-After") != "1" {
		t.Fatalf("429 %v %s", r.H, r.Body)
	}

	// Each dry run draws a token from bob's bucket (3), so the fourth
	// request, dry run or submit, is refused.
	batch := func(name string, dry bool) *resp {
		path := "/ns/docs/batch"
		if dry {
			path += "?dry-run=1"
		}
		return e.do(req{method: "POST", path: path, author: "bob", body: map[string]any{"items": []any{
			map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}})
	}
	for i := 0; i < 3; i++ {
		expect(t, batch("d"+strconv.Itoa(i), true), 200)
	}
	expectCode(t, batch("d3", true), 429, "rate")
	r = batch("d3", false)
	expectCode(t, r, 429, "rate")
	if r.Str("limit") != "ratePerPrincipal" || r.Obj()["retryAfter"] != 1.0 {
		t.Fatalf("429 %s", r.Body)
	}

	// The first allowance for svc:imp applies (burst 5, not 1); others
	// have a bucket per author.
	for i := 0; i < 5; i++ {
		e.create("docs", "imp"+strconv.Itoa(i), map[string]any{}, "svc:imp")
	}
	expectCode(t, e.write("PATCH", "docs", "imp5", "", addRoot(map[string]any{}), "svc:imp"), 429, "rate")
	for i := 0; i < 3; i++ {
		e.create("docs", "c"+strconv.Itoa(i), map[string]any{}, "carol")
	}
	expectCode(t, e.write("PATCH", "docs", "c3", "", addRoot(map[string]any{}), "carol"), 429, "rate")
	e.create("docs", "dave", map[string]any{}, "dave")
}

// v0.47 §C.4 "Operator grants": a request under one to a namespace that
// doesn't exist is 401, except a forced purge, which is 404. The ns check
// answers 403 first, and a purged namespace 410.
func TestV047OperatorGrantOrder(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	opG := func(ns string) string {
		return mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns},
			"can": []any{"purge", "purge-ns", "read", "config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	forced := func(path, ifMatch, bearer string) *resp {
		return e.do(req{method: "POST", path: path + "?force=1", ifMatch: ifMatch, bearer: bearer})
	}
	// A namespace that doesn't exist.
	expectCode(t, e.get("/ns/nope", opG("nope")), 401, "unauthenticated")
	expectCode(t, e.get("/r/nope/a", opG("nope")), 401, "unauthenticated")
	expectCode(t, e.purge("nope", "a", a, opG("nope")), 401, "unauthenticated")
	expectCode(t, forced("/r/nope/a/purge", a, opG("nope")), 404, "not_found")
	expectCode(t, forced("/ns/nope/purge", a, opG("nope")), 404, "not_found")
	// The ns check comes first.
	expectCode(t, e.get("/ns/nope", opG("other")), 403, "forbidden")
	expectCode(t, forced("/r/nope/a/purge", a, opG("other")), 403, "forbidden")
	expectCode(t, forced("/ns/nope/purge", a, opG("other")), 403, "forbidden")
	expectCode(t, forced("/r/sec/a/purge", a, opG("other")), 403, "forbidden")
	// A purged namespace: 410 for the forced purges it authorises.
	expect(t, e.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG), bearer: f.adminG}), 204)
	expectCode(t, forced("/r/sec/a/purge", a, opG("sec")), 410, "purged")
	expectCode(t, forced("/ns/sec/purge", e.nsHead("sec", f.adminG), opG("sec")), 410, "gone")
	expectCode(t, forced("/r/sec/a/purge", a, opG("other")), 403, "forbidden")
	expectCode(t, e.purge("sec", "a", a, opG("sec")), 401, "unauthenticated")
	expectCode(t, e.get("/ns/sec", opG("sec")), 401, "unauthenticated")
}

// v0.47 §C.4 "Keys follow the base": a kid the base adds hides the
// branch's own entry only while the base has it, and a kid copied from
// the base at creation never falls back.
func TestV047KeysFallBack(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.adminG), 201)
	removeKey := func(kid string) {
		t.Helper()
		for i, k := range e.nsDoc("sec", f.adminG)["keys"].([]any) {
			if k.(map[string]any)["kid"] == kid {
				expect(t, e.patchNS("sec", ops(map[string]any{"op": "remove", "path": "/keys/" + strconv.Itoa(i)}), f.adminG), 201)
				return
			}
		}
		t.Fatalf("no key %s", kid)
	}

	own, base := newKey("dup"), newKey("dup")
	expect(t, e.patchNS("sec-b", ops(op("add", "/keys/-", own.entry("read"))), f.adminG), 201)
	ownG := e.grant(own, "user:d", []string{"sec-b"}, []string{"read"})
	baseG := e.grant(base, "user:d", []string{"sec-b"}, []string{"read"})
	expect(t, e.get("/r/sec-b/a", ownG), 302)
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", base.entry("read"))), f.adminG), 201)
	expect(t, e.get("/r/sec-b/a", ownG), 401)
	expect(t, e.get("/r/sec-b/a", baseG), 302)
	removeKey("dup")
	expect(t, e.get("/r/sec-b/a", ownG), 302)
	expect(t, e.get("/r/sec-b/a", baseG), 401)

	issuerB := e.grant(f.issuer, "user:i", []string{"sec-b"}, []string{"read"})
	expect(t, e.get("/r/sec-b/a", issuerB), 302)
	removeKey("issuer")
	expect(t, e.get("/r/sec-b/a", issuerB), 401)
}
