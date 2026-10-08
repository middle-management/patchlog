package server

import (
	"strconv"
	"testing"
	"time"
)

// §7: a namespace that doesn't exist answers like an existing one whose
// read isn't public; with a grant, ns is checked before any key lookup.
func TestAuthUnknownNamespace(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	create := func(ns string, who ...string) *resp {
		return e.write("PATCH", ns, "a", "", addRoot(map[string]any{}), who...)
	}
	// Unauthenticated: 401 for the unknown namespace, as for "sec".
	for _, ns := range []string{"nope", "sec"} {
		expectCode(t, e.get("/r/"+ns+"/a"), 401, "unauthenticated")
		expectCode(t, e.get("/ns/"+ns), 401, "unauthenticated")
		expectCode(t, e.get("/ns/"+ns+"/log"), 401, "unauthenticated")
		expectCode(t, create(ns), 401, "unauthenticated")
		expectCode(t, e.get("/r/"+ns+"/a", "garbage"), 401, "unauthenticated")
	}
	// A grant that doesn't name the namespace: 403, existing or not.
	elsewhere := e.grant(f.issuer, "user:bob", []string{"elsewhere"}, []string{"read", "create"})
	for _, ns := range []string{"nope", "sec"} {
		expectCode(t, e.get("/r/"+ns+"/a", elsewhere), 403, "forbidden")
		expectCode(t, e.get("/ns/"+ns, elsewhere), 403, "forbidden")
		expectCode(t, create(ns, elsewhere), 403, "forbidden")
	}
	expectCode(t, e.get("/r/nope/a", f.issuerG), 403, "forbidden")
	expectCode(t, e.branch("nope", map[string]any{"name": "nope-b"}, f.issuerG), 403, "forbidden")
	// The ns check comes before the 401 cases: an expired grant for
	// another namespace is still 403.
	expired := e.grant(f.issuer, "user:bob", []string{"elsewhere"}, []string{"read"}, map[string]any{"exp": e.clock.Now().Add(-time.Minute).Format(time.RFC3339)})
	expectCode(t, e.get("/r/nope/a", expired), 403, "forbidden")
	// A grant naming it: no key of a missing namespace can verify it.
	named := e.grant(f.issuer, "user:bob", []string{"nope"}, []string{"read", "create"})
	expectCode(t, e.get("/r/nope/a", named), 401, "unauthenticated")
	expectCode(t, create("nope", named), 401, "unauthenticated")
	// An operator grant authorises only creating namespaces and forcing
	// purges (§C.4): a read under one is 401, as for an existing
	// namespace whose keys don't list it.
	expectCode(t, e.get("/ns/nope", e.operatorGrant("nope")), 401, "unauthenticated")
	expired = mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"nope"}, "can": []any{"config"},
		"exp": e.clock.Now().Add(-time.Minute).Format(time.RFC3339)})
	expectCode(t, e.get("/ns/nope", expired), 401, "unauthenticated")
}

// §C.4: "*" in ns names every namespace, and only operator grants may use
// it. From a namespace key it is refused (403).
func TestAuthStarNS(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{}, f.issuerG)
	star := e.grant(f.issuer, "user:bob", []string{"*"}, []string{"read", "append"})
	// A read answers 404, like any valid grant that doesn't allow it.
	expectCode(t, e.get("/r/sec/a", star), 404, "not_found")
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), star), 403, "forbidden")
	both := e.grant(f.issuer, "user:bob", []string{"sec", "*"}, []string{"read", "append"})
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), both), 403, "forbidden")
	// An operator grant with "*" creates any namespace.
	opStar := mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"config"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	doc := addRoot(map[string]any{"keys": []any{f.admin.entry("*")}})
	expect(t, e.do(req{method: "PATCH", path: "/ns/fresh1", ifNoneMatch: "*", body: doc, bearer: opStar}), 201)
	expect(t, e.do(req{method: "PATCH", path: "/ns/fresh2", ifNoneMatch: "*", body: doc, bearer: opStar}), 201)
}

// Public namespaces ignore a grant that doesn't name them, like an
// unusable one, and answer as to an unauthenticated request.
func TestAuthPublicIgnoresUnnamedGrant(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{f.admin.entry("*")}})
	pubAdmin := e.grant(f.admin, "user:root", []string{"pub"}, allVerbs)
	e.create("pub", "a", map[string]any{}, pubAdmin)
	for _, who := range []string{"", f.issuerG, "garbage"} {
		expect(t, e.get("/r/pub/a", who), 302)
		expect(t, e.get("/r/pub/missing", who), 404)
	}
	// Writes still need a grant naming the namespace.
	expectCode(t, e.write("PATCH", "pub", "b", "", addRoot(map[string]any{}), f.issuerG), 403, "forbidden")
}

// §C.4 v0.21: at must have been the head within maxLag before the grant was
// issued, max(nbf, exp − maxTtl); maxLag defaults to 60 seconds, and a key
// may set a stricter one.
func TestAuthMaxLagAtIssuance(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil) // no maxLag: the default 60 s
	e := f.tenv
	cat := newKey("cat")
	entry := cat.entry("read", "create", "append")
	entry["requireAt"] = true
	entry["maxTtl"] = "PT10M"
	strict := newKey("strict")
	sEntry := strict.entry("read", "create")
	sEntry["requireAt"] = true
	sEntry["maxTtl"] = "PT10M"
	sEntry["maxLag"] = "PT10S"
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: e.configID("sec", f.adminG), bearer: f.adminG,
		body: ops(op("add", "/keys/-", entry), op("add", "/keys/-", sEntry))}), 201)
	n := 0
	create := func(g string) *resp {
		n++
		return e.write("PATCH", "sec", "r"+strconv.Itoa(n), "", addRoot(map[string]any{}), g)
	}
	// Issued now (exp − maxTtl), at the head.
	mintAt := func(k keyPair, at string) string {
		return e.grant(k, "user:li", []string{"sec"}, []string{"read", "create"},
			map[string]any{"at": at, "exp": e.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	}
	moveHead := func() { n++; e.create("sec", "m"+strconv.Itoa(n), map[string]any{}, f.issuerG) }

	at := e.nsHead("sec", f.adminG)
	g := mintAt(cat, at)
	expect(t, create(g), 201)
	// The head moves on; the grant was issued while at was the head, so it
	// keeps working long after maxLag, until it expires.
	moveHead()
	e.clock.Advance(5 * time.Minute)
	expect(t, create(g), 201)
	// A grant issued now from that at is too late.
	expect(t, create(mintAt(cat, at)), 403)

	// Issued 59 s after at stopped being the head: in time, and it stays
	// valid; at 61 s: too late.
	at = e.nsHead("sec", f.adminG)
	moveHead()
	e.clock.Advance(59 * time.Second)
	inTime := mintAt(cat, at)
	e.clock.Advance(2 * time.Second)
	late := mintAt(cat, at)
	e.clock.Advance(3 * time.Minute)
	expect(t, create(inTime), 201)
	expect(t, create(late), 403)
	// nbf counts as issuance when it is later than exp − maxTtl.
	backdated := e.grant(cat, "user:li", []string{"sec"}, []string{"read", "create"}, map[string]any{"at": at,
		"nbf": e.clock.Now().Add(-3*time.Minute - 2*time.Second).Format(time.RFC3339), "exp": e.clock.Now().Add(time.Minute).Format(time.RFC3339)})
	expect(t, create(backdated), 201)

	// A key's stricter maxLag applies: 20 s is within 60 s, not within 10 s.
	at = e.nsHead("sec", f.adminG)
	moveHead()
	e.clock.Advance(20 * time.Second)
	expect(t, create(mintAt(cat, at)), 201)
	expect(t, create(mintAt(strict, at)), 403)
	// The namespace's own maxLag replaces the default; the key's still wins
	// when stricter.
	expect(t, e.patchNS("sec", ops(op("add", "/maxLag", "PT5M")), f.adminG), 201)
	at = e.nsHead("sec", f.adminG)
	moveHead()
	e.clock.Advance(2 * time.Minute)
	expect(t, create(mintAt(cat, at)), 201)
	expect(t, create(mintAt(strict, at)), 403)
}
