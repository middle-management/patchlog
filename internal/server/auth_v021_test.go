package server

import (
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
// it. From a namespace key the grant is invalid (401, v0.63).
func TestAuthStarNS(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{}, f.issuerG)
	star := e.grant(f.issuer, "user:bob", []string{"*"}, []string{"read", "append"})
	// No usable grant: a read is 401 too.
	expectCode(t, e.get("/r/sec/a", star), 401, "unauthenticated")
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), star), 401, "unauthenticated")
	both := e.grant(f.issuer, "user:bob", []string{"sec", "*"}, []string{"read", "append"})
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), both), 401, "unauthenticated")
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
