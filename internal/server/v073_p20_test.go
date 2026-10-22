package server

import (
	"testing"
)

// CIS-21, CIS-15, CIS-16 (§6.4.2, §6.6, §C.4): over HTTP, a namespace
// document whose rules carry a schema fragment that breaks the fragment
// rules is 422 invalid, at creation and on a config write, and a grant
// whose rules carry one is 401; \uXXXX in a rule's pattern and in a key's
// sub is read as \x{XXXX}.
func TestV073P20RuleFragmentsOverHTTP(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	frag := func(schema map[string]any) map[string]any {
		return map[string]any{"op": "test", "path": "/doc/v", "schema": schema}
	}
	// Creation.
	for _, s := range []map[string]any{{"$id": "x"}, {"format": "semver"}, {"foo": 1.0}} {
		r := e.do(req{method: "PATCH", path: "/ns/frag", ifNoneMatch: "*", bearer: e.operatorGrant("frag"),
			body: addRoot(map[string]any{"keys": []any{f.admin.entry("*")}, "rules": []any{frag(s)}})})
		expectCode(t, r, 422, "invalid")
	}
	// A config write, in rules and in a role.
	expectCode(t, e.patchNS("sec", ops(op("add", "/rules", []any{frag(map[string]any{"format": "nope"})})), f.adminG), 422, "invalid")
	expectCode(t, e.patchNS("sec", ops(op("add", "/roles/editor/rules", []any{frag(map[string]any{
		"$ref": "/r/schemas/s/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})})), f.adminG), 422, "invalid")
	expectCode(t, e.patchNS("sec", ops(op("add", "/rules", []any{frag(map[string]any{"pattern": `\ud800`})})), f.adminG), 422, "invalid")

	// A rule's pattern with \u.
	expect(t, e.patchNS("sec", ops(op("add", "/rules", []any{map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "create"}},
		"then": []any{frag(map[string]any{"type": "string", "pattern": `^\u00e9`})}}})), f.adminG), 201)
	expectCode(t, e.write("PATCH", "sec", "a", "", addRoot(map[string]any{"v": "eva"}), f.issuerG), 422, "rule")
	e.create("sec", "a", map[string]any{"v": "éva"}, f.issuerG)

	// A grant carrying a fragment that breaks the rules is invalid on
	// every request that doesn't ignore it.
	bad := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema"}}}})
	expectCode(t, e.get("/r/sec/a", bad), 401, "unauthenticated")
	expectCode(t, e.get("/ns/sec/principal", bad), 401, "unauthenticated")
	good := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": `^\u0061$`}}}})
	expect(t, e.get("/r/sec/a", good), 302)
	expectCode(t, e.get("/r/sec/b", good), 404, "not_found") // a refused read

	// GR-2: a noncharacter in a block makes the grant invalid.
	expectCode(t, e.get("/r/sec/a", e.grant(f.issuer, "user:bob\uFFFE", []string{"sec"}, []string{"read"})), 401, "unauthenticated")
}

// CIS-16 (§C.4): a key's sub with \u matches the whole root sub as the
// code point; a config write setting one RE2 doesn't accept, as §6.6 reads
// it, is 422 invalid.
func TestV073P20KeySubOverHTTP(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	k := newKey("intl")
	entry := k.entry("read")
	entry["sub"] = `user:\u00e9.*`
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", entry)), f.adminG), 201)
	e.create("sec", "a", map[string]any{"v": 1.0}, f.issuerG)
	expect(t, e.get("/r/sec/a", e.grant(k, "user:éva", []string{"sec"}, []string{"read"})), 302)
	// A sub outside the scope fails it: a refused read.
	expectCode(t, e.get("/r/sec/a", e.grant(k, "user:eva", []string{"sec"}, []string{"read"})), 404, "not_found")
	expectCode(t, e.get("/r/sec/a", e.grant(k, "xuser:éva", []string{"sec"}, []string{"read"})), 404, "not_found")

	for _, sub := range []string{`user:\ud800`, `user:\x{D800}`, `(?=user)`} {
		bad := newKey("bad").entry("read")
		bad["sub"] = sub
		r := e.patchNS("sec", ops(op("add", "/keys/-", bad)), f.adminG)
		expectCode(t, r, 422, "invalid")
	}
}

// GB-9 (§6.4.3): over HTTP, the path of a failing namespace rule descends
// through the first failing member of an all and of a then.
func TestV073P20RulePathOverHTTP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("p", map[string]any{"read": "public", "rules": []any{
		map[string]any{"op": "test", "path": "/action", "exists": true},
		map[string]any{"all": []any{
			map[string]any{"op": "test", "path": "/action", "exists": true},
			map[string]any{"if": []any{map[string]any{"op": "test", "path": "/action", "value": "create"}},
				"then": []any{
					map[string]any{"op": "test", "path": "/doc/a", "exists": true},
					map[string]any{"any": []any{map[string]any{"op": "test", "path": "/doc/b", "exists": true}}}}}}},
	}})
	r := e.write("PATCH", "p", "x", "", addRoot(map[string]any{"a": 1.0}))
	expectCode(t, r, 422, "rule")
	if r.Obj()["rule"] != 1.0 || r.Obj()["path"] != "/rules/1/all/1/then/1" {
		t.Fatalf("rule failure %s", r.Body)
	}
	r = e.write("PATCH", "p", "x", "", addRoot(map[string]any{"b": 1.0}))
	if r.Obj()["rule"] != 1.0 || r.Obj()["path"] != "/rules/1/all/1/then/0" {
		t.Fatalf("rule failure %s", r.Body)
	}
	e.create("p", "x", map[string]any{"a": 1.0, "b": 2.0})
}
