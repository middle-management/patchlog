package server

import (
	"testing"
)

// V01 (v0.74): grant answers.

// v0.74 §7 Private namespaces and existence, §C.2, §E.2.3 (GRANTS-2, Open
// 51): a verified grant that may not read is 403, at /keys too, in a
// public namespace there as well; only resource URLs answer 404 without
// read. A request without a grant keeps its 401.
func TestV074V01VerifiedGrantWithoutReadIs403(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	hdr := map[string]string{"Gesture": gA}
	expect(t, e.do(req{method: "PATCH", path: "/r/sec/a", ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: f.adminG, hdr: hdr}), 201)
	gid := grantIDOf(t, f.adminG)
	createOnly := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"create"})
	limited := e.grant(f.issuer, "user:l", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	for _, p := range []string{"/ns/sec", "/ns/sec/log", "/ns/sec/gestures/" + gA, "/ns/sec/grants/" + gid} {
		expectCode(t, e.get(p, createOnly), 403, "forbidden")
		expect(t, e.get(p), 401)
	}
	// One whose read is limited to some resources fails the unrestricted
	// read /ns/{ns}/log needs (CONFORMANCE Grant scope 2).
	expectCode(t, e.get("/ns/sec/log", limited), 403, "forbidden")
	// A resource URL keeps its 404, existing or not.
	expectCode(t, e.get("/r/sec/a", createOnly), 404, "not_found")
	expectCode(t, e.get("/r/sec/missing", createOnly), 404, "not_found")

	// /keys of a public sealed namespace (CONFORMANCE Levels 55).
	s := newSealedAuthEnv(t)
	k := newKey("k")
	s.mkNS("s", sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("*")}}))
	_, r := s.keysOf("s", nil, s.grant(k, "user:w", []string{"s"}, []string{"create"}))
	expectCode(t, r, 403, "forbidden")

	// /keys at E3 for a read grant whose rules refuse every read.
	x := newE2E(t)
	_, r = x.keysOf("e", nil, x.grant(x.writer, "user:r", []string{"e"}, []string{"read", "append"}, map[string]any{"enc": x.readerJWK, "rules": []any{map[string]any{"op": "test", "path": "/action", "value": "append"}}}))
	expectCode(t, r, 403, "forbidden")
}

// v0.74 §C.5.2 Refusals (GRANTS-3, Open 82): a grant's block and key
// rules may refer to /resource in other forms where it fixes /resource,
// and they must pass now with /resource set to each name it fixes.
func TestV074V01EdgeGrantRulesPerFixedName(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	test := func(v string) map[string]any { return map[string]any{"op": "test", "path": "/resource", "value": v} }
	not := func(r any) map[string]any { return map[string]any{"not": r} }
	enumAB := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}
	issue := func(k keyPair, ns string, rules ...any) *resp {
		return e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(k, "user:bob", []string{ns}, []string{"read"}, map[string]any{"rules": rules})})
	}
	r := issue(f.issuer, "sec", enumAB, not(test("c")))
	expect(t, r, 200)
	if got := prefixesOf(t, r); got != "/r/sec/a /r/sec/b" {
		t.Errorf("a fixing rule beside a rule referring to /resource otherwise: %q, want /r/sec/a /r/sec/b", got)
	}
	// The second rule fails for b, one of the names fixed.
	expectCode(t, issue(f.issuer, "sec", enumAB, not(test("b"))), 403, "forbidden")
	// Without a fixing rule, such a rule is still refused.
	expectCode(t, issue(f.issuer, "sec", not(test("c"))), 403, "forbidden")

	// A key-scope rule that passes for b alone.
	scoped := newKey("scoped")
	entry := scoped.entry("read")
	entry["rules"] = []any{not(test("a"))}
	e.mkNS("kr", map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), entry}})
	expectCode(t, issue(scoped, "kr", enumAB), 403, "forbidden")
	r = issue(scoped, "kr", test("b"))
	expect(t, r, 200)
	if got := prefixesOf(t, r); got != "/r/kr/b" {
		t.Errorf("key rule passing for the one name fixed: %q", got)
	}
}
