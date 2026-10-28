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
