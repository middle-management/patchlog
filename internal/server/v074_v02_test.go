package server

import (
	"testing"
)

// §7.4, §6.2 (v0.74, CORE-1): a gestures after not of the form
// {resource}/{id} is a request-shape 400, answered before the namespace
// is looked up, so ahead of the 401 a private namespace gives an
// anonymous caller; an after naming an entry of a purged resource is 404.
func TestV074GesturesAfter(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.mkNS("pub", map[string]any{"read": "public"})
	for _, bad := range []string{"nonsense", "a/nope", "A/" + gA, "/x", "a/"} {
		expectCode(t, e.get("/ns/pub/gestures/"+gA+"?after="+bad), 400, "bad_input")
		expectCode(t, e.get("/ns/sec/gestures/"+gA+"?after="+bad), 400, "bad_input")
	}
	// Still 401 for a well-formed after without a grant.
	expect(t, e.get("/ns/sec/gestures/"+gA+"?after=r/"+hashID(t, "", []byte("x"))), 401)

	wr := func(name, parent string, patches []any) string {
		q := req{method: "PATCH", path: "/r/sec/" + name, ifMatch: parent, bearer: f.adminG, body: patches, hdr: map[string]string{"Gesture": gA}}
		if parent == "" {
			q.ifNoneMatch = "*"
		}
		r := e.do(q)
		expect(t, r, 201)
		return etagOf(r)
	}
	r0 := wr("r", "", addRoot(map[string]any{"n": 0.0}))
	wr("r", r0, ops(op("replace", "/n", 1.0)))
	wr("s", "", addRoot(map[string]any{}))
	expect(t, e.get("/ns/sec/gestures/"+gA+"?after=r/"+r0, f.adminG), 200)
	expect(t, e.purge("sec", "r", e.head("sec", "r", f.adminG), f.adminG), 204)
	expectCode(t, e.get("/ns/sec/gestures/"+gA+"?after=r/"+r0, f.adminG), 404, "not_found")
}
