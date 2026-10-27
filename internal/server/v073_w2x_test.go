package server

import "testing"

// W2X: a delete under If-None-Match has no usable precondition: §C.3.1
// ("The parent") checks no signature for it, and step 2.5 answers 428
// whatever the resource's state (§6.2, §7.5, §12.1, GB-5, GB-6). With
// "signatures": "required", the missing signature must not answer first
// (422 signature at step 2.3), for a DELETE, a batch item whose first step
// is "delete", and that item in a dry run.
func TestW2XCoreDeleteIfNoneMatchSignaturesRequired(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("s", map[string]any{"read": "public"})
	e.create("s", "a", map[string]any{"n": 1.0})
	expect(t, e.patchNS("s", ops(op("add", "/signatures", "required")), "alice"), 201)
	r := e.do(req{method: "DELETE", path: "/r/s/a", ifNoneMatch: "*", author: "alice"})
	if r.Code != 428 {
		t.Errorf("DELETE with If-None-Match: %d, want 428: %s", r.Code, r.Body)
	}
	body := map[string]any{"items": []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{"delete"}}}}
	r = e.batchReq("s", body, "alice")
	if r.Code != 428 {
		t.Errorf("batch item delete under ifNoneMatch: %d, want 428: %s", r.Code, r.Body)
	}
	r = e.do(req{method: "POST", path: "/ns/s/batch?dry-run=1", body: body, author: "alice"})
	expect(t, r, 200)
	p15Item(t, r, 0, 428, "precondition_required")
	// A delete under If-None-Match of a resource that doesn't exist: the
	// same 428, not a missing signature.
	r = e.do(req{method: "DELETE", path: "/r/s/nosuch", ifNoneMatch: "*", author: "alice"})
	if r.Code != 428 {
		t.Errorf("DELETE of nothing with If-None-Match: %d, want 428: %s", r.Code, r.Body)
	}
	// A create under If-None-Match still needs its signature.
	r = e.do(req{method: "PATCH", path: "/r/s/b", ifNoneMatch: "*", body: addRoot(map[string]any{"n": 1.0}), author: "alice"})
	expectCode(t, r, 422, "signature")
}

// The same DELETE under If-None-Match gets 428 with a signature of a
// signer the grant lists and without one: neither is checked (§C.3.1), so
// whether a signature was sent can't decide the answer.
func TestW2XCoreDeleteIfNoneMatchSignatureDecides(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"signatures": "required"})
	e := f.tenv
	k1 := sigKey("k1", 1)
	g := e.grant(f.issuer, "user:alice", []string{"sec"}, []string{"read", "create", "append", "restore", "delete"},
		map[string]any{"signers": []any{k1.Entry()}})
	gen := addRoot(map[string]any{"t": "x"})
	r := e.swrite("PATCH", "sec", "a", "", gen, g, signP(t, k1, "sec", "a", "", gen))
	expect(t, r, 201)
	head := etagOf(r)
	r = e.do(req{method: "DELETE", path: "/r/sec/a", ifNoneMatch: "*", bearer: g, hdr: map[string]string{"Signature": signT(t, k1, "sec", "a", head)}})
	if r.Code != 428 {
		t.Errorf("with a signature: %d %s", r.Code, r.Body)
	}
	r = e.do(req{method: "DELETE", path: "/r/sec/a", ifNoneMatch: "*", bearer: g})
	if r.Code != 428 {
		t.Errorf("without a signature: %d, want 428 as with one: %s", r.Code, r.Body)
	}
}
