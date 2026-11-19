package server

import (
	"testing"
)

// §6.6 Cost and Exempt, §7.4, conformance scenario 93: a namespace's
// creation under an operator grant draws no token, its 412 for a taken
// name included; under the namespace's own grant with config the 412
// costs one token from that grant's principal bucket, and none from the
// namespace's.
func TestV086CreationTakenDraws(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{
		"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 2.0},
		"ratePerNamespace": map[string]any{"rate": 0.001, "burst": 3.0}}})
	e := f.tenv
	taken := func(bearer string) *resp {
		return e.do(req{method: "PATCH", path: "/ns/sec", ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: bearer})
	}

	// The operator grant: 412 however often, never limited.
	for i := 0; i < 5; i++ {
		expectCode(t, taken(e.operatorGrant("sec")), 412, "stale")
	}

	// The namespace's own grant with config: each 412 costs a token of
	// its principal bucket, which holds two.
	bob := f.issuerG
	expectCode(t, taken(bob), 412, "stale")
	expectCode(t, taken(bob), 412, "stale")
	r := taken(bob)
	expectCode(t, r, 429, "rate")
	if r.Obj()["limit"] != "ratePerPrincipal" || r.H.Get("Retry-After") == "" {
		t.Fatalf("429: %s", r.Body)
	}

	// The namespace's bucket was not drawn on: it still holds its three
	// tokens for another principal, and no fourth.
	amy := e.grant(f.issuer, "user:amy", []string{"sec"}, []string{"read", "create", "append", "config"})
	cat := e.grant(f.issuer, "user:cat", []string{"sec"}, []string{"read", "create", "append", "config"})
	expect(t, e.write("PATCH", "sec", "a", "", addRoot(map[string]any{}), amy), 201)
	expect(t, e.write("PATCH", "sec", "b", "", addRoot(map[string]any{}), amy), 201)
	expect(t, e.write("PATCH", "sec", "c", "", addRoot(map[string]any{}), cat), 201)
	r = e.write("PATCH", "sec", "d", "", addRoot(map[string]any{}), cat)
	expectCode(t, r, 429, "rate")
	if r.Obj()["limit"] != "ratePerNamespace" {
		t.Fatalf("429: %s", r.Body)
	}

	// A grant without config is refused before any draw, and one chained
	// to a * key pays as any grant but an operator's does.
	noCfg := e.grant(f.issuer, "user:dan", []string{"sec"}, []string{"read", "create"})
	for i := 0; i < 3; i++ {
		expectCode(t, taken(noCfg), 403, "forbidden")
	}
	expectCode(t, taken(f.adminG), 412, "stale")
	expectCode(t, taken(f.adminG), 412, "stale")
	expectCode(t, taken(f.adminG), 429, "rate")

	// The operator grant still isn't limited.
	expectCode(t, taken(e.operatorGrant("sec")), 412, "stale")
}
