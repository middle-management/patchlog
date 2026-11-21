package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// v0.88 §6.6 ("Every bucket but exchangeRate's is also the namespace's
// own, so a key listed in two namespaces has buckets in each"), §C.5.2
// Rate ("keyed by root sub and the verifying key's thumbprint, across
// namespaces, since a kid is unique only within one"), LIM-3: bob's key,
// listed in sec and sec-b, has a principal bucket in each, so emptying
// sec's leaves sec-b's full; and his exchanges draw on one exchangeRate
// bucket, whatever kid each namespace lists that key under. Until v0.88
// write buckets were the same in every namespace, and exchange buckets
// keyed by kid.
func TestV088BucketsPerNamespace(t *testing.T) {
	t.Parallel()
	limits := map[string]any{"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 1}}
	f := newAuthFixture(t, map[string]any{"limits": limits}, withExchangeRate(core.Rate{Rate: 0.001, Burst: 1}))
	e := f.tenv
	// sec-b lists the issuer's key, under its kid and under another.
	other := f.issuer
	other.kid = "issuer-b"
	e.mkNS("sec-b", map[string]any{"read": "grant", "limits": limits,
		"keys": []any{f.admin.entry("*"), f.issuer.entry("read", "create", "append"), other.entry("read", "create", "append")}})
	bobA := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read", "create"})
	bobB := e.grant(f.issuer, "user:bob", []string{"sec-b"}, []string{"read", "create"})
	bobOther := e.grant(other, "user:bob", []string{"sec-b"}, []string{"read", "create"})
	write := func(ns, name, bearer string) *resp {
		return e.do(req{method: "PATCH", path: "/r/" + ns + "/" + name, ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: bearer})
	}
	expect(t, write("sec", "a", bobA), 201)
	expectCode(t, write("sec", "b", bobA), 429, "rate")
	expect(t, write("sec-b", "a", bobB), 201)

	exchange := func(bearer string) *resp {
		return e.do(req{method: "POST", path: "/edge-grants", bearer: bearer})
	}
	expect(t, exchange(bobA), 200)
	if r := exchange(bobOther); r.Code != 429 || r.Str("limit") != "exchangeRate" {
		t.Fatalf("bob's exchange in sec-b, under another kid of the same key, after one in sec: %d %s, want 429 exchangeRate", r.Code, r.Body)
	}
}
