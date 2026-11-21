package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
)

// v0.88 §6.6 Cost ("Its config change, if any, costs what a config write
// does, drawn once the change passes its own step 1, even where an item
// then fails step 1"), LIM-3: a batch whose config change passes its step
// 1 and whose item fails step 1 outright (a verb the grant lacks) is 403
// and still draws the change's token, so bob's next config write is 429.
// Until v0.88 such a batch drew nothing.
func TestV088BatchConfigChangeDrawsDespiteItem(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{
		"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 1}}})
	e := f.tenv
	bob := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read", "config"})
	batch := map[string]any{
		"config": map[string]any{"ifMatch": e.configID("sec", f.adminG), "patches": ops(op("add", "/x-a", 1.0))},
		"items":  []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": true})}}}}
	expect(t, e.batchReq("sec", batch, bob), 403)
	r := e.batchReq("sec", map[string]any{"config": map[string]any{
		"ifMatch": e.configID("sec", f.adminG), "patches": ops(op("add", "/x-b", 1.0))}}, bob)
	expectCode(t, r, 429, "rate")
}

// v0.88 §6.6 Validation work ("those of step 1, a key scope's attrs
// schema (§C.4) and every candidate verb's included"), LIM-7: the check
// of a grant's attrs against its key's attrs schema counts against the
// budget of the check it is verified for. An attrs check and a step-1
// rule that each fit run out together, 422 validationSteps; an attrs
// check that runs out alone is a write's run-out at step 1, 422, never the
// 403 of attrs that don't match, and fails a read as a read's run-out
// does: 404 at a resource, 403 at /principal. Until v0.88 the attrs check
// had a budget of its own.
func TestV088AttrsSchemaCountsAgainstTheCheck(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, func(o *core.Options) { o.MaxValidationSteps = 3000 })
	admin, half, over := newKey("admin"), newKey("half"), newKey("over")
	entry := func(k keyPair, levels int) map[string]any {
		m := k.entry("read", "create")
		m["attrs"] = doubling(levels)
		return m
	}
	e.mkNS("at", map[string]any{"read": "grant", "keys": []any{admin.entry("*"), entry(half, 9), entry(over, 30)}})
	adminG := e.grant(admin, "user:root", []string{"at"}, allVerbs)
	put := func(name, who string) *resp { return e.write("PATCH", "at", name, "", addRoot(map[string]any{}), who) }
	g := func(k keyPair) string {
		return e.grant(k, "user:w", []string{"at"}, []string{"read", "create"}, map[string]any{"attrs": map[string]any{"desk": "x"}})
	}
	expect(t, put("a", g(half)), 201)
	mintHalf, err := grant.Decode(g(half), 0)
	if err != nil {
		t.Fatal(err)
	}
	slow := narrowed(t, mintHalf, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": doubling(9)}}})
	expectSteps(t, put("b", slow))
	expectSteps(t, put("c", g(over)))
	expect(t, put("d", adminG), 201)
	// A read fails as a read check that runs out does (scenario 79), and
	// /principal, which verification alone decides, refuses it.
	if r := e.get("/r/at/d", g(over)); r.Code != 404 {
		t.Fatalf("a read under a grant whose attrs check runs out: %d %s, want 404", r.Code, r.Body)
	}
	expect(t, e.get("/ns/at/principal", g(half)), 200)
	expectCode(t, e.get("/ns/at/principal", g(over)), 403, "forbidden")
}

// v0.88 §8.5 item 4, §6.1 ("dependents (§7.4, §8.5) list the dependents
// alike"): a namespace purge refused for dependents lists only those the
// caller may read, by name; one it may read none of is still 409, with
// []. Until v0.88 every direct branch was named, readable or not.
func TestV088PurgeNSDependentsFiltered(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	for _, b := range []string{"sec-b", "sec-c"} {
		expect(t, e.branch("sec", map[string]any{"name": b}, f.adminG), 201)
	}
	expect(t, e.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG), 201)
	purgeNS := func(bearer string) *resp {
		return e.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG), bearer: bearer})
	}
	// adminG names sec and sec-b, not sec-c.
	r := purgeNS(f.adminG)
	expectCode(t, r, 409, "in_use")
	if deps, _ := r.Obj()["dependents"].([]any); len(deps) != 1 || deps[0] != "sec-b" || r.Obj()["more"] != nil {
		t.Fatalf("dependents for a grant naming sec-b alone: %s, want [sec-b] without more", r.Body)
	}
	only := e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	r = purgeNS(only)
	expectCode(t, r, 409, "in_use")
	if deps, ok := r.Obj()["dependents"].([]any); !ok || len(deps) != 0 {
		t.Fatalf("dependents for a grant naming neither branch: %s, want []", r.Body)
	}
}

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
