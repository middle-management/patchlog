package server

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// principalOf asks GET /ns/{ns}/principal with bearer ("" for none) and
// checks that every answer is no-store (§7.4).
func (e *tenv) principalOf(ns, bearer string, hdr ...map[string]string) *resp {
	e.t.Helper()
	q := req{method: "GET", path: "/ns/" + ns + "/principal", bearer: bearer}
	if len(hdr) > 0 {
		q.hdr = hdr[0]
	}
	r := e.do(q)
	if cc := r.H.Get("Cache-Control"); cc != "no-store" {
		e.t.Fatalf("Cache-Control %q, want no-store: %d %s", cc, r.Code, r.Body)
	}
	return r
}

func strsOf(v any) []string {
	a, _ := v.([]any)
	out := []string{}
	for _, x := range a {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// sixSixKeys are the keys of §6.6's table.
var sixSixKeys = []string{"patchSetSize", "opsPerSet", "documentSize", "valueSize", "pathSize", "nestingDepth",
	"rulesPerNamespace", "rulesPerGrant", "grantSize", "itemsPerBatch", "batchSize", "logPageBytes", "logPageSize",
	"branchDepth", "branchesPerNamespace", "ratePerResource", "ratePerPrincipal", "ratePerNamespace", "retryWindow",
	"keepPerResource", "remoteRegistration", "blobSize", "blobsPerDocument", "blobPending", "blobGrace", "blobRate",
	"exchangeRate"}

// v0.55 §7.4: what a grant is in a namespace, to a grant limited to some
// resources or without read too, and what a writer needs from the
// namespace document.
func TestV055Principal(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{"patchSetSize": 100000,
		"ratePerNamespace": map[string]any{"rate": 200, "burst": 400}, "retryWindow": "PT5M"}})
	e := f.tenv

	r := e.principalOf("sec", f.issuerG)
	expect(t, r, 200)
	if got := r.H.Get("X-Config-Revision"); got != e.configID("sec", f.adminG) {
		t.Fatalf("X-Config-Revision %q", got)
	}
	b := r.Obj()
	p, _ := b["principal"].(map[string]any)
	if p["id"] != "user:bob" || b["kid"] != "issuer" || p["grant"] == "" || p["attrs"] == nil {
		t.Fatalf("principal %v kid %v", p, b["kid"])
	}
	if got := strsOf(b["can"]); !reflect.DeepEqual(got, []string{"append", "branch", "config", "create", "delete", "read", "restore"}) {
		t.Fatalf("can %v", got)
	}
	if got := strsOf(b["roles"]); len(got) != 0 {
		t.Fatalf("roles %v", got)
	}
	w, _ := b["writer"].(map[string]any)
	if w["frozen"] != false || w["nonce"] != "optional" || w["signatures"] != "optional" {
		t.Fatalf("writer %v", w)
	}
	for _, k := range []string{"successor", "level"} {
		if _, has := w[k]; has {
			t.Fatalf("writer has %s: %v", k, w)
		}
	}
	l, _ := w["limits"].(map[string]any)
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	want := append([]string{}, sixSixKeys...)
	sort.Strings(keys)
	sort.Strings(want)
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("limit keys %v, want %v", keys, want)
	}
	def := core.DefaultLimits()
	if l["patchSetSize"] != 100000.0 || l["opsPerSet"] != float64(def.OpsPerSet) || l["logPageSize"] != float64(def.LogPageSize) ||
		!reflect.DeepEqual(l["ratePerNamespace"], map[string]any{"rate": 200.0, "burst": 400.0}) ||
		!reflect.DeepEqual(l["exchangeRate"], map[string]any{"rate": def.ExchangeRate.Rate, "burst": def.ExchangeRate.Burst}) ||
		l["retryWindow"] != "PT5M" || l["remoteRegistration"] != "P30D" || l["blobGrace"] != "P1D" ||
		l["documentSize"] != float64(def.DocumentSize) {
		t.Fatalf("limits %v", l)
	}

	// A grant limited to one resource, and without read, learns them too.
	fixed := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}
	limited := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"}, fixed)
	r = e.principalOf("sec", limited)
	expect(t, r, 200)
	if got := strsOf(r.Obj()["can"]); !reflect.DeepEqual(got, []string{"append"}) {
		t.Fatalf("limited can %v", got)
	}
	// With roles, only the verbs an effective role lists; roles the
	// namespace doesn't define aren't effective (§C.1.1).
	roled := e.grant(f.admin, "user:t", []string{"sec"}, []string{"read", "append", "delete"}, map[string]any{"roles": []any{"translator", "ghost"}})
	r = e.principalOf("sec", roled)
	expect(t, r, 200)
	if got := strsOf(r.Obj()["can"]); !reflect.DeepEqual(got, []string{"append", "read"}) {
		t.Fatalf("roled can %v", got)
	}
	if got := strsOf(r.Obj()["roles"]); !reflect.DeepEqual(got, []string{"translator"}) {
		t.Fatalf("roled roles %v", got)
	}
	if p, _ := r.Obj()["principal"].(map[string]any); !reflect.DeepEqual(strsOf(p["roles"]), []string{"translator"}) {
		t.Fatalf("principal roles %v", p)
	}
	byRole := e.grant(f.admin, "user:e", []string{"sec"}, nil, map[string]any{"roles": []any{"editor"}})
	r = e.principalOf("sec", byRole)
	expect(t, r, 200)
	if got := strsOf(r.Obj()["can"]); !reflect.DeepEqual(got, []string{"append", "create", "delete", "read", "restore"}) {
		t.Fatalf("role can %v", got)
	}

	// The grant is the question: none, or one that can't be used, is 401.
	expectCode(t, e.principalOf("sec", ""), 401, "unauthenticated")
	expectCode(t, e.principalOf("sec", "garbage"), 401, "unauthenticated")
	expired := e.grant(f.issuer, "user:x", []string{"sec"}, []string{"read"}, map[string]any{"exp": t0.Add(-time.Minute).Format(time.RFC3339)})
	expectCode(t, e.principalOf("sec", expired), 401, "unauthenticated")
	stranger := newKey("stranger")
	expectCode(t, e.principalOf("sec", e.grant(stranger, "user:x", []string{"sec"}, []string{"read"})), 401, "unauthenticated")
	// The ns check comes first (§7), and key scopes apply (§C.4).
	expectCode(t, e.principalOf("sec", e.grant(f.issuer, "user:x", []string{"other"}, []string{"read"})), 403, "forbidden")
	expectCode(t, e.principalOf("sec", e.grant(f.svc, "user:x", []string{"sec"}, []string{"read"})), 403, "forbidden")
	expectLimit(t, e.principalOf("sec", strings.Repeat("A", 12000)), 413, "grantSize", 9000, int64(def.GrantSize))
	// No parameter is defined for it (§7).
	expectCode(t, e.do(req{method: "GET", path: "/ns/sec/principal?verbose=1", bearer: f.issuerG}), 400, "bad_input")

	// An edge cookie is no grant here (§C.5), though it reads /ns/sec.
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	ck := edgeCookies(t, e.do(req{method: "POST", path: "/edge-grants", bearer: reader}))["/ns/sec"]
	if ck == nil {
		t.Fatal("no /ns/sec cookie")
	}
	expect(t, e.do(req{method: "GET", path: "/ns/sec", hdr: cookieHdr(ck)}), 302)
	expectCode(t, e.principalOf("sec", "", cookieHdr(ck)), 401, "unauthenticated")

	// A key whose readScope is resource signs read grants that fix
	// /resource (§C.4); one that doesn't fails verification.
	rk := newKey("rk")
	rkEntry := rk.entry("read", "append")
	rkEntry["readScope"] = "resource"
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", rkEntry)), f.adminG), 201)
	expect(t, e.principalOf("sec", e.grant(rk, "user:x", []string{"sec"}, []string{"read"}, fixed)), 200)
	expect(t, e.principalOf("sec", e.grant(rk, "user:x", []string{"sec"}, []string{"append"})), 200)
	expectCode(t, e.principalOf("sec", e.grant(rk, "user:x", []string{"sec"}, []string{"read"})), 403, "forbidden")
	// So does every request under it: a read answers 404 as for any
	// refusal (§7), a write 403.
	unfixed := e.grant(rk, "user:x", []string{"sec"}, []string{"read", "append"})
	e.create("sec", "a", map[string]any{}, f.adminG)
	expectCode(t, e.get("/r/sec/a", unfixed), 404, "not_found")
	expectCode(t, e.write("PATCH", "sec", "a", e.head("sec", "a", f.adminG), ops(op("add", "/x", 1)), unfixed), 403, "forbidden")
}

// v0.55 §7.4, §7, §C.4: in a public namespace the grant is still
// required; an absent namespace answers as for any request, but 404 to an
// operator grant, which learns whether a namespace exists.
func TestV055PrincipalExistence(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	pk := newKey("pk")
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{pk.entry("*")}})
	expectCode(t, e.principalOf("pub", ""), 401, "unauthenticated")
	expectCode(t, e.principalOf("pub", "garbage"), 401, "unauthenticated")
	expectCode(t, e.principalOf("pub", f.issuerG), 403, "forbidden") // names sec, not pub
	pg := e.grant(pk, "user:p", []string{"pub"}, []string{"read"})
	expect(t, e.principalOf("pub", pg), 200)

	expectCode(t, e.principalOf("nope", ""), 401, "unauthenticated")
	expectCode(t, e.principalOf("nope", f.issuerG), 403, "forbidden")
	expectCode(t, e.principalOf("nope", e.grant(f.issuer, "user:x", []string{"nope"}, []string{"read"})), 401, "unauthenticated")
	op := e.operatorGrant("nope")
	expectCode(t, e.principalOf("nope", op), 404, "not_found")
	// An operator grant verifies in an existing namespace too (§7.4).
	r := e.principalOf("pub", e.operatorGrant("pub"))
	expect(t, r, 200)
	if r.Obj()["kid"] != "operator" || !reflect.DeepEqual(strsOf(r.Obj()["can"]), []string{"config"}) {
		t.Fatalf("operator %s", r.Body)
	}
}

// v0.55 §7.4, §8.5: frozen, nonce, signatures and encryption levels, and
// a purged namespace's 410 once the grant verifies, no-store.
func TestV055PrincipalWriterSettings(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	doc := func(m map[string]any) map[string]any {
		m["keys"] = []any{k.entry("*")}
		return m
	}
	e.mkNS("n", doc(map[string]any{"nonce": "required", "signatures": "required"}))
	e.mkNS("s", sealedDoc(doc(map[string]any{})))
	e.mkNS("x", e2eDoc(doc(map[string]any{})))
	e.mkNS("r", atRest(doc(map[string]any{})))
	e.mkNS("old", doc(map[string]any{}))
	e.mkNS("new", doc(map[string]any{}))
	g := func(ns string) string { return e.grant(k, "user:a", []string{ns}, allVerbs) }
	expect(t, e.patchNS("old", ops(op("add", "/frozen", true), op("add", "/successor", "new")), g("old")), 201)
	writer := func(ns string) map[string]any {
		t.Helper()
		r := e.principalOf(ns, g(ns))
		expect(t, r, 200)
		w, _ := r.Obj()["writer"].(map[string]any)
		return w
	}
	if w := writer("n"); w["nonce"] != "required" || w["signatures"] != "required" || w["level"] != nil {
		t.Fatalf("n %v", w)
	}
	if w := writer("s"); w["level"] != "sealed" || w["nonce"] != "required" {
		t.Fatalf("s %v", w)
	}
	if w := writer("x"); w["level"] != "e2e" || w["nonce"] != "optional" {
		t.Fatalf("x %v", w)
	}
	if w := writer("r"); w["level"] != "at-rest" || w["nonce"] != "optional" {
		t.Fatalf("r %v", w)
	}
	if w := writer("old"); w["frozen"] != true || w["successor"] != "new" {
		t.Fatalf("old %v", w)
	}

	// Purged: 410 purged with head once the grant verifies, never cached.
	e.mkNS("p", doc(map[string]any{"frozen": true}))
	expect(t, e.do(req{method: "POST", path: "/ns/p/purge", ifMatch: e.nsHead("p", g("p")), bearer: g("p")}), 204)
	expectCode(t, e.principalOf("p", ""), 401, "unauthenticated")
	r := e.principalOf("p", e.grant(k, "user:z", []string{"p"}, []string{"append"}))
	expectCode(t, r, 410, "purged")
	if r.Str("head") == "" {
		t.Fatalf("410 without head: %s", r.Body)
	}
}

// v0.55 §7.4 with authentication disabled (§1): no grant, so no principal
// or kid, every verb, and an absent namespace is 404 as for other reads.
func TestV055PrincipalAuthDisabled(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("d", map[string]any{"limits": map[string]any{"opsPerSet": 7}})
	r := e.principalOf("d", "")
	expect(t, r, 200)
	b := r.Obj()
	if _, has := b["principal"]; has {
		t.Fatalf("principal with auth disabled: %s", r.Body)
	}
	if _, has := b["kid"]; has {
		t.Fatalf("kid with auth disabled: %s", r.Body)
	}
	if got := strsOf(b["can"]); len(got) != 11 || len(strsOf(b["roles"])) != 0 {
		t.Fatalf("can %v roles %v", got, b["roles"])
	}
	if l := b["writer"].(map[string]any)["limits"].(map[string]any); l["opsPerSet"] != 7.0 {
		t.Fatalf("limits %v", l)
	}
	if r.H.Get("X-Config-Revision") != e.configID("d") {
		t.Fatalf("X-Config-Revision %q", r.H.Get("X-Config-Revision"))
	}
	expectCode(t, e.principalOf("nope", ""), 404, "not_found")
}
