package server

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// §6.2 step 2.3, §C.3.1 (v0.42): author signatures are checked after the
// retry lookup and after the verb is settled, so a retry is answered as
// first recorded and authorisation failures come first.
func TestV042SignatureOrder(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	k1 := sigKey("k1", 1)
	g := e.grant(f.issuer, "user:alice", []string{"sec", "sec-b"}, []string{"read", "create", "append", "restore", "delete"},
		map[string]any{"signers": []any{k1.Entry()}})
	a0 := e.create("sec", "a", map[string]any{}, g)
	p := ops(op("add", "/x", "1"))
	r := e.swrite("PATCH", "sec", "a", a0, p, g, "")
	expect(t, r, 201)
	a1 := etagOf(r)
	s0 := addRoot(map[string]any{"n": "1"})
	unsignedBatch := map[string]any{"items": []any{map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{s0}}}}
	expect(t, e.batchReq("sec", unsignedBatch, g), 201)

	// Authorisation failures are reported before a bad signature: a verb
	// the grant lacks at step 1...
	bad := signP(t, k1, "sec", "a", a1, ops(op("add", "/y", "2")))
	noAppend := e.grant(f.issuer, "user:alice", []string{"sec"}, []string{"read", "create"}, map[string]any{"signers": []any{k1.Entry()}})
	expectCode(t, e.swrite("PATCH", "sec", "a", a1, ops(op("add", "/y", "1")), noAppend, bad), 403, "forbidden")
	// ...and a verb settled at step 2 that isn't a candidate.
	tomb := e.del("sec", "a", a1, g)
	noRestore := e.grant(f.issuer, "user:alice", []string{"sec"}, []string{"read", "append"}, map[string]any{"signers": []any{k1.Entry()}})
	expectCode(t, e.swrite("PATCH", "sec", "a", tomb, []any{}, noRestore, signP(t, k1, "sec", "a", tomb, ops(op("add", "/q", "1")))), 403, "forbidden")
	// The same bad signature with the verb allowed: 422.
	expectCode(t, e.swrite("PATCH", "sec", "a", tomb, []any{}, g, signP(t, k1, "sec", "a", tomb, ops(op("add", "/q", "1")))), 422, "signature")
	// In a batch, the unauthorised item is reported, not the bad signature.
	mixed := map[string]any{"items": []any{
		map[string]any{"resource": "d", "ifNoneMatch": "*", "steps": []any{map[string]any{"patches": s0, "signature": signP(t, k1, "sec", "zz", "", s0)}}},
		map[string]any{"resource": "c", "ifMatch": e.head("sec", "c", g), "steps": []any{"delete"}},
	}}
	noDelete := e.grant(f.issuer, "user:alice", []string{"sec"}, []string{"read", "create", "append"}, map[string]any{"signers": []any{k1.Entry()}})
	r = e.batchReq("sec", mixed, noDelete)
	expect(t, r, 403)
	if items := r.Obj()["items"].([]any); len(items) != 1 || items[0].(map[string]any)["index"] != 1.0 {
		t.Fatalf("batch failure %s", r.Body)
	}
	// A dry run reports a bad signature per item, like later steps.
	r = e.do(req{method: "POST", path: "/ns/sec/batch?dry-run=1", bearer: g, body: map[string]any{"items": []any{
		map[string]any{"resource": "d", "ifNoneMatch": "*", "steps": []any{map[string]any{"patches": s0, "signature": signP(t, k1, "sec", "zz", "", s0)}}},
		map[string]any{"resource": "e", "ifNoneMatch": "*", "steps": []any{s0}},
	}}})
	expect(t, r, 200)
	items := r.Obj()["items"].([]any)
	if d, ok := items[0].(map[string]any); !ok || d["status"] != 422.0 || d["code"] != "signature" || items[1].(map[string]any)["status"] != 200.0 {
		t.Fatalf("dry run %s", r.Body)
	}

	// Turn "required" on.
	expect(t, e.patchNS("sec", ops(op("add", "/signatures", "required")), f.adminG), 201)
	// An idempotent retry is answered with the entry as first recorded,
	// whatever well-formed signature it carries or lacks.
	r = e.swrite("PATCH", "sec", "a", a0, p, g, "")
	expect(t, r, 200)
	if etagOf(r) != a1 {
		t.Fatalf("retry answered %s", r.Body)
	}
	expect(t, e.swrite("PATCH", "sec", "a", a0, p, g, signP(t, k1, "sec", "a", a0, ops(op("add", "/other", "1")))), 200)
	expect(t, e.batchReq("sec", unsignedBatch, g), 200)
	// A new unsigned write is refused.
	expectCode(t, e.swrite("PATCH", "sec", "b", "", s0, g, ""), 422, "signature")
	// A write without a precondition has no parent to bind: it gets the
	// precondition's own error.
	expectCode(t, e.do(req{method: "PATCH", path: "/r/sec/b", body: s0, bearer: g}), 428, "precondition_required")

	// A batch whose config change is stale fails with it, whatever its
	// items' signatures: they are never judged under another
	// configuration.
	stale := e.configID("sec", f.adminG)
	expect(t, e.patchNS("sec", ops(op("add", "/x-note", "n")), f.adminG), 201)
	turnOff := map[string]any{"config": map[string]any{"ifMatch": stale, "patches": ops(op("replace", "/signatures", "optional"))},
		"items": []any{map[string]any{"resource": "f", "ifNoneMatch": "*", "steps": []any{s0}}}}
	expectCode(t, e.batchReq("sec", turnOff, f.adminG), 412, "stale")
	expect(t, e.patchNS("sec", ops(op("replace", "/signatures", "optional")), f.adminG), 201)
	stale = e.configID("sec", f.adminG)
	expect(t, e.patchNS("sec", ops(op("replace", "/x-note", "m")), f.adminG), 201)
	turnOn := map[string]any{"config": map[string]any{"ifMatch": stale, "patches": ops(op("replace", "/signatures", "required"))},
		"items": []any{map[string]any{"resource": "f", "ifNoneMatch": "*", "steps": []any{s0}}}}
	expectCode(t, e.batchReq("sec", turnOn, f.adminG), 412, "stale")
	if r := e.get("/r/sec/f", f.adminG); r.Code != 404 {
		t.Fatalf("f written: %d", r.Code)
	}
}

// §6.2 (v0.42): rate limits are step 1, so a 429 comes before a 422
// signature.
func TestV042RateBeforeSignature(t *testing.T) {
	e := newEnv(t)
	e.mkNS("rl", map[string]any{"signatures": "required", "limits": map[string]any{
		"ratePerResource": map[string]any{"rate": 0.001, "burst": 1.0},
	}})
	gen := addRoot(map[string]any{})
	expectCode(t, e.write("PATCH", "rl", "a", "", gen), 422, "signature")
	expectCode(t, e.write("PATCH", "rl", "a", "", gen), 429, "rate")
}

// §7 (v0.42): an endpoint accepts only the query parameters the spec
// defines for it, and flags only the value 1.
func TestV042QueryParams(t *testing.T) {
	e := newEnv(t)
	e.mkNS("q", map[string]any{"read": "public"})
	a0 := e.create("q", "a", map[string]any{"n": 1.0})
	head := e.nsHead("q")
	bad := func(q req) {
		t.Helper()
		r := e.do(q)
		expectCode(t, r, 400, "bad_input")
		if cc := r.H.Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s %s: Cache-Control %q", q.method, q.path, cc)
		}
	}
	for _, p := range []string{
		"/?x=1",
		"/r/q/a?limit=5",
		"/r/q/a/rev/" + a0 + "?since=&limit=5",
		"/r/q/a/rev/" + a0 + "/log?after=" + a0,
		"/r/q/a/rev/" + a0 + "/log?since=" + a0 + "&since=" + a0,
		"/r/q/a/log?x=1",
		"/r/q/a/events?limit=1",
		"/ns/q?x",
		"/ns/q/rev/" + head + "/log?limit=10",
		"/ns/q/rev/" + head + "/heads?since=a",
		"/ns/q/log?since=&foo=bar",
		"/ns/q/branches?all=1",
		"/ns/q/gestures/" + strings.Repeat("a", 32) + "?since=x",
		"/ns/q?%zz",
	} {
		bad(req{method: "GET", path: p})
	}
	// Before authorisation: an unknown namespace too.
	bad(req{method: "GET", path: "/ns/nope/rev/" + head + "?x=1"})
	// Writes: rejected before anything is written.
	bad(req{method: "PATCH", path: "/r/q/a?dry-run=1", ifMatch: a0, body: ops(op("replace", "/n", 2.0)), author: "alice"})
	body := map[string]any{"items": []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}
	bad(req{method: "POST", path: "/ns/q/batch?dry-run=true", body: body, author: "alice"})
	bad(req{method: "POST", path: "/ns/q/batch?dry-run", body: body, author: "alice"})
	bad(req{method: "POST", path: "/ns/q/batch?force=1", body: body, author: "alice"})
	bad(req{method: "POST", path: "/r/q/a/purge?force=true", ifMatch: a0, author: "admin"})
	bad(req{method: "POST", path: "/ns/q/purge?force=yes", ifMatch: e.nsHead("q"), author: "admin"})
	if e.head("q", "a") != a0 || e.get("/r/q/b").Code != 404 {
		t.Fatal("a refused request wrote")
	}

	// Defined parameters work.
	expect(t, e.get("/r/q/a/rev/"+a0+"/log?since="), 200)
	expect(t, e.get("/ns/q/rev/"+head+"/heads?after=a"), 200)
	expect(t, e.get("/ns/q/log?since="+head), 302)
	expect(t, e.do(req{method: "POST", path: "/ns/q/batch?dry-run=1", body: body, author: "alice"}), 200)
	expect(t, e.do(req{method: "POST", path: "/r/q/a/purge?force=1", ifMatch: a0, author: "admin"}), 204)
	// The JWKS isn't a core endpoint: cache busters pass.
	expect(t, e.get(core.DefaultJWKSPath+"?v=2"), 200)
}

// §C.3.1, §E.2.2, §8.5 (v0.42): grants are served sealed in sealed
// namespaces, privately in end-to-end ones, and 410 after a purge.
func TestV042Grants(t *testing.T) {
	// Sealed: a JWE with pl { ns, grant }, stored once.
	s := newSealedAuthEnv(t)
	k := newKey("k")
	s.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	w := s.grant(k, "user:w", []string{"s"}, []string{"create", "append", "read"})
	s.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})), w)
	gid := grantIDOf(t, w)
	r := s.get("/ns/s/grants/"+gid, w)
	expect(t, r, 200)
	if !isJOSE(r) || r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("sealed grant headers %v", r.H)
	}
	keys, kr := s.keysOf("s", nil, w)
	if kr != nil && kr.Code != 200 {
		t.Fatalf("keys %d %s", kr.Code, kr.Body)
	}
	pt := open(t, string(r.Body), keys["s#1"], "s#1", seal.GrantPL("s", gid))
	m := jsonv.MustParse(pt).(map[string]any)
	if root, _ := m["root"].(map[string]any); m["id"] != gid || root["sub"] != "user:w" || len(m["stored"].([]any)) != 1 {
		t.Fatalf("sealed grant %s", pt)
	}
	if r2 := s.get("/ns/s/grants/"+gid, w); string(r2.Body) != string(r.Body) {
		t.Fatal("sealed grant bytes differ between reads")
	}
	expectCode(t, s.get("/ns/s/grants/"+grantIDOf(t, s.grant(k, "user:z", []string{"s"}, []string{"read"})), w), 404, "not_found")

	// End-to-end: in the clear, Cache-Control private.
	f := newE2E(t)
	expect(t, f.patchNS("e", ops(op("add", "/x-note", "n")), f.adminG), 201)
	r = f.get("/ns/e/grants/"+grantIDOf(t, f.adminG), f.adminG)
	expect(t, r, 200)
	if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") || strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage") ||
		r.H.Get("CDN-Cache-Control") != "no-store" || isJOSE(r) || r.Str("id") != grantIDOf(t, f.adminG) {
		t.Fatalf("e2e grant %v %s", r.H, r.Body)
	}

	// Purged: 410 after the read check.
	a := newAuthFixture(t, nil)
	ag := a.tenv
	ag.create("sec", "a", map[string]any{}, a.issuerG)
	igid := grantIDOf(t, a.issuerG)
	expect(t, ag.get("/ns/sec/grants/"+igid, a.adminG), 200)
	expect(t, ag.patchNS("sec", ops(op("add", "/frozen", true)), a.adminG), 201)
	expect(t, ag.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: ag.nsHead("sec", a.adminG), bearer: a.adminG}), 204)
	expectCode(t, ag.get("/ns/sec/grants/"+igid, a.adminG), 410, "gone")
	expect(t, ag.get("/ns/sec/grants/"+igid), 401)
}

// §C.4 (v0.42): a key past its until authorises nothing, judged against
// the current time.
func TestV042OperatorKeyUntil(t *testing.T) {
	var opPriv ed25519.PrivateKey
	until := t0.Add(time.Hour)
	e := newEnv(t, withAuth(&opPriv), func(o *core.Options) {
		o.OperatorKeyHistory = []core.OperatorKeyPeriod{{Kid: "operator", Pub: opPriv.Public().(ed25519.PublicKey), From: t0.Add(-time.Hour), Until: until}}
	})
	e.opPriv = opPriv
	e.mkNS("n1", map[string]any{})
	r := e.get(core.DefaultJWKSPath)
	expect(t, r, 200)
	if r.H.Get("Content-Type") != "application/jwk-set+json" || r.H.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("jwks headers %v", r.H)
	}
	if k := r.Obj()["keys"].([]any)[0].(map[string]any); k["patchlog"].(map[string]any)["until"] != until.Format(time.RFC3339) {
		t.Fatalf("jwks %s", r.Body)
	}
	e.clock.Advance(2 * time.Hour)
	expect(t, e.do(req{method: "PATCH", path: "/ns/n2", ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: e.operatorGrant("n2")}), 401)
}
