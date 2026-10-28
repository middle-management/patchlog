package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// Spec v0.73, package P14: remote branch creation and registration (§G.3,
// §G.5.2).

// A creation that fails at the base's deployment is 502 with code
// upstream, and origin naming that deployment (§G.3, §12.1).
func TestV073RemoteUpstreamOrigin(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "p", map[string]any{"v": 1.0})
	at := a.nsHead("main")
	expectUpstream := func(what string, r *resp) {
		t.Helper()
		if r.Code != 502 || r.Str("code") != "upstream" || r.Str("origin") != originA {
			t.Fatalf("%s: %d %s, want 502 upstream with origin %s", what, r.Code, r.Body, originA)
		}
		expect(t, b.get("/ns/rel"), 404)
	}
	// No answer.
	rt.set("http://127.0.0.1:1", "")
	expectUpstream("unreachable", b.mkRemote("rel", remoteGenesis("main", at, nil)))
	// A 5xx, on the first fetch or a later one.
	for _, match := range []string{"/heads", "/r/main/p/"} {
		rt.set(refusing(t, a, match, 503), "")
		expectUpstream("503 for "+match, b.mkRemote("rel", remoteGenesis("main", at, nil)))
	}
	// Data that fails verification.
	rt.set(tamper(t, a, "/r/main/p/rev/", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(`"v":1`), []byte(`"v":7`)) }), "")
	expectUpstream("tampered", b.mkRemote("rel", remoteGenesis("main", at, nil)))
	rt.set(a.srv.URL, "")
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
}

// What A answers for its own URLs, 401, 403 or 404, is a base B can't
// read: 422 invalid. Only no answer, or a 5xx, is 502 (§G.3, §G.5.2).
func TestV073RemoteUnreadableBase(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "p", map[string]any{"v": 1.0})
	at := a.nsHead("main")
	for _, match := range []string{"/ns/main", "/r/main/p/"} {
		for _, status := range []int{401, 403, 404} {
			rt.set(refusing(t, a, match, status), "")
			r := b.mkRemote("rel", remoteGenesis("main", at, nil))
			if r.Code != 422 || r.Str("code") != "invalid" {
				t.Fatalf("%d for %s: %d %s, want 422 invalid", status, match, r.Code, r.Body)
			}
			expect(t, b.get("/ns/rel"), 404)
		}
		rt.set(refusing(t, a, match, 500), "")
		expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 502, "upstream")
	}
	rt.set(a.srv.URL, "")
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
}

// The genesis gives base.chain: a missing chain is 422 at /base/chain,
// before anything is fetched, and a wrong one too. The genesis is stored as
// sent, so its config id is the creator's (§G.3).
func TestV073RemoteChainRequired(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateChain(t, a)
	expectPointer := func(r *resp, ptr string) {
		t.Helper()
		expectCode(t, r, 422, "invalid")
		errs, _ := r.Obj()["errors"].([]any)
		if len(errs) != 1 || errs[0].(map[string]any)["pointer"] != ptr {
			t.Fatalf("errors %s, want one at %s", r.Body, ptr)
		}
		expect(t, b.get("/ns/rel"), 404)
	}
	noChain := addRoot(map[string]any{"read": "public", "base": map[string]any{"origin": originA, "ns": "r7", "at": f.atA}})
	rt.set("http://127.0.0.1:1", "") // nothing is fetched
	expectPointer(b.mkRemote("rel", noChain), "/base/chain")
	rt.set(a.srv.URL, "")
	expectPointer(b.mkRemote("rel", noChain), "/base/chain")
	expectPointer(b.mkRemote("rel", remoteGenesis("r7", f.atA, nil)), "/base/chain")
	expectPointer(b.mkRemote("rel", remoteGenesisChain([]string{"r7", "matches", "schemas"}, f.atA, nil)), "/base/chain")

	// A genesis of several ops, stored as sent: the config id is over it.
	genesis := append(remoteGenesisChain(r7Chain, f.atA, nil), op("add", "/x-title", "B's"))
	r := b.mkRemote("rel", genesis)
	expect(t, r, 201)
	if want := hashID(t, "", canonical(genesis)); r.H.Get("X-Config-Revision") != want || b.configID("rel") != want {
		t.Fatalf("config id %s, want %s", r.H.Get("X-Config-Revision"), want)
	}
	doc := b.get("/ns/rel/rev/" + b.nsHead("rel")).Obj()
	if string(canonical(doc["base"])) != string(canonical(map[string]any{"origin": originA, "ns": "r7", "at": f.atA, "chain": strs(r7Chain)})) || doc["x-title"] != "B's" {
		t.Fatalf("document %v", doc)
	}
}

// A missing schema mirror is created with the genesis document exactly
// { "read": "public" } if its source at A is public, and { "read": "grant" }
// otherwise, whatever the remote branch's own read, followed by the nonce
// config write where the source requires nonces (§G.3, §2.1, §C.7).
func TestV073RemoteSchemaMirrorGenesis(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("pub", map[string]any{"read": "public", "nonce": "required"})
	a.mkNS("priv", map[string]any{"read": "grant"})
	nonced := matchSchema()
	nonced["$nonce"] = seal.NewNonce()
	sPub := a.create("pub", "match", nonced)
	sPriv := a.create("priv", "match", matchSchema())
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "x", map[string]any{"$schema": "/r/pub/match/rev/" + sPub, "score": "1-0"})
	a.create("main", "y", map[string]any{"$schema": "/r/priv/match/rev/" + sPriv, "score": "0-1"})
	a.mkNS("hidden", map[string]any{"read": "grant"})
	a.create("hidden", "z", map[string]any{"$schema": "/r/pub/match/rev/" + sPub, "score": "2-2"})

	// A public remote branch of the public main.
	expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
	genesis := func(ns string) string {
		t.Helper()
		lg := b.nsLog(ns)
		if lg[0]["kind"] != "config" {
			t.Fatalf("%s: log %v", ns, lg)
		}
		return lg[0]["target"].(string)
	}
	for ns, read := range map[string]string{"pub": "public", "priv": "grant"} {
		if got, want := genesis(ns), hashID(t, "", canonical(addRoot(map[string]any{"read": read}))); got != want {
			t.Errorf("%s: genesis %s, want that of {read: %s}", ns, got, read)
		}
	}
	// The nonce setting follows, by a config write, once the history is in.
	if k := b.nsKinds("pub"); len(k) != 3 || k[1] != "batch" || k[2] != "config" {
		t.Fatalf("pub's log %v", k)
	}
	if doc := b.get("/ns/pub/rev/" + b.nsHead("pub")).Obj(); string(canonical(doc)) != `{"nonce":"required","read":"public"}` {
		t.Fatalf("pub's document %v", doc)
	}
	if k := b.nsKinds("priv"); len(k) != 2 {
		t.Fatalf("priv's log %v", k)
	}

	// A private remote branch doesn't make the mirror of a public source
	// private (b2 has no mirror yet).
	b2 := newEnv(t, withOrigin(originB), withRemote(&route{url: a.srv.URL}))
	expect(t, b2.mkRemote("rel", remoteGenesis("hidden", a.nsHead("hidden"), map[string]any{"read": "grant"})), 201)
	if doc := b2.get("/ns/pub/rev/" + b2.nsHead("pub")).Obj(); doc["read"] != "public" {
		t.Fatalf("pub's document %v", doc)
	}
}

// A mirror, created or existing, that ranks below its source is 422; a
// frozen one refuses the history with 409 frozen, where there is history to
// write, and a purged one with 410 purged; nothing is written (§G.3, §2.1).
func TestV073RemoteSchemaMirrorRefusals(t *testing.T) {
	t.Parallel()
	a, _, rt := pair(t, nil, nil)
	a.mkNS("schemas", map[string]any{"read": "grant"})
	s1 := a.create("schemas", "match", matchSchema())
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "d", map[string]any{"$schema": "/r/schemas/match/rev/" + s1, "score": "1-0"})
	at := a.nsHead("main")
	fresh := func() *tenv { return newEnv(t, withOrigin(originB), withRemote(rt)) }
	nothing := func(b *tenv, schemasLog int) {
		t.Helper()
		expect(t, b.get("/ns/rel"), 404)
		if k := b.nsKinds("schemas"); len(k) != schemasLog {
			t.Fatalf("schemas' log %v", k)
		}
	}

	// A public mirror of a private source.
	b := fresh()
	b.mkNS("schemas", map[string]any{"read": "public"})
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 422, "invalid")
	nothing(b, 1)
	expect(t, b.patchNS("schemas", ops(op("replace", "/read", "grant")), ""), 201)
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)

	// Frozen: refused where history would be written, and only there.
	b = fresh()
	b.mkNS("other", map[string]any{"read": "grant"})
	b.mkNS("schemas", map[string]any{"read": "grant"})
	expect(t, b.patchNS("schemas", ops(op("add", "/frozen", true), op("add", "/successor", "other")), ""), 201)
	r := b.mkRemote("rel", remoteGenesis("main", at, nil))
	expectCode(t, r, 409, "frozen")
	if r.Str("successor") != "other" {
		t.Fatalf("409 %s", r.Body)
	}
	nothing(b, 2)
	if g := b.get("/r/schemas/match"); g.Code != 404 {
		t.Fatalf("mirrored into a frozen namespace: %d", g.Code)
	}
	b = fresh()
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
	expect(t, b.patchNS("schemas", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, b.mkRemote("rel2", remoteGenesis("main", at, nil)), 201) // nothing to write

	// Purged: 410 purged, naming the namespace and its purge.
	b = fresh()
	b.mkNS("schemas", map[string]any{"read": "grant"})
	head := b.nsPurge("schemas")
	r = b.mkRemote("rel", remoteGenesis("main", at, nil))
	expectCode(t, r, 410, "purged")
	if r.Str("ns") != "schemas" || r.Str("head") != head {
		t.Fatalf("410 %s, want ns schemas and head %s", r.Body, head)
	}
	expect(t, b.get("/ns/rel"), 404)

	// A branch, or a different history, is still name_conflict.
	b = fresh()
	b.mkNS("base", map[string]any{"read": "grant"})
	expect(t, b.branch("base", map[string]any{"name": "schemas"}, "alice"), 201)
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 409, "name_conflict")
}

// A registration retry answers 200 only while the latest registration is
// unexpired, and has no other bound: an If-None-Match retry works past the
// retry window, and an If-Match retry naming the entry before the latest
// is 412 once the latest expired (§G.3).
func TestV073RegistrationRetryExpiry(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA))
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "p", map[string]any{"v": 1.0})
	at := a.nsHead("main")

	r := a.register("main", "rel", at, "", "b")
	expect(t, r, 201)
	reg1 := r.Str("ns_id")
	a.clock.Advance(2 * time.Hour) // past the retry window, not the registration
	if r := a.register("main", "rel", at, "", "b"); r.Code != 200 || r.Str("ns_id") != reg1 {
		t.Errorf("retry past the retry window: %d %s, want 200 with %s", r.Code, r.Body, reg1)
	}
	expectCode(t, a.register("main", "rel", at, "", "c"), 412, "stale")

	r = a.register("main", "rel", at, reg1, "b")
	expect(t, r, 201)
	reg2 := r.Str("ns_id")
	r = a.register("main", "rel", at, reg1, "b")
	expect(t, r, 200)
	if r.Str("ns_id") != reg2 {
		t.Fatalf("renewal retry %s", r.Body)
	}
	a.clock.Advance(31 * 24 * time.Hour) // reg2 expired
	r = a.register("main", "rel", at, reg1, "b")
	expectCode(t, r, 412, "stale")
	if r.Str("head") != reg2 {
		t.Fatalf("412 %s, want head %s", r.Body, reg2)
	}
	// Renewing the expired latest still works.
	expect(t, a.register("main", "rel", at, reg2, "b"), 201)
}

// "Same principal" for a registration retry is the same root sub and kid:
// a grant for the same sub from another key is 412 (§G.3, §7.2).
func TestV073RegistrationSamePrincipal(t *testing.T) {
	t.Parallel()
	a := newAuthEnv(t, withOrigin(originA))
	k1, k2 := newKey("k1"), newKey("k2")
	a.mkNS("main", map[string]any{"read": "grant", "keys": []any{k1.entry("*"), k2.entry("*")}})
	g1 := a.grant(k1, "svc:b", []string{"main"}, []string{"read", "export"})
	g2 := a.grant(k2, "svc:b", []string{"main"}, []string{"read", "export"})
	at := a.nsHead("main", g1)

	r := a.register("main", "rel", at, "", g1)
	expect(t, r, 201)
	reg1 := r.Str("ns_id")
	expectCode(t, a.register("main", "rel", at, "", g2), 412, "stale")
	a.clock.Advance(time.Minute)
	g1b := a.grant(k1, "svc:b", []string{"main"}, []string{"read", "export"}) // reminted, same key
	if r := a.register("main", "rel", at, "", g1b); r.Code != 200 || r.Str("ns_id") != reg1 {
		t.Fatalf("retry under the same sub and kid: %d %s", r.Code, r.Body)
	}

	r = a.register("main", "rel", at, reg1, g1)
	expect(t, r, 201)
	reg2 := r.Str("ns_id")
	expectCode(t, a.register("main", "rel", at, reg1, g2), 412, "stale")
	if r := a.register("main", "rel", at, reg1, g1b); r.Code != 200 || r.Str("ns_id") != reg2 {
		t.Fatalf("renewal retry under the same sub and kid: %d %s", r.Code, r.Body)
	}
}

// Creation is judged against the base's current namespace document, as a
// local branch's is against its base's: its read, its level, and an at
// before its raise to e2e (§G.5.2, §7.4, Addendum E Levels).
func TestV073RemoteCurrentSourceDocument(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t))})
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "p", map[string]any{"v": 1.0})
	at := a.nsHead("main")
	// A public at at, private now: a public remote branch is refused.
	expect(t, a.patchNS("main", ops(op("replace", "/read", "grant")), ""), 201)
	if r := b.mkRemote("pub", remoteGenesis("main", at, nil)); r.Code != 422 || r.Str("code") != "invalid" {
		t.Errorf("public remote branch of a base private now: %d %s, want 422 invalid", r.Code, r.Body)
	}
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, map[string]any{"read": "grant"})), 201)

	// e2e now, but not at at: at is before the raise, whatever the
	// branch's level. (A's deployment is made to claim the raise; this
	// server raises nothing to e2e.)
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "p", map[string]any{"v": 1.0})
	atM := a.nsHead("m")
	expect(t, a.patchNS("m", ops(op("add", "/x-title", "raised")), ""), 201)
	head := a.nsHead("m")
	rt.set(tamper(t, a, "/ns/m/rev/"+head, func(b []byte) []byte {
		return bytes.Replace(b, []byte(`{"read"`), []byte(`{"encryption":{"level":"e2e"},"read"`), 1)
	}), "")
	for name, doc := range map[string]map[string]any{
		"private": {"read": "grant"},
		"e2e":     e2eDoc(map[string]any{"read": "grant"}),
	} {
		r := b.mkRemote("relm", remoteGenesis("m", atM, doc))
		expectCode(t, r, 422, "invalid")
		if errs, _ := r.Obj()["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/base/at" {
			t.Fatalf("%s: %s, want an error at /base/at", name, r.Body)
		}
		expect(t, b.get("/ns/relm"), 404)
	}
}

// An E3 remote branch can't have the name of a namespace in its
// base.chain: a kid {ns}#{e} names one keyring (§G.5.2, §F.8.1).
func TestV073RemoteE2ENameInChain(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("e", e2eDoc(map[string]any{"read": "grant"}))
	at := a.nsHead("e")
	r := b.mkRemote("e", remoteGenesis("e", at, e2eDoc(map[string]any{"read": "grant"})))
	expectCode(t, r, 422, "invalid")
	if errs, _ := r.Obj()["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/base/chain" {
		t.Fatalf("%s, want an error at /base/chain", r.Body)
	}
	expect(t, b.get("/ns/e"), 404)
	expect(t, b.mkRemote("rel", remoteGenesis("e", at, e2eDoc(map[string]any{"read": "grant"}))), 201)

	// Below E3 the name is free (§G.5.2 binds e2e sources only).
	a.mkNS("plain", map[string]any{"read": "public"})
	expect(t, b.mkRemote("plain", remoteGenesis("plain", a.nsHead("plain"), nil)), 201)
}

// The operator grant that creates a remote branch is checked for config,
// which covers the schema namespaces it creates and mirrors into: without
// it, 403 and nothing is written (§C.2, §C.4).
func TestV073RemoteOperatorConfig(t *testing.T) {
	t.Parallel()
	var bPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA))
	f := populateA(t, a)
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(&route{url: a.srv.URL}))
	b.opPriv = bPriv
	opGrant := func(can ...string) string {
		return mint(t, bPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"rel"}, "can": strs(can),
			"exp": b.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	genesis := remoteGenesis("main", f.at, map[string]any{"read": "grant"})
	for _, can := range [][]string{{"read"}, {"purge", "purge-ns"}} {
		r := b.do(req{method: "PATCH", path: "/ns/rel", ifNoneMatch: "*", body: genesis, bearer: opGrant(can...)})
		expectCode(t, r, 403, "forbidden")
		// To an operator grant, /principal of a missing namespace is 404 (§7.4).
		expect(t, b.get("/ns/rel/principal", b.operatorGrant("rel")), 404)
		expect(t, b.get("/ns/schemas/principal", b.operatorGrant("schemas")), 404)
	}
	r := b.do(req{method: "PATCH", path: "/ns/rel", ifNoneMatch: "*", body: genesis, bearer: opGrant("config")})
	expect(t, r, 201)
	expect(t, b.get("/ns/schemas/principal", b.operatorGrant("schemas")), 200)
}

// A schema mirror that is end-to-end refuses the history where there is
// history to write: only a key holder seals content into e2e, and this
// deployment writes it as it is (422, §2.1, §G.3, §E.3.1). It ranks above
// any source, so the rank check alone would let a private source be
// mirrored, in the clear, into an e2e namespace whose read is public.
func TestV073RemoteSchemaMirrorE2E(t *testing.T) {
	t.Parallel()
	// A public source.
	a, b, _ := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("schemas", map[string]any{"read": "public"})
	s1 := a.create("schemas", "match", matchSchema())
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "d", map[string]any{"$schema": "/r/schemas/match/rev/" + s1, "score": "1-0"})
	b.mkNS("schemas", e2eDoc(map[string]any{"read": "public"}))
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 422, "invalid")
	expect(t, b.get("/ns/rel"), 404)
	if k := b.nsKinds("schemas"); len(k) != 1 {
		t.Fatalf("schemas' log %v", k)
	}
	expect(t, b.get("/r/schemas/match/rev/"+s1+"/log"), 404)

	// A private source at A, and an e2e mirror on B that anyone may read.
	var aPriv, bPriv ed25519.PrivateKey
	a = newEnv(t, withOrigin(originA), withAuth(&aPriv))
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{kA.entry("*")}})
	a.mkNS("main", map[string]any{"read": "public", "keys": []any{kA.entry("*")}})
	gA := a.grant(kA, "user:a", []string{"main", "schemas"}, []string{"read", "create", "append"})
	secret := matchSchema()
	secret["description"] = "private at A"
	s1 = a.create("schemas", "match", secret, gA)
	a.create("main", "d", map[string]any{"$schema": "/r/schemas/match/rev/" + s1, "score": "1-0"}, gA)
	at := a.nsHead("main", gA)
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"main", "schemas"}, []string{"read"})}
	b = newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	b.mkNS("schemas", e2eDoc(map[string]any{"read": "public"}))
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 422, "invalid")
	expect(t, b.get("/ns/rel/principal", b.operatorGrant("rel")), 404)
	if g := b.get("/r/schemas/match/rev/" + s1 + "/log"); g.Code != 404 {
		t.Fatalf("A's private schema at B, read with no grant: %d %s", g.Code, g.Body)
	}
}

// A schema path on B that holds a purged resource refuses the history as
// any write to a purged resource does, 410 gone, before the frozen check,
// where its chain is the base's, a prefix of it or contains it; one whose
// chain is a different history is 409 name_conflict. A resource row
// without entries, as a pending blob's, holds no resource (§G.3, §7.2,
// §8.3, §6.2).
func TestV073RemoteSchemaMirrorPurgedResource(t *testing.T) {
	t.Parallel()
	a, _, rt := pair(t, nil, nil)
	a.mkNS("schemas", map[string]any{"read": "public"})
	s1 := a.create("schemas", "match", matchSchema())
	s2 := a.appendRev("schemas", "match", s1, ops(op("add", "/title", "Match")))
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "d", map[string]any{"$schema": "/r/schemas/match/rev/" + s2, "score": "1-0"})
	at := a.nsHead("main")
	fresh := func() *tenv {
		b := newEnv(t, withOrigin(originB), withRemote(rt))
		b.mkNS("schemas", map[string]any{"read": "public"})
		return b
	}
	expectGone := func(b *tenv, what string) {
		t.Helper()
		r := b.mkRemote("rel", remoteGenesis("main", at, nil))
		if r.Code != 410 || r.Str("code") != "gone" || r.Str("path") != "/r/schemas/match/rev/"+s2 {
			t.Fatalf("%s: %d %s, want 410 gone naming the revision", what, r.Code, r.Body)
		}
		expect(t, b.get("/ns/rel"), 404)
	}

	// A prefix of A's chain, purged: B's own create on the path is 410 too.
	b := fresh()
	if id := b.create("schemas", "match", matchSchema()); id != s1 {
		t.Fatalf("B's revision %s, want A's %s", id, s1)
	}
	expect(t, b.purge("schemas", "match", s1, "admin"), 204)
	expectCode(t, b.do(req{method: "PATCH", path: "/r/schemas/match", ifNoneMatch: "*", body: addRoot(matchSchema()), author: "admin"}), 410, "gone")
	expectGone(b, "a prefix")
	// Frozen too: the purged resource answers first.
	expect(t, b.patchNS("schemas", ops(op("add", "/frozen", true)), ""), 201)
	expectGone(b, "a prefix in a frozen namespace")

	// A's very chain, and one that contains it.
	for _, extra := range []bool{false, true} {
		b = fresh()
		b.create("schemas", "match", matchSchema())
		head := b.appendRev("schemas", "match", s1, ops(op("add", "/title", "Match")))
		if extra {
			head = b.appendRev("schemas", "match", head, ops(op("add", "/description", "B's")))
		}
		expect(t, b.purge("schemas", "match", head, "admin"), 204)
		expectGone(b, fmt.Sprintf("A's chain (extended: %v)", extra))
	}

	// A different history, purged, is still name_conflict.
	b = fresh()
	other := matchSchema()
	other["title"] = "B's own"
	id := b.create("schemas", "match", other)
	expect(t, b.purge("schemas", "match", id, "admin"), 204)
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 409, "name_conflict")

	// A pending blob's row: the history goes in as for a missing resource.
	b = fresh()
	b.upload("schemas", "match", "image/png", []byte("not yet referenced"))
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
	if g := b.get("/r/schemas/match"); etagOf(g) != s2 {
		t.Fatalf("mirrored head: %d %s, want %s", g.Code, g.H.Get("ETag"), s2)
	}
}

// A registration entry that records no grant, written while authentication
// was disabled, matches no one once authentication is on, a retry by its
// author included, as write retries do (§7.2, §G.3, v0.74).
func TestV073RegistrationNoGrantEntry(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "a.db")
	k := newKey("k")
	a := newEnv(t, withOrigin(originA), withPath(path))
	a.mkNS("main", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	at := a.nsHead("main")
	r := a.register("main", "rel", at, "", "svc:b")
	expect(t, r, 201)
	reg1 := r.Str("ns_id")
	a.close()

	a = newAuthEnv(t, withOrigin(originA), withPath(path))
	g := a.grant(k, "svc:b", []string{"main"}, []string{"read", "export"})
	if r := a.register("main", "rel", at, "", g); r.Code != 412 {
		t.Fatalf("retry by its author: %d %s, want 412 (the entry %s records no grant)", r.Code, r.Body, reg1)
	}
	expectCode(t, a.register("main", "rel", at, "", a.grant(k, "svc:c", []string{"main"}, []string{"read", "export"})), 412, "stale")
}
