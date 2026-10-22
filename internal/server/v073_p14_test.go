package server

import (
	"bytes"
	"testing"
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
