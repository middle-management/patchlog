package server

import (
	"context"
	"testing"
	"time"
)

// Wave-3 integration tests: behaviour that two wave-3 packages decide
// together.

// §6.4.3 "Operator overrides" with §6.2 step 6 (P25 x P26): a purge forced
// past an in_use refusal under a deployment operator grant isn't judged by
// namespace rules, but the operator grant's own rules still judge it (403),
// and a forced purge that needed no forcing is judged by namespace rules
// as any purge is (422 rule).
func TestV073W3PurgeOperatorRules(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk := newKey("sk")
	noPurge := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"purge", "purge-ns"}}}},
		"then": []any{map[string]any{"op": "test", "path": "/doc/ok", "exists": true}},
	}
	e.mkNS("sch", map[string]any{"read": "public", "keys": []any{sk.entry("*")}, "rules": []any{noPurge}})
	e.mkNS("docs", map[string]any{"read": "public", "keys": []any{sk.entry("*")}})
	sg := e.grant(sk, "user:admin", []string{"sch", "docs"}, allVerbs)
	s := e.create("sch", "s", map[string]any{"$schema": dialect, "type": "object"}, sg)
	e.create("docs", "d", map[string]any{"$schema": "/r/sch/s/rev/" + s}, sg)
	lone := e.create("sch", "lone", map[string]any{"v": 1.0}, sg)

	opG := func(rules ...any) string {
		root := map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"sch"}, "can": []any{"purge", "purge-ns"},
			"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}
		if len(rules) > 0 {
			root["rules"] = rules
		}
		return mint(t, e.opPriv, root)
	}
	// A block rule that refers to /doc, so step 6 decides it.
	needsDoc := map[string]any{"op": "test", "path": "/doc/granted", "exists": true}

	// The namespace's grants: s is referenced (409 in_use), and lone is
	// refused by the namespace rule.
	expectCode(t, e.purge("sch", "s", s, sg), 409, "in_use")
	expectCode(t, e.purge("sch", "lone", lone, sg), 422, "rule")

	// The operator forces a purge that needs no forcing: the namespace
	// rule judges it.
	expectCode(t, e.forcePurge("/r/sch/lone/purge", lone, opG()), 422, "rule")

	// The operator forces past the in_use refusal: the namespace rule
	// doesn't judge it, but the operator grant's own rule does.
	expectCode(t, e.forcePurge("/r/sch/s/purge", s, opG(needsDoc)), 403, "forbidden")
	expect(t, e.forcePurge("/r/sch/s/purge", s, opG()), 204)
	if en := e.lastNSEntry("sch"); en["kind"] != "purge" || en["forced"] != true {
		t.Fatalf("forced purge entry %v", en)
	}
}

// §7.8 check 2 with §1 (P27 x P32): an upload to a resource a remote
// branch answers 502 upstream for gets that 502, after authorisation and
// the purged namespace's 410, as a write does at step 2.1. P27 put the
// upstreamRefusal hook in the upload gate while P32 filled it in. A
// resource the base didn't have at the branch's at takes uploads still.
func TestV073W3UploadToUpstreamResource(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	r, _ := b.putBlob("r", "x", "text/plain", "", []byte("before"), "admin")
	expect(t, r, 201)
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, _ = b.putBlob("r", "x", "text/plain", "", []byte("after"), "admin")
	expectCode(t, r, 502, "upstream")
	r, _ = b.putBlob("r", "fresh", "text/plain", "", []byte("after"), "admin")
	expect(t, r, 201)
}
