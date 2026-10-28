package server

import (
	"crypto/ed25519"
	"testing"
)

// v0.74 §7.2 Idempotent retry (GRANTS-4, Open 83; CONFORMANCE Grant scope
// 54): "under grants, an entry without a recorded grant matches no one".
// Entries written while authentication was disabled record grant null; once
// it is on, a retry by a grant whose root sub is their author is 412, for a
// resource write, a batch, a config write and a branch's creation alike.
// A remote registration's: TestV073RegistrationNoGrantEntry.
func TestV074V01NoGrantEntryMatchesNoOne(t *testing.T) {
	t.Parallel()
	k := newKey("k")
	e, reopen := v073Reopenable(t)
	e.mkNS("n", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	d0 := e.create("n", "doc", map[string]any{"v": 1.0}, "user:bob")
	patch := ops(op("replace", "/v", 2.0))
	e.appendRev("n", "doc", d0, patch, "user:bob")
	batch := map[string]any{"items": []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}
	expect(t, e.batchReq("n", batch, "user:bob"), 201)
	parent := e.configID("n")
	config := func(q req) *resp {
		q.method, q.path, q.ifMatch, q.body = "PATCH", "/ns/n", parent, ops(op("add", "/x-a", 1.0))
		return e.do(q)
	}
	expect(t, config(req{author: "user:bob"}), 201)
	expect(t, e.branch("n", map[string]any{"name": "nb"}, "user:bob"), 201)

	var priv ed25519.PrivateKey
	e = reopen(withAuth(&priv))
	bob := e.grant(k, "user:bob", []string{"n", "nb"}, allVerbs)
	expectCode(t, e.write("PATCH", "n", "doc", d0, patch, bob), 412, "stale")
	expectCode(t, e.batchReq("n", batch, bob), 412, "batch")
	expectCode(t, config(req{bearer: bob}), 412, "stale")
	expectCode(t, e.branch("n", map[string]any{"name": "nb"}, bob), 412, "stale")
}
