package server

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// expectNonceKept expects the 422 of a branch turning off its base's nonce
// requirement (§7.6).
func expectNonceKept(t *testing.T, r *resp) {
	t.Helper()
	expectCode(t, r, 422, "invalid")
	if !strings.Contains(r.Str("message"), "nonce requirement its base has") {
		t.Fatalf("message %s", r.Body)
	}
}

// v0.48 §C.7 "Requiring it": in a namespace with "nonce": "required", every
// resource create, append and restore must result in a document with a
// fresh $nonce that differs from its parent's (422 nonce); deletes,
// config and branch writes are exempt.
func TestNonceRequired(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, bad := range []any{"sometimes", true} {
		q := req{method: "PATCH", path: "/ns/bad", ifNoneMatch: "*", author: "admin", body: addRoot(map[string]any{"read": "grant", "nonce": bad})}
		expectCode(t, e.do(q), 422, "invalid")
	}
	e.mkNS("n", map[string]any{"read": "grant", "nonce": "required"})

	// Create.
	expectCode(t, e.write("PATCH", "n", "a", "", addRoot(map[string]any{"v": 1.0})), 422, "nonce")
	expectCode(t, e.write("PATCH", "n", "a", "", addRoot(map[string]any{"v": 1.0, "$nonce": "short"})), 422, "nonce")
	n1 := seal.NewNonce()
	a1 := e.create("n", "a", map[string]any{"v": 1.0, "$nonce": n1})
	// Append: the parent's nonce kept, or set again, is refused.
	expectCode(t, e.write("PATCH", "n", "a", a1, ops(op("replace", "/v", 2.0))), 422, "nonce")
	expectCode(t, e.write("PATCH", "n", "a", a1, ops(op("replace", "/v", 2.0), op("replace", "/$nonce", n1))), 422, "nonce")
	expectCode(t, e.write("PATCH", "n", "a", a1, ops(op("remove", "/$nonce"))), 422, "nonce")
	a2 := e.appendRev("n", "a", a1, withNonce(ops(op("replace", "/v", 2.0))))
	// Deletes are exempt; a restore needs a fresh nonce, [] is refused.
	tomb := e.del("n", "a", a2)
	expectCode(t, e.write("PATCH", "n", "a", tomb, []any{}), 422, "nonce")
	a3 := e.appendRev("n", "a", tomb, withNonce(nil))
	if d := e.doc("n", "a"); d["v"] != 2.0 {
		t.Fatalf("restored %v", d)
	}

	// Batches item by item, dry runs too.
	b1 := e.create("n", "b", map[string]any{"$nonce": seal.NewNonce()})
	body := map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a3, "steps": []any{withNonce(ops(op("add", "/w", 1.0))), "delete", withNonce(nil)}},
		map[string]any{"resource": "b", "ifMatch": b1, "steps": []any{"delete", []any{}}},
		map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
	}}
	r := e.do(req{method: "POST", path: "/ns/n/batch?dry-run=1", body: body, author: "alice"})
	expect(t, r, 200)
	rep := r.Obj()["items"].([]any)
	if a, b, c := rep[0].(map[string]any), rep[1].(map[string]any), rep[2].(map[string]any); a["status"] != 200.0 || b["code"] != "nonce" || c["code"] != "nonce" {
		t.Fatalf("dry run %s", r.Body)
	}
	r = e.batchReq("n", body, "alice")
	expectCode(t, r, 422, "batch")
	if s := r.String(); strings.Count(s, `"code":"nonce"`) != 2 {
		t.Fatalf("batch failure %s", s)
	}
	body["items"] = body["items"].([]any)[:1]
	expect(t, e.batchReq("n", body, "alice"), 201)

	// Config writes are exempt; a namespace that isn't a branch may turn
	// the requirement off, and on again.
	expect(t, e.patchNS("n", ops(op("add", "/x-note", "config needs no nonce")), ""), 201)

	// A branch copies it and can't turn it off, at creation or later.
	expectNonceKept(t, e.branch("n", map[string]any{"name": "nb0", "patches": ops(op("replace", "/nonce", "optional"))}, "alice"))
	expect(t, e.branch("n", map[string]any{"name": "nb"}, "alice"), 201)
	if d := e.nsDoc("nb"); d["nonce"] != "required" {
		t.Fatalf("branch document %v", d)
	}
	expectCode(t, e.write("PATCH", "nb", "a", e.head("nb", "a"), ops(op("add", "/x", 1.0))), 422, "nonce")
	expectNonceKept(t, e.patchNS("nb", ops(op("remove", "/nonce")), ""))
	expectNonceKept(t, e.patchNS("nb", ops(op("replace", "/nonce", "optional")), ""))
	expect(t, e.patchNS("n", ops(op("replace", "/nonce", "optional")), ""), 201)
	e.create("n", "plain", map[string]any{})
	expect(t, e.patchNS("nb", ops(op("replace", "/nonce", "optional")), ""), 201)

	// Not in an end-to-end namespace, before anything about its keys.
	q := req{method: "PATCH", path: "/ns/z", ifNoneMatch: "*", author: "admin",
		body: addRoot(map[string]any{"read": "grant", "nonce": "required", "encryption": map[string]any{"level": "e2e"}})}
	if r := e.do(q); r.Code != 422 || !strings.Contains(r.String(), "/nonce") {
		t.Fatalf("e2e: %d %s", r.Code, r.Body)
	}
}

// The check applies to every patch set, whatever its origin: history
// written before the setting can't be fast-forwarded into a namespace that
// requires nonces, and the branch it comes from can still be frozen (§C.7).
func TestNonceRequiredFastForward(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "grant"})
	d1 := e.create("m", "d", map[string]any{"v": 1.0})
	expect(t, e.branch("m", map[string]any{"name": "mb"}, "alice"), 201)
	step := ops(op("replace", "/v", 2.0))
	e.appendRev("mb", "d", d1, step)
	// The branch first (§7.4).
	expectCode(t, e.patchNS("m", ops(op("add", "/nonce", "required")), ""), 409, "in_use")
	expect(t, e.patchNS("mb", ops(op("add", "/nonce", "required")), ""), 201)
	expect(t, e.patchNS("m", ops(op("add", "/nonce", "required")), ""), 201)
	body := map[string]any{"source": map[string]any{"ns": "mb", "at": e.nsHead("mb")},
		"items": []any{map[string]any{"resource": "d", "ifMatch": d1, "steps": []any{step}}}}
	r := e.batchReq("m", body, "alice")
	expectCode(t, r, 422, "batch")
	if !strings.Contains(r.String(), `"code":"nonce"`) {
		t.Fatalf("fast-forward %s", r.Body)
	}
	// Re-authored with a fresh $nonce, it goes in.
	body["items"] = []any{map[string]any{"resource": "d", "ifMatch": d1, "steps": []any{withNonce(step)}}}
	expect(t, e.batchReq("m", body, "alice"), 201)
	expect(t, e.patchNS("mb", ops(op("add", "/frozen", true)), ""), 201)
}

// Setting or changing it needs a * key (§7.4); in a branch, a * key of the
// base (§7.6).
func TestNonceRequiredGuarded(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, ck := newKey("sk"), newKey("ck")
	e.mkNS("g", map[string]any{"read": "grant", "keys": []any{sk.entry("*"), ck.entry("config", "read", "branch")}})
	sg := e.grant(sk, "user:admin", []string{"g", "gb"}, allVerbs)
	cg := e.grant(ck, "user:cfg", []string{"g", "gb"}, []string{"config", "read", "branch"})
	expectCode(t, e.patchNS("g", ops(op("add", "/nonce", "required")), cg), 403, "forbidden")
	expect(t, e.patchNS("g", ops(op("add", "/nonce", "required")), sg), 201)
	expectCode(t, e.branch("g", map[string]any{"name": "gb", "patches": ops(op("replace", "/nonce", "required"))}, cg), 403, "forbidden")
	expect(t, e.branch("g", map[string]any{"name": "gb"}, cg), 201)
	expectCode(t, e.patchNS("gb", ops(op("replace", "/nonce", "optional")), cg), 403, "forbidden")
	expectNonceKept(t, e.patchNS("gb", ops(op("replace", "/nonce", "optional")), sg))
}

// §G.3: a remote branch of a base that requires nonces must be created
// requiring them, and can't turn them off; schema namespaces mirrored for
// it take their source's setting (§C.7).
func TestNonceRequiredRemoteBranch(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("schemas", map[string]any{"read": "public", "nonce": "required"})
	s1 := a.create("schemas", "match", map[string]any{"$schema": dialect, "type": "object", "$nonce": seal.NewNonce()})
	a.mkNS("main", map[string]any{"read": "public", "nonce": "required"})
	a.create("main", "derby", map[string]any{"$schema": "/r/schemas/match/rev/" + s1, "$nonce": seal.NewNonce()})
	at := a.nsHead("main")

	r := b.mkRemote("rel", remoteGenesis("main", at, nil))
	if r.Code != 422 || !strings.Contains(r.String(), "/nonce") {
		t.Fatalf("remote branch without nonce: %d %s", r.Code, r.Body)
	}
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, map[string]any{"nonce": "required"})), 201)
	if d := b.nsDoc("schemas"); d["nonce"] != "required" {
		t.Fatalf("mirrored schema namespace %v", d)
	}
	h := b.head("rel", "derby")
	expectCode(t, b.write("PATCH", "rel", "derby", h, ops(op("add", "/x", 1.0))), 422, "nonce")
	b.appendRev("rel", "derby", h, withNonce(ops(op("add", "/x", 1.0))))
	expectNonceKept(t, b.patchNS("rel", ops(op("replace", "/nonce", "optional")), ""))
}

// A sealed namespace that requires nonces: a [] restore, which sealing
// alone allows, needs a lone fresh $nonce (§C.7, §8.2).
func TestNonceRequiredSealed(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public", "nonce": "required"}))
	a1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	tomb := e.del("s", "a", a1)
	expectCode(t, e.write("PATCH", "s", "a", tomb, []any{}), 422, "nonce")
	e.wr("s", "a", tomb, withNonce(nil))
}
