package server

import (
	"testing"
	"time"
)

// P26: purge and prune (§6.1, §6.2, §6.6, §7.2, §8.3, §8.5, §8.6).

// forcePurge sends a purge with ?force=1 to path (…/purge).
func (e *tenv) forcePurge(path, ifMatch, bearer string) *resp {
	e.t.Helper()
	return e.do(req{method: "POST", path: path + "?force=1", ifMatch: ifMatch, bearer: bearer})
}

// v0.73 §6.2 step 2.1, §8.3 (BBD-38): a resource purge checks the verb,
// then a purged resource (410, before the precondition), then 428, then
// 412 with the head; a name never written is 404 once a precondition is
// sent.
func TestV073P26ResourcePurgeOrder(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("po", map[string]any{"read": "public"})
	x := e.create("po", "x", map[string]any{"n": 1.0})
	expect(t, e.purge("po", "x", x, "admin"), 204)
	expectCode(t, e.purge("po", "x", "", "admin"), 410, "gone")
	expectCode(t, e.purge("po", "x", x, "admin"), 410, "gone")

	expectCode(t, e.purge("po", "nope", "", "admin"), 428, "precondition_required")
	expect(t, e.purge("po", "nope", x, "admin"), 404)

	y := e.create("po", "y", map[string]any{"n": 1.0})
	y2 := e.appendRev("po", "y", y, ops(op("replace", "/n", 2.0)))
	expectCode(t, e.purge("po", "y", "", "admin"), 428, "precondition_required")
	r := e.purge("po", "y", y, "admin")
	expectCode(t, r, 412, "stale")
	if r.Str("head") != y2 {
		t.Fatalf("412 head %s, want %s", r.Body, y2)
	}
}

// v0.73 §6.1 Forcing, §8.5 (CIS-25, BBD-39): ?force=1 under a grant that
// can't force is 403 right after authorisation, before the 410, 428, 412
// and not_frozen, whether or not the purge needs forcing. A grant can
// force when chained to a deployment operator key, or, for a purge of a
// branch or of a resource in one, to a * key of that branch.
func TestV073P26ForceNeedsPower(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, pk := newKey("sk"), newKey("pk")
	can := []string{"read", "create", "append", "purge", "purge-ns", "config"}
	e.mkNS("fp", map[string]any{"read": "public", "keys": []any{sk.entry("*"), pk.entry(can...)}})
	sg := e.grant(sk, "user:admin", []string{"fp", "fpb"}, allVerbs)
	pg := e.grant(pk, "user:p", []string{"fp", "fpb"}, can)
	x := e.create("fp", "x", map[string]any{"n": 1.0}, pg)
	y := e.create("fp", "y", map[string]any{"n": 1.0}, pg)

	// Nothing refuses this purge, yet ?force=1 is 403: without a
	// precondition, with a stale one, and under a * key of a namespace
	// that isn't a branch.
	expectCode(t, e.forcePurge("/r/fp/x/purge", "", pg), 403, "forbidden")
	expectCode(t, e.forcePurge("/r/fp/x/purge", y, pg), 403, "forbidden")
	expectCode(t, e.forcePurge("/r/fp/x/purge", x, sg), 403, "forbidden")
	// Without it the purge goes through; then the purged resource's 410
	// comes after the 403 too.
	expect(t, e.purge("fp", "x", x, pg), 204)
	expectCode(t, e.forcePurge("/r/fp/x/purge", x, pg), 403, "forbidden")
	expectCode(t, e.purge("fp", "x", x, pg), 410, "gone")

	// The operator forces.
	og := mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"fp", "fpb"}, "can": []any{"purge", "purge-ns"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, e.forcePurge("/r/fp/y/purge", y, og), 204)
	if en := e.lastNSEntry("fp"); en["kind"] != "purge" || en["forced"] != nil {
		t.Fatalf("a purge nothing refused says forced: %v", en)
	}

	// In a branch, a * key of the branch forces, inherited here; the
	// plain grant still can't.
	expect(t, e.branch("fp", map[string]any{"name": "fpb"}, sg), 201)
	w := e.create("fpb", "w", map[string]any{"n": 1.0}, pg)
	expectCode(t, e.forcePurge("/r/fpb/w/purge", w, pg), 403, "forbidden")
	expect(t, e.forcePurge("/r/fpb/w/purge", w, sg), 204)

	// Namespace purges: 403 before not_frozen and the 428.
	expectCode(t, e.forcePurge("/ns/fp/purge", "", pg), 403, "forbidden")
	expectCode(t, e.forcePurge("/ns/fp/purge", "", sg), 403, "forbidden")
	expectCode(t, e.forcePurge("/ns/fpb/purge", "", pg), 403, "forbidden")
	expectCode(t, e.do(req{method: "POST", path: "/ns/fpb/purge", bearer: pg}), 409, "not_frozen")
	expect(t, e.patchNS("fpb", ops(op("add", "/frozen", true)), sg), 201)
	expectCode(t, e.forcePurge("/ns/fpb/purge", e.nsHead("fpb", sg), pg), 403, "forbidden")
	expect(t, e.forcePurge("/ns/fpb/purge", e.nsHead("fpb", sg), sg), 204)
	// And before the purged namespace's 410.
	expectCode(t, e.forcePurge("/ns/fpb/purge", "", pg), 403, "forbidden")
	expectCode(t, e.forcePurge("/r/fpb/w/purge", w, pg), 403, "forbidden")
	expectCode(t, e.do(req{method: "POST", path: "/ns/fpb/purge", bearer: pg}), 410, "purged")
}

// v0.73 §8.5 Requirements (BBD-40): a namespace purge checks the verb,
// purged (410), frozen (409 not_frozen, step 2.4), the precondition (428,
// 412 with the head, step 2.5), dependents, then schema references.
func TestV073P26NamespacePurgeOrder(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("np", map[string]any{"read": "public"})
	e.create("np", "a", map[string]any{})
	stale := e.nsHead("np")
	e.create("np", "b", map[string]any{})
	purgeNS := func(ifMatch string) *resp {
		return e.do(req{method: "POST", path: "/ns/np/purge", ifMatch: ifMatch, author: "admin"})
	}
	expectCode(t, purgeNS(""), 409, "not_frozen")
	expectCode(t, purgeNS(stale), 409, "not_frozen")

	expect(t, e.patchNS("np", ops(op("add", "/frozen", true)), ""), 201)
	expectCode(t, purgeNS(""), 428, "precondition_required")
	r := purgeNS(stale)
	expectCode(t, r, 412, "stale")
	if r.Str("head") != e.nsHead("np") {
		t.Fatalf("412 head %s, want %s", r.Body, e.nsHead("np"))
	}
	expect(t, e.branch("np", map[string]any{"name": "npb"}, "admin"), 201)
	expectCode(t, purgeNS(stale), 412, "stale")
	r = purgeNS(e.nsHead("np"))
	expectCode(t, r, 409, "in_use")
	if deps, _ := r.Obj()["dependents"].([]any); len(deps) != 1 || deps[0] != "npb" {
		t.Fatalf("dependents %s", r.Body)
	}
}
