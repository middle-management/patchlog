package server

import (
	"context"
	"testing"
	"time"
)

// P26: purge and prune (§6.1, §6.2, §6.6, §7.2, §8.3, §8.5, §8.6).

// forcePurge sends a purge with ?force=1 to path (…/purge).
func (e *tenv) forcePurge(path, ifMatch, bearer string) *resp {
	e.t.Helper()
	return e.do(req{method: "POST", path: path + "?force=1", ifMatch: ifMatch, bearer: bearer})
}

// noEntry checks that a write answered without X-Namespace-Revision and
// left ns's head at head (§7.2, §8.6).
func noEntry(t *testing.T, e *tenv, r *resp, ns, head string) {
	t.Helper()
	if got := r.H.Get("X-Namespace-Revision"); got != "" {
		t.Fatalf("X-Namespace-Revision %s on a write that records nothing: %s", got, r.Body)
	}
	if now := e.nsHead(ns); now != head {
		t.Fatalf("%s's head moved from %s to %s", ns, head, now)
	}
}

// pruneEntry checks that a prune answered with the prune entry it appended
// to ns, targeting horizon (§3.5, §8.6).
func pruneEntry(t *testing.T, e *tenv, r *resp, ns, name, horizon string) {
	t.Helper()
	expect(t, r, 200)
	if r.Str("horizon") != horizon {
		t.Fatalf("horizon %s, want %s", r.Body, horizon)
	}
	en := e.lastNSEntry(ns)
	if r.H.Get("X-Namespace-Revision") != en["id"] || en["kind"] != "prune" || en["resource"] != name || en["target"] != horizon {
		t.Fatalf("X-Namespace-Revision %q, last entry %v", r.H.Get("X-Namespace-Revision"), en)
	}
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

// v0.73 §8.6 Request, §6.4.1 (BBD-46, GB-14): a prune that sends keep
// replaces the keep set, and [] clears it; one without keep leaves it, and
// its documents stay as the horizon moves past them. A prune that changes
// only the keep set appends a prune entry targeting the effective horizon,
// with X-Namespace-Revision; one that changes nothing writes nothing. The
// envelope's doc carries keep only when it was sent.
func TestV073P26KeepSet(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withoutRetentionLoop)
	e.mkNS("ks", map[string]any{"read": "public"})
	revs := e.chain("ks", "a", 10)
	e.clock.Advance(time.Hour)
	prune := func(body map[string]any) *resp { return e.prune("ks", "a", body, "admin") }
	served := func(i int) { t.Helper(); expect(t, e.get("/r/ks/a/rev/"+revs[i]), 200) }
	pruned := func(i int) { t.Helper(); expectCode(t, e.get("/r/ks/a/rev/"+revs[i]), 410, "pruned") }

	pruneEntry(t, e, prune(map[string]any{"horizon": revs[4], "keep": []any{revs[2]}}), "ks", "a", revs[4])
	served(2)
	pruned(1)
	pruned(3)
	// Without keep, the set stays, past the horizon too.
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[6]}), "ks", "a", revs[6])
	served(2)
	pruned(4)
	served(6)

	// Only the keep set changes: an entry targeting the effective
	// horizon, here the current one, above the one asked for.
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[5], "keep": []any{}}), "ks", "a", revs[6])
	pruned(2)
	served(6)
	// Nothing changes: no entry, keep sent or not.
	head := e.nsHead("ks")
	r := prune(map[string]any{"horizon": revs[6], "keep": []any{}})
	expect(t, r, 200)
	noEntry(t, e, r, "ks", head)
	r = prune(map[string]any{"horizon": revs[6]})
	expect(t, r, 200)
	noEntry(t, e, r, "ks", head)
	// Revisions above the horizon join the set (an entry); the same set
	// in another order is no change. A prune past them keeps them.
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[6], "keep": []any{revs[8], revs[7]}}), "ks", "a", revs[6])
	head = e.nsHead("ks")
	r = prune(map[string]any{"horizon": revs[6], "keep": []any{revs[7], revs[8], revs[7]}})
	expect(t, r, 200)
	noEntry(t, e, r, "ks", head)
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[9]}), "ks", "a", revs[9])
	served(7)
	served(8)
	pruned(6)
	// Dropping one of them from the set drops its document.
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[9], "keep": []any{revs[8]}}), "ks", "a", revs[9])
	pruned(7)
	served(8)
	// Retention, which sends no keep, leaves the set too.
	revs = append(revs, e.appendRev("ks", "a", revs[9], ops(op("replace", "/n", 10.0))))
	revs = append(revs, e.appendRev("ks", "a", revs[10], ops(op("replace", "/n", 11.0))))
	expect(t, e.patchNS("ks", ops(op("add", "/retention", []any{map[string]any{"keep": map[string]any{"revisions": 1.0}, "archive": false}})), ""), 201)
	e.clock.Advance(time.Hour)
	if rep, err := e.e.ApplyRetention(context.Background()); err != nil || rep.Pruned != 1 {
		t.Fatalf("retention %+v %v", rep, err)
	}
	pruned(10)
	served(8)
	served(11)

	// The envelope: { horizon } without keep, { horizon, keep } with it,
	// [] included.
	noKeep := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "prune"}},
		"then": []any{map[string]any{"op": "test", "path": "/doc/keep", "exists": false}},
	}
	e.mkNS("kr", map[string]any{"read": "public", "rules": []any{noKeep}})
	k := e.chain("kr", "a", 3)
	e.clock.Advance(time.Hour)
	expectCode(t, e.prune("kr", "a", map[string]any{"horizon": k[1], "keep": []any{}}, "admin"), 422, "rule")
	pruneEntry(t, e, e.prune("kr", "a", map[string]any{"horizon": k[1]}, "admin"), "kr", "a", k[1])
}

// v0.73 §8.6 Request, §12.2 (BBD-47): outside a branch, each keep id is a
// revision of the resource whose document is still served, or the prune is
// 422 invalid, whether or not the horizon moves; more ids than
// keepPerResource is 422 limit.
func TestV073P26KeepServed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withoutRetentionLoop)
	e.mkNS("kv", map[string]any{"read": "public", "limits": map[string]any{"keepPerResource": 2.0}})
	revs := e.chain("kv", "a", 8)
	e.clock.Advance(time.Hour)
	prune := func(body map[string]any) *resp { return e.prune("kv", "a", body, "admin") }
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[4], "keep": []any{revs[1]}}), "kv", "a", revs[4])

	head := e.nsHead("kv")
	// revs[2] is pruned: 422 whether the horizon stays or moves.
	expectCode(t, prune(map[string]any{"horizon": revs[4], "keep": []any{revs[1], revs[2]}}), 422, "invalid")
	expectCode(t, prune(map[string]any{"horizon": revs[6], "keep": []any{revs[2]}}), 422, "invalid")
	// Not a revision of the resource.
	expectCode(t, prune(map[string]any{"horizon": revs[4], "keep": []any{hashID(t, "", nil)}}), 422, "invalid")
	expectLimit(t, prune(map[string]any{"horizon": revs[6], "keep": []any{revs[1], revs[4], revs[6]}}), 422, "keepPerResource", 3, 2)
	if e.nsHead("kv") != head {
		t.Fatal("a refused prune wrote an entry")
	}
	expect(t, e.get("/r/kv/a/rev/"+revs[1]), 200)
	expect(t, e.get("/r/kv/a/rev/"+revs[5]), 200)
	// Still served: a kept revision and the horizon.
	pruneEntry(t, e, prune(map[string]any{"horizon": revs[6], "keep": []any{revs[1], revs[4]}}), "kv", "a", revs[6])
	expect(t, e.get("/r/kv/a/rev/"+revs[4]), 200)
	expectCode(t, e.get("/r/kv/a/rev/"+revs[5]), 410, "pruned")
}

// v0.73 §8.6 Request (BBD-52): where no retention rule matches the
// resource, retention keeps everything, so a prune that moves its horizon
// needs a grant chained to a * key, archive or not. A prune that moves
// nothing needs none, and within a matching rule prune suffices.
func TestV073P26NoRuleNeedsStar(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	sk, pk := newKey("sk"), newKey("pk")
	can := []string{"read", "create", "append", "prune"}
	e.mkNS("nr", map[string]any{"read": "public", "keys": []any{sk.entry("*"), pk.entry(can...)}})
	sg := e.grant(sk, "user:admin", []string{"nr"}, allVerbs)
	pg := e.grant(pk, "user:p", []string{"nr"}, can)
	a := e.chain("nr", "a", 5, pg)
	e.clock.Advance(10 * time.Minute)

	expectCode(t, e.prune("nr", "a", map[string]any{"horizon": a[3]}, pg), 403, "forbidden")
	expect(t, e.get("/r/nr/a/rev/"+a[1], pg), 200)
	// Moving nothing: the genesis, and a change to keep alone.
	r := e.prune("nr", "a", map[string]any{"horizon": a[0]}, pg)
	expect(t, r, 200)
	if r.Str("horizon") != a[0] {
		t.Fatalf("prune at the genesis %s", r.Body)
	}
	pruneEntry(t, e, e.prune("nr", "a", map[string]any{"horizon": a[0], "keep": []any{a[2]}}, pg), "nr", "a", a[0])
	// The * key moves it.
	pruneEntry(t, e, e.prune("nr", "a", map[string]any{"horizon": a[3]}, sg), "nr", "a", a[3])

	// A rule selecting a: prune suffices within what it keeps.
	expect(t, e.patchNS("nr", ops(op("add", "/retention", []any{map[string]any{"select": map[string]any{"names": []any{"a"}}, "keep": map[string]any{"revisions": 2.0}}})), sg), 201)
	expectCode(t, e.prune("nr", "a", map[string]any{"horizon": a[4]}, pg), 403, "forbidden")
	a5 := e.appendRev("nr", "a", a[4], ops(op("replace", "/n", 5.0)), pg)
	a6 := e.appendRev("nr", "a", a5, ops(op("replace", "/n", 6.0)), pg)
	_ = a6
	e.clock.Advance(10 * time.Minute)
	pruneEntry(t, e, e.prune("nr", "a", map[string]any{"horizon": a5}, pg), "nr", "a", a5)
	// A resource the rule doesn't select needs a * key.
	b := e.chain("nr", "b", 3, pg)
	e.clock.Advance(10 * time.Minute)
	expectCode(t, e.prune("nr", "b", map[string]any{"horizon": b[2]}, pg), 403, "forbidden")
}

// v0.73 §6.6 Cost (GB-41, BBD-55): a prune isn't exempt; it costs a token
// from the principal, namespace and per-resource buckets, checked last in
// step 1, so a 429 comes before a precondition's 428 (§7.2).
func TestV073P26PruneRate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withoutRetentionLoop)
	slow := func(burst float64) map[string]any { return map[string]any{"rate": 0.0001, "burst": burst} }
	e.mkNS("pr", map[string]any{"read": "public", "limits": map[string]any{"ratePerResource": slow(2)}})
	a0 := e.create("pr", "a", map[string]any{"n": 0.0}, "admin")
	expect(t, e.prune("pr", "a", map[string]any{"horizon": a0}, "admin"), 200)
	r := e.prune("pr", "a", map[string]any{"horizon": a0}, "admin")
	expectCode(t, r, 429, "rate")
	if r.Str("limit") != "ratePerResource" {
		t.Fatalf("limit %s", r.Body)
	}
	expectCode(t, e.do(req{method: "POST", path: "/r/pr/a/prune", body: map[string]any{"horizon": a0}, ifMatch: a0, author: "admin"}), 429, "rate")
	// Another resource has its own bucket.
	b0 := e.create("pr", "b", map[string]any{"n": 0.0})
	expect(t, e.prune("pr", "b", map[string]any{"horizon": b0}, "admin"), 200)

	e.mkNS("pn", map[string]any{"read": "public", "limits": map[string]any{"ratePerNamespace": slow(3)}})
	x0 := e.create("pn", "x", map[string]any{"n": 0.0})
	y0 := e.create("pn", "y", map[string]any{"n": 0.0})
	expect(t, e.prune("pn", "x", map[string]any{"horizon": x0}, "admin"), 200)
	r = e.prune("pn", "y", map[string]any{"horizon": y0}, "admin")
	expectCode(t, r, 429, "rate")
	if r.Str("limit") != "ratePerNamespace" {
		t.Fatalf("limit %s", r.Body)
	}

	e.mkNS("pq", map[string]any{"read": "public", "limits": map[string]any{"ratePerPrincipal": slow(2)}})
	q0 := e.create("pq", "q", map[string]any{"n": 0.0}, "pat")
	expect(t, e.prune("pq", "q", map[string]any{"horizon": q0}, "pat"), 200)
	r = e.prune("pq", "q", map[string]any{"horizon": q0}, "pat")
	expectCode(t, r, 429, "rate")
	if r.Str("limit") != "ratePerPrincipal" {
		t.Fatalf("limit %s", r.Body)
	}
}

// v0.73 §7.2, §8.6, §12.1 (GB-58, BBD-45): a prune takes no precondition;
// one sent, If-Match or If-None-Match, is 428 at step 2.5: after the verb
// (403), the purged namespace's and resource's 410, and before the 404 of
// an unknown resource and the horizon's 422. Nothing is pruned.
func TestV073P26PrunePrecondition(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, withoutRetentionLoop)
	sk, pk := newKey("sk"), newKey("pk")
	can := []string{"read", "create", "append", "purge", "prune"}
	e.mkNS("pp", map[string]any{"read": "grant", "keys": []any{sk.entry("*"), pk.entry(can...)}})
	sg := e.grant(sk, "user:admin", []string{"pp", "ppb", "ppx"}, allVerbs)
	pg := e.grant(pk, "user:p", []string{"pp", "ppb"}, can)
	ng := e.grant(pk, "user:n", []string{"pp"}, []string{"read", "create", "append"})
	a := e.chain("pp", "a", 3, pg)
	e.clock.Advance(10 * time.Minute)
	pre := func(ns, name string, body map[string]any, bearer, ifMatch, ifNoneMatch string) *resp {
		t.Helper()
		return e.do(req{method: "POST", path: "/r/" + ns + "/" + name + "/prune", body: body, bearer: bearer, ifMatch: ifMatch, ifNoneMatch: ifNoneMatch})
	}
	h := map[string]any{"horizon": a[2]}

	expectCode(t, pre("pp", "a", h, ng, a[2], ""), 403, "forbidden")
	expectCode(t, pre("pp", "a", h, sg, a[2], ""), 428, "precondition_required")
	expectCode(t, pre("pp", "a", h, sg, "", "*"), 428, "precondition_required")
	expectCode(t, pre("pp", "a", map[string]any{"horizon": hashID(t, "", nil)}, sg, a[2], ""), 428, "precondition_required")
	expectCode(t, pre("pp", "nope", h, sg, a[2], ""), 428, "precondition_required")
	expect(t, e.get("/r/pp/a/rev/"+a[0], pg), 200)

	// In a branch too.
	expect(t, e.branch("pp", map[string]any{"name": "ppb"}, sg), 201)
	expectCode(t, pre("ppb", "a", h, pg, a[2], ""), 428, "precondition_required")

	// A purged resource, and a purged namespace: 410 first.
	expect(t, e.purge("pp", "a", a[2], pg), 204)
	expectCode(t, pre("pp", "a", h, pg, a[2], ""), 410, "gone")
	e.mkNS("ppx", map[string]any{"read": "grant", "keys": []any{sk.entry("*")}})
	x := e.create("ppx", "x", map[string]any{"n": 0.0}, sg)
	e.purgeNSAs("ppx", sg)
	expectCode(t, pre("ppx", "x", map[string]any{"horizon": x}, sg, x, ""), 410, "purged")
}
