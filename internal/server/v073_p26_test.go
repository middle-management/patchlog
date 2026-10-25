package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
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

// v0.73 §8.6 Request (BBD-48): the prune answer is { horizon } alone; the
// archive written is linked from the pruned revisions' 410 (§7.1).
func TestV073P26PruneAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	e.mkNS("pa", map[string]any{"read": "public"})
	revs := e.chain("pa", "a", 4)
	e.clock.Advance(time.Hour)
	r := e.prune("pa", "a", map[string]any{"horizon": revs[2]}, "admin")
	expect(t, r, 200)
	if len(r.Obj()) != 1 || r.Str("horizon") != revs[2] {
		t.Fatalf("prune answer %s, want { horizon } alone", r.Body)
	}
	if g := e.get("/r/pa/a/rev/" + revs[0]); g.Code != 410 || g.Str("archive") == "" {
		t.Fatalf("pruned revision %d %s", g.Code, g.Body)
	}
}

// v0.73 §8.6 Branches don't prune (BBD-49): a prune in a branch runs its
// checks (the verb, purged, 404 or 410 for the resource, 428, the horizon
// in the branch's view, the rules) and moves nothing. It answers 200 with
// the resource's current horizon as the branch sees it, else its genesis
// id, ignores keep, needs neither an archive nor a * key, and writes
// nothing.
func TestV073P26BranchPrune(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withoutRetentionLoop)
	e.mkNS("bp", map[string]any{"read": "public"})
	c := e.chain("bp", "c", 4)
	expect(t, e.branch("bp", map[string]any{"name": "bpb"}, "alice"), 201)
	c4 := e.appendRev("bp", "c", c[3], ops(op("replace", "/n", 4.0)))
	e.clock.Advance(time.Hour)
	prune := func(body map[string]any) *resp { return e.prune("bpb", "c", body, "admin") }
	check := func(r *resp, horizon string) {
		t.Helper()
		expect(t, r, 200)
		if len(r.Obj()) != 1 || r.Str("horizon") != horizon {
			t.Fatalf("branch prune %s, want horizon %s", r.Body, horizon)
		}
	}

	// No horizon yet: the genesis. keep isn't checked, nor applied.
	bHead, mHead := e.nsHead("bpb"), e.nsHead("bp")
	r := prune(map[string]any{"horizon": c[3], "keep": []any{c[1], hashID(t, "", nil)}})
	check(r, c[0])
	noEntry(t, e, r, "bpb", bHead)
	noEntry(t, e, r, "bp", mHead)
	expect(t, e.get("/r/bpb/c/rev/"+c[0]), 200)
	// c4 came after the branch point: not in the branch's view.
	expectCode(t, prune(map[string]any{"horizon": c4}), 422, "invalid")
	expect(t, e.prune("bpb", "nope", map[string]any{"horizon": c[3]}, "admin"), 404)
	expectCode(t, e.do(req{method: "POST", path: "/r/bpb/c/prune", body: map[string]any{"horizon": c[3]}, ifMatch: c[3], author: "admin"}), 428, "precondition_required")

	// The base prunes, protected at the branch point; the branch sees the
	// base's horizon, under its own revisions too.
	check(e.prune("bp", "c", map[string]any{"horizon": c4}, "admin"), c[3])
	check(prune(map[string]any{"horizon": c[3]}), c[3])
	b1 := e.appendRev("bpb", "c", c[3], ops(op("replace", "/n", 5.0)))
	r = prune(map[string]any{"horizon": b1})
	check(r, c[3])
	noEntry(t, e, r, "bpb", e.nsHead("bpb"))
	expect(t, e.get("/r/bpb/c/rev/"+c[3]), 200)

	// The rules run, with keep in the envelope as sent.
	noKeep := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "prune"}},
		"then": []any{map[string]any{"op": "test", "path": "/doc/keep", "exists": false}},
	}
	expect(t, e.patchNS("bpb", ops(op("add", "/rules", []any{noKeep})), ""), 201)
	expectCode(t, prune(map[string]any{"horizon": b1, "keep": []any{}}), 422, "rule")
	check(prune(map[string]any{"horizon": b1}), c[3])

	// A purged resource is 410.
	expect(t, e.purge("bpb", "c", b1, "admin"), 204)
	expectCode(t, prune(map[string]any{"horizon": b1}), 410, "gone")
}

// v0.73 §8.6, §13, Encryption levels scenario 18 (BBD-49, F-B6): an E3
// prune in a branch moves nothing, but its snapshot is still required and
// checked, its kid included: one sealed under the base's kid is 422, its pl
// the branch's or not; no archive is needed, nor a * key.
func TestV073P26BranchPruneE3(t *testing.T) {
	t.Parallel()
	f := newE2E(t) // no archive destination
	e := f.tenv
	k := seal.NewKey()
	d0 := etagOf(e.writeRaw("e", "d", "", sealed(t, k, "e#1", "e", "d", "", addRoot(map[string]any{"n": 0.0})), f.writerG))
	d1 := etagOf(e.writeRaw("e", "d", d0, sealed(t, k, "e#1", "e", "d", d0, ops(op("replace", "/n", 1.0))), f.writerG))
	expect(t, e.branch("e", map[string]any{"name": "eb"}, f.adminG), 201)
	bg := e.grant(f.writer, "user:writer", []string{"eb"}, []string{"read", "prune"})
	e.clock.Advance(10 * time.Minute)

	expectCode(t, e.prune("eb", "d", map[string]any{"horizon": d1}, bg), 422, "invalid")
	expectCode(t, e.prune("eb", "d", map[string]any{"horizon": d1, "snapshot": "x", "keep": []any{d0}}, bg), 422, "invalid")
	baseKid, err := seal.SealSnapshot(k, "e#1", "e", "d", d1, map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, e.prune("eb", "d", map[string]any{"horizon": d1, "snapshot": baseKid}, bg), 422, "invalid")
	// The base's kid with the branch's pl: only the kid is wrong.
	baseKidOnly, err := seal.SealSnapshot(k, "e#1", "eb", "d", d1, map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	r := e.prune("eb", "d", map[string]any{"horizon": d1, "snapshot": baseKidOnly}, bg)
	expectCode(t, r, 422, "invalid")
	if !strings.Contains(r.Str("message"), "kid") || r.Obj()["pl"] != nil {
		t.Fatalf("a snapshot under the base's kid: %s", r.Body)
	}
	own, err := seal.SealSnapshot(k, "eb#1", "eb", "d", d1, map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	head := e.nsHead("eb", bg)
	r = e.prune("eb", "d", map[string]any{"horizon": d1, "snapshot": own}, bg)
	expect(t, r, 200)
	if r.Str("horizon") != d0 || r.H.Get("X-Namespace-Revision") != "" || e.nsHead("eb", bg) != head {
		t.Fatalf("E3 branch prune %s %v", r.Body, r.H)
	}
}

// v0.73 §8.6 Request (BBD-52): where no retention rule matches the
// resource, retention keeps everything, so a prune that moves its horizon
// needs a grant chained to a * key, archive or not. A prune that moves
// nothing and drops no kept document needs none (TestV073P26KeepDropNeedsStar),
// and within a matching rule prune suffices.
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

// v0.73 §8.6 Request (BBD-46, BBD-52; review of P26): a prune that changes
// only the keep set drops the documents below the horizon it no longer
// keeps. Dropping one that retention keeps, everything where no rule
// matches the resource, goes below what retention keeps, so it needs a
// grant chained to a * key even though the horizon doesn't move: 403, and
// the document stays. Dropping only documents below what a rule keeps,
// adding to the set, or a no-change keep needs only prune.
func TestV073P26KeepDropNeedsStar(t *testing.T) {
	t.Parallel()
	t.Run("rule without archive", func(t *testing.T) {
		t.Parallel()
		e := newAuthEnv(t, withoutRetentionLoop)
		sk, pk := newKey("sk"), newKey("pk")
		can := []string{"read", "create", "append", "prune"}
		e.mkNS("kd", map[string]any{"read": "public", "keys": []any{sk.entry("*"), pk.entry(can...)}})
		sg := e.grant(sk, "user:admin", []string{"kd"}, allVerbs)
		pg := e.grant(pk, "user:p", []string{"kd"}, can)
		// Retention keeps the last 5 revisions, without an archive, which
		// prune alone may apply within what it keeps.
		expect(t, e.patchNS("kd", ops(op("add", "/retention", []any{map[string]any{"keep": map[string]any{"revisions": 5.0}, "archive": false}})), sg), 201)
		a := e.chain("kd", "a", 8, pg)
		e.clock.Advance(10 * time.Minute)
		served := func(i int) { t.Helper(); expect(t, e.get("/r/kd/a/rev/"+a[i]), 200) }
		pruned := func(i int) { t.Helper(); expectCode(t, e.get("/r/kd/a/rev/"+a[i]), 410, "pruned") }
		// Retention keeps a[3..7]. The * key goes past that, keeping a[1],
		// below what retention keeps, and a[4], within it.
		pruneEntry(t, e, e.prune("kd", "a", map[string]any{"horizon": a[6], "keep": []any{a[1], a[4]}}, sg), "kd", "a", a[6])
		served(1)
		served(4)
		expectCode(t, e.prune("kd", "a", map[string]any{"horizon": a[7]}, pg), 403, "forbidden")
		// Dropping a[4], which retention keeps, is 403 and writes nothing;
		// with archive: false nothing would hold it afterwards.
		head := e.nsHead("kd")
		for _, keep := range [][]any{{}, {a[1]}, {a[1], a[7]}} {
			r := e.prune("kd", "a", map[string]any{"horizon": a[6], "keep": keep}, pg)
			expectCode(t, r, 403, "forbidden")
			noEntry(t, e, r, "kd", head)
			served(1)
			served(4)
		}
		// Sending the set unchanged, or no keep, changes nothing.
		for _, body := range []map[string]any{{"horizon": a[6], "keep": []any{a[4], a[1]}}, {"horizon": a[6]}} {
			r := e.prune("kd", "a", body, pg)
			expect(t, r, 200)
			noEntry(t, e, r, "kd", head)
		}
		// Dropping a[1], below what retention keeps, and adding a[7] needs
		// only prune.
		pruneEntry(t, e, e.prune("kd", "a", map[string]any{"horizon": a[6], "keep": []any{a[4], a[7]}}, pg), "kd", "a", a[6])
		pruned(1)
		served(4)
		// The * key may drop a[4].
		pruneEntry(t, e, e.prune("kd", "a", map[string]any{"horizon": a[6], "keep": []any{}}, sg), "kd", "a", a[6])
		pruned(4)
	})
	t.Run("no rule", func(t *testing.T) {
		t.Parallel()
		e := newAuthEnv(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
		sk, pk := newKey("sk"), newKey("pk")
		can := []string{"read", "create", "append", "prune"}
		e.mkNS("kn", map[string]any{"read": "public", "keys": []any{sk.entry("*"), pk.entry(can...)}})
		sg := e.grant(sk, "user:admin", []string{"kn"}, allVerbs)
		pg := e.grant(pk, "user:p", []string{"kn"}, can)
		a := e.chain("kn", "a", 5, pg)
		e.clock.Advance(10 * time.Minute)
		pruneEntry(t, e, e.prune("kn", "a", map[string]any{"horizon": a[3], "keep": []any{a[1]}}, sg), "kn", "a", a[3])
		expect(t, e.get("/r/kn/a/rev/"+a[1]), 200)
		// Retention keeps everything here, a[1] included: dropping it is
		// 403, the archive notwithstanding.
		head := e.nsHead("kn")
		r := e.prune("kn", "a", map[string]any{"horizon": a[3], "keep": []any{}}, pg)
		expectCode(t, r, 403, "forbidden")
		noEntry(t, e, r, "kn", head)
		expect(t, e.get("/r/kn/a/rev/"+a[1]), 200)
		// Adding to the set drops nothing.
		pruneEntry(t, e, e.prune("kn", "a", map[string]any{"horizon": a[3], "keep": []any{a[1], a[4]}}, pg), "kn", "a", a[3])
		expect(t, e.get("/r/kn/a/rev/"+a[1]), 200)
		// The * key may drop it.
		pruneEntry(t, e, e.prune("kn", "a", map[string]any{"horizon": a[3], "keep": []any{a[4]}}, sg), "kn", "a", a[3])
		expectCode(t, e.get("/r/kn/a/rev/"+a[1]), 410, "pruned")
	})
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

// v0.73 §8.3 Branches (BBD-15): a purge propagates to every branch,
// recursively; a branch that sees no entry for the name is skipped, with no
// entry, but its own branches aren't, and a branch's purge entry targets
// its own view's head.
func TestV073P26PurgeSkipsBranchWithoutEntry(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	expect(t, e.branch("m", map[string]any{"name": "m1"}, "alice"), 201) // before x
	x := e.create("m", "x", map[string]any{"v": 1.0})
	expect(t, e.branch("m1", map[string]any{"name": "m2"}, "alice"), 201)
	w := e.create("m2", "x", map[string]any{"v": 2.0}) // m2's own chain
	m1 := e.nsHead("m1")

	expect(t, e.purge("m", "x", x, "admin"), 204)
	if e.nsHead("m1") != m1 {
		t.Fatalf("m1, with no entry for x, got one: %v", e.lastNSEntry("m1"))
	}
	expect(t, e.get("/r/m1/x"), 404)
	if en := e.lastNSEntry("m2"); en["kind"] != "purge" || en["resource"] != "x" || en["target"] != w {
		t.Fatalf("m2's last entry %v, want a purge of x targeting %s", en, w)
	}
	expectCode(t, e.get("/r/m2/x"), 410, "gone")
}
