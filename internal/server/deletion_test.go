package server

import (
	"testing"
	"time"
)

func (e *tenv) purge(ns, name, ifMatch, who string) *resp {
	e.t.Helper()
	q := req{method: "POST", path: "/r/" + ns + "/" + name + "/purge", ifMatch: ifMatch}
	if e.auth {
		q.bearer = who
	} else {
		q.author = who
	}
	return e.do(q)
}

func (e *tenv) nsKinds(ns string) []string {
	e.t.Helper()
	var out []string
	for _, x := range e.get("/ns/" + ns + "/rev/" + e.nsHead(ns) + "/log").Arr() {
		out = append(out, x.(map[string]any)["kind"].(string))
	}
	return out
}

func lastOf(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[len(xs)-1]
}

// §8.1–§8.3: tombstone, restore, purge and its propagation to branches.
func TestPurge(t *testing.T) {
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	a1 := e.create("main", "a", map[string]any{"secret": "s"})
	a2 := e.appendRev("main", "a", a1, ops(op("replace", "/secret", "t")))
	keep := e.create("main", "keep", map[string]any{})
	at := e.nsHead("main")
	expect(t, e.branch("main", map[string]any{"name": "rt"}, "alice"), 201)  // reads a through
	expect(t, e.branch("main", map[string]any{"name": "own"}, "alice"), 201) // will have its own chain
	o1 := e.appendRev("own", "a", a2, ops(op("add", "/x", 1.0)))
	expect(t, e.branch("rt", map[string]any{"name": "rt2"}, "alice"), 201) // branch of a branch
	_ = at

	// Restore with [] after delete.
	tomb := e.del("main", "a", a2)
	a3 := e.appendRev("main", "a", tomb, []any{})
	if d := e.doc("main", "a"); d["secret"] != "t" {
		t.Fatalf("restore %v", d)
	}
	// Purge preconditions.
	expectCode(t, e.purge("main", "a", "", "admin"), 428, "precondition_required")
	r := e.purge("main", "a", a2, "admin")
	expectCode(t, r, 412, "stale")
	if r.Str("head") != a3 {
		t.Fatalf("purge 412 %s", r.Body)
	}
	expect(t, e.purge("main", "missing", a2, "admin"), 404)

	r = e.purge("main", "a", a3, "admin")
	expect(t, r, 204)
	if r.H.Get("X-Namespace-Revision") != e.nsHead("main") {
		t.Fatalf("purge response lacks X-Namespace-Revision: %v", r.H)
	}
	// All /r/main/a/... URLs are 410, with the long cache.
	for _, p := range []string{"/r/main/a", "/r/main/a/rev/" + a1, "/r/main/a/rev/" + a3 + "/log", "/r/main/a/events", "/r/main/a/log?live=long-poll"} {
		g := e.get(p)
		if g.Code != 410 {
			t.Errorf("%s after purge: %d %s", p, g.Code, g.Body)
		}
	}
	if cc := e.get("/r/main/a").H.Get("Cache-Control"); cc != ccLong {
		t.Fatalf("purged head Cache-Control %q", cc)
	}
	expect(t, e.purge("main", "a", a3, "admin"), 410)
	// The ids and the namespace chain stay verifiable: a purge entry names the head.
	if lastOf(e.nsKinds("main")) != "purge" {
		t.Fatalf("main log %v", e.nsKinds("main"))
	}
	// Other resources are unaffected.
	expect(t, e.get("/r/main/keep/rev/"+keep), 200)

	// Propagation: every branch, read-through or own chain, recursively, with an entry each.
	for _, br := range []string{"rt", "own", "rt2"} {
		if g := e.get("/r/" + br + "/a"); g.Code != 410 {
			t.Errorf("%s/a after purge in base: %d", br, g.Code)
		}
		if g := e.get("/r/" + br + "/a/rev/" + a1); g.Code != 410 {
			t.Errorf("%s/a/rev after purge in base: %d", br, g.Code)
		}
		if k := lastOf(e.nsKinds(br)); k != "purge" {
			t.Errorf("%s log does not end with a purge entry: %v", br, e.nsKinds(br))
		}
	}
	expect(t, e.get("/r/own/a/rev/"+o1), 410)
	expect(t, e.get("/r/rt/keep"), 302)
	// Writes to purged resources in branches are 410 too.
	expect(t, e.write("PATCH", "own", "a", o1, ops(op("add", "/y", 1.0))), 410)
	expect(t, e.write("PATCH", "rt", "a", a2, ops(op("add", "/y", 1.0))), 410)

	// Purge never propagates upwards.
	b1 := e.create("main", "b", map[string]any{})
	expect(t, e.branch("main", map[string]any{"name": "up"}, "alice"), 201)
	expect(t, e.purge("up", "b", b1, "admin"), 204)
	expect(t, e.get("/r/main/b"), 302)
	expect(t, e.get("/r/up/b"), 410)
}

// §8.4: freezing.
func TestFreeze(t *testing.T) {
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	e.mkNS("next", map[string]any{"read": "public"})
	a := e.create("main", "a", map[string]any{"n": 1.0})
	// successor must exist with the same base.
	expect(t, e.patchNS("main", ops(op("add", "/successor", "nope")), ""), 422)
	expect(t, e.patchNS("main", ops(op("add", "/frozen", true), op("add", "/successor", "next")), ""), 201)
	r := e.write("PATCH", "main", "a", a, ops(op("replace", "/n", 2.0)))
	expectCode(t, r, 409, "frozen")
	if r.Str("successor") != "next" {
		t.Fatalf("frozen body %s", r.Body)
	}
	expectCode(t, e.write("DELETE", "main", "a", a, nil), 409, "frozen")
	expectCode(t, e.write("PATCH", "main", "new", "", addRoot(map[string]any{})), 409, "frozen")
	// Frozen comes after authorisation and before the precondition.
	expectCode(t, e.write("PATCH", "main", "a", hashID(t, "", nil), []any{}), 409, "frozen")
	// Still allowed: reads, config, branches, purge, prune.
	expect(t, e.get("/r/main/a"), 302)
	expect(t, e.patchNS("main", ops(op("add", "/x-title", "t")), ""), 201)
	expect(t, e.branch("main", map[string]any{"name": "fb"}, "alice"), 201)
	r = e.do(req{method: "POST", path: "/r/main/a/prune", body: map[string]any{"horizon": a}, author: "admin"})
	expect(t, r, 200)
	b := e.head("main", "a")
	expect(t, e.purge("main", "a", b, "admin"), 204)
	// Unfreezing.
	expect(t, e.patchNS("main", ops(op("replace", "/frozen", false)), ""), 201)
	e.create("main", "new", map[string]any{})
}

// §8.5: purging a namespace.
func TestPurgeNamespace(t *testing.T) {
	e := newEnv(t)
	e.mkNS("old", map[string]any{"read": "public"})
	e.mkNS("other", map[string]any{"read": "public"})
	a := e.create("old", "a", map[string]any{})
	nspurge := func(ns string) *resp {
		return e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns), author: "admin"})
	}
	expectCode(t, nspurge("old"), 409, "not_frozen")
	expect(t, e.branch("old", map[string]any{"name": "oldb"}, "alice"), 201)
	expect(t, e.patchNS("old", ops(op("add", "/frozen", true)), ""), 201)
	r := nspurge("old")
	expectCode(t, r, 409, "in_use")
	if deps, _ := r.Obj()["dependents"].([]any); len(deps) != 1 || deps[0] != "oldb" {
		t.Fatalf("dependents %s", r.Body)
	}
	// Leaves first.
	expect(t, e.patchNS("oldb", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, nspurge("oldb"), 204)
	// A referenced schema revision blocks the purge.
	expect(t, e.patchNS("old", ops(op("replace", "/frozen", false)), ""), 201)
	s := e.create("old", "schema", map[string]any{"$schema": dialect, "type": "object"})
	ref := e.create("other", "user", map[string]any{"$schema": "/r/old/schema/rev/" + s})
	expect(t, e.patchNS("old", ops(op("replace", "/frozen", true)), ""), 201)
	expectCode(t, nspurge("old"), 409, "in_use")
	expect(t, e.purge("other", "user", ref, "admin"), 204)
	// Stale and missing preconditions.
	expect(t, e.do(req{method: "POST", path: "/ns/old/purge", ifMatch: a, author: "admin"}), 412)
	expect(t, e.do(req{method: "POST", path: "/ns/old/purge", author: "admin"}), 428)
	expect(t, nspurge("old"), 204)

	// Afterwards: every /r/old/... is 410; /ns/old and its log stay readable.
	expect(t, e.get("/r/old/a"), 410)
	expect(t, e.get("/r/old/a/rev/"+a), 410)
	expect(t, e.get("/r/old/nothing"), 410)
	if k := lastOf(e.nsKinds("old")); k != "purge-ns" {
		t.Fatalf("old log %v", e.nsKinds("old"))
	}
	expect(t, e.get("/ns/old/rev/"+e.nsHead("old")), 200)
	// Writes are 410; the name stays reserved; no branches from it.
	expect(t, e.write("PATCH", "old", "a", a, []any{}), 410)
	expect(t, e.write("PATCH", "old", "z", "", addRoot(map[string]any{})), 410)
	expect(t, e.do(req{method: "PATCH", path: "/ns/old", ifNoneMatch: "*", body: addRoot(map[string]any{})}), 412)
	expect(t, e.branch("old", map[string]any{"name": "oldc"}, "alice"), 410)
	expect(t, nspurge("old"), 410)
	// The listing reports the purged branch.
	bl := e.get("/ns/old/branches").Arr()
	if len(bl) != 1 || bl[0].(map[string]any)["purged"] != true {
		t.Fatalf("branches of purged %v", bl)
	}
}

// §8.6: pruning.
func TestPrune(t *testing.T) {
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	prune := func(name string, body map[string]any) *resp {
		return e.do(req{method: "POST", path: "/r/main/" + name + "/prune", body: body, author: "admin"})
	}
	var revs []string
	h := e.create("main", "a", map[string]any{"n": 0.0})
	revs = append(revs, h)
	for i := 1; i <= 4; i++ {
		h = e.appendRev("main", "a", h, ops(op("replace", "/n", float64(i))))
		revs = append(revs, h)
	}
	// A branch at revs[4]'s time protects nothing below revs[4].
	// Everything is within the retry window: the horizon moves down to the
	// oldest protected revision (genesis), which changes nothing and writes nothing.
	before := e.nsHead("main")
	r := prune("a", map[string]any{"horizon": revs[3]})
	expect(t, r, 200)
	if r.Str("horizon") != revs[0] {
		t.Fatalf("effective horizon %s, want genesis %s", r.Str("horizon"), revs[0])
	}
	if e.nsHead("main") != before {
		t.Fatalf("a prune that changes nothing wrote %v", e.nsKinds("main"))
	}
	expect(t, e.get("/r/main/a/rev/"+revs[1]), 200)

	e.clock.Advance(10 * time.Minute)
	r5 := e.appendRev("main", "a", h, ops(op("replace", "/n", 5.0)))
	// Horizon must be an ancestor of the head (or the head).
	expect(t, prune("a", map[string]any{"horizon": hashID(t, "", nil)}), 422)
	expect(t, prune("missing", map[string]any{"horizon": revs[0]}), 404)
	expect(t, prune("a", map[string]any{}), 400)
	// Past the retry window: prune to revs[3], keeping revs[1].
	r = prune("a", map[string]any{"horizon": revs[3], "keep": []any{revs[1]}})
	expect(t, r, 200)
	if r.Str("horizon") != revs[3] {
		t.Fatalf("horizon %s", r.Body)
	}
	if k := lastOf(e.nsKinds("main")); k != "prune" {
		t.Fatalf("no prune entry: %v", e.nsKinds("main"))
	}
	pl := e.get("/ns/main/rev/" + e.nsHead("main") + "/log?since=" + e.nsHeadPrev("main"))
	if m := pl.Arr()[0].(map[string]any); m["resource"] != "a" || m["target"] != revs[3] {
		t.Fatalf("prune entry %v", m)
	}
	// Below the horizon: 410 pruned (unless kept); at and above: 200.
	g := e.get("/r/main/a/rev/" + revs[2])
	expectCode(t, g, 410, "pruned")
	if g.Str("horizon") != revs[3] || g.H.Get("Cache-Control") != ccPruned || g.H.Get("Cache-Tag") != "ns:main,r:main/a" {
		t.Fatalf("pruned 410 %s %v", g.Body, g.H)
	}
	expectCode(t, e.get("/r/main/a/rev/"+revs[0]), 410, "pruned")
	expect(t, e.get("/r/main/a/rev/"+revs[1]), 200)
	if d := e.get("/r/main/a/rev/" + revs[3]); d.Code != 200 || d.String() != `{"n":3}` {
		t.Fatalf("horizon doc %d %s", d.Code, d.Body)
	}
	expect(t, e.get("/r/main/a/rev/"+r5), 200)
	// Logs: 410 naming the horizon if the range crosses it; since may lie below it.
	lg := e.get("/r/main/a/rev/" + r5 + "/log?since=" + revs[0])
	expectCode(t, lg, 410, "pruned")
	if lg.Str("horizon") != revs[3] {
		t.Fatalf("log 410 %s", lg.Body)
	}
	expectCode(t, e.get("/r/main/a/rev/"+r5+"/log"), 410, "pruned")
	lg = e.get("/r/main/a/rev/" + r5 + "/log?since=" + revs[2])
	expect(t, lg, 200)
	if len(lg.Arr()) != 3 {
		t.Fatalf("log from below the horizon %s", lg.Body)
	}
	// The ids and parent links are kept (the 404 check still works below the horizon).
	expect(t, e.get("/r/main/a/rev/"+r5+"/log?since="+hashID(t, "", nil)), 404)
	// Writes on top keep working; so does an idempotent retry within the window.
	r6 := e.appendRev("main", "a", r5, ops(op("replace", "/n", 6.0)))
	rr := e.write("PATCH", "main", "a", r5, ops(op("replace", "/n", 6.0)))
	expect(t, rr, 200)
	if etagOf(rr) != r6 {
		t.Fatal("retry after prune")
	}
	// Pruning again below the current horizon changes nothing.
	r = prune("a", map[string]any{"horizon": revs[1]})
	expect(t, r, 200)
	if r.Str("horizon") != revs[3] {
		t.Fatalf("lower prune %s", r.Body)
	}

	// A tombstone horizon keeps the last live document, so restore works.
	b0 := e.create("main", "b", map[string]any{"b": 0.0})
	b := e.appendRev("main", "b", b0, ops(op("replace", "/b", 1.0)))
	bt := e.del("main", "b", b)
	e.clock.Advance(10 * time.Minute)
	expect(t, prune("b", map[string]any{"horizon": bt}), 200)
	expectCode(t, e.get("/r/main/b/rev/"+b0), 410, "pruned")
	expect(t, e.get("/r/main/b/rev/"+b), 200) // the last live document is kept
	e.appendRev("main", "b", bt, []any{})
	if d := e.doc("main", "b"); d["b"] != 1.0 {
		t.Fatalf("restore after prune %v", d)
	}

	// Branch points are protected; branches don't prune.
	c1 := e.create("main", "c", map[string]any{"c": 1.0})
	c2 := e.appendRev("main", "c", c1, ops(op("replace", "/c", 2.0)))
	expect(t, e.branch("main", map[string]any{"name": "br"}, "alice"), 201)
	c3 := e.appendRev("main", "c", c2, ops(op("replace", "/c", 3.0)))
	e.clock.Advance(10 * time.Minute)
	c4 := e.appendRev("main", "c", c3, ops(op("replace", "/c", 4.0)))
	r = prune("c", map[string]any{"horizon": c4})
	expect(t, r, 200)
	if r.Str("horizon") != c2 {
		t.Fatalf("branch point not protected: %s", r.Body)
	}
	expect(t, e.get("/r/br/c/rev/"+c2), 200)
	expect(t, e.do(req{method: "POST", path: "/r/br/c/prune", body: map[string]any{"horizon": c2}, author: "admin"}), 422)

	// Referenced schema revisions keep their documents below the horizon.
	s1 := e.create("main", "s", map[string]any{"$schema": dialect, "type": "object"})
	s2 := e.appendRev("main", "s", s1, ops(op("add", "/title", "x")))
	e.create("main", "user", map[string]any{"$schema": "/r/main/s/rev/" + s1})
	e.clock.Advance(10 * time.Minute)
	expect(t, prune("s", map[string]any{"horizon": s2}), 200)
	expect(t, e.get("/r/main/s/rev/"+s1), 200)
	e.appendRev("main", "user", e.head("main", "user"), ops(op("add", "/x", 1.0)))
}

// nsHeadPrev returns the namespace entry before the head.
func (e *tenv) nsHeadPrev(ns string) string {
	e.t.Helper()
	all := e.get("/ns/" + ns + "/rev/" + e.nsHead(ns) + "/log").Arr()
	return all[len(all)-2].(map[string]any)["id"].(string)
}

// §7.2 retry lookups that find purged or pruned entries.
func TestRetryAfterPurgeAndPrune(t *testing.T) {
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	genesis := addRoot(map[string]any{"n": 0.0})
	a := e.create("main", "a", map[string]any{"n": 0.0})
	expect(t, e.purge("main", "a", a, "alice"), 204)
	// The purged resource answers 410, never a replay of purged content.
	expectCode(t, e.write("PATCH", "main", "a", "", genesis), 410, "gone")
	expectCode(t, e.write("DELETE", "main", "a", a, nil), 410, "gone")

	h := e.create("main", "b", map[string]any{"n": 0.0})
	p1 := ops(op("replace", "/n", 1.0))
	b1 := e.appendRev("main", "b", h, p1)
	b2 := e.appendRev("main", "b", b1, ops(op("replace", "/n", 2.0)))
	e.clock.Advance(10 * time.Minute)
	e.appendRev("main", "b", b2, ops(op("replace", "/n", 3.0)))
	r := e.do(req{method: "POST", path: "/r/main/b/prune", body: map[string]any{"horizon": b2}, author: "admin"})
	expect(t, r, 200)
	// Retrying an append whose revision was pruned, after the retry window:
	// the lookup still finds it by id (ids are kept), so it is not a 5xx.
	r = e.write("PATCH", "main", "b", h, p1)
	if r.Code >= 500 {
		t.Fatalf("retry of a pruned revision: %d %s", r.Code, r.Body)
	}
	if r.Code == 200 && etagOf(r) != b1 {
		t.Fatalf("retry of a pruned revision: %s", r.Body)
	}
	// The server is still healthy.
	e.create("main", "c", map[string]any{})
}
