package server

import (
	"strings"
	"testing"
)

func (e *tenv) branch(base string, body map[string]any, who string) *resp {
	e.t.Helper()
	q := req{method: "POST", path: "/ns/" + base + "/branches", ifNoneMatch: "*", body: body}
	if e.auth {
		q.bearer = who
	} else {
		q.author = who
	}
	return e.do(q)
}

// §7.6 branches: creation, read-through, first writes, config copy, listings.
func TestBranches(t *testing.T) {
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public", "x-title": "Main"})
	a1 := e.create("main", "a", map[string]any{"v": 1.0})
	a2 := e.appendRev("main", "a", a1, ops(op("replace", "/v", 2.0)))
	b1 := e.create("main", "b", map[string]any{"b": true})
	d1 := e.create("main", "d", map[string]any{})
	dt := e.del("main", "d", d1)
	expect(t, e.patchNS("main", ops(op("add", "/frozen", true)), ""), 201)
	at := e.nsHead("main")
	expect(t, e.patchNS("main", ops(op("replace", "/frozen", false)), ""), 201)

	// Base changes after at.
	a3 := e.appendRev("main", "a", a2, ops(op("replace", "/v", 3.0)))
	e.create("main", "c", map[string]any{})
	e.del("main", "b", b1)
	e.appendRev("main", "d", dt, []any{})
	expect(t, e.patchNS("main", ops(op("replace", "/x-title", "Main2")), ""), 201)

	// 428 without If-None-Match; 422 for an at not in the chain; 400 for a bad name.
	expect(t, e.do(req{method: "POST", path: "/ns/main/branches", body: map[string]any{"name": "rel"}, author: "alice"}), 428)
	expect(t, e.branch("main", map[string]any{"name": "rel", "at": hashID(t, "", nil)}, "alice"), 422)
	expect(t, e.branch("main", map[string]any{"name": "Rel", "at": at}, "alice"), 400)
	expect(t, e.branch("nope", map[string]any{"name": "rel"}, "alice"), 404)

	body := map[string]any{"name": "rel", "at": at, "patches": ops(op("add", "/x-branchNote", "x"))}
	before := e.nsHead("main")
	r := e.branch("main", body, "alice")
	expect(t, r, 201)
	if r.H.Get("Location") != "/ns/rel" || r.H.Get("X-Namespace-Revision") != e.nsHead("main") {
		t.Fatalf("branch headers %v", r.H)
	}
	// The branch's config: the base's current document, frozen removed, base added, patches applied.
	br := e.get("/ns/rel/rev/" + e.nsHead("rel"))
	expect(t, br, 200)
	doc := br.Obj()
	wantDoc := map[string]any{"read": "public", "x-title": "Main2", "frozen": nil, "base": map[string]any{"ns": "main", "at": at}, "x-branchNote": "x"}
	delete(wantDoc, "frozen")
	// The base had frozen: false at creation; it is removed.
	if string(canonical(doc)) != string(canonical(wantDoc)) {
		t.Fatalf("branch document %s", br.Body)
	}
	cfgID := hashID(t, "", canonical(addRoot(doc)))
	if e.configID("rel") != cfgID {
		t.Fatalf("branch config id %s, want %s", e.configID("rel"), cfgID)
	}
	// The base's log records the branch entry, hash-verifiable.
	lg := e.get("/ns/main/rev/" + e.nsHead("main") + "/log?since=" + before).Arr()
	if len(lg) != 1 {
		t.Fatalf("branch wrote %d base entries", len(lg))
	}
	be := lg[0].(map[string]any)
	want := map[string]any{"kind": "branch", "name": "rel", "at": at, "target": cfgID}
	if be["id"] != hashID(t, before, canonical(want)) {
		t.Fatalf("branch entry %v", be)
	}
	// The branch's own log starts with its config.
	own := e.get("/ns/rel/rev/" + e.nsHead("rel") + "/log").Arr()
	if len(own) != 1 || own[0].(map[string]any)["kind"] != "config" {
		t.Fatalf("branch log %v", own)
	}

	// Retry: same principal, at and patches: 200. Otherwise the name is taken: 412.
	r = e.branch("main", body, "alice")
	expect(t, r, 200)
	expect(t, e.branch("main", body, "bob"), 412)
	expect(t, e.branch("main", map[string]any{"name": "rel"}, "alice"), 412)
	expect(t, e.branch("main", map[string]any{"name": "main"}, "alice"), 412)

	// Read-through: the base as of at.
	h := e.get("/r/rel/a")
	expect(t, h, 302)
	if h.H.Get("Location") != "/r/rel/a/rev/"+a2 {
		t.Fatalf("read-through Location %s", h.H.Get("Location"))
	}
	if h.H.Get("Cache-Tag") != "ns:rel,r:rel/a" {
		t.Fatalf("read-through tags %s", h.H.Get("Cache-Tag"))
	}
	expect(t, e.get("/r/rel/a/rev/"+a1), 200)
	expect(t, e.get("/r/rel/a/rev/"+a3), 404) // after at: invisible
	expect(t, e.get("/r/rel/b"), 302)         // deleted after at: still live
	expect(t, e.get("/r/rel/c"), 404)         // created after at
	g := e.get("/r/rel/d")                    // tombstoned at at
	expect(t, g, 410)
	if g.Str("tombstone") != dt || g.Str("last") != d1 {
		t.Fatalf("read-through tombstone %s", g.Body)
	}

	// First write: precondition against the base's head as of at; foreign parent.
	r = e.write("PATCH", "rel", "a", a3, ops(op("replace", "/v", 9.0)))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != a2 {
		t.Fatalf("412 head %s", r.Body)
	}
	fw := e.appendRev("rel", "a", a2, ops(op("replace", "/v", 10.0)))
	if fw != hashID(t, a2, canonical(ops(op("replace", "/v", 10.0)))) {
		t.Fatal("foreign parent not used")
	}
	lgr := e.get("/r/rel/a/rev/" + fw + "/log").Arr()
	if len(lgr) != 3 || lgr[0].(map[string]any)["id"] != a1 || lgr[2].(map[string]any)["parent"] != a2 {
		t.Fatalf("log across the foreign parent %v", lgr)
	}
	if n := len(e.get("/r/rel/a/rev/" + fw + "/log?since=" + a1).Arr()); n != 2 {
		t.Fatalf("since across foreign parent: %d", n)
	}
	// The base is unaffected.
	if e.head("main", "a") != a3 {
		t.Fatal("base changed by a branch write")
	}
	// A first write that deletes, and one that restores.
	bt := e.del("rel", "b", b1)
	if bt != hashID(t, b1, []byte("tombstone")) {
		t.Fatal("tombstone of a foreign parent")
	}
	dr := e.appendRev("rel", "d", dt, []any{})
	if dr != hashID(t, dt, []byte("[]")) || e.doc("rel", "d") == nil {
		t.Fatal("restore of a foreign tombstone")
	}
	// A name that didn't exist at at is an ordinary create.
	e.create("rel", "c", map[string]any{"mine": true})
	// Branch log holds only the branch's own entries.
	if n := len(e.get("/ns/rel/rev/" + e.nsHead("rel") + "/log").Arr()); n != 5 {
		t.Fatalf("branch log has %d entries", n)
	}

	// Heads include read-through resources.
	e.create("main", "e", map[string]any{})
	r = e.branch("main", map[string]any{"name": "rel2", "at": at}, "alice")
	expect(t, r, 201)
	hs := e.get("/ns/rel2/rev/" + e.nsHead("rel2") + "/heads").Obj()["items"].([]any)
	var names []string
	for _, x := range hs {
		m := x.(map[string]any)
		names = append(names, m["resource"].(string)+":"+m["kind"].(string)+":"+m["target"].(string))
	}
	if strings.Join(names, ",") != "a:head:"+a2+",b:head:"+b1+",d:tombstone:"+dt {
		t.Fatalf("branch heads %v", names)
	}
	hs = e.get("/ns/rel/rev/" + e.nsHead("rel") + "/heads").Obj()["items"].([]any)
	if len(hs) != 4 {
		t.Fatalf("rel heads %v", hs)
	}

	// Listing of branches.
	bl := e.get("/ns/main/branches")
	expect(t, bl, 200)
	list := bl.Arr()
	if len(list) != 2 {
		t.Fatalf("branches %s", bl.Body)
	}
	b0 := list[0].(map[string]any)
	if b0["name"] != "rel" || b0["at"] != at || b0["frozen"] != false || b0["purged"] != false {
		t.Fatalf("branch listing %v", b0)
	}

	// base can't change; successor must share the base.
	expect(t, e.patchNS("rel", ops(op("replace", "/base/at", e.nsHead("main"))), ""), 422)
	expect(t, e.patchNS("rel", ops(op("remove", "/base")), ""), 422)
	expect(t, e.patchNS("rel", ops(op("add", "/successor", "main")), ""), 422)
	expect(t, e.patchNS("rel", ops(op("add", "/frozen", true), op("add", "/successor", "rel2")), ""), 201)
	bl = e.get("/ns/main/branches")
	if m := bl.Arr()[0].(map[string]any); m["frozen"] != true || m["successor"] != "rel2" {
		t.Fatalf("frozen branch listing %v", m)
	}
	r = e.write("PATCH", "rel", "a", fw, ops(op("replace", "/v", 11.0)))
	expectCode(t, r, 409, "frozen")
	if r.Str("successor") != "rel2" {
		t.Fatalf("frozen body %s", r.Body)
	}
	// Branches of branches read through recursively.
	r = e.branch("rel2", map[string]any{"name": "rel3"}, "alice")
	expect(t, r, 201)
	if l := e.get("/r/rel3/a").H.Get("Location"); l != "/r/rel3/a/rev/"+a2 {
		t.Fatalf("nested read-through %s", l)
	}
	// Schema refs never name a branch; rel2 can't be referenced (covered in TestSchemas).
}

// A branch of a non-public namespace can't be public (§7.4, §7.6).
func TestBranchPublicity(t *testing.T) {
	e := newEnv(t)
	e.mkNS("priv", map[string]any{"read": "grant"})
	e.mkNS("pub", map[string]any{"read": "public"})
	expect(t, e.branch("priv", map[string]any{"name": "pb", "patches": ops(op("replace", "/read", "public"))}, "alice"), 422)
	expect(t, e.branch("priv", map[string]any{"name": "pb"}, "alice"), 201)
	expect(t, e.patchNS("pb", ops(op("replace", "/read", "public")), ""), 422)
	// A namespace with public dependents can't stop being public.
	expect(t, e.branch("pub", map[string]any{"name": "pubb"}, "alice"), 201)
	r := e.patchNS("pub", ops(op("replace", "/read", "grant")), "")
	expectCode(t, r, 409, "in_use")
	if deps, _ := r.Obj()["dependents"].([]any); len(deps) != 1 || deps[0] != "pubb" {
		t.Fatalf("dependents %s", r.Body)
	}
	expect(t, e.patchNS("pubb", ops(op("replace", "/read", "grant")), ""), 201)
	expect(t, e.patchNS("pub", ops(op("replace", "/read", "grant")), ""), 201)
}
