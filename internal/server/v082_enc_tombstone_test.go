package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// v82encTombstone checks the 410 of tombstone tomb's own /rev (§7.1): the
// body names it and last, its parent, with the tombstone's immutable
// validators; HEAD answers the same without the body, and /raw as the
// document URL does where the level serves raw documents (not in the
// tests' sealed namespace s and e2e namespace e).
func v82encTombstone(t *testing.T, e *tenv, what, ns, name, tomb, last string, bearer ...string) {
	t.Helper()
	b := ""
	if len(bearer) > 0 {
		b = bearer[0]
	}
	paths := []string{"/r/" + ns + "/" + name + "/rev/" + tomb}
	if raw := e.do(req{method: "GET", path: paths[0] + "/raw", bearer: b}); ns != "s" && ns != "e" {
		paths = append(paths, paths[0]+"/raw")
	} else if raw.Code != 404 || raw.Str("code") != "not_offered" {
		// A sealed or e2e namespace serves no raw documents (§7.1).
		t.Fatalf("%s: /raw: %d %s", what, raw.Code, raw.Body)
	}
	for _, path := range paths {
		r := e.do(req{method: "GET", path: path, bearer: b})
		expectCode(t, r, 410, "gone")
		m := r.Obj()
		if len(m) != 3 || m["tombstone"] != tomb || m["last"] != last {
			t.Fatalf("%s: GET %s: %s, want tombstone %s and last %s", what, path, r.Body, tomb, last)
		}
		if r.H.Get("ETag") != quote(tomb) || r.H.Get("Location") != "" {
			t.Fatalf("%s: GET %s: headers %v", what, path, r.H)
		}
		h := e.do(req{method: "HEAD", path: path, bearer: b})
		if h.Code != 410 || len(h.Body) != 0 || h.H.Get("ETag") != quote(tomb) || h.H.Get("Cache-Control") != r.H.Get("Cache-Control") {
			t.Fatalf("%s: HEAD %s: %d %v %q", what, path, h.Code, h.H, h.Body)
		}
	}
}

// E2E-3 (§7.1 table, "id is a tombstone, below a horizon too"; scenario
// 64): a tombstone's own /rev/{T} is 410 with { tombstone: T, last: its
// parent }, immutable, at every level: for the head tombstone, for one
// down the chain after a restore, and below a pruning horizon. A purged
// resource keeps its plain 410, without last.
func TestV082TombstoneRevLast(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("p", map[string]any{"read": "public"})
	e.mkNS("r", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	for _, ns := range []string{"p", "r", "s"} {
		d1 := e.wr(ns, "d", "", withNonce(addRoot(map[string]any{"n": 1.0})))
		d2 := e.wr(ns, "d", d1, withNonce(ops(op("replace", "/n", 2.0))))
		tomb := e.del(ns, "d", d2)
		v82encTombstone(t, e, ns+" head tombstone", ns, "d", tomb, d2)
		if cc := e.get("/r/" + ns + "/d/rev/" + tomb).H.Get("Cache-Control"); cc != ccImmutable {
			t.Fatalf("%s: Cache-Control %q", ns, cc)
		}
		// The tombstoned head names the same two members.
		if h := e.get("/r/" + ns + "/d"); h.Code != 410 || h.Str("tombstone") != tomb || h.Str("last") != d2 {
			t.Fatalf("%s: the head: %s", ns, h.Body)
		}
		// Restored: the tombstone is down the chain, and its /rev is the
		// same.
		d3 := e.wr(ns, "d", tomb, withNonce(addRoot(map[string]any{"n": 3.0})))
		d4 := e.wr(ns, "d", d3, withNonce(ops(op("replace", "/n", 4.0))))
		v82encTombstone(t, e, ns+" mid-chain tombstone", ns, "d", tomb, d2)
		// Below a horizon too: the prune keeps the tombstone's row.
		e.clock.Advance(10 * time.Minute)
		expect(t, e.prune(ns, "d", map[string]any{"horizon": d4}, "admin"), 200)
		expectCode(t, e.get("/r/"+ns+"/d/rev/"+d2), 410, "pruned")
		v82encTombstone(t, e, ns+" tombstone below the horizon", ns, "d", tomb, d2)
		// A purge: a plain 410, long-lived, naming nothing.
		expect(t, e.purge(ns, "d", d4, "admin"), 204)
		r := e.get("/r/" + ns + "/d/rev/" + tomb)
		expectCode(t, r, 410, "gone")
		if m := r.Obj(); len(m) != 1 || r.H.Get("ETag") != "" {
			t.Fatalf("%s: a purged resource's tombstone: %v %s", ns, r.H, r.Body)
		}
	}
}

// E2E-3 at E3 (§7.1, §E.3.1; scenario 64's tail): the tombstone's 410
// names last for the head tombstone, at a tombstone horizon (whose parent
// serves the snapshot) and below a later horizon.
func TestV082TombstoneRevLastE3(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	p0 := e.e3Write(k, "e", "d", "", addRoot(map[string]any{"n": 0.0}))
	p := e.e3Write(k, "e", "d", p0, ops(op("replace", "/n", 1.0)))
	tomb := e.del("e", "d", p)
	v82encTombstone(t, e, "e2e head tombstone", "e", "d", tomb, p)
	l := etagOf(e.writeAs("e", "d", tomb, "[]", "alice")) // a restore
	l2 := e.e3Write(k, "e", "d", l, ops(op("replace", "/n", 2.0)))
	v82encTombstone(t, e, "e2e mid-chain tombstone", "e", "d", tomb, p)
	e.clock.Advance(10 * time.Minute)
	snap, _ := seal.SealSnapshot(k, "e#1", "e", "d", p, map[string]any{"n": 1.0})
	expect(t, e.prune("e", "d", map[string]any{"horizon": tomb, "snapshot": snap}, "admin"), 200)
	v82encTombstone(t, e, "e2e tombstone horizon", "e", "d", tomb, p)
	if r := e.get("/r/e/d/rev/" + p); r.Code != 200 || string(r.Body) != snap {
		t.Fatalf("/rev/{P} at a tombstone horizon: %d %s", r.Code, r.Body)
	}
	// A later prune moves the horizon above the tombstone.
	e.clock.Advance(10 * time.Minute)
	snap2, _ := seal.SealSnapshot(k, "e#1", "e", "d", l2, map[string]any{"n": 2.0})
	expect(t, e.prune("e", "d", map[string]any{"horizon": l2, "snapshot": snap2}, "admin"), 200)
	v82encTombstone(t, e, "e2e tombstone below the horizon", "e", "d", tomb, p)
}

// E2E-3 in a branch (§7.6): a tombstone the branch writes on a base's
// revision names that revision as last; a base's tombstone read through
// names its parent too.
func TestV082TombstoneRevLastBranch(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("p", map[string]any{"read": "public"})
	a1 := e.wr("p", "a", "", addRoot(map[string]any{"n": 1.0}))
	b1 := e.wr("p", "b", "", addRoot(map[string]any{"n": 1.0}))
	bt := e.del("p", "b", b1)
	expect(t, e.branch("p", map[string]any{"name": "pb"}, "alice"), 201)
	at := e.del("pb", "a", a1)
	v82encTombstone(t, e, "a branch's tombstone on a base's revision", "pb", "a", at, a1)
	v82encTombstone(t, e, "a base's tombstone read through", "pb", "b", bt, b1)
	// The base never had the branch's tombstone.
	expect(t, e.get("/r/p/a/rev/"+at), 404)
}

// E2E-3: last is sent only after the read check (§7.1): without read on a
// private namespace the tombstone's /rev is that check's answer.
func TestV082TombstoneRevLastAfterReadCheck(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	k := seal.NewKey()
	d1 := etagOf(f.writeRaw("e", "d", "", sealed(t, k, "e#1", "e", "d", "", addRoot(map[string]any{"n": 1.0})), f.writerG))
	del := f.do(req{method: "DELETE", path: "/r/e/d", ifMatch: d1, bearer: f.writerG})
	expect(t, del, 200)
	tomb := del.Str("tombstone")
	expect(t, f.get("/r/e/d/rev/"+tomb), 401)
	noRead := f.grant(f.writer, "user:x", []string{"e"}, []string{"append"})
	r := f.get("/r/e/d/rev/"+tomb, noRead)
	expect(t, r, 404)
	if r.Obj()["last"] != nil || r.Obj()["tombstone"] != nil {
		t.Fatalf("without read: %s", r.Body)
	}
	v82encTombstone(t, f.tenv, "with read", "e", "d", tomb, d1, f.readerG)
}
