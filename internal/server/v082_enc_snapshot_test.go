package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82encSnap seals the snapshot of ns/d at id under k (kid ns#1).
func v82encSnap(t *testing.T, k []byte, ns, id string, n float64) string {
	t.Helper()
	s, err := seal.SealSnapshot(k, ns+"#1", ns, "d", id, map[string]any{"n": n})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// v82encIDBytes is id as revisions.id stores it.
func v82encIDBytes(t *testing.T, id string) []byte {
	t.Helper()
	x, err := ids.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	return x[:]
}

// v82encRestore restores every archive of e.
func v82encRestore(t *testing.T, e *tenv) {
	t.Helper()
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{})
	if err != nil || len(reps) == 0 || !reps[0].Cleared {
		t.Fatalf("restore %+v %v", reps, err)
	}
	e.e.FlushCaches()
}

// v82encNotOffered expects 404 not_offered naming horizon (and last, ""
// for none) at ns/d's /rev/{id}, never a snapshot.
func v82encNotOffered(t *testing.T, e *tenv, what, ns, id, horizon, last string) {
	t.Helper()
	r := e.get("/r/" + ns + "/d/rev/" + id)
	expectCode(t, r, 404, "not_offered")
	if l, _ := r.Obj()["last"].(string); r.Str("horizon") != horizon || l != last || isJOSE(r) {
		t.Fatalf("%s: %s, want horizon %s last %q", what, r.Body, horizon, last)
	}
}

// E2E-5 (§7.1 End-to-end namespaces, HTTP-68; scenario 71): a stored
// snapshot is served at its revision, also after an archive restore, and
// no longer once a later prune moves the horizon, to a revision below it
// too: /rev/{H1} is then 404 not_offered naming the new horizon, never
// the old snapshot.
func TestV082SnapshotEndsAtLowerPrune(t *testing.T) {
	t.Parallel()
	e, path := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	d1 := e.e3Write(k, "e", "d", "", addRoot(map[string]any{"n": 1.0}))
	d2 := e.e3Write(k, "e", "d", d1, ops(op("replace", "/n", 2.0)))
	d3 := e.e3Write(k, "e", "d", d2, ops(op("replace", "/n", 3.0)))
	d4 := e.e3Write(k, "e", "d", d3, ops(op("replace", "/n", 4.0)))
	e.clock.Advance(10 * time.Minute)
	s3 := v82encSnap(t, k, "e", d3, 3)
	expect(t, e.prune("e", "d", map[string]any{"horizon": d3, "snapshot": s3}, "admin"), 200)
	served := func(what, id, snap string) {
		t.Helper()
		if r := e.get("/r/e/d/rev/" + id); r.Code != 200 || string(r.Body) != snap || !isJOSE(r) {
			t.Fatalf("%s: %d %s", what, r.Code, r.Body)
		}
	}
	served("/rev/{H1}", d3, s3)
	// A restore keeps it: the log is whole again, the snapshot stays.
	v82encRestore(t, e)
	served("/rev/{H1} after the restore", d3, s3)
	v82encNotOffered(t, e, "/rev/{d2} after the restore", "e", d2, "", "")
	// A prune at a lower revision moves the horizon: the older snapshot
	// ends.
	e.clock.Advance(10 * time.Minute)
	s2 := v82encSnap(t, k, "e", d2, 2)
	expect(t, e.prune("e", "d", map[string]any{"horizon": d2, "snapshot": s2}, "admin"), 200)
	served("/rev/{h2}", d2, s2)
	v82encNotOffered(t, e, "/rev/{H1} after the lower prune", "e", d3, d2, "")
	v82encNotOffered(t, e, "/rev/{d4}", "e", d4, d2, "")
	expectCode(t, e.get("/r/e/d/rev/"+d1), 410, "pruned")
	db, pg := v0261DB(t, path)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 1 {
		t.Fatalf("%d snapshots stored", n)
	}
	// A purge ends every snapshot.
	expect(t, e.purge("e", "d", d4, "admin"), 204)
	if r := e.get("/r/e/d/rev/" + d2); r.Code != 410 || r.Str("code") != "gone" || isJOSE(r) {
		t.Fatalf("/rev/{h2} after the purge: %d %s", r.Code, r.Body)
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 0 {
		t.Fatalf("%d snapshots after the purge", n)
	}
}

// E2E-5 at a tombstone horizon (§E.3.1): the snapshot stored at T is
// served at its parent P until a later prune moves the horizon, below T
// too; then /rev/{P} is not_offered, and /rev/{T} stays T's 410.
func TestV082TombstoneSnapshotEndsAtLowerPrune(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	g := e.e3Write(k, "e", "d", "", addRoot(map[string]any{"n": 0.0}))
	p0 := e.e3Write(k, "e", "d", g, ops(op("replace", "/n", 1.0)))
	p := e.e3Write(k, "e", "d", p0, ops(op("replace", "/n", 2.0)))
	tomb := e.del("e", "d", p)
	l := etagOf(e.writeAs("e", "d", tomb, "[]", "alice")) // a restore
	e.clock.Advance(10 * time.Minute)
	sp := v82encSnap(t, k, "e", p, 2)
	expect(t, e.prune("e", "d", map[string]any{"horizon": tomb, "snapshot": sp}, "admin"), 200)
	if r := e.get("/r/e/d/rev/" + p); r.Code != 200 || string(r.Body) != sp {
		t.Fatalf("/rev/{P}: %d %s", r.Code, r.Body)
	}
	v82encRestore(t, e)
	if r := e.get("/r/e/d/rev/" + p); r.Code != 200 || string(r.Body) != sp {
		t.Fatalf("/rev/{P} after the restore: %d %s", r.Code, r.Body)
	}
	e.clock.Advance(10 * time.Minute)
	s0 := v82encSnap(t, k, "e", p0, 1)
	expect(t, e.prune("e", "d", map[string]any{"horizon": p0, "snapshot": s0}, "admin"), 200)
	v82encNotOffered(t, e, "/rev/{P} after the lower prune", "e", p, p0, "")
	v82encNotOffered(t, e, "/rev/{l}", "e", l, p0, "")
	v82encTombstone(t, e, "the tombstone", "e", "d", tomb, p)
	if r := e.get("/r/e/d/rev/" + p0); r.Code != 200 || string(r.Body) != s0 {
		t.Fatalf("/rev/{h2}: %d %s", r.Code, r.Body)
	}
}

// E2E-14, E2E-5 (§7.1, §7.6): a branch serves a base's stored snapshot at
// the revision it stands for whatever the branch wrote since; a prune in
// the branch touches no row of the base; and the base's later prune ends
// the snapshot through the branch too.
func TestV082BranchReadsBaseSnapshot(t *testing.T) {
	t.Parallel()
	e, path := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	d1 := e.e3Write(k, "e", "d", "", addRoot(map[string]any{"n": 1.0}))
	d2 := e.e3Write(k, "e", "d", d1, ops(op("replace", "/n", 2.0)))
	d3 := e.e3Write(k, "e", "d", d2, ops(op("replace", "/n", 3.0)))
	e.clock.Advance(10 * time.Minute)
	s2 := v82encSnap(t, k, "e", d2, 2)
	expect(t, e.prune("e", "d", map[string]any{"horizon": d2, "snapshot": s2}, "admin"), 200)
	expect(t, e.branch("e", map[string]any{"name": "eb"}, "alice"), 201)
	kb := seal.NewKey()
	b1 := etagOf(e.writeAs("eb", "d", d3, sealed(t, kb, "eb#1", "eb", "d", d3, ops(op("replace", "/n", 4.0))), "alice"))
	b2 := etagOf(e.writeAs("eb", "d", b1, sealed(t, kb, "eb#1", "eb", "d", b1, ops(op("replace", "/n", 5.0))), "alice"))
	b3 := etagOf(e.writeAs("eb", "d", b2, sealed(t, kb, "eb#1", "eb", "d", b2, ops(op("replace", "/n", 6.0))), "alice"))
	through := func(what string) {
		t.Helper()
		if r := e.get("/r/eb/d/rev/" + d2); r.Code != 200 || string(r.Body) != s2 || !isJOSE(r) {
			t.Fatalf("%s: the base's snapshot through the branch: %d %s", what, r.Code, r.Body)
		}
	}
	through("after the branch wrote past it")
	// A prune in the branch checks its snapshot and moves nothing (§8.6):
	// the base's row stays, and the branch stores none.
	e.clock.Advance(10 * time.Minute)
	pr := e.prune("eb", "d", map[string]any{"horizon": b2, "snapshot": v82encSnap(t, kb, "eb", b2, 5)}, "admin")
	expect(t, pr, 200)
	if pr.Str("horizon") != d2 {
		t.Fatalf("the branch's prune: %s, want the base's horizon %s", pr.Body, d2)
	}
	through("after the branch's prune")
	if r := e.get("/r/e/d/rev/" + d2); r.Code != 200 || string(r.Body) != s2 {
		t.Fatalf("the base's own /rev/{H}: %d %s", r.Code, r.Body)
	}
	v82encNotOffered(t, e, "the branch's own revision", "eb", b3, d2, "")
	db, pg := v0261DB(t, path)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 1 {
		t.Fatalf("%d snapshots stored", n)
	}
	// The base's later prune moves its horizon: its snapshot at d2 ends,
	// through the branch as well.
	d4 := e.e3Write(k, "e", "d", d3, ops(op("replace", "/n", 7.0)))
	e.clock.Advance(10 * time.Minute)
	s3 := v82encSnap(t, k, "e", d3, 3)
	expect(t, e.prune("e", "d", map[string]any{"horizon": d3, "snapshot": s3}, "admin"), 200)
	for _, ns := range []string{"e", "eb"} {
		if r := e.get("/r/" + ns + "/d/rev/" + d2); r.Code != 410 || r.Str("code") != "pruned" || isJOSE(r) {
			t.Fatalf("%s: /rev/{d2} after the base's later prune: %d %s", ns, r.Code, r.Body)
		}
		if r := e.get("/r/" + ns + "/d/rev/" + d3); r.Code != 200 || string(r.Body) != s3 {
			t.Fatalf("%s: /rev/{d3}: %d %s", ns, r.Code, r.Body)
		}
	}
	v82encNotOffered(t, e, "the base's head", "e", d4, d3, "")
}

// E2E-5, stored data (stored.md): snapshots a version before v0.82 left
// behind a moved horizon are deleted at Open and never served: a row above
// the current horizon, and both rows of a resource without a horizon that
// has two. The one snapshot at the horizon, and the one a restore kept,
// stay.
func TestV082OpenCleansStaleSnapshots(t *testing.T) {
	t.Parallel()
	var path string
	ks, dir := newKeyStore(t), t.TempDir()
	opts := []envOpt{withKeyStore(ks), withEncTuning, withArchive(t, dir), withoutRetentionLoop}
	e := newEnv(t, append(opts, withFileDB(t), func(o *core.Options) { path = o.Path })...)
	k := seal.NewKey()
	type res struct{ d1, d2, d3, s2, s3 string }
	mk := func(ns string) res {
		e.mkNS(ns, e2eDoc(map[string]any{"read": "public"}))
		var r res
		r.d1 = e.e3Write(k, ns, "d", "", addRoot(map[string]any{"n": 1.0}))
		r.d2 = e.e3Write(k, ns, "d", r.d1, ops(op("replace", "/n", 2.0)))
		r.d3 = e.e3Write(k, ns, "d", r.d2, ops(op("replace", "/n", 3.0)))
		e.e3Write(k, ns, "d", r.d3, ops(op("replace", "/n", 4.0)))
		r.s2, r.s3 = v82encSnap(t, k, ns, r.d2, 2), v82encSnap(t, k, ns, r.d3, 3)
		return r
	}
	// stale: pruned at d2, with a row left above it at d3, as v0.27.0
	// left one after a restore and a lower prune. two: no horizon, two
	// rows. kept: a restore's one row. cur: pruned, one row.
	stale, two, kept, cur := mk("stale"), mk("two"), mk("kept"), mk("cur")
	e.clock.Advance(10 * time.Minute)
	for ns, r := range map[string]res{"stale": stale, "two": two, "kept": kept, "cur": cur} {
		expect(t, e.prune(ns, "d", map[string]any{"horizon": r.d2, "snapshot": r.s2}, "admin"), 200)
	}
	for _, ns := range []string{"two", "kept"} {
		reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{NS: ns})
		if err != nil || len(reps) != 1 || !reps[0].Cleared {
			t.Fatalf("restore %s: %+v %v", ns, reps, err)
		}
	}
	db, pg := v0261DB(t, path)
	ph := func(q string) string {
		for i := 1; pg && strings.Contains(q, "?"); i++ {
			q = strings.Replace(q, "?", "$"+strconv.Itoa(i), 1)
		}
		return q
	}
	for ns, r := range map[string]res{"stale": stale, "two": two} {
		if _, err := db.Exec(ph(`INSERT INTO e2e_snapshots (seq, res, jwe) SELECT v.seq, v.res, ? FROM revisions v JOIN resources r ON r.res = v.res JOIN namespaces n ON n.ns = r.ns WHERE n.name = ? AND v.id = ?`),
			r.s3, ns, v82encIDBytes(t, r.d3)); err != nil {
			t.Fatal(err)
		}
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 6 {
		t.Fatalf("%d snapshot rows before the upgrade, want 6", n)
	}
	e.e.FlushCaches()
	// As v0.27.0 served it: the stale row at d3.
	if r := e.get("/r/stale/d/rev/" + stale.d3); r.Code != 200 || string(r.Body) != stale.s3 {
		t.Fatalf("the fixture's stale row isn't served: %d %s", r.Code, r.Body)
	}

	// The upgrade: a second engine opens the database.
	e2 := newEnv(t, append(opts, withPath(path))...)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 3 {
		t.Fatalf("%d snapshot rows after Open, want 3", n)
	}
	v82encNotOffered(t, e2, "the stale row's revision", "stale", stale.d3, stale.d2, "")
	for what, c := range map[string]struct{ ns, id, snap string }{
		"the horizon of the resource that had a stale row": {"stale", stale.d2, stale.s2},
		"a restore's one snapshot":                         {"kept", kept.d2, kept.s2},
		"a current horizon":                                {"cur", cur.d2, cur.s2},
	} {
		if r := e2.get("/r/" + c.ns + "/d/rev/" + c.id); r.Code != 200 || string(r.Body) != c.snap {
			t.Fatalf("%s: %d %s", what, r.Code, r.Body)
		}
	}
	// Two rows and no horizon: neither is served; readers fold the
	// restored log.
	v82encNotOffered(t, e2, "two rows, d2", "two", two.d2, "", "")
	v82encNotOffered(t, e2, "two rows, d3", "two", two.d3, "", "")
	// Idempotent: a third Open deletes nothing.
	newEnv(t, append(opts, withPath(path))...)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 3 {
		t.Fatalf("%d snapshot rows after a second Open, want 3", n)
	}
}
