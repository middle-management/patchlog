package server

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// newE3Env is a dev-mode server with an archive destination, for E3 prunes
// (§8.6), whose database is at the returned path.
func newE3Env(t *testing.T) (*tenv, string) {
	t.Helper()
	var path string
	e := newEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withKeyStore(newKeyStore(t)), withEncTuning, withArchive(t, t.TempDir()), withoutRetentionLoop)
	return e, path
}

// e3Write writes a sealed op under k (kid ns#1) to ns/name on parent.
func (e *tenv) e3Write(k []byte, ns, name, parent string, patches []any) string {
	e.t.Helper()
	r := e.writeAs(ns, name, parent, sealed(e.t, k, ns+"#1", ns, name, parent, patches), "alice")
	expect(e.t, r, 201)
	return etagOf(r)
}

// E2E-4 (§7.1 End-to-end namespaces, §9, §12.1; scenarios 62, 63): the
// server never folds. A revision without a stored snapshot is 404
// not_offered, cached short with the resource's tags, naming no horizon
// before a prune; after a prune at H, it names H, and /rev/{H} serves the
// snapshot as application/jose, immutable, with ETag "{H}" and 304.
func TestV081E3RevNotOffered(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("matches", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	d1 := e.e3Write(k, "matches", "derby", "", addRoot(map[string]any{"n": 1.0}))
	d2 := e.e3Write(k, "matches", "derby", d1, ops(op("replace", "/n", 2.0)))
	d3 := e.e3Write(k, "matches", "derby", d2, ops(op("replace", "/n", 3.0)))
	r := e.get("/r/matches/derby/rev/" + d3)
	expectCode(t, r, 404, "not_offered")
	if _, ok := r.Obj()["horizon"]; ok || r.H.Get("Cache-Control") != ccShort || r.H.Get("X-E2E") != "" {
		t.Fatalf("not_offered before a prune: %v %s", r.H, r.Body)
	}
	if tags := r.H.Get("Cache-Tag"); !strings.Contains(tags, "ns:matches") || !strings.Contains(tags, "r:matches/derby") {
		t.Fatalf("tags %q", tags)
	}
	e.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "matches#1", "matches", "derby", d2, map[string]any{"n": 2.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.prune("matches", "derby", map[string]any{"horizon": d2, "snapshot": snap}, "admin"), 200)
	r = e.get("/r/matches/derby/rev/" + d3)
	expectCode(t, r, 404, "not_offered")
	if r.Str("horizon") != d2 || r.Obj()["last"] != nil {
		t.Fatalf("not_offered after the prune: %s", r.Body)
	}
	r = e.get("/r/matches/derby/rev/" + d2)
	expect(t, r, 200)
	if string(r.Body) != snap || r.H.Get("Content-Type") != seal.ContentType || r.H.Get("ETag") != quote(d2) || r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("/rev/{H}: %v %s", r.H, r.Body)
	}
	expect(t, e.do(req{method: "GET", path: "/r/matches/derby/rev/" + d2, ifNoneMatch: quote(d2)}), 304)
	// Below the horizon: 410 pruned, as before.
	expectCode(t, e.get("/r/matches/derby/rev/"+d1), 410, "pruned")
}

// E2E-4: not_offered comes after the read check (§7.1): a caller without
// read gets that check's answer.
func TestV081E3NotOfferedAfterReadCheck(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	k := seal.NewKey()
	d1 := etagOf(f.writeRaw("e", "d", "", sealed(t, k, "e#1", "e", "d", "", addRoot(map[string]any{"n": 1.0})), f.writerG))
	expect(t, f.get("/r/e/d/rev/"+d1), 401)
	noRead := f.grant(f.writer, "user:x", []string{"e"}, []string{"append"})
	expect(t, f.get("/r/e/d/rev/"+d1, noRead), 404)
	expectCode(t, f.get("/r/e/d/rev/"+d1, f.readerG), 404, "not_offered")
}

// E2E-5, scenario 64 (§E.3.1, §7.1): at a tombstone horizon T with parent
// P, the snapshot is P's document, bound to P: one bound to T is 422.
// /rev/{P} serves it, /rev/{T} is a plain 410, and a later live revision
// is 404 not_offered with horizon T and last P. A stored snapshot bound
// to T, as before v0.81, is never served: /rev/{P} is 410 pruned.
func TestV081E3TombstoneHorizonSnapshot(t *testing.T) {
	t.Parallel()
	e, path := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	p0 := e.e3Write(k, "e", "d", "", addRoot(map[string]any{"n": 0.0}))
	p := e.e3Write(k, "e", "d", p0, ops(op("replace", "/n", 1.0)))
	tomb := e.del("e", "d", p)
	l := etagOf(e.writeAs("e", "d", tomb, "[]", "alice")) // a restore
	e.clock.Advance(10 * time.Minute)
	atT, _ := seal.SealSnapshot(k, "e#1", "e", "d", tomb, map[string]any{"n": 1.0})
	expectCode(t, e.prune("e", "d", map[string]any{"horizon": tomb, "snapshot": atT}, "admin"), 422, "invalid")
	snap, _ := seal.SealSnapshot(k, "e#1", "e", "d", p, map[string]any{"n": 1.0})
	expect(t, e.prune("e", "d", map[string]any{"horizon": tomb, "snapshot": snap}, "admin"), 200)
	r := e.get("/r/e/d/rev/" + p)
	if r.Code != 200 || string(r.Body) != snap || r.H.Get("Content-Type") != seal.ContentType || r.H.Get("ETag") != quote(p) {
		t.Fatalf("/rev/{P}: %d %v %s", r.Code, r.H, r.Body)
	}
	r = e.get("/r/e/d/rev/" + tomb)
	if r.Code != 410 || r.Obj()["snapshot"] != nil {
		t.Fatalf("/rev/{T}: %d %s", r.Code, r.Body)
	}
	r = e.get("/r/e/d/rev/" + l)
	expectCode(t, r, 404, "not_offered")
	if r.Str("horizon") != tomb || r.Str("last") != p {
		t.Fatalf("/rev/{later}: %s", r.Body)
	}
	expectCode(t, e.get("/r/e/d/rev/"+p0), 410, "pruned")

	// A legacy row, bound to the tombstone.
	db, pg := v0261DB(t, path)
	ph := "?"
	if pg {
		ph = "$1"
	}
	if _, err := db.Exec(`UPDATE e2e_snapshots SET jwe = `+ph, atT); err != nil {
		t.Fatal(err)
	}
	e.e.FlushCaches()
	r = e.get("/r/e/d/rev/" + p)
	expectCode(t, r, 410, "pruned")
	if r.Str("horizon") != tomb || string(r.Body) == atT {
		t.Fatalf("/rev/{P} with a legacy snapshot: %s", r.Body)
	}
}

// E2E-3 (§7.1, CONFORMANCE HTTP-17): at E3 a blob's epoch URL is 404
// not_offered, after the resource's read check.
func TestV081E3BlobEpochNotOffered(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	ref := e.uploadE2E("e", "a", []byte("bytes"), "alice")
	bid := ref["$blob"].(string)
	expect(t, e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(map[string]any{"f": ref}), bid), "alice"), 201)
	expectCode(t, e.get(blobPath("e", "a", bid)+"/e/1"), 404, "not_offered")
	expect(t, e.get(blobPath("e", "a", bid)), 200)
}

// E2E-3 (§E.3.1): a snapshot's kid names the namespace pruning, a
// branch's own, never a base's, whatever its chain reads through.
func TestV081E3BranchSnapshotKidNamesBranch(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("e", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	d1 := e.e3Write(k, "e", "d", "", addRoot(map[string]any{"n": 1.0}))
	expect(t, e.branch("e", map[string]any{"name": "eb"}, "alice"), 201)
	kb := seal.NewKey()
	b1 := etagOf(e.writeAs("eb", "d", d1, sealed(t, kb, "eb#1", "eb", "d", d1, ops(op("replace", "/n", 2.0))), "alice"))
	b2 := etagOf(e.writeAs("eb", "d", b1, sealed(t, kb, "eb#1", "eb", "d", b1, ops(op("replace", "/n", 3.0))), "alice"))
	e.clock.Advance(10 * time.Minute)
	base, _ := seal.SealSnapshot(k, "e#1", "e", "d", b2, map[string]any{"n": 3.0})
	r := e.prune("eb", "d", map[string]any{"horizon": b2, "snapshot": base}, "admin")
	expectCode(t, r, 422, "invalid")
	own, _ := seal.SealSnapshot(kb, "eb#1", "eb", "d", b2, map[string]any{"n": 3.0})
	expect(t, e.prune("eb", "d", map[string]any{"horizon": b2, "snapshot": own}, "admin"), 200)
}
