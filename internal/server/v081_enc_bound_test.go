package server

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
)

func withSealBound(bound, rotateAt, block int64) envOpt {
	return func(o *core.Options) { o.SealBound, o.SealRotateAt, o.SealBlock = bound, rotateAt, block }
}

// boundNS is sealed namespace s with three resources written: four
// namespace entries, each reserving its range's sealing under K_n, and
// the whole range read once (plainNSLog), one sealing.
func boundNS(t *testing.T, e *tenv) []string {
	t.Helper()
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	for _, name := range []string{"a", "b", "c"} {
		e.wr("s", name, "", withNonce(addRoot(map[string]any{"v": 1.0})))
	}
	plain := e.plainNSLog("s", e.nsHead("s"))
	var ids []string
	for _, m := range plain.Entries {
		ids = append(ids, m["id"].(string))
	}
	return ids
}

// KEYS-9 (§E.2.1 Message bound, §12.1 behind; ENC-26, scenario 60): the
// origin counts its sealings per key with what writes reserve, and a
// request that would need a sealing past the bound is 503 behind with
// Retry-After; nothing is sealed or stored. With a bound of 8, the four
// entries' reservations on K_n and the range boundNS read, three more
// distinct ranges seal; the next is refused, and so is a write, whose
// reservations would pass the bound.
func TestV081SealBound(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(8, 1<<30, 1))
	ids := boundNS(t, e)
	head := ids[len(ids)-1]
	for i := 0; i < 3; i++ {
		expect(t, e.get("/ns/s/rev/"+head+"/log?since="+ids[i]), 200)
	}
	db, pg := v0261DB(t, path)
	stored := v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed WHERE kind = 'range'`)
	r := e.get("/ns/s/rev/" + ids[1] + "/log")
	expectCode(t, r, 503, "behind")
	if r.H.Get("Retry-After") == "" {
		t.Fatalf("no Retry-After: %v", r.H)
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed WHERE kind = 'range'`); n != stored {
		t.Fatalf("a refused range stored: %d rows, were %d", n, stored)
	}
	w := e.write("PATCH", "s", "d", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	expectCode(t, w, 503, "behind")
	// A stored range is served as stored, needing no sealing.
	expect(t, e.get("/ns/s/rev/"+head+"/log?since="+ids[0]), 200)
}

// KEYS-9: a key of the current epoch reaching SealRotateAt makes the
// rotation due, which the leader makes as RotateAuthor, a frozen namespace
// included (§7.4 exempts *-key config writes); a purge deletes the counts.
func TestV081SealRotateAt(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(1<<20, 6, 1))
	ids := boundNS(t, e)
	expect(t, e.patchNS("s", ops(op("add", "/frozen", true)), ""), 201)
	head := e.nsHead("s")
	expect(t, e.get("/ns/s/rev/"+head+"/log?since="+ids[0]), 200)
	db, pg := v0261DB(t, path)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM rotations_due WHERE reason = 'bound'`); n != 1 {
		t.Fatalf("%d rotations due at the bound", n)
	}
	done, err := e.e.RetryRotations(context.Background())
	if err != nil || len(done) != 1 || done[0] != "s" {
		t.Fatalf("rotated %v %v", done, err)
	}
	if ep := e.configOf("s")["encryption"].(map[string]any)["epoch"]; ep != 2.0 {
		t.Fatalf("epoch %v after the rotation", ep)
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM seal_counts`); n == 0 {
		t.Fatal("no counts")
	}
	expect(t, e.do(req{method: "POST", path: "/ns/s/purge", ifMatch: e.nsHead("s"), author: "admin"}), 204)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM seal_counts WHERE ns IN (SELECT ns FROM namespaces WHERE name = 's')`); n != 0 {
		t.Fatalf("%d counts after the purge", n)
	}
}

// KEYS-9: two instances on one Postgres database share the count.
func TestV081SealBoundShared(t *testing.T) {
	t.Parallel()
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	path := pgtest.NewDB(t)
	ks := newKeyStore(t)
	a := newSealedEnv(t, withPath(path), withKeyStore(ks), withSealBound(8, 1<<30, 1))
	ids := boundNS(t, a)
	b := newSealedEnv(t, withPath(path), withKeyStore(ks), withSealBound(8, 1<<30, 1))
	head := ids[len(ids)-1]
	expect(t, a.get("/ns/s/rev/"+head+"/log?since="+ids[0]), 200)
	expect(t, b.get("/ns/s/rev/"+head+"/log?since="+ids[1]), 200)
	expect(t, a.get("/ns/s/rev/"+head+"/log?since="+ids[2]), 200)
	expectCode(t, a.get("/ns/s/rev/"+ids[1]+"/log"), 503, "behind")
	expectCode(t, b.get("/ns/s/rev/"+ids[1]+"/log"), 503, "behind")
}
