package server

import (
	"context"
	"fmt"
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

// KEYS-9 (§E.2.1 "reserving what may still be sealed under an epoch after
// it ends"): a read sealing a revision's document or log entry counts it
// from what its write reserved, moved to sealed, so reservations filling
// K_r never make their own revisions unreadable. With a bound of 4, two
// revisions of a reserve all 4; their documents and the two-entry log
// read, and end at 4 sealed, none reserved (5 and 6 leave room).
func TestV081ReservedRoomServesReads(t *testing.T) {
	t.Parallel()
	for _, bound := range []int64{6, 5, 4} {
		t.Run(fmt.Sprint(bound), func(t *testing.T) {
			t.Parallel()
			var path string
			e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(bound, 1<<30, 1))
			e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
			id1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
			id2 := e.wr("s", "a", id1, withNonce([]any{op("replace", "/v", 2.0)}))
			expect(t, e.get("/r/s/a/rev/"+id1), 200)
			expect(t, e.get("/r/s/a/rev/"+id2), 200)
			expect(t, e.get("/r/s/a/rev/"+id2+"/log"), 200)
			db, pg := v0261DB(t, path)
			sealed := v0261Count(t, db, pg, `SELECT sealed FROM seal_counts WHERE name = 'a'`)
			reserved := v0261Count(t, db, pg, `SELECT reserved FROM seal_counts WHERE name = 'a'`)
			if sealed != 4 || reserved != 0 {
				t.Fatalf("K_r(a): %d sealed, %d reserved; want 4 and 0", sealed, reserved)
			}
		})
	}
}

// KEYS-9 (§E.2.1): counting a read's sealings is all or none. With K_r(a)
// at 3 sealed and 1 reserved of a bound of 4, the two-entry log needs one
// count past the bound: 503 behind, and the reservation it could have
// used stays reserved, so a retry burns nothing. A document read then
// uses it.
func TestV081ReservedRoomAllOrNone(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(4, 1<<30, 1))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	id1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	id2 := e.wr("s", "a", id1, withNonce([]any{op("replace", "/v", 2.0)}))
	db, pg := v0261DB(t, path)
	if _, err := db.Exec(`UPDATE seal_counts SET sealed = 3, reserved = 1 WHERE name = 'a'`); err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		return v0261Count(t, db, pg, `SELECT sealed FROM seal_counts WHERE name = 'a'`), v0261Count(t, db, pg, `SELECT reserved FROM seal_counts WHERE name = 'a'`)
	}
	for range 2 {
		expectCode(t, e.get("/r/s/a/rev/"+id2+"/log"), 503, "behind")
		if s, r := counts(); s != 3 || r != 1 {
			t.Fatalf("after a refused log: %d sealed, %d reserved; want 3 and 1", s, r)
		}
	}
	expect(t, e.get("/r/s/a/rev/"+id1), 200)
	if s, r := counts(); s != 4 || r != 0 {
		t.Fatalf("after a document read: %d sealed, %d reserved; want 4 and 0", s, r)
	}
}
