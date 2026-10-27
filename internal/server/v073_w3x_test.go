package server

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/seal"
)

// W3X (P29 x P34 x P26; §8.6, §D.4, Addendum E Levels): a namespace raised
// from none to e2e keeps its pre-raise history in the clear. Restoring it
// must check each archived entry by the level its revision was written at,
// not the namespace's current one: a plain archive written by a prune
// before the raise, and the sealed bundle an E3 prune writes after it, of
// a history that is plaintext before the raise and sealed ops after it,
// both come back whole and clear the horizon.
func TestW3XRaisedE2EArchiveRestores(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop, withKeyStore(newKeyStore(t)))
	e.mkNS("rz", map[string]any{"read": "public"})
	revs := e.chain("rz", "d", 4)
	// p is pruned before the raise: a plain archive.
	prevs := e.chain("rz", "p", 4)
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("rz", "p", map[string]any{"horizon": prevs[2]}, "admin"), 200)
	expect(t, e.patchNS("rz", ops(op("add", "/encryption", map[string]any{"level": "e2e", "epoch": 1.0})), ""), 201)
	preps, err := archive.Restore(ctx, e.e, archive.RestoreOptions{NS: "rz", Name: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(preps) != 1 || preps[0].Restored != 2 || preps[0].Skipped != 0 || !preps[0].Cleared {
		t.Errorf("restore of a plain archive written before the raise to e2e: %+v, want 2 restored and the horizon cleared", preps)
	}
	if r := e.get("/r/rz/p/rev/" + prevs[0]); r.Code == 410 {
		t.Errorf("p's first revision after the restore: %d %s", r.Code, r.Body)
	}
	// d gets two sealed revisions after the raise, then an E3 prune to the
	// last archives four plaintext patch sets and one sealed op.
	k := seal.NewKey()
	for i := 4; i < 6; i++ {
		r := e.writeAs("rz", "d", revs[i-1], sealed(t, k, "rz#1", "rz", "d", revs[i-1], ops(op("replace", "/n", float64(i)))), "alice")
		expect(t, r, 201)
		revs = append(revs, etagOf(r))
	}
	e.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "rz#1", "rz", "d", revs[5], map[string]any{"n": 5.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.prune("rz", "d", map[string]any{"horizon": revs[5], "snapshot": snap}, "admin"), 200)
	expect(t, e.get("/r/rz/d/rev/"+revs[0]), 410)
	reps, err := archive.Restore(ctx, e.e, archive.RestoreOptions{NS: "rz", Name: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 || len(reps[0].Failed) != 0 || reps[0].Restored != 5 || reps[0].Skipped != 0 || !reps[0].Cleared {
		t.Fatalf("restore of a pre- and post-raise history archived by an E3 prune: %+v, want 5 restored and the horizon cleared", reps)
	}
	for _, id := range []string{revs[0], revs[4]} {
		if r := e.get("/r/rz/d/rev/" + id); r.Code == 410 {
			t.Errorf("d's revision %s after the restore: %d %s", id, r.Code, r.Body)
		}
	}
}
