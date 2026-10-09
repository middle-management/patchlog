package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// v0.49 §8.5: a purge propagated to a branch purged meanwhile skips it:
// nothing follows its purge-ns entry. A remote follow locks only the
// branch it follows before listing that one's branches; the purge-ns
// takes its base's lock too, so the purge waits for it there or at the
// branch's. Runs only with PATCHLOG_TEST_PG set.
func TestPGPurgeSkipsBranchPurgedMeanwhile(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	mkNS(t, a, "m", map[string]any{"read": "public"})
	if _, err := put(a, "m", "x", "", 1); err != nil {
		t.Fatal(err)
	}
	br, err := a.CreateBranch(ctx, Request{NS: "m", Cred: who.Cred}, BranchRequest{Name: "mb", IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	r := who
	r.NS = "mb"
	frozen, err := a.WriteConfig(ctx, r, ConfigChange{IfMatch: br.ConfigID, Patches: []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}})
	if err != nil {
		t.Fatal(err)
	}

	// b purges mb and doesn't commit until a's purge of x in m waits for it.
	var hold atomic.Bool
	inside, release := make(chan struct{}), make(chan struct{})
	b.opt.BeforeCommit = func(context.Context) {
		if hold.CompareAndSwap(true, false) {
			close(inside)
			<-release
		}
	}
	hold.Store(true)
	bDone := make(chan error, 1)
	go func() {
		_, err := b.PurgeNamespace(ctx, r, frozen.NSID, false)
		bDone <- err
	}()
	<-inside
	aDone := make(chan error, 1)
	go func() {
		aDone <- a.update(ctx, func(t *tx) error {
			m := t.nsByNameLocked("m", lockExclusive)
			t.purgeResource(m, "x", t.authorID(who.Cred.Author), false)
			return nil
		})
	}()
	if !waitFor(5*time.Second, func() bool { return waiting(a) > 0 }) {
		t.Fatal("the purge doesn't wait for the purge-ns")
	}
	close(release)
	for _, c := range []chan error{bDone, aDone} {
		if err := <-c; err != nil {
			t.Fatal(err)
		}
	}
	var kinds []int
	if err := a.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT kind FROM ns_log WHERE ns = ? ORDER BY seq`, t.nsByName("mb").id)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var k int
			t.must(rows.Scan(&k))
			kinds = append(kinds, k)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(kinds) == 0 || kinds[len(kinds)-1] != 5 {
		t.Fatalf("mb's log kinds %v: an entry followed purge-ns", kinds)
	}
}
