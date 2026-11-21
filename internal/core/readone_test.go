package core

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A write's check reads its namespace, the item's resource, its head and
// the retry lookup's revision in one statement, and keeps them in the
// transaction's memo for every sub-step of step 2 (lookupResource,
// memoView). That snapshot is still what the re-check under the lock
// compares: a head moved by another write between the check and the lock
// fails it, and the write answers 412 with the new head, on the path
// without a group and in a group commit.
func TestRecheckAfterHeadMove(t *testing.T) {
	t.Parallel()
	for _, grouped := range []bool{false, true} {
		t.Run(fmt.Sprintf("grouped=%v", grouped), func(t *testing.T) {
			t.Parallel()
			if grouped && !pgtest.Enabled() {
				t.Skip("group commit: Postgres only")
			}
			e := openInstance(t, pgtest.DB(t), t.TempDir())
			e.opt.LockedCheckBytes = -1 // check outside the lock (D.3)
			e.noSolo = grouped
			mkNS(t, e, "n", map[string]any{"read": "public"})
			head, err := put(e, "n", "r", "", 0)
			if err != nil {
				t.Fatal(err)
			}
			// Between the check and the lock, once: another write moves r's
			// head.
			var moved atomic.Value
			var once atomic.Bool
			e.opt.BeforeWriteLock = func() {
				if once.Swap(true) {
					return // the concurrent write's own
				}
				h, err := put(e, "n", "r", head, 100)
				if err != nil {
					t.Errorf("concurrent write: %v", err)
				}
				moved.Store(h)
			}
			_, err = put(e, "n", "r", head, 1)
			if status(err) != 412 {
				t.Fatalf("write after a head moved: %v, want 412", err)
			}
			var ae *Error
			if !errors.As(err, &ae) || ae.Body["head"] != moved.Load() {
				t.Fatalf("412 names head %v, want the moved head %v", ae.Body["head"], moved.Load())
			}
		})
	}
}

// The plan's check saw the head as of its snapshot, the re-check under the
// lock reads it again: one plan, re-checked after a concurrent write, fails.
func TestRecheckSeesMovedHead(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	mkNS(t, e, "n", map[string]any{"read": "public"})
	head, err := put(e, "n", "r", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := who
	r.NS = "n"
	it := Item{Resource: "r", IfMatch: head, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 1.0}}}}}
	plan, deps, res, err := e.checkOutside(ctx, r, []Item{it}, nil, false, false)
	if err != nil || res != nil || plan == nil {
		t.Fatalf("check: %v %v", res, err)
	}
	recheck := func() bool {
		var ok bool
		if err := e.update(ctx, func(t *tx) error {
			t.lockDeps(plan.n.id, deps)
			_, ok = t.recheck(plan, deps)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !recheck() {
		t.Fatal("re-check failed with nothing changed")
	}
	if _, err := put(e, "n", "r", head, 2); err != nil {
		t.Fatal(err)
	}
	if recheck() {
		t.Fatal("re-check passed after the head moved")
	}
}

// A resource's view kept by the transaction (memoView) goes with its row:
// a row read again (memoRes) is resolved afresh.
func TestViewMemoFollowsRow(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	mkNS(t, e, "n", map[string]any{"read": "public"})
	if _, err := put(e, "n", "r", "", 0); err != nil {
		t.Fatal(err)
	}
	err := e.read(context.Background(), func(t *tx) error {
		n := t.nsByName("n")
		v := t.resolve(n, "r", nil)
		if v.state != Live || t.resolve(n, "r", nil) != v {
			return fmt.Errorf("view %v not kept", v.state)
		}
		gone := *v.own
		gone.state = statePurged
		t.memoRes(resKey{n.id, "r"}, &gone)
		if w := t.resolve(n, "r", nil); w == v || w.state != Purged {
			return fmt.Errorf("view after the row changed: %v", w.state)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// On Postgres a check of one statement runs without a transaction
// (readOne). A check that needs more, a branch's reading its base, is
// abandoned at its second statement and runs again in a read transaction,
// with the same answers; the namespace then reads in a transaction for a
// while. Revision reads alike, a revision read through from a base
// included.
func TestReadOneAbandoned(t *testing.T) {
	t.Parallel()
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	e.opt.LockedCheckBytes = -1
	mkNS(t, e, "n", map[string]any{"read": "public"})
	first, err := put(e, "n", "r", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := who
	r.NS = "n"
	if _, err := e.CreateBranch(ctx, r, BranchRequest{Name: "b", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	var lone, txs atomic.Int32
	e.onReadTx = func() { txs.Add(1) }
	e.onStatement = func(string, []any) { lone.Add(1) }
	count := func(f func()) (int32, int32) {
		lone.Store(0)
		txs.Store(0)
		f()
		return lone.Load(), txs.Load()
	}
	// A write to the branch, read through to the base's head.
	var head string
	stmts, n := count(func() {
		head, err = put(e, "b", "r", first, 1)
		if err != nil {
			t.Fatal(err)
		}
	})
	if n == 0 {
		t.Errorf("a branch's check ran in no read transaction (%d statements)", stmts)
	}
	if _, ok := e.lone.m.Load("b"); !ok {
		t.Error("the branch's abandoned read isn't backed off")
	}
	if e.lone.try("b") {
		t.Error("the branch reads without a transaction right after one was abandoned")
	}
	// The base's revision, read through the branch, and the branch's own.
	for _, id := range []string{first, head} {
		rev, err := e.ResourceRev(ctx, "b", "r", id, Credentials{})
		if err != nil || rev.Status != 200 {
			t.Fatalf("rev %s in the branch: %+v %v", id, rev, err)
		}
	}
	// The base's own namespace: one statement, no transaction, once its
	// backing off since its first write (whose check read the namespace's
	// document, not cached yet) is over.
	if _, err := put(e, "n", "r", first, 2); err != nil {
		t.Fatal(err)
	}
	e.lone.m.Delete("n")
	stmts, n = count(func() {
		rev, err := e.ResourceRev(ctx, "n", "r", first, Credentials{})
		if err != nil || rev.Status != 200 {
			t.Fatalf("rev in n: %+v %v", rev, err)
		}
	})
	if stmts != 1 || n != 0 {
		t.Errorf("an older revision of n: %d statements in %d transactions, want 1 in none", stmts, n)
	}
}

// A check abandoned after drawing from the engine's own rate-limit buckets
// doesn't draw again when it runs in a transaction: a namespace whose
// bucket holds exactly its writes takes them all. The draw comes before
// step 5, whose schema, read for the first time, is the check's second
// statement.
func TestReadOneDrawsOnce(t *testing.T) {
	t.Parallel()
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	const writes = 6
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal = fast, fast
	lim.RatePerNamespace = Rate{1e-6, writes} // a namespace's first config write draws nothing
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1,
		Limits: lim, Purger: discardPurger{}, LocalRateBuckets: true, LockedCheckBytes: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mkNS(t, e, "n", map[string]any{"read": "public"})
	ctx := context.Background()
	r := who
	r.NS = "n"
	var abandoned int
	for i := 0; i < writes/2; i++ {
		s := fmt.Sprintf("s%d", i)
		if _, err := e.WriteResource(ctx, r, createItem(s, kSchema(i))); err != nil {
			t.Fatalf("schema %d: %v", i, err)
		}
		// Each typed by a schema not read before: so its check reads it,
		// after its draw. Without backing off, so that each is abandoned.
		e.lone = loneGate{}
		var lone atomic.Int32
		e.onStatement = func(string, []any) { lone.Add(1) }
		if _, err := e.WriteResource(ctx, r, createItem(fmt.Sprintf("d%d", i), typedDoc(fmt.Sprintf("/r/n/%s/rev/%s", s, headIn(t, e, s)), i))); err != nil {
			t.Fatalf("typed write %d: %v", i, err)
		}
		e.onStatement = nil
		if _, ok := e.lone.m.Load("n"); ok {
			abandoned++
		}
	}
	if abandoned == 0 {
		t.Fatal("no check was abandoned: the test checks nothing")
	}
	if _, err := put(e, "n", "extra", "", 0); status(err) != 429 {
		t.Fatalf("a write past the bucket: %v, want 429", err)
	}
}

func headIn(t *testing.T, e *Engine, name string) string {
	t.Helper()
	h, err := e.ResourceHead(context.Background(), "n", name, Credentials{})
	if err != nil || h == nil {
		t.Fatalf("head of %s: %v", name, err)
	}
	return h.Head
}
