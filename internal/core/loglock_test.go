package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// D.8 (v0.34): namespace entries are ordered by a separate advisory log
// lock, taken last and held through commit. These tests run only with
// PATCHLOG_TEST_PG set.

// A transaction holding a log lock never waits for a namespace lock: it
// tries it, and if it is busy rolls back and runs again with it taken up
// front, taking its log locks again at its first append. Meanwhile the
// holder of the namespace lock can take that log lock, so nobody deadlocks.
func TestPGLogLockNeverWaitsForStateLock(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	holding, release := make(chan struct{}), make(chan struct{})
	bDone := make(chan error, 1)
	go func() {
		bDone <- b.update(ctx, func(t *tx) error {
			t.lockNS(5, lockExclusive)
			close(holding)
			<-release
			t.lockLog(1) // waits for a, if a still held it
			return nil
		})
	}()
	<-holding
	var runs atomic.Int64
	var logged atomic.Bool
	aDone := make(chan error, 1)
	go func() {
		aDone <- a.update(ctx, func(t *tx) error {
			if runs.Add(1) == 1 {
				defer close(release)
			}
			t.lockNS(1, lockShared)
			t.lockLog(1)
			logged.Store(t.logLocks[lockKey(1)])
			t.lockNS(5, lockShared) // held by b: only tried
			return nil
		})
	}()
	for _, c := range []chan error{aDone, bDone} {
		select {
		case err := <-c:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("deadlock")
		}
	}
	if runs.Load() != 2 || !logged.Load() {
		t.Fatalf("a ran %d times (want 2: rolled back once), log lock held %v", runs.Load(), logged.Load())
	}
}

// Several log locks are taken in ascending key order: one below a log lock
// held is only tried, and on a restart all of them are taken in order at
// the first append.
func TestPGLogLocksAscending(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	holding, release := make(chan struct{}), make(chan struct{})
	bDone := make(chan error, 1)
	go func() {
		bDone <- b.update(ctx, func(t *tx) error {
			t.lockLog(2)
			close(holding)
			<-release
			t.lockLog(3) // waits for a, if a still held it
			return nil
		})
	}()
	<-holding
	var runs atomic.Int64
	var order []int32
	aDone := make(chan error, 1)
	go func() {
		aDone <- a.update(ctx, func(t *tx) error {
			if runs.Add(1) == 1 {
				defer close(release)
			}
			t.lockLog(3)
			t.lockLog(2) // below 3 and held by b: tried
			order = nil
			for _, k := range []int32{2, 3} {
				if t.logLocks[k] {
					order = append(order, k)
				}
			}
			return nil
		})
	}()
	for _, c := range []chan error{aDone, bDone} {
		select {
		case err := <-c:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("deadlock")
		}
	}
	if runs.Load() != 2 || len(order) != 2 {
		t.Fatalf("a ran %d times (want 2), holds %v", runs.Load(), order)
	}
}

// Appends to one namespace wait for each other's commit at the log lock,
// not for a row lock on the namespace: a concurrent resource create (which
// key-share locks the namespace row) proceeds while an appender holds the
// log lock, and entries commit in chain order with growing seqs.
func TestPGLogLockOrdersEntries(t *testing.T) {
	a, b := twoInstances(t)
	ctx := context.Background()
	mkNS(t, a, "n", map[string]any{"read": "public"})
	var hold atomic.Bool
	inside, release := make(chan struct{}), make(chan struct{})
	a.opt.BeforeCommit = func(context.Context) {
		if hold.CompareAndSwap(true, false) {
			close(inside)
			<-release
		}
	}
	hold.Store(true)
	aDone := make(chan error, 1)
	go func() {
		_, err := put(a, "n", "x", "", 1)
		aDone <- err
	}()
	<-inside
	// a holds n's log lock until it commits. b's write checks and inserts
	// its rows meanwhile, and waits only at the log lock.
	bDone := make(chan error, 1)
	go func() {
		_, err := put(b, "n", "y", "", 2)
		bDone <- err
	}()
	var waiting bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !waiting {
		err := b.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory'
			AND classid = ($1::bigint)::oid AND objsubid = 2 AND NOT granted)`, logClass).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("the second writer doesn't wait at the log lock")
	}
	close(release)
	for _, c := range []chan error{aDone, bDone} {
		if err := <-c; err != nil {
			t.Fatal(err)
		}
	}
	rows, err := a.db.QueryContext(ctx, `SELECT seq, prev_seq FROM ns_log WHERE ns = (SELECT ns FROM namespaces WHERE name = 'n') ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var last int64
	for rows.Next() {
		var seq int64
		var prev *int64
		if err := rows.Scan(&seq, &prev); err != nil {
			t.Fatal(err)
		}
		if last != 0 && (prev == nil || *prev != last) {
			t.Fatalf("entry %d follows %v, want %d: seqs don't grow along the chain", seq, prev, last)
		}
		last = seq
	}
}
