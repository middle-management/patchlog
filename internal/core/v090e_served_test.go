package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

// v0.90 §8.3 CDN ("ns:{ns} once a view of the namespace has been served";
// markServed, tagFilteredRanges): the answer that first serves a view of
// a namespace is read from a snapshot taken after the namespace's
// filtered_served row is committed. Before, the row was written after the
// answer's snapshot: a purge that chose its tags before the row existed
// and committed after that snapshot was taken left a range of the
// pre-purge state cached, ns:{ns} cleared neither by it nor by its
// queued repeat.
func TestV090EFirstViewReadAfterServedMark(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV76fWorld(t, false)
	red, st := v76fRedirect(t, w.v75World, "matches", "", w.li())
	if st != 0 {
		t.Fatalf("li's redirect to her view: %d", st)
	}
	marked := func() bool {
		var ok bool
		q := `SELECT EXISTS (SELECT 1 FROM filtered_served WHERE ns = ?)`
		if w.e.pg {
			q = `SELECT EXISTS (SELECT 1 FROM filtered_served WHERE ns = $1)`
		}
		if err := w.e.db.QueryRowContext(ctx, q, "matches").Scan(&ok); err != nil {
			t.Errorf("reading filtered_served: %v", err)
		}
		return ok
	}
	if marked() {
		t.Fatal("matches is marked before any view of it is served: the test shows nothing")
	}
	var mu sync.Mutex
	var begun []bool
	w.e.onReadTx = func() {
		m := marked()
		mu.Lock()
		begun = append(begun, m)
		mu.Unlock()
	}
	if _, _, err := w.e.FilteredLog(ctx, "matches", red.View, red.At, "", 10, w.li()); err != nil {
		t.Fatal(err)
	}
	w.e.onReadTx = nil
	mu.Lock()
	defer mu.Unlock()
	if len(begun) == 0 || !begun[len(begun)-1] {
		t.Fatalf("read transactions began with filtered_served holding matches: %v; the last, whose snapshot the answer is from, must", begun)
	}
	// Once marked, a view's read takes one transaction, as before.
	begun = nil
	w.e.onReadTx = func() { mu.Lock(); begun = append(begun, true); mu.Unlock() }
	mu.Unlock()
	if _, _, err := w.e.FilteredLog(ctx, "matches", red.View, red.At, "", 10, w.li()); err != nil {
		mu.Lock()
		t.Fatal(err)
	}
	mu.Lock()
	w.e.onReadTx = nil
	if len(begun) != 1 {
		t.Errorf("a view's read once the namespace is marked: %d read transactions, want 1", len(begun))
	}
}

// The mark waits for a purge in progress, which holds the namespace's
// lock exclusively (Postgres) or the writer (SQLite), so that the answer
// read after it sees the purge, and a purge that chooses its tags after
// the mark sees it (tagFilteredRanges).
func TestV090EServedMarkWaitsForPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV76fWorld(t, false)
	red, st := v76fRedirect(t, w.v75World, "matches", "", w.li())
	if st != 0 {
		t.Fatalf("li's redirect to her view: %d", st)
	}
	release := func() {}
	if w.e.pg {
		var id int64
		if err := w.e.db.QueryRowContext(ctx, `SELECT ns FROM namespaces WHERE name = $1`, "matches").Scan(&id); err != nil {
			t.Fatal(err)
		}
		conn, err := w.e.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1, $2)`, lockClass, lockKey(id)); err != nil {
			t.Fatal(err)
		}
		release = func() {
			if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1, $2)`, lockClass, lockKey(id)); err != nil {
				t.Error(err)
			}
			conn.Close()
		}
	} else {
		w.e.mu.Lock()
		release = w.e.mu.Unlock
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := w.e.FilteredLog(ctx, "matches", red.View, red.At, "", 10, w.li())
		done <- err
	}()
	select {
	case err := <-done:
		release()
		t.Fatalf("the first view of matches was answered (%v) while a purge of it held its lock", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the view's read didn't end once the lock was released")
	}
}
