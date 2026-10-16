package index_test

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// clock is an index's own clock in these tests; the core keeps its own.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now()} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// repurgeOn sends second purges a minute of c after the first, looking
// every millisecond.
func repurgeOn(c *clock) func(*indexOpts) {
	return func(o *indexOpts) {
		o.Now, o.RepurgeDelay, o.RepurgeInterval = c.Now, time.Minute, time.Millisecond
	}
}

func (s *svc) purgesSoFar() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprint(s.purges)
}

// TestRepurge (D.8, as the core's second purge): a purge's cache tags are
// sent at once, after the apply commits, and once more RepurgeDelay later,
// from a queue the apply's transaction wrote, so that a result read before
// the commit and handed to the CDN after the first purge doesn't stay
// there. Applies that purge nothing queue nothing.
func TestRepurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	c := newClock()
	s := startSvcWith(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true}, repurgeOn(c))
	s.caughtUp("matches")

	// An update and a tombstone purge nothing, so nothing is sent twice.
	h := must(w.c.Head(ctx, "matches", "cup"))
	must(w.c.Append(ctx, "matches", "cup", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Cup quarter final"}}))
	must(w.c.Delete(ctx, "matches", "derby", must(w.c.Head(ctx, "matches", "derby")).ID))
	s.appliedUpTo(s.caughtUp("matches"))
	if q := s.ix.QueuedRepurges(); len(q) != 0 {
		t.Fatalf("queued without a purge: %v", q)
	}
	c.Advance(time.Hour)
	if n, err := s.ix.Repurge(ctx); err != nil || n != 0 {
		t.Fatalf("sent %d second purges without a purge (%v)", n, err)
	}

	// A purge: once at once, queued with the commit; the clock hasn't
	// reached its due time, so the loop sends nothing more.
	must(w.c.Purge(ctx, "matches", "final", must(w.c.Head(ctx, "matches", "final")).ID, false))
	s.appliedUpTo(s.caughtUp("matches"))
	const once = "[[r:matches/final idx:matches:counts]]"
	if got := s.purgesSoFar(); got != once {
		t.Fatalf("purges %s, want %s", got, once)
	}
	if q := s.ix.QueuedRepurges(); !reflect.DeepEqual(q, [][]string{{"r:matches/final", "idx:matches:counts"}}) {
		t.Fatalf("queued %v", q)
	}
	c.Advance(time.Minute - time.Millisecond)
	if n, err := s.ix.Repurge(ctx); err != nil || n != 0 {
		t.Fatalf("sent %d second purges before they were due (%v)", n, err)
	}
	if got := s.purgesSoFar(); got != once {
		t.Fatalf("purges before the delay %s, want %s", got, once)
	}
	// Once more after the delay, by the loop, and then never again.
	c.Advance(time.Millisecond)
	waitFor(t, "the second purge", func() bool { return len(s.ix.QueuedRepurges()) == 0 })
	if got, want := s.purgesSoFar(), "[[r:matches/final idx:matches:counts] [r:matches/final idx:matches:counts]]"; got != want {
		t.Errorf("purges %s, want %s", got, want)
	}
	c.Advance(time.Hour)
	if n, err := s.ix.Repurge(ctx); err != nil || n != 0 {
		t.Errorf("sent %d more (%v)", n, err)
	}
}

// TestRepurgeAfterRestart: the second purge of a purge-ns survives the
// index stopping before it is due, and the next start sends it.
func TestRepurgeAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	c := newClock()
	db := filepath.Join(t.TempDir(), "i.db")
	s := startSvcWith(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true}, repurgeOn(c))
	s.caughtUp("matches")
	must(w.c.PatchConfig(ctx, "matches", must(w.c.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.c.PurgeNamespace(ctx, "matches", must(w.c.NSHead(ctx, "matches")).ID))
	waitFor(t, "the purge-ns to be published", func() bool { return s.ix.Checkpoint("matches") == purged })
	if got := s.purgesSoFar(); got != "[[idx:matches ns:matches]]" {
		t.Fatalf("purges %s", got)
	}
	s.stop()

	s2 := startSvcWith(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true, noRun: true}, repurgeOn(c))
	if q := s2.ix.QueuedRepurges(); !reflect.DeepEqual(q, [][]string{{"idx:matches", "ns:matches"}}) {
		t.Fatalf("queued after the restart %v", q)
	}
	c.Advance(time.Minute)
	waitFor(t, "the second purge after the restart", func() bool { return len(s2.ix.QueuedRepurges()) == 0 })
	if got := s2.purgesSoFar(); got != "[[idx:matches ns:matches]]" {
		t.Errorf("purges after the restart %s", got)
	}
	if got := s.purgesSoFar(); got != "[[idx:matches ns:matches]]" {
		t.Errorf("the stopped index purged %s", got)
	}
}

// TestRepurgeDisabled: a negative RepurgeDelay sends each purge once and
// queues nothing.
func TestRepurgeDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	c := newClock()
	s := startSvcWith(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true}, repurgeOn(c),
		func(o *indexOpts) { o.RepurgeDelay = -1 })
	s.caughtUp("matches")
	must(w.c.Purge(ctx, "matches", "final", must(w.c.Head(ctx, "matches", "final")).ID, false))
	s.appliedUpTo(s.caughtUp("matches"))
	if q := s.ix.QueuedRepurges(); len(q) != 0 {
		t.Errorf("queued %v", q)
	}
	c.Advance(time.Hour)
	if n, err := s.ix.Repurge(ctx); err != nil || n != 0 {
		t.Errorf("sent %d second purges (%v)", n, err)
	}
	if got := s.purgesSoFar(); got != "[[r:matches/final idx:matches:counts]]" {
		t.Errorf("purges %s", got)
	}
}
