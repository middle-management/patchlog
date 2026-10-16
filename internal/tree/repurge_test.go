package tree_test

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/tree"
)

// clock is a tree service's own clock in these tests; the core keeps its
// own.
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

// repurgeOn sends second purges a minute of now after the first, looking
// every millisecond.
func repurgeOn(now func() time.Time) func(*tree.Options) {
	return func(o *tree.Options) {
		o.Now, o.RepurgeDelay, o.RepurgeInterval = now, time.Minute, time.Millisecond
	}
}

func (s *svc) purgesSoFar() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprint(s.purges)
}

// TestRepurge (D.8, as the core's second purge): a purge's cache tags are
// sent at once, after the apply commits, and once more RepurgeDelay later,
// from a queue the apply's transaction wrote, so that a listing read
// before the commit and handed to the CDN after the first purge doesn't
// stay there. Applies that purge nothing queue nothing.
func TestRepurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	c := newClock()
	x := startSvc(t, w.c, svcOpts{}, repurgeOn(c.Now))
	x.caughtUp("cat", "matches")

	// A tombstone and a move purge nothing, so nothing is sent twice.
	w.del(t, "matches", "opener")
	w.replace(t, "cat", "season", "/parents", parents("derbies"))
	x.caughtUp("cat", "matches")
	if q := x.s.QueuedRepurges(); len(q) != 0 {
		t.Fatalf("queued without a purge: %v", q)
	}
	c.Advance(time.Hour)
	if n, err := x.s.Repurge(ctx); err != nil || n != 0 {
		t.Fatalf("sent %d second purges without a purge (%v)", n, err)
	}

	// A purge: once at once, queued with the commit; the clock hasn't
	// reached its due time, so the loop sends nothing more.
	must(w.c.Purge(ctx, "matches", "derby", must(w.c.Head(ctx, "matches", "derby")).ID, false))
	x.caughtUp("matches")
	const once = "[[r:matches/derby rs:cat]]"
	if got := x.purgesSoFar(); got != once {
		t.Fatalf("purges %s, want %s", got, once)
	}
	if q := x.s.QueuedRepurges(); !reflect.DeepEqual(q, [][]string{{"r:matches/derby", "rs:cat"}}) {
		t.Fatalf("queued %v", q)
	}
	c.Advance(time.Minute - time.Millisecond)
	if n, err := x.s.Repurge(ctx); err != nil || n != 0 {
		t.Fatalf("sent %d second purges before they were due (%v)", n, err)
	}
	if got := x.purgesSoFar(); got != once {
		t.Fatalf("purges before the delay %s, want %s", got, once)
	}
	// Once more after the delay, by the loop, and then never again.
	c.Advance(time.Millisecond)
	waitFor(t, "the second purge", func() bool { return len(x.s.QueuedRepurges()) == 0 })
	if got, want := x.purgesSoFar(), "[[r:matches/derby rs:cat] [r:matches/derby rs:cat]]"; got != want {
		t.Errorf("purges %s, want %s", got, want)
	}
	c.Advance(time.Hour)
	if n, err := x.s.Repurge(ctx); err != nil || n != 0 {
		t.Errorf("sent %d more (%v)", n, err)
	}
}

// TestRepurgeAfterRestart: the second purge of a purge-ns survives the
// service stopping before it is due, and the next start sends it.
func TestRepurgeAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	c := newClock()
	o := svcOpts{db: filepath.Join(t.TempDir(), "tree.db")}
	x := startSvc(t, w.c, o, repurgeOn(c.Now))
	x.caughtUp("cat", "matches")
	must(w.c.PatchConfig(ctx, "matches", must(w.c.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.c.PurgeNamespace(ctx, "matches", must(w.c.NSHead(ctx, "matches")).ID))
	waitFor(t, "the purge-ns", func() bool { return x.s.Checkpoint("matches") == purged })
	const once = "[[ns:matches rs:cat]]"
	if got := x.purgesSoFar(); got != once {
		t.Fatalf("purges %s, want %s", got, once)
	}
	x.stop()

	y := startSvc(t, w.c, o, repurgeOn(c.Now))
	if q := y.s.QueuedRepurges(); !reflect.DeepEqual(q, [][]string{{"ns:matches", "rs:cat"}}) {
		t.Fatalf("queued after the restart %v", q)
	}
	c.Advance(time.Minute)
	waitFor(t, "the second purge after the restart", func() bool { return len(y.s.QueuedRepurges()) == 0 })
	if got := y.purgesSoFar(); got != once {
		t.Errorf("purges after the restart %s, want %s", got, once)
	}
	if got := x.purgesSoFar(); got != once {
		t.Errorf("the stopped service purged %s", got)
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
	x := startSvc(t, w.c, svcOpts{}, repurgeOn(c.Now), func(o *tree.Options) { o.RepurgeDelay = -1 })
	x.caughtUp("cat", "matches")
	must(w.c.Purge(ctx, "matches", "derby", must(w.c.Head(ctx, "matches", "derby")).ID, false))
	x.caughtUp("matches")
	if q := x.s.QueuedRepurges(); len(q) != 0 {
		t.Errorf("queued %v", q)
	}
	c.Advance(time.Hour)
	if n, err := x.s.Repurge(ctx); err != nil || n != 0 {
		t.Errorf("sent %d second purges (%v)", n, err)
	}
	if got := x.purgesSoFar(); got != "[[r:matches/derby rs:cat]]" {
		t.Errorf("purges %s", got)
	}
}
