package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// isConflict recognises the UNIQUE violations D.3 names as a lost race, and
// nothing else.
func TestIsConflict(t *testing.T) {
	t.Parallel()
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	exec := func(q string, args ...any) error {
		if e.pg {
			q = rebind(q)
		}
		_, err := e.db.ExecContext(ctx, q, args...)
		return err
	}
	mustExec := func(q string, args ...any) {
		if err := exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	id := func(b byte) []byte { x := make([]byte, 20); x[0] = b; return x }
	mustExec(`INSERT INTO authors (author, name) VALUES (1, 'a')`)
	mustExec(`INSERT INTO namespaces (ns, name) VALUES (1, 'n')`)
	mustExec(`INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created) VALUES (1, ?, NULL, 3, '{}', 1, 1, 0)`, id(1))
	err = exec(`INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created) VALUES (1, ?, NULL, 3, '{}', 1, 1, 0)`, id(2))
	if err == nil || !isConflict(panicErr(err)) {
		t.Fatalf("namespace chain fork: %v", err)
	}
	mustExec(`INSERT INTO resources (res, ns, name) VALUES (1, 1, 'r')`)
	mustExec(`INSERT INTO revisions (seq, res, id, parent_seq, first, kind, author, created) VALUES (1, 1, ?, NULL, 1, 0, 1, 0)`, id(3))
	mustExec(`INSERT INTO revisions (seq, res, id, parent_seq, first, kind, author, created) VALUES (2, 1, ?, 1, 0, 0, 1, 0)`, id(4))
	err = exec(`INSERT INTO revisions (seq, res, id, parent_seq, first, kind, author, created) VALUES (3, 1, ?, 1, 0, 0, 1, 0)`, id(5))
	if err == nil || !isConflict(err) {
		t.Fatalf("resource chain fork: %v", err)
	}
	err = exec(`INSERT INTO namespaces (ns, name) VALUES (2, 'n')`)
	if err == nil || isConflict(err) {
		t.Fatalf("a taken namespace name is not a write race: %v", err)
	}
}

// A transaction whose context is cancelled mid-way reports the cancellation,
// not the sql.ErrTxDone its later statements hit.
func TestCancelledTxReportsContextError(t *testing.T) {
	t.Parallel()
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for name, run := range map[string]func(context.Context, func(*tx) error) error{
		"read":   e.read,
		"update": e.update,
	} {
		ctx, cancel := context.WithCancel(context.Background())
		err := run(ctx, func(t *tx) error {
			cancel()
			// database/sql rolls back from a goroutine watching ctx; wait
			// for it.
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := t.ExecContext(context.Background(), `SELECT 1`); err != nil {
					return err
				}
				time.Sleep(time.Millisecond)
			}
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A write whose context is cancelled before it commits rolls back, also
// while database/sql's transaction context, derived from it, isn't
// cancelled yet: context.WithCancel cancels a derived context only after
// closing its parent's Done, and Commit checks the derived one. A graceful
// shutdown's timeout cancels writes so (lifecycle); the server's
// TestShutdownTimeoutRollsBackWrite, whose write waits right before its
// commit for the cancellation, found it committed when load stretched that
// window.
func TestCancelledWriteRollsBack(t *testing.T) {
	t.Parallel()
	var hold atomic.Bool
	inside := make(chan struct{})
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		BeforeCommit: func(ctx context.Context) {
			if hold.CompareAndSwap(true, false) {
				close(inside)
				<-ctx.Done()
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	head, err := put(e, "n", "x", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newLagCtx()
	defer ctx.release()
	lags := ctx.lags(t)
	hold.Store(true)
	go func() {
		<-inside
		ctx.cancel()
	}()
	r := who
	r.NS = "n"
	res, err := e.WriteResource(ctx, r, Item{Resource: "x", IfMatch: head,
		Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}}}}})
	lags()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %+v, %v", res, err)
	}
	if strings.Count(err.Error(), context.Canceled.Error()) != 1 {
		t.Fatalf("cancelled write: %q, want the cancellation reported once", err)
	}
	if h := headOf(t, e, "n", "x"); h != head {
		t.Fatalf("the cancelled write committed: head %s, want %s", h, head)
	}
}

// lagCtx is a context whose cancellation reaches the contexts derived from
// it only at release (context.WithCancel registers a child of a parent with
// an AfterFunc method through that method): it holds open the window a
// context.WithCancel context has between closing its Done and cancelling
// its children.
type lagCtx struct {
	context.Context
	done chan struct{}

	mu       sync.Mutex
	err      error
	after    map[int]func()
	next     int
	released bool
}

func newLagCtx() *lagCtx {
	return &lagCtx{Context: context.Background(), done: make(chan struct{}), after: map[int]func(){}}
}

func (c *lagCtx) Done() <-chan struct{} { return c.done }

func (c *lagCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// AfterFunc runs f at release, or at once in its own goroutine once
// released.
func (c *lagCtx) AfterFunc(f func()) (stop func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		go f()
		return func() bool { return false }
	}
	i := c.next
	c.next++
	c.after[i] = f
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, ok := c.after[i]
		delete(c.after, i)
		return ok
	}
}

// cancel cancels c, but not yet the contexts derived from it.
func (c *lagCtx) cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = context.Canceled
	close(c.done)
}

// lags returns a check, for once c is cancelled and before it is
// released, that what is derived from c (context.WithCancel and
// context.AfterFunc) doesn't know of the cancellation yet. If context ever
// stopped registering children through an AfterFunc method, they would
// learn of it at once, and the tests using lagCtx would pass without the
// window they hold open.
func (c *lagCtx) lags(t *testing.T) func() {
	child, stop := context.WithCancel(c)
	var ran atomic.Bool
	stopAfter := context.AfterFunc(c, func() { ran.Store(true) })
	t.Cleanup(func() {
		stop()
		stopAfter()
	})
	return func() {
		t.Helper()
		if c.Err() == nil {
			t.Fatal("lagCtx isn't cancelled")
		}
		select {
		case <-child.Done():
			t.Fatal("a context derived from a lagCtx learnt of its cancellation before release")
		default:
		}
		if ran.Load() {
			t.Fatal("a context.AfterFunc of a lagCtx ran before release")
		}
	}
}

// release lets a cancellation reach the derived contexts.
func (c *lagCtx) release() {
	c.mu.Lock()
	if c.err == nil || c.released {
		c.mu.Unlock()
		return
	}
	after := c.after
	c.after, c.released = nil, true
	c.mu.Unlock()
	for _, f := range after {
		f()
	}
}
