package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// isConflict recognises the UNIQUE violations D.3 names as a lost race, and
// nothing else.
func TestIsConflict(t *testing.T) {
	t.Parallel()
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
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
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
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
