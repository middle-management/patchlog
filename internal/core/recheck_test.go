package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

// isConflict recognises the UNIQUE violations D.3 names as a lost race, and
// nothing else.
func TestIsConflict(t *testing.T) {
	e, err := Open(Options{Path: ":memory:", AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	mustExec := func(q string, args ...any) {
		if _, err := e.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO authors (author, name) VALUES (1, 'a')`)
	mustExec(`INSERT INTO namespaces (ns, name) VALUES (1, 'n')`)
	mustExec(`INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created) VALUES (1, x'01', NULL, 3, '{}', 1, 1, 0)`)
	_, err = e.db.ExecContext(ctx, `INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created) VALUES (1, x'02', NULL, 3, '{}', 1, 1, 0)`)
	if err == nil || !isConflict(panicErr(err)) {
		t.Fatalf("namespace chain fork: %v", err)
	}
	mustExec(`INSERT INTO resources (res, ns, name) VALUES (1, 1, 'r')`)
	mustExec(`INSERT INTO revisions (res, id, parent_seq, first, kind, author, created) VALUES (1, x'03', NULL, 1, 0, 1, 0)`)
	mustExec(`INSERT INTO revisions (res, id, parent_seq, first, kind, author, created) VALUES (1, x'04', 1, 0, 0, 1, 0)`)
	_, err = e.db.ExecContext(ctx, `INSERT INTO revisions (res, id, parent_seq, first, kind, author, created) VALUES (1, x'05', 1, 0, 0, 1, 0)`)
	if err == nil || !isConflict(err) {
		t.Fatalf("resource chain fork: %v", err)
	}
	_, err = e.db.ExecContext(ctx, `INSERT INTO namespaces (ns, name) VALUES (2, 'n')`)
	if err == nil || isConflict(err) {
		t.Fatalf("a taken namespace name is not a write race: %v", err)
	}
}

// A transaction whose context is cancelled mid-way reports the cancellation,
// not the sql.ErrTxDone its later statements hit.
func TestCancelledTxReportsContextError(t *testing.T) {
	e, err := Open(Options{Path: ":memory:", AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
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
