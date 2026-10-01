package core

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Intermediate snapshots (D.4) fall every SnapshotEveryRevisions patch
// sets, counted on the resource row by step 7, across the steps of a batch
// item too, and counted from the revisions again when the row doesn't have
// the counts (a database from before them).
func TestSnapshotCounts(t *testing.T) {
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Purger: discardPurger{}, HeadSnapshotMax: 8, SnapshotEveryRevisions: 3, SnapshotEveryBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	ctx := context.Background()
	// snapped lists, by position in name's chain (1 for its first
	// revision), the revisions with a snapshot.
	snapped := func(name string) []int {
		t.Helper()
		var out []int
		err := e.read(ctx, func(t *tx) error {
			rows, err := t.Query(`SELECT EXISTS (SELECT 1 FROM snapshots s WHERE s.seq = r.seq) FROM revisions r
				JOIN resources o ON o.res = r.res JOIN namespaces n ON n.ns = o.ns WHERE n.name = 'n' AND o.name = ? ORDER BY r.seq`, name)
			if err != nil {
				return err
			}
			defer rows.Close()
			for i := 1; rows.Next(); i++ {
				var has bool
				if err := rows.Scan(&has); err != nil {
					return err
				}
				if has {
					out = append(out, i)
				}
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := func(name string, positions ...int) {
		t.Helper()
		got := snapped(name)
		if len(got) != len(positions) {
			t.Fatalf("%s: snapshots at %v, want %v", name, got, positions)
		}
		for i := range got {
			if got[i] != positions[i] {
				t.Fatalf("%s: snapshots at %v, want %v", name, got, positions)
			}
		}
	}

	head, err := put(e, "n", "a", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 8; i++ {
		if head, err = put(e, "n", "a", head, i); err != nil {
			t.Fatal(err)
		}
	}
	want("a", 3, 6)
	// Counts unknown: counted from the revisions since the last snapshot.
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE resources SET snap_revs = NULL, snap_bytes = NULL`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := 8; i < 12; i++ {
		if head, err = put(e, "n", "a", head, i); err != nil {
			t.Fatal(err)
		}
	}
	want("a", 3, 6, 9, 12)

	// A batch item's steps, and its other item's single step.
	r := who
	r.NS = "n"
	step := func(n int) Step {
		return Step{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": float64(n)}}}}
	}
	replace := func(n int) Step {
		return Step{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": float64(n)}}}
	}
	if _, err := e.Batch(ctx, r, []Item{
		{Resource: "b", IfNoneMatch: true, Steps: []Step{step(0), replace(1), replace(2), replace(3), replace(4), replace(5), replace(6)}},
		{Resource: "c", IfNoneMatch: true, Steps: []Step{step(0)}},
	}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	want("b", 3, 6)
	want("c")
}
