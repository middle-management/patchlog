package core

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// Intermediate snapshots (D.4) fall every SnapshotEveryRevisions patch
// sets, counted on the resource row by step 7, across the steps of a batch
// item too, and counted from the revisions again when the row doesn't have
// the counts (a database from before them). A genesis that adds the whole
// document is a snapshot of it: the count starts after it, and a document
// read there is cut from it.
func TestSnapshotCounts(t *testing.T) {
	t.Parallel()
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
	want("a", 4, 7)
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
	want("a", 4, 7, 10)

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
	want("b", 4, 7)
	want("c")
	// Read at its genesis, a document is the genesis's value.
	var doc []byte
	if err := e.read(ctx, func(t *tx) error {
		e.docs.flush()
		var err error
		doc, err = t.docBytesAt(t.rev(t.resource(t.nsByName("n").id, "c").headSeq.Int64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if string(doc) != `{"n":0}` {
		t.Fatalf("c at its genesis: %s", doc)
	}
}

// A whole-document genesis is its own snapshot (D.4): a create stores its
// document once, in its patch set, with no heads row, and a read cuts it
// from there; the head moving on writes a heads row again.
func TestGenesisHead(t *testing.T) {
	t.Parallel()
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	ctx := context.Background()
	headRow := func(name string) bool {
		t.Helper()
		var n int
		if err := e.read(ctx, func(t *tx) error {
			return t.QueryRow(`SELECT COUNT(*) FROM heads h JOIN resources r ON r.res = h.res WHERE r.name = ?`, name).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	docAt := func(name, id string) string {
		t.Helper()
		e.FlushCaches()
		rev, err := e.ResourceRev(ctx, "n", name, id, Credentials{})
		if err != nil {
			t.Fatal(err)
		}
		return string(rev.Doc)
	}
	a0, err := put(e, "n", "a", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if headRow("a") || docAt("a", a0) != `{"n":0}` {
		t.Fatalf("a created: heads row %v, document %s", headRow("a"), docAt("a", a0))
	}
	a1, err := put(e, "n", "a", a0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !headRow("a") || docAt("a", a1) != `{"n":1}` || docAt("a", a0) != `{"n":0}` {
		t.Fatal("a appended")
	}
	// A create and a delete in one item: the tombstone's document is the
	// genesis's.
	r := who
	r.NS = "n"
	res, err := e.Batch(ctx, r, []Item{{Resource: "b", IfNoneMatch: true, Steps: []Step{
		{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"s": "x\"]}"}}}}, {Delete: true}}}}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if headRow("b") || docAt("b", res.Items[0].IDs[0]) != `{"s":"x\"]}"}` {
		t.Fatalf("b: heads row %v", headRow("b"))
	}
}

// valueEnd finds the end of the value a canonical whole-document genesis
// adds as json.Valid would tell it: a patch set with anything after the
// value, another op or member, is not a whole document.
func FuzzWholeDocument(f *testing.F) {
	for _, s := range []string{`{"a":[1,{"b":"]}"}]}`, `"x\\\"}]"`, `1`, `null`, `[]`, `{}`, `"\\\\"`, `{"a":"é"}`} {
		f.Add(`[{"op":"add","path":"","value":` + s + `}]`)
		f.Add(`[{"op":"add","path":"","value":` + s + `},{"op":"add","path":"/z","value":` + s + `}]`)
		f.Add(`[{"op":"add","path":"","value":` + s + `,"x":1}]`)
	}
	f.Fuzz(func(t *testing.T, in string) {
		v, err := jsonv.Parse([]byte(in))
		if err != nil {
			return
		}
		canon := jsonv.Canonical(v)
		want := []byte(nil)
		if bytes.HasPrefix(canon, genesisPrefix) && bytes.HasSuffix(canon, []byte("}]")) {
			if v := canon[len(genesisPrefix) : len(canon)-2]; json.Valid(v) {
				want = v
			}
		}
		if got := wholeDocument(canon); !bytes.Equal(got, want) || (got == nil) != (want == nil) {
			t.Fatalf("%s: %q, want %q", canon, got, want)
		}
	})
}
