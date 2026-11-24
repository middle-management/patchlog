package core

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A base's live branches are counted by the frozen and purged columns
// (liveBranches): a branch created frozen has the column set, as one frozen
// later, and doesn't count against branchesPerNamespace (§6.6); the rows
// created frozen before the column was written at creation are set by the
// namespaces_frozen migration.
func TestLiveBranchesFrozenColumn(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public", "limits": map[string]any{"branchesPerNamespace": 2.0}})
	branch := func(name string, frozen bool) error {
		r := who
		r.NS = "n"
		br := BranchRequest{Name: name, IfNoneMatch: true}
		if frozen {
			br.Patches = []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}
		}
		_, err := e.CreateBranch(ctx, r, br)
		return err
	}
	for _, b := range []struct {
		name   string
		frozen bool
	}{{"f1", true}, {"l1", false}, {"f2", true}, {"l2", false}} {
		if err := branch(b.name, b.frozen); err != nil {
			t.Fatalf("branch %s: %v", b.name, err)
		}
	}
	if err := branch("l3", false); status(err) != 422 {
		t.Fatalf("a third live branch: %v, want 422", err)
	}
	frozen := func() string {
		t.Helper()
		var out []string
		if err := e.read(ctx, func(t *tx) error {
			rows, err := t.Query(`SELECT name FROM namespaces WHERE frozen <> 0 ORDER BY name`)
			t.must(err)
			defer rows.Close()
			for rows.Next() {
				var s string
				t.must(rows.Scan(&s))
				out = append(out, s)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return strings.Join(out, " ")
	}
	if got := frozen(); got != "f1 f2" {
		t.Fatalf("frozen column set for %q, want f1 f2", got)
	}
	// The rows as they were written before: the migration sets them.
	if pgtest.Spanner() {
		return // Spanner's baseline has the column from the start
	}
	dialect := "sqlite"
	if pgtest.Enabled() {
		dialect = "postgres"
	}
	files, err := fs.Glob(migrations, "migrations/"+dialect+"/*_namespaces_frozen.sql")
	if err != nil || len(files) != 1 {
		t.Fatalf("the namespaces_frozen migration: %v, %v", files, err)
	}
	sqlText, err := fs.ReadFile(migrations, files[0])
	if err != nil {
		t.Fatal(err)
	}
	stmt := string(sqlText)
	stmt = stmt[strings.Index(stmt, "UPDATE namespaces"):]
	stmt = stmt[:strings.Index(stmt, ";")]
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE namespaces SET frozen = 0`)
		t.must(err)
		_, err = t.Tx.Exec(stmt)
		t.must(err)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := frozen(); got != "f1 f2" {
		t.Fatalf("frozen column after the migration set for %q, want f1 f2", got)
	}
}
