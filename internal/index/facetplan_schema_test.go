package index

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// TestSchemaIndexedBy opens a database with initSchema and runs driven
// queries: query.go names the tables' indexes, their primary keys'
// autoindexes included, in INDEXED BY, and a missing one fails the query.
func TestSchemaIndexedBy(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(filepath.Join(t.TempDir(), "i.db"), ""))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ix := &Index{opt: Options{Logf: t.Logf}, db: db, cps: follow.SQLCheckpoints{DB: db}, sealed: derived.NewCache(0, db)}
	if err := ix.initSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO docs (ns, resource, head, schema) VALUES ('a', 'r1', 'h', 's')`); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'index'`)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var n string
		rows.Scan(&n)
		have[n] = true
	}
	rows.Close()
	for _, n := range []string{"sqlite_autoindex_facet_1", "sqlite_autoindex_sort_1", "sqlite_autoindex_refs_1", "facet_q", "sort_q", "refs_t"} {
		if !have[n] {
			t.Errorf("missing %s", n)
		}
	}
	ctx := context.Background()
	for _, s := range []string{"facet[/a]=x&ref=/r/t/one&ge[/s]=1&counts=/a", "facet[/a]=x&facet[/b]=y&lt[/t]=b"} {
		v, _ := url.ParseQuery(s)
		q, err := ParseQuery(v)
		if err != nil {
			t.Fatal(err)
		}
		tx, _ := db.BeginTx(ctx, nil)
		fs := q.filters()
		for d := -1; d < len(fs); d++ {
			stmt, args := ix.candidateSQL("a", q, fs, d)
			if _, err := tx.Exec(stmt, args...); err != nil {
				t.Errorf("%s driven by %d: %v", s, d, err)
			}
		}
		if _, err := ix.run(ctx, tx, "a", q, nil); err != nil {
			t.Errorf("%s: %v", s, err)
		}
		if _, err := ix.counts(ctx, tx, "a", []string{"/a"}, nil); err != nil {
			t.Errorf("counts: %v", err)
		}
		tx.Rollback()
	}
}
