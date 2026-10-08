package index

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
)

var schemaAt_0f182dd = []string{
	`CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS ns_state (ns TEXT PRIMARY KEY, purged INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS docs (docid INTEGER PRIMARY KEY, ns TEXT NOT NULL, resource TEXT NOT NULL, head TEXT NOT NULL, schema TEXT, UNIQUE (ns, resource))`,
	`CREATE TABLE IF NOT EXISTS facet (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value TEXT NOT NULL, raw TEXT NOT NULL, PRIMARY KEY (ns, resource, path, value))`,
	`CREATE TABLE IF NOT EXISTS "sort" (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value, PRIMARY KEY (ns, resource, path))`,
	`CREATE INDEX IF NOT EXISTS docs_q ON docs (ns, schema)`,
	`CREATE INDEX IF NOT EXISTS facet_q ON facet (ns, path, value)`,
	`CREATE INDEX IF NOT EXISTS sort_q ON "sort" (ns, path, value)`,
}

var schemaAt_8e09906 = []string{
	`CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS ns_state (ns TEXT PRIMARY KEY, purged INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS docs (docid INTEGER PRIMARY KEY, ns TEXT NOT NULL, resource TEXT NOT NULL, head TEXT NOT NULL, schema TEXT, UNIQUE (ns, resource))`,
	`CREATE TABLE IF NOT EXISTS facet (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value TEXT NOT NULL, raw TEXT NOT NULL, PRIMARY KEY (ns, resource, path, value))`,
	`CREATE TABLE IF NOT EXISTS "sort" (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value, PRIMARY KEY (ns, resource, path))`,
	`CREATE TABLE IF NOT EXISTS refs (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, ref TEXT NOT NULL, target_ns TEXT NOT NULL, target TEXT NOT NULL, rev TEXT, entry TEXT, PRIMARY KEY (ns, resource, path))`,
	`CREATE INDEX IF NOT EXISTS docs_q ON docs (ns, schema)`,
	`CREATE INDEX IF NOT EXISTS refs_q ON refs (target_ns, target, rev, entry)`,
	`CREATE INDEX IF NOT EXISTS facet_q ON facet (ns, path, value)`,
	`CREATE INDEX IF NOT EXISTS sort_q ON "sort" (ns, path, value)`,
}

var schemaAt_596f067 = []string{
	`CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS ns_state (ns TEXT PRIMARY KEY, purged INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS docs (docid INTEGER PRIMARY KEY, ns TEXT NOT NULL, resource TEXT NOT NULL, head TEXT NOT NULL, schema TEXT, UNIQUE (ns, resource))`,
	`CREATE TABLE IF NOT EXISTS facet (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value TEXT NOT NULL, raw TEXT NOT NULL, PRIMARY KEY (ns, resource, path, value))`,
	`CREATE TABLE IF NOT EXISTS "sort" (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value, raw TEXT, PRIMARY KEY (ns, resource, path))`,
	`CREATE TABLE IF NOT EXISTS refs (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, ref TEXT NOT NULL, target_ns TEXT NOT NULL, target TEXT NOT NULL, rev TEXT, entry TEXT, PRIMARY KEY (ns, resource, path))`,
	`CREATE INDEX IF NOT EXISTS docs_q ON docs (ns, schema)`,
	`CREATE INDEX IF NOT EXISTS refs_q ON refs (target_ns, target, rev, entry)`,
	`CREATE INDEX IF NOT EXISTS facet_q ON facet (ns, path, value)`,
	`CREATE INDEX IF NOT EXISTS sort_q ON "sort" (ns, path, value)`,
}

// TestOldSchemasIndexedBy opens databases created by each earlier schema
// with the current initSchema and runs driven queries: query.go names the
// tables' indexes, their primary keys' autoindexes included, in INDEXED BY,
// and a missing one fails the query.
func TestOldSchemasIndexedBy(t *testing.T) {
	t.Parallel()
	for name, stmts := range map[string][]string{"0f182dd": schemaAt_0f182dd, "8e09906": schemaAt_8e09906, "596f067": schemaAt_596f067} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "i.db")
			db, err := sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range append(stmts, ftsCreate) {
				if _, err := db.Exec(s); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`INSERT INTO docs (ns, resource, head, schema) VALUES ('a', 'r1', 'h', 's')`); err != nil {
				t.Fatal(err)
			}
			db.Close()
			db, err = sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ix := &Index{opt: Options{Logf: t.Logf}, db: db, cps: follow.SQLCheckpoints{DB: db}, sealed: derived.NewCache(0, db)}
			if err := ix.initSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
			rows, err := db.Query(`SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' ORDER BY name`)
			if err != nil {
				t.Fatal(err)
			}
			have := map[string]bool{}
			for rows.Next() {
				var n, tb string
				rows.Scan(&n, &tb)
				have[n] = true
				t.Logf("index %s on %s", n, tb)
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
		})
	}
}
