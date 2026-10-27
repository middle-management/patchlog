package dbmigrate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/middle-management/mmmigrate/source"
)

// Every package's committed migrations are unchanged since they were
// committed (their checksums and chain hold), and, in CI, current.sql holds
// nothing left to commit: a migration tests apply but deployments wouldn't.
func TestMigrations(t *testing.T) {
	dirs, err := filepath.Glob("../*/migrations/*/current.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no migrations found")
	}
	for _, f := range dirs {
		dir := filepath.Dir(f)
		if err := source.ValidateChain(dir); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
		if os.Getenv("CI") != "" {
			if err := source.CheckDirtyCurrent(dir); err != nil {
				t.Errorf("%s: %v (make migration)", dir, err)
			}
		}
	}
}

// Migrate runs the directory of db's dialect and then its seed, and
// refuses a database whose dialect has none rather than run another's SQL
// on it.
func TestMigrateDialect(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	fsys := fstest.MapFS{
		"migrations/sqlite/001_a.sql":   {Data: []byte(`CREATE TABLE a (x INTEGER PRIMARY KEY);`)},
		"migrations/postgres/001_b.sql": {Data: []byte(`CREATE TABLE b (x bigint);`)},
		"migrations/seed/sqlite.sql":    {Data: []byte(`INSERT INTO a (x) VALUES (1) ON CONFLICT DO NOTHING;`)},
	}
	// Twice: the seed runs every time, and once emptied, puts its row back.
	if err := Migrate(ctx, db, fsys, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM a`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, fsys, "test"); err != nil {
		t.Fatal(err)
	}
	var seeded int
	if err := db.QueryRow(`SELECT count(*) FROM a`).Scan(&seeded); err != nil || seeded != 1 {
		t.Fatalf("seeded rows %d (%v), want 1", seeded, err)
	}
	var tables []string
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('a', 'b')`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	if len(tables) != 1 || tables[0] != "a" {
		t.Fatalf("tables %v, want [a]", tables)
	}
	pgOnly := fstest.MapFS{"migrations/postgres/001_b.sql": {Data: []byte(`CREATE TABLE b (x bigint);`)}}
	if err := Migrate(ctx, db, pgOnly, "other"); err == nil || !strings.Contains(err.Error(), "no sqlite migrations") {
		t.Fatalf("postgres-only migrations on SQLite: %v", err)
	}
}
