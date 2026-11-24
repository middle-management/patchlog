package dbmigrate

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/middle-management/mmmigrate/source"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Every package's committed migrations (every directory under a
// migrations directory but seed: every dialect's) load as mmmigrate loads
// them at startup, so no two share a version (two branches that each
// committed the next number and were merged), are unchanged since they were
// committed (their checksums and chain hold), and, in CI, current.sql holds
// nothing left to commit: a migration tests apply but deployments wouldn't.
func TestMigrations(t *testing.T) {
	dirs, err := filepath.Glob("../*/migrations/*")
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no migrations found")
	}
	for _, dir := range dirs {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || filepath.Base(dir) == "seed" {
			continue
		}
		if _, err := source.LoadMigrations(os.DirFS(dir), false); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
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

// On Postgres, deployments in different schemas of one database (by
// search_path) each get their migrations, though mmmigrate keeps every
// schema's records in its own schema mmmigrate.
func TestMigratePostgresSchemas(t *testing.T) {
	if !pgtest.Enabled() || pgtest.Spanner() {
		t.Skip("Postgres only (" + pgtest.Env + ")")
	}
	ctx := context.Background()
	base := pgtest.FreshDB(t)
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`CREATE SCHEMA a; CREATE SCHEMA b`); err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"migrations/postgres/001_t.sql": {Data: []byte(`CREATE TABLE t (x bigint);`)}}
	for _, schema := range []string{"a", "b"} {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		db, err := sql.Open("pgx", u.String())
		if err != nil {
			t.Fatal(err)
		}
		err = Migrate(ctx, db, fsys, "test")
		db.Close()
		if err != nil {
			t.Fatalf("%s: %v", schema, err)
		}
	}
	var n int
	if err := admin.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name = 't' AND table_schema IN ('a', 'b')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("tables t in a and b: %d (%v), want 2", n, err)
	}
}

// A Postgres database migrated while two of the core's migrations were both
// numbered 030 upgrades. One that applied purge_follows_by_importer as 30 (the
// spec branches) gets rate_draws_batched as 31. One that applied
// rate_draws_batched as 30 (main between PR #39 and PR #37) is refused by
// mmmigrate, which would otherwise skip purge_follows_by_importer and run
// rate_draws_batched again, with an error saying to move the record; once
// it is moved (README, Schema migrations), it gets purge_follows_by_importer.
func TestMigrateRenumbered(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only (" + pgtest.Env + ")")
	}
	ctx := context.Background()
	dir := "../core/migrations/postgres"
	core := os.DirFS("../core")
	// The core's migrations as they were on each side: 001–029 and one 030.
	before := func(keep string) fstest.MapFS {
		fsys := fstest.MapFS{}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			v, _, err := source.ParseMigrationName(name)
			if err != nil || v > 31 {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case v < 30:
			case strings.Contains(name, keep):
				name = "030_" + strings.SplitN(name, "_", 2)[1]
			default:
				continue
			}
			fsys["migrations/postgres/"+name] = &fstest.MapFile{Data: data}
		}
		return fsys
	}
	for _, tc := range []struct{ applied, other string }{
		{"rate_draws_batched", "purge_follows_by_importer"},
		{"purge_follows_by_importer", "rate_draws_batched"},
	} {
		t.Run(tc.applied, func(t *testing.T) {
			db, err := sql.Open("pgx", pgtest.DSN(pgtest.FreshDB(t)))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := Migrate(ctx, db, before(tc.applied), "patchlog"); err != nil {
				t.Fatal(err)
			}
			if tc.applied == "rate_draws_batched" {
				err := Migrate(ctx, db, core, "patchlog")
				if err == nil || !strings.Contains(err.Error(), `version 30 is recorded as applied as "rate_draws_batched"`) ||
					!strings.Contains(err.Error(), `"rate_draws_batched" is now version 31`) {
					t.Fatalf("expected mmmigrate to refuse the record, got %v", err)
				}
				// The README's manual step.
				if _, err := db.Exec(`UPDATE mmmigrate.applied SET version = 31
					WHERE namespace LIKE 'patchlog@%' AND version = 30 AND name = 'rate_draws_batched'`); err != nil {
					t.Fatal(err)
				}
			}
			if err := Migrate(ctx, db, core, "patchlog"); err != nil {
				t.Fatal(err)
			}
			got := map[int]string{}
			rows, err := db.Query(`SELECT version, name FROM mmmigrate.applied WHERE namespace LIKE 'patchlog@%' AND version >= 30`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var v int
				var n string
				rows.Scan(&v, &n)
				got[v] = n
			}
			rows.Close()
			if got[30] != "purge_follows_by_importer" || got[31] != "rate_draws_batched" {
				t.Fatalf("applied 30, 31: %v", got)
			}
			// Both migrations' objects exist: importer is 030's column,
			// rate_draws 031's function.
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'purge_follow_names' AND column_name = 'importer'`).Scan(&n); err != nil || n != 1 {
				t.Errorf("purge_follow_names.importer: %d (%v)", n, err)
			}
			if err := db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname = 'rate_draws'`).Scan(&n); err != nil || n < 1 {
				t.Errorf("rate_draws: %d (%v)", n, err)
			}
		})
	}
}
