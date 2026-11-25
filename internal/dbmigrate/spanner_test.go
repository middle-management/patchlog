package dbmigrate

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

func TestSplitSQL(t *testing.T) {
	got := splitSQL(`-- a comment; not a statement
CREATE TABLE a (x text DEFAULT ';'); /* b; */ INSERT INTO a VALUES ($1, 'it''s');
DO $f$ BEGIN; END $f$;
`)
	want := []string{
		`CREATE TABLE a (x text DEFAULT ';')`,
		`INSERT INTO a VALUES ($1, 'it''s')`,
		`DO $f$ BEGIN; END $f$`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The core's Spanner migrations apply to an empty database
// (PATCHLOG_TEST_SPANNER, pgtest.SpannerEnv), and a second run finds
// everything applied.
func TestMigrateSpanner(t *testing.T) {
	if !pgtest.Spanner() {
		t.Skip(pgtest.SpannerEnv + " is not set")
	}
	db := pgtest.Open(t, pgtest.FreshDB(t))
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db, os.DirFS("../core"), "patchlog"); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ns_log'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ns_log: %d, %v", n, err)
	}
	if err := db.QueryRow(`SELECT gen FROM cache_gen WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Migration 003 dropped every foreign key.
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.table_constraints WHERE constraint_type = 'FOREIGN KEY'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("foreign keys left: %d, %v", n, err)
	}
}
