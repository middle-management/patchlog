package dbmigrate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
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

// The core's Spanner migrations apply to an empty database through
// PGAdapter (PATCHLOG_TEST_SPANNER, e.g. postgres://x@127.0.0.1:5432/
// any?sslmode=disable; the database named is replaced by a new one), and
// a second run finds everything applied.
func TestMigrateSpanner(t *testing.T) {
	raw := os.Getenv("PATCHLOG_TEST_SPANNER")
	if raw == "" {
		t.Skip("PATCHLOG_TEST_SPANNER is not set")
	}
	u, err := url.Parse(strings.Replace(raw, "spanner+postgres://", "postgres://", 1))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	rand.Read(b)
	u.Path = "/plmig_" + hex.EncodeToString(b)
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := MigrateSpanner(ctx, db, os.DirFS("../core"), "patchlog"); err != nil {
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
}
