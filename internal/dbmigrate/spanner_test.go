package dbmigrate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// spannerDB opens a new database on the PGAdapter of PATCHLOG_TEST_SPANNER
// (e.g. postgres://x@127.0.0.1:5432/any?sslmode=disable; the database named
// is replaced by a new one, which the emulator's PGAdapter creates).
func spannerDB(t *testing.T) *sql.DB {
	t.Helper()
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
	t.Cleanup(func() { db.Close() })
	return db
}

// The core's Spanner migrations apply to an empty database with mmmigrate's
// Spanner dialect, which Migrate picks for a pgx connection to Spanner, and
// a second run finds everything applied.
func TestMigrateSpanner(t *testing.T) {
	db := spannerDB(t)
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
	// Recorded by mmmigrate: its own migrations too, and the core's in the
	// namespace patchlog (no @schema, as on SQLite).
	if err := db.QueryRow(`SELECT count(*) FROM mmmigrate_applied WHERE namespace = '_mmmigrate'`).Scan(&n); err != nil || n < 1 {
		t.Fatalf("mmmigrate's own migrations: %d, %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM mmmigrate_applied WHERE namespace = 'patchlog' AND version = 1`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("baseline recorded: %d, %v", n, err)
	}
}

// Instances starting together on an empty database: one applies the
// migrations, under mmmigrate's lease, and all succeed.
func TestMigrateSpannerConcurrent(t *testing.T) {
	db := spannerDB(t)
	ctx := context.Background()
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() { errs <- Migrate(ctx, db, os.DirFS("../core"), "patchlog") }()
	}
	for i := 0; i < 3; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM mmmigrate_applied WHERE namespace = 'patchlog'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("baseline recorded %d times (%v)", n, err)
	}
}

// A database the earlier runner (MigrateSpanner) migrated, with its own
// mmmigrate_applied and mmmigrate_current, is adopted: its records move to
// mmmigrate's tables and the migrations they record don't run again (001
// here would fail if it did: its table exists).
func TestMigrateSpannerAdoptsLegacy(t *testing.T) {
	db := spannerDB(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	for _, q := range []string{
		// The earlier runner's tables, as it created them.
		`CREATE TABLE IF NOT EXISTS mmmigrate_applied (namespace text NOT NULL, version bigint NOT NULL, name text NOT NULL, applied_at bigint NOT NULL, PRIMARY KEY (namespace, version))`,
		`CREATE TABLE IF NOT EXISTS mmmigrate_current (namespace text NOT NULL PRIMARY KEY, checksum text NOT NULL, applied_at bigint NOT NULL)`,
		// What its migration 001 created.
		`CREATE TABLE t (id bigint PRIMARY KEY)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO mmmigrate_applied (namespace, version, name, applied_at) VALUES ('patchlog', 1, 't', $1)`, at.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mmmigrate_current (namespace, checksum, applied_at) VALUES ('patchlog', 'abc', $1)`, at.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"migrations/spanner/001_t.sql": {Data: []byte(`CREATE TABLE t (id bigint PRIMARY KEY);`)},
		"migrations/spanner/002_u.sql": {Data: []byte(`CREATE TABLE u (id bigint PRIMARY KEY);`)},
	}
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db, fsys, "patchlog"); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	var got time.Time
	if err := db.QueryRow(`SELECT applied_at FROM mmmigrate_applied WHERE namespace = 'patchlog' AND version = 1`).Scan(&got); err != nil || !got.Equal(at) {
		t.Fatalf("001's record: %v (%v), want applied at %v", got, err, at)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM mmmigrate_applied WHERE namespace = 'patchlog'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("records: %d (%v), want 001 adopted and 002 applied", n, err)
	}
	var sum string
	if err := db.QueryRow(`SELECT checksum FROM mmmigrate_current WHERE namespace = 'patchlog'`).Scan(&sum); err != nil || sum != "abc" {
		t.Fatalf("current.sql's checksum: %q (%v)", sum, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('u', '` + legacyStash + `')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("u and no stash: %d tables (%v)", n, err)
	}
}

// A run that died after stashing the earlier runner's records and dropping
// its tables leaves the stash; the next run finishes the adoption.
func TestMigrateSpannerAdoptsStash(t *testing.T) {
	db := spannerDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE ` + legacyStash + ` (kind varchar NOT NULL, namespace varchar NOT NULL, version bigint NOT NULL, name varchar NOT NULL, applied_at bigint NOT NULL, PRIMARY KEY (kind, namespace, version))`,
		`CREATE TABLE t (id bigint PRIMARY KEY)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO `+legacyStash+` (kind, namespace, version, name, applied_at) VALUES ('applied', 'patchlog', 1, 't', $1)`, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"migrations/spanner/001_t.sql": {Data: []byte(`CREATE TABLE t (id bigint PRIMARY KEY);`)}}
	if err := Migrate(ctx, db, fsys, "patchlog"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name = '` + legacyStash + `'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stash left: %d (%v)", n, err)
	}
}

// Spanner doesn't apply a DDL batch atomically: a run that died while
// dropping the earlier runner's tables may leave only one of them. The next
// run adopts what is left.
func TestMigrateSpannerAdoptsPartialLegacy(t *testing.T) {
	db := spannerDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS mmmigrate_current (namespace text NOT NULL PRIMARY KEY, checksum text NOT NULL, applied_at bigint NOT NULL)`,
		`CREATE TABLE ` + legacyStash + ` (kind varchar NOT NULL, namespace varchar NOT NULL, version bigint NOT NULL, name varchar NOT NULL, applied_at bigint NOT NULL, PRIMARY KEY (kind, namespace, version))`,
		`CREATE TABLE t (id bigint PRIMARY KEY)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO `+legacyStash+` (kind, namespace, version, name, applied_at) VALUES ('applied', 'patchlog', 1, 't', $1)`, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"migrations/spanner/001_t.sql": {Data: []byte(`CREATE TABLE t (id bigint PRIMARY KEY);`)}}
	if err := Migrate(ctx, db, fsys, "patchlog"); err != nil {
		t.Fatal(err)
	}
	var typ string
	if err := db.QueryRow(`SELECT data_type FROM information_schema.columns WHERE table_name = 'mmmigrate_current' AND column_name = 'applied_at'`).Scan(&typ); err != nil || typ == "bigint" {
		t.Fatalf("mmmigrate_current.applied_at: %q (%v), want mmmigrate's", typ, err)
	}
}
