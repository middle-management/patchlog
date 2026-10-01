// Package pgtest lets tests run against Postgres (Addendum D.8) instead of
// an in-memory SQLite database: with PATCHLOG_TEST_PG set to a Postgres URL
// (e.g. postgres://postgres@127.0.0.1:5432/postgres), DB creates a fresh
// database per test there and drops it when the test ends.
package pgtest

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Env is the environment variable naming the Postgres server for tests.
const Env = "PATCHLOG_TEST_PG"

// Enabled reports whether tests run against Postgres.
func Enabled() bool { return os.Getenv(Env) != "" }

// DB returns the database path for a test's engine: ":memory:", or with
// PATCHLOG_TEST_PG set, the URL of a fresh Postgres database.
func DB(t testing.TB) string {
	t.Helper()
	if !Enabled() {
		return ":memory:"
	}
	return NewDB(t)
}

// NewDB creates a fresh Postgres database, dropped when the test ends, and
// returns its URL. It skips the test if PATCHLOG_TEST_PG isn't set.
func NewDB(t testing.TB) string {
	t.Helper()
	admin := os.Getenv(Env)
	if admin == "" {
		t.Skip(Env + " is not set")
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("%s: %v", Env, err)
	}
	b := make([]byte, 8)
	rand.Read(b)
	name := "patchlog_test_" + hex.EncodeToString(b)
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE DATABASE ` + name + ` TEMPLATE template0`); err != nil {
		db.Close()
		t.Fatalf("creating test database: %v", err)
	}
	t.Cleanup(func() {
		defer db.Close()
		if _, err := db.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Logf("dropping test database %s: %v", name, err)
		}
	})
	u.Path = "/" + name
	return u.String()
}
