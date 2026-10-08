// Package pgtest lets tests run against Postgres (Addendum D.8) instead of
// an in-memory SQLite database: with PATCHLOG_TEST_PG set to a Postgres URL
// (e.g. postgres://postgres@127.0.0.1:5432/postgres), DB gives each test a
// database of its own there.
//
// Creating a database and its schema costs about 450 ms, more than most
// tests, so DB and NewDB hand out databases from a pool the test process
// keeps: when a test ends, its database is emptied (every table's rows
// deleted, every sequence restarted, about 10 ms) and goes to the next
// test, schema and all; the engine's migration finds it in place. A test
// that changes the schema, or needs a database with none, takes FreshDB.
// The pool's databases outlive the process; the next process to start
// drops them (each process holds a lock per database it created until it
// exits).
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Env is the environment variable naming the Postgres server for tests.
const Env = "PATCHLOG_TEST_PG"

// Enabled reports whether tests run against Postgres.
func Enabled() bool { return os.Getenv(Env) != "" }

// DB returns the database path for a test's engine: ":memory:", or with
// PATCHLOG_TEST_PG set, the URL of an empty Postgres database (NewDB).
func DB(t testing.TB) string {
	t.Helper()
	if !Enabled() {
		return ":memory:"
	}
	return NewDB(t)
}

// NewDB returns the URL of an empty Postgres database, the test's own
// until it ends; it may already hold the schema, from the pool. It skips
// the test if PATCHLOG_TEST_PG isn't set.
func NewDB(t testing.TB) string {
	t.Helper()
	u := adminURL(t)
	if err := pool.start(u.String()); err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	name, err := pool.take()
	if err != nil {
		t.Fatalf("pgtest: creating a test database: %v", err)
	}
	u.Path = "/" + name
	t.Cleanup(func() { pool.give(u, name) })
	return u.String()
}

// FreshDB is DB with a brand-new database, with no schema, dropped when
// the test ends: for tests that change the schema (a migration from an
// older one), which a pooled database would carry to the next test.
func FreshDB(t testing.TB) string {
	t.Helper()
	if !Enabled() {
		return ":memory:"
	}
	return newDB(t, "")
}

// NewDBCollated is FreshDB with an ICU locale (e.g. "en") as the database's
// default collation, whose order of text differs from byte order (it
// ignores punctuation at first), for tests of orders a spec defines in
// bytes. It skips the test if PATCHLOG_TEST_PG isn't set or the server
// lacks ICU.
func NewDBCollated(t testing.TB, icuLocale string) string {
	t.Helper()
	return newDB(t, ` LOCALE_PROVIDER icu ICU_LOCALE '`+icuLocale+`' LOCALE 'C.UTF-8'`)
}

func adminURL(t testing.TB) *url.URL {
	t.Helper()
	admin := os.Getenv(Env)
	if admin == "" {
		t.Skip(Env + " is not set")
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("%s: %v", Env, err)
	}
	return u
}

func newDB(t testing.TB, with string) string {
	t.Helper()
	u := adminURL(t)
	name := "patchlog_test_" + randHex()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	// Hold no connection between the create and the drop: parallel tests
	// would each keep one open for their whole run.
	db.SetMaxIdleConns(0)
	if _, err := db.Exec(`CREATE DATABASE ` + name + ` TEMPLATE template0` + with); err != nil {
		db.Close()
		if with != "" {
			t.Skipf("creating a test database%s: %v", with, err)
		}
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

func randHex() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// lockClass is the first key of the advisory locks on pool databases (the
// second is hashtext of the name): "pgts".
const lockClass = 0x70677473

const poolPrefix = "patchlog_pool_"

// pool is the process's databases, created on demand.
var pool dbPool

type dbPool struct {
	once  sync.Once
	err   error
	admin *sql.DB
	mu    sync.Mutex
	owner *sql.Conn // holds the lock on each database the process created
	free  []string
	// schema is the fingerprint of the schema, as the first emptied
	// database with one had it: a database whose schema differs (a test
	// changed it) is dropped, not reused.
	schema string
}

func (p *dbPool) start(admin string) error {
	p.once.Do(func() {
		ctx := context.Background()
		if p.admin, p.err = sql.Open("pgx", admin); p.err != nil {
			return
		}
		p.admin.SetMaxIdleConns(2)
		if p.owner, p.err = p.admin.Conn(ctx); p.err != nil {
			return
		}
		// Drop what processes that have exited left behind: a database
		// whose lock is free has no owner.
		rows, err := p.admin.QueryContext(ctx, `SELECT datname FROM pg_database WHERE datname LIKE '`+poolPrefix+`%'`)
		if err != nil {
			p.err = err
			return
		}
		var left []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				p.err = err
				return
			}
			left = append(left, n)
		}
		rows.Close()
		for _, n := range left {
			var free bool
			if err := p.owner.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, lockClass, n).Scan(&free); err != nil || !free {
				continue
			}
			p.admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+n+` WITH (FORCE)`)
			p.owner.ExecContext(ctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, lockClass, n)
		}
	})
	return p.err
}

// take returns a free database, or creates one, locked by the process
// before it exists.
func (p *dbPool) take() (string, error) {
	ctx := context.Background()
	p.mu.Lock()
	if n := len(p.free); n > 0 {
		name := p.free[n-1]
		p.free = p.free[:n-1]
		p.mu.Unlock()
		return name, nil
	}
	name := poolPrefix + randHex()
	_, err := p.owner.ExecContext(ctx, `SELECT pg_advisory_lock($1, hashtext($2))`, lockClass, name)
	p.mu.Unlock()
	if err != nil {
		return "", err
	}
	if _, err := p.admin.ExecContext(ctx, `CREATE DATABASE `+name+` TEMPLATE template0`); err != nil {
		p.drop(name)
		return "", err
	}
	return name, nil
}

// give empties a test's database for the next one, or drops it.
func (p *dbPool) give(u *url.URL, name string) {
	if err := p.empty(u, name); err != nil {
		p.drop(name)
		return
	}
	p.mu.Lock()
	p.free = append(p.free, name)
	p.mu.Unlock()
}

func (p *dbPool) drop(name string) {
	ctx := context.Background()
	p.admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
	p.mu.Lock()
	p.owner.ExecContext(ctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, lockClass, name)
	p.mu.Unlock()
}

// fingerprint is the schema's tables, columns, defaults, indexes and
// constraints.
const fingerprint = `SELECT coalesce(md5(string_agg(x, E'\n' ORDER BY x)), '') FROM (
  SELECT c.relkind::text || ' ' || c.relname || coalesce(' ' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
    || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END || ' ' || a.attidentity::text
    || coalesce(' default ' || pg_get_expr(d.adbin, d.adrelid), ''), '')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  WHERE n.nspname = current_schema()
  UNION ALL SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema()
  UNION ALL SELECT conname || ' ' || pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace = current_schema()::regnamespace
) s(x)`

// empty deletes every row and restarts every sequence of the database,
// after ending any session a test left open on it.
func (p *dbPool) empty(u *url.URL, name string) error {
	ctx := context.Background()
	if _, err := p.admin.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name); err != nil {
		return err
	}
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	var fp string
	var dels, seqs sql.NullString
	if err := c.QueryRowContext(ctx, fingerprint).Scan(&fp); err != nil {
		return err
	}
	if fp != "" {
		p.mu.Lock()
		if p.schema == "" {
			p.schema = fp
		}
		same := p.schema == fp
		p.mu.Unlock()
		if !same {
			return errors.New("the test changed the schema")
		}
	}
	if err := c.QueryRowContext(ctx, `SELECT
  (SELECT string_agg('DELETE FROM ' || quote_ident(tablename), '; ') FROM pg_tables WHERE schemaname = current_schema()),
  (SELECT string_agg('ALTER SEQUENCE ' || quote_ident(sequencename) || ' RESTART', '; ') FROM pg_sequences WHERE schemaname = current_schema())`).Scan(&dels, &seqs); err != nil {
		return err
	}
	if !dels.Valid && !seqs.Valid {
		return nil
	}
	// replica: foreign keys don't fire, so the order of the deletes
	// doesn't matter (it takes a superuser, as the tests' databases are
	// made by one).
	_, err = c.ExecContext(ctx, `SET lock_timeout = '10s'; SET session_replication_role = replica; `+dels.String+`; `+seqs.String)
	return err
}
