package core

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"runtime"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// migrations holds the schema, one directory per dialect, applied under
// the namespace "patchlog" (package dbmigrate; on Postgres, per schema),
// which keeps it apart in a database shared with others.
//
//go:embed migrations
var migrations embed.FS

// openDB opens the database: a Postgres URL (openPG), or a SQLite
// file or ":memory:", migrated with fsys (nil: migrations). before, if
// not nil, runs before its schema is migrated (checkLegacyE2E); an error
// closes it.
//
// In SQLite, secure_delete zeroes deleted and overwritten content, so a
// purge (and turning encryption at rest on, which rewrites rows) leaves no
// plaintext in free pages once the WAL is checkpointed. Postgres has no
// equivalent: deleted and overwritten tuples stay in the table's files
// until VACUUM reclaims them (and in WAL and backups until those expire).
func openDB(path string, fsys fs.FS, before func(db *sql.DB, pg bool) error) (db *sql.DB, pg bool, err error) {
	if fsys == nil {
		fsys = migrations
	}
	if isPostgresURL(path) {
		db, err := openPG(path, fsys, before)
		return db, true, err
	}
	db, err = openSQLite(path, fsys, before)
	return db, false, err
}

func openSQLite(path string, fsys fs.FS, before func(db *sql.DB, pg bool) error) (*sql.DB, error) {
	// A database that an earlier release kept under another name (see
	// sqlitedsn.Legacy) must be moved first: opened here it would be an
	// empty one, and the blob sweep would delete its blob files.
	if path != ":memory:" {
		if err := sqlitedsn.CheckLegacy(path); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		// One connection keeps the in-memory database alive and shared.
		db.SetMaxOpenConns(1)
	} else {
		// Keep connections open: a new SQLite connection parses the whole
		// schema and loses its prepared statements, and database/sql keeps
		// only two idle ones by default, so under concurrent reads most of
		// the time went to reopening connections.
		n := readerConns()
		db.SetMaxOpenConns(n)
		db.SetMaxIdleConns(n)
	}
	if before != nil {
		if err := before(db, false); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := dbmigrate.Migrate(context.Background(), db, fsys, "patchlog"); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	return db, nil
}

// openPG opens a Postgres database and creates or migrates its schema.
func openPG(url string, fsys fs.FS, before func(db *sql.DB, pg bool) error) (*sql.DB, error) {
	url, pool, err := parsePGPool(url)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	pool.sizeMain(db)
	if before != nil {
		if err := before(db, true); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := dbmigrate.Migrate(context.Background(), db, fsys, "patchlog"); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	return db, nil
}

// Entry kinds, as stored.
const (
	kindRev       = 0
	kindTombstone = 1
)

const (
	stateLive       = 0
	stateTombstoned = 1
	statePurged     = 2
)

var nsKindNames = []string{"head", "tombstone", "purge", "config", "batch", "purge-ns", "branch", "prune"}

func nsKindCode(k string) int {
	for i, n := range nsKindNames {
		if n == k {
			return i
		}
	}
	panic("unknown ns kind " + k)
}

// sqliteDSN is the DSN of the SQLite file path (or ":memory:").
// wal_autocheckpoint(0): no checkpoint inside a write's COMMIT; the engine
// runs them alongside its writer (checkpoint.go).
func sqliteDSN(path string) string {
	if path == ":memory:" {
		return sqlitedsn.DSN(path, "_pragma=foreign_keys(ON)&_pragma=secure_delete(ON)&_txlock=immediate")
	}
	return sqlitedsn.DSN(path, "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)&_pragma=wal_autocheckpoint(0)&_txlock=immediate")
}

// readerConns is the size of a SQLite file's main pool, which every
// transaction but the writer's takes: two connections per CPU. All the
// connections of a process share one page cache, behind one mutex (the
// driver's SQLite is built with SQLITE_ENABLE_MEMORY_MANAGEMENT), which
// each takes for every page it reads; and in WAL mode a read transaction
// that begins after a commit empties its connection's share of it. So
// readers beyond the CPUs, which add no throughput to reads served from
// memory, made the writer wait on that mutex under Engine.mu: with 16
// connections on 4 CPUs instead of 8, writers alongside readers committed
// 5–13% less (BenchmarkNamespaceWriters, readers=8).
func readerConns() int { return 2 * runtime.GOMAXPROCS(0) }

// openSQLiteWriter opens the one connection of a SQLite file's writer
// (Engine.wdb): every write transaction runs on it, under Engine.mu, and so
// do the checkpoints taken under Engine.mu (checkpointWait). On the main
// pool the writer queued for a connection, holding Engine.mu, behind reads
// that held them all; none of those can take this one.
func openSQLiteWriter(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
