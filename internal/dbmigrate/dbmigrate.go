// Package dbmigrate applies a package's schema migrations with mmmigrate
// (README, Schema migrations). Each package that owns tables keeps them as
// numbered migrations in its own migrations directory, one subdirectory
// per dialect it supports (migrations/sqlite, migrations/postgres),
// embedded in the binary, and applies them under a namespace of its own,
// so several packages' tables share a database (the index's holds its
// own, the edge store's and the repurge queue's) with independent
// histories.
//
// Seeds, rows the code expects to exist, are SQL too: migrations/seed/
// <dialect>.sql, run after the migrations on every start, so they must be
// safe to run again (INSERT … ON CONFLICT DO NOTHING). Running them every
// time restores them in a database emptied of rows but not of its schema
// (the Postgres test pool).
package dbmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/middle-management/mmmigrate"
	"github.com/middle-management/mmmigrate/driver/postgres"
	mmsqlite "github.com/middle-management/mmmigrate/driver/sqlite"
	"modernc.org/sqlite"
)

// Migrate applies the migrations in fsys's directory migrations/<dialect>
// to db, under namespace, the dialect being db's driver's: sqlite
// (modernc.org/sqlite) or postgres (pgx). On Postgres the namespace is
// scoped by the schema the tables go to (current_schema(), from the
// search_path): mmmigrate records every schema's migrations in its own
// schema mmmigrate, so deployments in different schemas of one database
// would otherwise share one history. The committed migrations run in
// order, each in its own transaction, recorded in mmmigrate's tables
// (mmmigrate_applied on SQLite, the mmmigrate schema on Postgres, under an
// advisory lock so instances starting together don't race). Tests also
// apply current.sql, so a migration being written is tested before it is
// committed. Then the dialect's seed, if fsys has one, runs in a
// transaction.
func Migrate(ctx context.Context, db *sql.DB, fsys fs.FS, namespace string) error {
	var dialect mmmigrate.Dialect
	var name string
	switch d := db.Driver().(type) {
	case *sqlite.Driver:
		dialect, name = mmsqlite.Dialect{}, "sqlite"
	case *stdlib.Driver:
		dialect, name = postgres.Dialect{}, "postgres"
	default:
		return fmt.Errorf("migrating %s: no migrations for driver %T", namespace, d)
	}
	sub, err := fs.Sub(fsys, "migrations/"+name)
	if err == nil {
		_, err = fs.Stat(sub, ".")
	}
	if err != nil {
		return fmt.Errorf("migrating %s: no %s migrations: %w", namespace, name, err)
	}
	base := namespace
	if name == "postgres" {
		var schema sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
			return fmt.Errorf("migrating %s: %w", namespace, err)
		}
		if !schema.Valid {
			return fmt.Errorf("migrating %s: no schema in the search_path exists", namespace)
		}
		namespace += "@" + schema.String
	}
	if err := rerecord(ctx, db, name, base, namespace); err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	if err := mmmigrate.RunMigrations(ctx, db, dialect, sub, testing.Testing(), mmmigrate.WithNamespace(namespace)); err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	seed, err := fs.ReadFile(fsys, "migrations/seed/"+name+".sql")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("seeding %s: %w", namespace, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("seeding %s: %w", namespace, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, string(seed)); err != nil {
		return fmt.Errorf("seeding %s: %w", namespace, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("seeding %s: %w", namespace, err)
	}
	return nil
}

// renumbering is a migration that was committed under a version another
// migration of its directory had also taken, and later moved to a version of
// its own. A database that applied it under the old version has it recorded
// there, where mmmigrate, which goes by version alone, would take it for the
// migration now numbered so: it would skip that one and run this one again
// under its new number. rerecord moves the record first.
type renumbering struct {
	dialect   string
	namespace string // before the "@schema" Postgres adds
	name      string // the migration's name, as mmmigrate records it
	from, to  int
}

var renumberings = []renumbering{
	// The core's Postgres migrations 030_purge_follows_by_importer (from
	// spec v0.88, PR #37) and 030_rate_draws_batched (PR #39) were both
	// committed as 030 and merged, #39 first: main ran with rate_draws_batched
	// as 030 from 2026-11-21 to 11-23, and the spec branches with
	// purge_follows_by_importer as 030. rate_draws_batched is now 031. A
	// database recording purge_follows_by_importer as 30 needs nothing: 031
	// runs next.
	{dialect: "postgres", namespace: "patchlog", name: "rate_draws_batched", from: 30, to: 31},
}

// rerecord moves the applied record of each renumbered migration from its
// old version to its new one, where the database has it under the old one
// and nothing under the new. It is one conditional UPDATE, so instances
// starting together move it once, and every instance moves it (or finds it
// moved) before mmmigrate reads the records.
func rerecord(ctx context.Context, db *sql.DB, dialect, base, namespace string) error {
	for _, r := range renumberings {
		if r.dialect != dialect || r.namespace != base {
			continue
		}
		if dialect != "postgres" {
			return fmt.Errorf("renumbering %s: no rerecord for dialect %s", r.name, dialect)
		}
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('mmmigrate.applied') IS NOT NULL`).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			continue // a new database
		}
		res, err := db.ExecContext(ctx, `UPDATE mmmigrate.applied SET version = $3
			WHERE namespace = $1 AND version = $2 AND name = $4
			AND NOT EXISTS (SELECT 1 FROM mmmigrate.applied WHERE namespace = $1 AND version = $3)`,
			namespace, r.from, r.to, r.name)
		if err != nil {
			return fmt.Errorf("re-recording migration %s as %d: %w", r.name, r.to, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			slog.Info("re-recorded a renumbered migration", "namespace", namespace, "name", r.name, "from", r.from, "to", r.to)
		}
	}
	return nil
}
