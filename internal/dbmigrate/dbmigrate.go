// Package dbmigrate applies a package's schema migrations with mmmigrate
// (README, Schema migrations). Each package that owns tables keeps them as
// numbered migrations in its own migrations directory, one subdirectory
// per dialect it supports (migrations/sqlite, migrations/postgres),
// embedded in the binary, and applies them under a namespace of its own,
// so several packages' tables share a database (the tree service's holds
// the tree's, the catalog's, the sealed-view cache's and the repurge
// queue's) with independent histories.
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
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/middle-management/mmmigrate"
	"github.com/middle-management/mmmigrate/driver/postgres"
	mmsqlite "github.com/middle-management/mmmigrate/driver/sqlite"
	"modernc.org/sqlite"
)

// Migrate applies the migrations in fsys's directory migrations/<dialect>
// to db, under namespace, the dialect being db's driver's: sqlite
// (modernc.org/sqlite) or postgres (pgx). The committed migrations run in
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
