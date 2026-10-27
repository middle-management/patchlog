// Package dbmigrate applies a package's schema migrations with mmmigrate
// (README, Schema migrations). Each package that owns tables keeps them as
// numbered migrations in its own migrations directory, embedded in the
// binary, and applies them under a namespace of its own, so several
// packages' tables share a database (the tree service's holds the tree's,
// the catalog's, the sealed-view cache's and the repurge queue's) with
// independent histories.
package dbmigrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"testing"

	"github.com/middle-management/mmmigrate"
	"github.com/middle-management/mmmigrate/driver/postgres"
	"github.com/middle-management/mmmigrate/driver/sqlite"
)

// SQLite applies the migrations in the directory dir of fsys to a SQLite
// database, under namespace.
func SQLite(ctx context.Context, db *sql.DB, fsys fs.FS, dir, namespace string) error {
	return run(ctx, db, sqlite.Dialect{}, fsys, dir, namespace)
}

// Postgres applies the migrations in the directory dir of fsys to a
// Postgres database, under namespace, holding an advisory lock so instances
// starting together don't race.
func Postgres(ctx context.Context, db *sql.DB, fsys fs.FS, dir, namespace string) error {
	return run(ctx, db, postgres.Dialect{}, fsys, dir, namespace)
}

// run applies the committed migrations, in order, each in its own
// transaction, recorded in mmmigrate's tables (mmmigrate_applied on SQLite,
// the mmmigrate schema on Postgres). Tests also apply current.sql, so a
// migration being written is tested before it is committed.
func run(ctx context.Context, db *sql.DB, dialect mmmigrate.Dialect, fsys fs.FS, dir, namespace string) error {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return err
	}
	if err := mmmigrate.RunMigrations(ctx, db, dialect, sub, testing.Testing(), mmmigrate.WithNamespace(namespace)); err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	return nil
}
