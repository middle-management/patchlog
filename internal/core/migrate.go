package core

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"testing"

	"github.com/middle-management/mmmigrate"
	"github.com/middle-management/mmmigrate/driver/postgres"
	"github.com/middle-management/mmmigrate/driver/sqlite"
)

// migrations holds the schema as mmmigrate migrations, one directory per
// dialect: numbered files are committed (and never edited), current.sql is
// the one being written (README, Schema migrations).
//
//go:embed migrations
var migrations embed.FS

// migrationNamespace scopes the core's migration history, so a Postgres
// database it shares keeps others apart.
const migrationNamespace = "patchlog"

// migrate brings the schema up to date: the committed migrations, in
// order, each in its own transaction, recorded in mmmigrate's tables
// (mmmigrate_applied on SQLite, the mmmigrate schema on Postgres, under an
// advisory lock so instances starting together don't race). Tests also
// apply current.sql, so a migration being written is tested before it is
// committed.
func migrate(ctx context.Context, db *sql.DB, pg bool) error {
	dir, dialect := "migrations/sqlite", mmmigrate.Dialect(sqlite.Dialect{})
	if pg {
		dir, dialect = "migrations/postgres", postgres.Dialect{}
	}
	fsys, err := fs.Sub(migrations, dir)
	if err != nil {
		return err
	}
	return mmmigrate.RunMigrations(ctx, db, dialect, fsys, testing.Testing(), mmmigrate.WithNamespace(migrationNamespace))
}
