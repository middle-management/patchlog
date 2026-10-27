package core

import (
	"context"
	"database/sql"
	"embed"

	"github.com/middle-management/patchlog/internal/dbmigrate"
)

// migrations holds the schema as migrations, one directory per dialect
// (package dbmigrate).
//
//go:embed migrations
var migrations embed.FS

// migrationNamespace scopes the core's migration history, so a Postgres
// database it shares keeps others apart.
const migrationNamespace = "patchlog"

// migrate brings the schema up to date.
func migrate(ctx context.Context, db *sql.DB, pg bool) error {
	if pg {
		return dbmigrate.Postgres(ctx, db, migrations, "migrations/postgres", migrationNamespace)
	}
	return dbmigrate.SQLite(ctx, db, migrations, "migrations/sqlite", migrationNamespace)
}
