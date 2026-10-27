package core

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The Postgres layout (Addendum D.8, migrations/postgres) is that of SQLite
// (migrations/sqlite). The tables, columns and constraints are the same, so
// every query runs on both; the types differ:
//
//   - integer keys are bigint identities, flags and small codes smallint
//     (not boolean: queries compare them with 0 and 1 on both dialects);
//   - hashes are bytea, checked to be 20 bytes;
//   - canonical JSON is text, never jsonb, which would reorder keys and
//     normalise numbers: ids are served and re-hashed from exactly the
//     stored bytes (§3.1). The columns that hold an encrypted row when
//     encryption at rest is on (crypt.go: revisions.patches, heads.doc,
//     snapshots.doc, grants.blocks) are bytea, which keeps the plaintext's
//     bytes just as exactly;
//   - timestamps stay integer Unix milliseconds, as in SQLite.
//
// Patch sets stay in revisions, as in the SQLite layout, rather than in a
// table of their own (D.8 "content apart from the skeleton"): purge and
// pruning set them to NULL, and vacuum reclaims the space.

// openPG opens a Postgres database and creates or migrates its schema.
func openPG(url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	n := 4 * runtime.GOMAXPROCS(0)
	db.SetMaxOpenConns(n)
	db.SetMaxIdleConns(n)
	ctx := context.Background()
	if err := migrate(ctx, db, true); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	// cache_gen's one row (tailer.go), on every open: a database emptied
	// of rows keeps its schema, and the migrations don't run again.
	if _, err := db.ExecContext(ctx, `INSERT INTO cache_gen (id, gen) VALUES (1, 0) ON CONFLICT DO NOTHING`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
