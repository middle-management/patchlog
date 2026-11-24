package dbmigrate

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"testing/fstest"
	"time"

	"github.com/middle-management/mmmigrate"
	mmspanner "github.com/middle-management/mmmigrate/driver/spanner"
)

// isSpanner reports whether a pgx connection reaches Spanner's PostgreSQL
// interface (through PGAdapter) rather than Postgres: only Spanner has the
// schema spanner_sys. PGAdapter answers version() as Postgres would.
func isSpanner(ctx context.Context, db *sql.DB) (bool, error) {
	var n int64
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.schemata WHERE schema_name = 'spanner_sys'`).Scan(&n)
	return n > 0, err
}

// The first-phase Spanner backend migrated with a runner of its own
// (MigrateSpanner, until mmmigrate had a Spanner dialect). It created
// mmmigrate_applied and mmmigrate_current, the names mmmigrate's Spanner
// dialect uses, but with applied_at a bigint of Unix milliseconds where the
// dialect's is a timestamptz, and recorded none of mmmigrate's own
// (_mmmigrate) migrations. mmmigrate can't write to those tables, and Spanner
// can't change a column's type, so a database that runner migrated is adopted:
// its records are copied to a stash table, its two tables dropped, mmmigrate
// creates its own, and the records are copied into them. Its migrations are
// then found applied, not run again.
//
// The steps that drop tables run under the lease mmmigrate itself takes
// before it creates its tables (in the _mmmigrate namespace), so an instance
// starting meanwhile can't create mmmigrate's tables only for another to drop
// them. The copy back runs outside the lease, before any migration: it is
// idempotent, every instance that sees the stash completes it before
// migrating, and the stash is dropped only once a copy is complete. A run
// that dies at any step leaves either the old tables or the stash, and the
// next run carries on from there.
const legacyStash = "patchlog_legacy_migrations"

func adoptLegacySpanner(ctx context.Context, db *sql.DB) error {
	legacy, stashed, err := legacySpannerState(ctx, db)
	if err != nil || !legacy && !stashed {
		// The usual case: adopted already, or never migrated by the old
		// runner. That doesn't change back, so no lease is needed to know.
		return err
	}
	d := mmspanner.Dialect{}
	if legacy {
		if err := stashLegacySpanner(ctx, db, d); err != nil {
			return err
		}
	}
	// mmmigrate's tables, created as RunMigrations would (Status applies
	// nothing else).
	if _, err := mmmigrate.Status(ctx, db, d, fstest.MapFS{}); err != nil {
		return err
	}
	return restoreLegacySpanner(ctx, db, d)
}

// legacyTables returns which of the old runner's tables are there: its
// mmmigrate_applied and mmmigrate_current have a bigint applied_at. Usually
// both or neither, but Spanner doesn't apply a DDL batch atomically, so a run
// that died while dropping them may have left one.
func legacyTables(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name IN ('mmmigrate_applied', 'mmmigrate_current')
		AND column_name = 'applied_at' AND data_type = 'bigint'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		tables[n] = true
	}
	return tables, rows.Err()
}

// legacySpannerState reports whether any of the old runner's tables are
// there, and whether a stash of their records is.
func legacySpannerState(ctx context.Context, db *sql.DB) (legacy, stashed bool, err error) {
	tables, err := legacyTables(ctx, db)
	if err != nil {
		return false, false, err
	}
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = $1`, legacyStash).Scan(&n); err != nil {
		return false, false, err
	}
	return len(tables) > 0, n > 0, nil
}

type legacyRecord struct {
	kind, namespace, name string
	version, at           int64
}

func scanLegacy(rows *sql.Rows, err error) ([]legacyRecord, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recs []legacyRecord
	for rows.Next() {
		var r legacyRecord
		if err := rows.Scan(&r.kind, &r.namespace, &r.version, &r.name, &r.at); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, rows.Err()
}

// stashLegacySpanner copies the old runner's records into the stash and
// drops its tables, under mmmigrate's own lease.
func stashLegacySpanner(ctx context.Context, db *sql.DB, d mmspanner.Dialect) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	lctx, release, err := d.AcquireLock(ctx, db, conn, mmmigrate.SelfNamespace)
	if err != nil {
		return err
	}
	defer release()
	ctx = lctx

	// Again under the lease: another instance may have adopted it since.
	tables, err := legacyTables(ctx, db)
	if err != nil || len(tables) == 0 {
		return err
	}
	slog.Info("adopting the Spanner migration records of the earlier runner")
	if err := d.Exec(ctx, conn, `CREATE TABLE IF NOT EXISTS `+legacyStash+` (
		kind        varchar NOT NULL,
		namespace   varchar NOT NULL,
		version     bigint NOT NULL,
		name        varchar NOT NULL,
		applied_at  bigint NOT NULL,
		PRIMARY KEY (kind, namespace, version)
	)`); err != nil {
		return err
	}
	var recs []legacyRecord
	for table, q := range map[string]string{
		"mmmigrate_applied": `SELECT 'applied', namespace, version, name, applied_at FROM mmmigrate_applied`,
		"mmmigrate_current": `SELECT 'current', namespace, 0, checksum, applied_at FROM mmmigrate_current`,
	} {
		if !tables[table] {
			continue
		}
		rs, err := scanLegacy(conn.QueryContext(ctx, q))
		if err != nil {
			return err
		}
		recs = append(recs, rs...)
	}
	for _, r := range recs {
		if _, err := conn.ExecContext(ctx, `INSERT INTO `+legacyStash+` (kind, namespace, version, name, applied_at)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (kind, namespace, version) DO NOTHING`,
			r.kind, r.namespace, r.version, r.name, r.at); err != nil {
			return err
		}
	}
	var drops []string
	for table := range tables {
		drops = append(drops, "DROP TABLE IF EXISTS "+table)
	}
	return d.Exec(ctx, conn, strings.Join(drops, ";\n"))
}

// restoreLegacySpanner copies the stashed records into mmmigrate's tables,
// keeping their times, and drops the stash.
func restoreLegacySpanner(ctx context.Context, db *sql.DB, d mmspanner.Dialect) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	recs, err := scanLegacy(conn.QueryContext(ctx, `SELECT kind, namespace, version, name, applied_at FROM `+legacyStash))
	if err != nil {
		return err
	}
	for _, r := range recs {
		at := time.UnixMilli(r.at).UTC()
		var q string
		var args []any
		if r.kind == "current" {
			q = `INSERT INTO mmmigrate_current (namespace, checksum, applied_at) VALUES ($1, $2, $3) ON CONFLICT (namespace) DO NOTHING`
			args = []any{r.namespace, r.name, at}
		} else {
			q = `INSERT INTO mmmigrate_applied (namespace, version, name, applied_at) VALUES ($1, $2, $3, $4) ON CONFLICT (namespace, version) DO NOTHING`
			args = []any{r.namespace, r.version, r.name, at}
		}
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("restoring %s %s/%d: %w", r.kind, r.namespace, r.version, err)
		}
	}
	slog.Info("adopted the earlier runner's Spanner migration records", "records", len(recs))
	return d.Exec(ctx, conn, `DROP TABLE IF EXISTS `+legacyStash)
}
