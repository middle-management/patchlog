package dbmigrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/mmmigrate/source"
)

// MigrateSpanner is Migrate for a database on Spanner's PostgreSQL
// interface, reached through PGAdapter with the pgx driver, whose
// migrations are in migrations/spanner and seed in migrations/seed/
// spanner.sql (docs/SPANNER.md).
//
// mmmigrate's Postgres dialect can't run there: it applies each migration
// in a transaction, Spanner runs DDL only outside one, and it serialises
// runs with an advisory lock, which Spanner lacks. So this runner applies
// a migration's statements one by one, consecutive DDL as one batch (START
// BATCH DDL … RUN BATCH, a single schema change), and then records it in
// mmmigrate_applied, as mmmigrate's SQLite dialect names its table. A
// migration that fails halfway is left half applied and runs again from
// its start at the next run, so Spanner migrations are written to be
// repeatable (IF NOT EXISTS). Instances starting together may both run a
// migration; IF NOT EXISTS makes that harmless, and the record is inserted
// once (ON CONFLICT). Tests also apply current.sql, recorded by checksum in
// mmmigrate_current. The seed runs statement by statement, each committed
// on its own.
func MigrateSpanner(ctx context.Context, db *sql.DB, fsys fs.FS, namespace string) error {
	sub, err := fs.Sub(fsys, "migrations/spanner")
	if err == nil {
		_, err = fs.Stat(sub, ".")
	}
	if err != nil {
		return fmt.Errorf("migrating %s: no spanner migrations: %w", namespace, err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	defer conn.Close()
	// Created only if missing: a schema change takes seconds on Spanner
	// even when it changes nothing, and the emulator refuses one while a
	// read-write transaction (another instance's) is open.
	var have int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN ('mmmigrate_applied', 'mmmigrate_current')`).Scan(&have); err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	if have < 2 {
		if err := runSpannerDDL(ctx, conn, []string{
			`CREATE TABLE IF NOT EXISTS mmmigrate_applied (namespace text NOT NULL, version bigint NOT NULL, name text NOT NULL, applied_at bigint NOT NULL, PRIMARY KEY (namespace, version))`,
			`CREATE TABLE IF NOT EXISTS mmmigrate_current (namespace text NOT NULL PRIMARY KEY, checksum text NOT NULL, applied_at bigint NOT NULL)`,
		}); err != nil {
			return fmt.Errorf("migrating %s: creating the migrations tables: %w", namespace, err)
		}
	}
	migrations, err := source.LoadMigrations(sub, testing.Testing())
	if err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	applied := map[int]bool{}
	rows, err := conn.QueryContext(ctx, `SELECT version FROM mmmigrate_applied WHERE namespace = $1`, namespace)
	if err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("migrating %s: %w", namespace, err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrating %s: %w", namespace, err)
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	var current *source.Migration
	for _, m := range migrations {
		if m.IsCurrent {
			current = m
			continue
		}
		if applied[m.Version] {
			continue
		}
		if err := runSpannerScript(ctx, conn, m.SQL); err != nil {
			return fmt.Errorf("migrating %s: migration %d (%s): %w", namespace, m.Version, m.Name, err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO mmmigrate_applied (namespace, version, name, applied_at) VALUES ($1, $2, $3, $4) ON CONFLICT (namespace, version) DO NOTHING`,
			namespace, int64(m.Version), m.Name, time.Now().UnixMilli()); err != nil {
			return fmt.Errorf("migrating %s: recording migration %d: %w", namespace, m.Version, err)
		}
		slog.Info("applied migration", "namespace", namespace, "version", m.Version, "name", m.Name)
	}
	if current != nil && len(splitSQL(current.SQL)) > 0 {
		sum := fmt.Sprintf("%x", sha256.Sum256([]byte(current.SQL)))
		var have string
		err := conn.QueryRowContext(ctx, `SELECT checksum FROM mmmigrate_current WHERE namespace = $1`, namespace).Scan(&have)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("migrating %s: %w", namespace, err)
		}
		if have != sum {
			if err := runSpannerScript(ctx, conn, current.SQL); err != nil {
				return fmt.Errorf("migrating %s: current.sql: %w", namespace, err)
			}
			if _, err := conn.ExecContext(ctx, `INSERT INTO mmmigrate_current (namespace, checksum, applied_at) VALUES ($1, $2, $3)
				ON CONFLICT (namespace) DO UPDATE SET checksum = excluded.checksum, applied_at = excluded.applied_at`,
				namespace, sum, time.Now().UnixMilli()); err != nil {
				return fmt.Errorf("migrating %s: recording current.sql: %w", namespace, err)
			}
			slog.Info("applied current.sql", "namespace", namespace, "checksum", sum[:8])
		}
	}
	seed, err := fs.ReadFile(fsys, "migrations/seed/spanner.sql")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("seeding %s: %w", namespace, err)
	}
	for _, q := range splitSQL(string(seed)) {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("seeding %s: %w", namespace, err)
		}
	}
	return nil
}

// runSpannerScript runs a migration's statements in order: each run of
// DDL as one batch, any other statement on its own.
func runSpannerScript(ctx context.Context, conn *sql.Conn, script string) error {
	var ddl []string
	for _, q := range splitSQL(script) {
		if isDDL(q) {
			ddl = append(ddl, q)
			continue
		}
		if err := runSpannerDDL(ctx, conn, ddl); err != nil {
			return err
		}
		ddl = nil
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("%s: %w", firstLine(q), err)
		}
	}
	return runSpannerDDL(ctx, conn, ddl)
}

// runSpannerDDL runs DDL statements as one batch, a single schema change
// on Spanner rather than one per statement (each of which takes seconds).
func runSpannerDDL(ctx context.Context, conn *sql.Conn, ddl []string) error {
	if len(ddl) == 0 {
		return nil
	}
	if _, err := conn.ExecContext(ctx, `START BATCH DDL`); err != nil {
		return err
	}
	for _, q := range ddl {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			conn.ExecContext(ctx, `ABORT BATCH`)
			return fmt.Errorf("%s: %w", firstLine(q), err)
		}
	}
	if _, err := conn.ExecContext(ctx, `RUN BATCH`); err != nil {
		return err
	}
	return nil
}

func isDDL(q string) bool {
	w, _, _ := strings.Cut(strings.TrimSpace(q), " ")
	switch strings.ToUpper(w) {
	case "CREATE", "ALTER", "DROP", "ANALYZE":
		return true
	}
	return false
}

func firstLine(q string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(q), "\n")
	return l
}

// splitSQL splits a script into its statements, without comments: at
// semicolons outside quotes, quoted identifiers, dollar quotes and
// comments.
func splitSQL(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if q := strings.TrimSpace(b.String()); q != "" {
			out = append(out, q)
		}
		b.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += end + 3
			}
			b.WriteByte(' ')
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(s) && s[j] != c {
				j++
			}
			b.WriteString(s[i:min(j+1, len(s))])
			i = j
		case c == '$':
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
				j++
			}
			if j < len(s) && s[j] == '$' {
				tag := s[i : j+1]
				end := strings.Index(s[j+1:], tag)
				if end < 0 {
					end = len(s) - j - 1
				} else {
					end += len(tag)
				}
				b.WriteString(s[i:min(j+1+end, len(s))])
				i = j + end
			} else {
				b.WriteByte(c)
			}
		case c == ';':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}
