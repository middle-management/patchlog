package pgtest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// Spanner's databases (SpannerEnv), through PGAdapter: the emulator's
// PGAdapter creates a database on the first connection to it, so a new
// one is just a new name. Applying the schema to one takes about a second
// (dbmigrate.MigrateSpanner), so, as on Postgres, a test's database goes
// back to a pool when it ends, emptied: every table's rows deleted but
// mmmigrate's, so the next engine finds its migrations applied and only
// seeds it again. Spanner has no TRUNCATE, nor a way to turn foreign keys
// off, so tables are emptied in rounds, each deleting from those no other
// table's rows still reference. The pool lasts for the process: the
// emulator keeps its databases in memory, until it restarts.

// spannerPrefix and spannerFreshPrefix name the pool's databases and
// FreshDB's: names of 2 to 30 lowercase letters, digits and underscores.
const (
	spannerPrefix      = "plpool_"
	spannerFreshPrefix = "plfresh_"
)

var spannerPool struct {
	mu   sync.Mutex
	free []string
}

// spannerDB is NewDB (pooled) or FreshDB on Spanner.
func spannerDB(t testing.TB, pooled bool) string {
	t.Helper()
	raw := os.Getenv(SpannerEnv)
	u, err := url.Parse(pgxURL(raw))
	if err != nil {
		t.Fatalf("%s: %v", SpannerEnv, err)
	}
	var name string
	if pooled {
		spannerPool.mu.Lock()
		if n := len(spannerPool.free); n > 0 {
			name = spannerPool.free[n-1]
			spannerPool.free = spannerPool.free[:n-1]
		}
		spannerPool.mu.Unlock()
		if name == "" {
			name = spannerPrefix + randHex()
		}
		t.Cleanup(func() {
			u := *u
			u.Path = "/" + name
			if err := emptySpanner(u.String()); err != nil {
				t.Logf("pgtest: emptying %s: %v", name, err)
				return
			}
			spannerPool.mu.Lock()
			spannerPool.free = append(spannerPool.free, name)
			spannerPool.mu.Unlock()
		})
	} else {
		name = spannerFreshPrefix + randHex()[:12]
	}
	u.Path = "/" + name
	q := u.Query()
	for k, v := range PoolParams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return "spanner+postgres://" + strings.TrimPrefix(u.String(), "postgres://")
}

// emptySpanner deletes every row of the database's tables but mmmigrate's.
func emptySpanner(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		return err
	}
	var left []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		if !strings.HasPrefix(n, "mmmigrate_") {
			left = append(left, n)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for round := 0; len(left) > 0; round++ {
		var next []string
		var last error
		for _, n := range left {
			if _, err := db.ExecContext(ctx, `DELETE FROM `+n+` WHERE true`); err != nil {
				next, last = append(next, n), err
			}
		}
		if len(next) == len(left) || round > len(left) {
			return fmt.Errorf("tables %v: %w", next, last)
		}
		left = next
	}
	return nil
}

// pgxURL is a URL as pgx takes it: a Spanner URL's scheme is postgres://.
func pgxURL(raw string) string {
	if s, ok := strings.CutPrefix(raw, "spanner+postgres://"); ok {
		return "postgres://" + s
	}
	return raw
}
