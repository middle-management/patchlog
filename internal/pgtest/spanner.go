package pgtest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// Spanner's databases (SpannerEnv), through PGAdapter: the emulator's
// PGAdapter creates a database on the first connection to it, so a new
// one is just a new name. Applying the schema to one takes about a second
// (dbmigrate.MigrateSpanner), so, as on Postgres, a test's database goes
// back to a pool when it ends, emptied: every table's rows deleted but
// mmmigrate's, so the next engine finds its migrations applied and only
// seeds it again. Spanner has no TRUNCATE, nor a way to turn foreign keys
// off: the deletes run in one transaction, each table after those that
// reference it. The pool's databases outlive the process, and the next
// reuses them (claimSpannerDB).

// spannerPrefix and spannerFreshPrefix name the pool's databases and
// FreshDB's: names of 2 to 30 lowercase letters, digits and underscores.
// FreshDB's are new each time, so a test run on the emulator uses a dozen
// of the instance's 100 databases: restart it between runs.
const (
	spannerPrefix      = "plpool_"
	spannerFreshPrefix = "plfresh_"
)

var spannerPool struct {
	mu   sync.Mutex
	free []string
	held map[string]bool
}

// claimSpannerDB claims a pool database no other process holds, and
// empties it of what an earlier process left. The names are numbered, so
// runs reuse them: an instance holds 100 databases at most, and PGAdapter
// can't drop one. A process holds each it claimed until it exits, by a
// lock on a file of the same name.
func claimSpannerDB(u *url.URL) (string, error) {
	spannerPool.mu.Lock()
	defer spannerPool.mu.Unlock()
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("%s%02d", spannerPrefix, i)
		if spannerPool.held[name] {
			continue
		}
		f, err := os.OpenFile(filepath.Join(os.TempDir(), "patchlog-"+name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return "", err
		}
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			f.Close()
			continue
		}
		if spannerPool.held == nil {
			spannerPool.held = map[string]bool{}
		}
		spannerPool.held[name] = true // and f stays open, locked, until exit
		v := *u
		v.Path = "/" + name
		if err := emptySpanner(v.String()); err != nil {
			return "", fmt.Errorf("emptying %s: %w", name, err)
		}
		return name, nil
	}
	return "", errors.New("every pool database is held")
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
			if name, err = claimSpannerDB(u); err != nil {
				t.Fatalf("pgtest: %v", err)
			}
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
	// Children first, by the foreign keys, in one transaction.
	refs := map[string][]string{} // table -> the tables referencing it
	rows, err = db.QueryContext(ctx, `SELECT tc.table_name, ccu.table_name FROM information_schema.table_constraints tc
		JOIN information_schema.constraint_table_usage ccu ON ccu.constraint_name = tc.constraint_name
		WHERE tc.constraint_type = 'FOREIGN KEY'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			rows.Close()
			return err
		}
		if child != parent {
			refs[parent] = append(refs[parent], child)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var order []string
	done := map[string]bool{}
	var visit func(n string)
	visit = func(n string) {
		if done[n] {
			return
		}
		done[n] = true
		for _, c := range refs[n] {
			visit(c)
		}
		order = append(order, n)
	}
	for _, n := range left {
		visit(n)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range order {
		if strings.HasPrefix(n, "mmmigrate_") {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+n+` WHERE true`); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	return tx.Commit()
}

// pgxURL is a URL as pgx takes it: a Spanner URL's scheme is postgres://.
func pgxURL(raw string) string {
	if s, ok := strings.CutPrefix(raw, "spanner+postgres://"); ok {
		return "postgres://" + s
	}
	return raw
}
