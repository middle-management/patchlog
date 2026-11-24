package pgtest

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	_ "github.com/googleapis/go-sql-spanner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/middle-management/patchlog/internal/spannerurl"
)

// Spanner's databases (SpannerEnv): on the emulator the driver creates a
// database on the first connection to it, of the PostgreSQL dialect, so a
// new one is just a new name; on Spanner, the instance must allow it.
// Applying the schema to one takes seconds (mmmigrate's Spanner dialect), so,
// as on Postgres, a test's database goes back to a pool when it ends,
// emptied: every table's rows deleted but mmmigrate's, so the next engine
// finds its migrations applied and only seeds it again. Spanner has no
// TRUNCATE, nor a way to turn foreign keys off: the deletes run in one
// transaction, each table after those that reference it. The pool's
// databases outlive the process, and the next reuses them
// (claimSpannerDB); FreshDB's are dropped when their test ends.

// spannerPrefix and spannerFreshPrefix name the pool's databases and
// FreshDB's: names of 2 to 30 lowercase letters, digits and underscores.
// FreshDB's are new each time, and dropped after.
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
// runs reuse them: an instance holds 100 databases at most. A process holds each it claimed until it exits, by a
// lock on a file of the same name.
func claimSpannerDB(instance string) (string, error) {
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
		if err := emptySpanner(spannerDBURL(instance, name)); err != nil {
			return "", fmt.Errorf("emptying %s: %w", name, err)
		}
		return name, nil
	}
	return "", errors.New("every pool database is held")
}

// spannerInstance is SpannerEnv's instance, spanner://projects/P/instances/I.
func spannerInstance(t testing.TB) string {
	raw := strings.TrimRight(os.Getenv(SpannerEnv), "/")
	p := strings.Split(strings.TrimPrefix(raw, spannerurl.Scheme), "/")
	if !spannerurl.Is(raw) || len(p) != 4 || p[0] != "projects" || p[2] != "instances" {
		t.Fatalf("%s=%q: want %sprojects/P/instances/I", SpannerEnv, raw, spannerurl.Scheme)
	}
	return raw
}

// spannerDBURL is the URL of the instance's database name.
func spannerDBURL(instance, name string) string {
	return instance + "/databases/" + name
}

// spannerDB is NewDB (pooled) or FreshDB on Spanner.
func spannerDB(t testing.TB, pooled bool) string {
	t.Helper()
	instance := spannerInstance(t)
	var name string
	var err error
	if pooled {
		spannerPool.mu.Lock()
		if n := len(spannerPool.free); n > 0 {
			name = spannerPool.free[n-1]
			spannerPool.free = spannerPool.free[:n-1]
		}
		spannerPool.mu.Unlock()
		if name == "" {
			if name, err = claimSpannerDB(instance); err != nil {
				t.Fatalf("pgtest: %v", err)
			}
		}
		t.Cleanup(func() {
			if err := emptySpanner(spannerDBURL(instance, name)); err != nil {
				t.Logf("pgtest: emptying %s: %v", name, err)
				return
			}
			spannerPool.mu.Lock()
			spannerPool.free = append(spannerPool.free, name)
			spannerPool.mu.Unlock()
		})
	} else {
		name = spannerFreshPrefix + randHex()[:12]
		t.Cleanup(func() {
			if err := dropSpanner(spannerDBURL(instance, name)); err != nil {
				t.Logf("pgtest: dropping %s: %v", name, err)
			}
		})
	}
	q := url.Values{}
	for k, v := range PoolParams {
		q.Set(k, v)
	}
	return spannerDBURL(instance, name) + "?" + q.Encode()
}

// spannerDSN is the driver's connection string for a URL of spannerDB.
func spannerDSN(raw string) string {
	var drop []string
	for k := range PoolParams {
		drop = append(drop, k)
	}
	dsn, err := spannerurl.DSN(raw, drop...)
	if err != nil {
		return raw
	}
	return dsn
}

// dropSpanner drops a database, if it was created.
func dropSpanner(raw string) error {
	db, _, err := spannerurl.Parse(raw)
	if err != nil {
		return err
	}
	ctx := context.Background()
	c, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	err = c.DropDatabase(ctx, &databasepb.DropDatabaseRequest{Database: db})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

// emptySpanner deletes every row of the database's tables but mmmigrate's.
func emptySpanner(raw string) error {
	db, err := spannerurl.Open(spannerDSN(raw))
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
