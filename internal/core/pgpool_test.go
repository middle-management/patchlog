package core

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// The pool parameters of a Postgres URL are read and removed, the rest of
// the URL kept; a URL without them is untouched, and bad values refused.
func TestParsePGPool(t *testing.T) {
	for _, c := range []struct {
		in, out string
		pool    pgPool
		err     string
	}{
		{in: "postgres://u:p%40ss@h:5432/db?sslmode=disable", out: "postgres://u:p%40ss@h:5432/db?sslmode=disable"},
		{in: "postgres://h/db?search_path=pool_x", out: "postgres://h/db?search_path=pool_x"},
		{in: "postgres://u:p%40ss@h/db?pool_max_conns=6&sslmode=disable", out: "postgres://u:p%40ss@h/db?sslmode=disable", pool: pgPool{maxConns: 6}},
		{in: "postgres://h/db?pool_max_conn_idle_time=90s&pool_max_conns=2", out: "postgres://h/db", pool: pgPool{2, 90 * time.Second}},
		{in: "postgres://h/db?pool_max_conns=1", err: "pool_max_conns"},
		{in: "postgres://h/db?pool_max_conns=x", err: "pool_max_conns"},
		{in: "postgres://h/db?pool_max_conn_idle_time=0s", err: "pool_max_conn_idle_time"},
		{in: "postgres://h/db?pool_max_conn_idle_time=5", err: "pool_max_conn_idle_time"},
	} {
		out, pool, err := parsePGPool(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, want an error naming %s", c.in, err, c.err)
			}
			continue
		}
		if err != nil || out != c.out || pool != c.pool {
			t.Errorf("%s: %q %+v %v, want %q %+v", c.in, out, pool, err, c.out, c.pool)
		}
	}
}

// An engine's two pools on Postgres take the URL's cap: pgtest's 8, a
// quarter of it for the buckets.
func TestPGPoolCap(t *testing.T) {
	url := pgtest.NewDB(t)
	e, err := Open(Options{Path: url, BlobDir: t.TempDir(), AuthDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got, want := e.db.Stats().MaxOpenConnections, min(8, mainConns()); got != want {
		t.Errorf("main pool: %d connections, want pgtest's cap, %d", got, want)
	}
	if got, want := e.rate.store.db.Stats().MaxOpenConnections, min(2, bucketConns()); got != want {
		t.Errorf("bucket pool: %d connections, want %d", got, want)
	}
	bad := strings.Replace(url, "pool_max_conns=8", "pool_max_conns=1", 1)
	if _, err := Open(Options{Path: bad, BlobDir: t.TempDir(), AuthDisabled: true}); err == nil || !strings.Contains(err.Error(), "pool_max_conns") {
		t.Errorf("pool_max_conns=1: %v, want refused", err)
	}
}
