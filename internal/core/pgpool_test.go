package core

import (
	"fmt"
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

// pool_max_conns sets the main pool's size, above 4 × GOMAXPROCS too, and
// the bucket and commit pools are a quarter of it, at least 2; without it
// the main pool is 4 × GOMAXPROCS.
func TestPGPoolSizes(t *testing.T) {
	for _, c := range []struct {
		pool       pgPool
		main, side int
	}{
		{pgPool{}, mainConns(), max(2, mainConns()/4)},
		{pgPool{maxConns: 2}, 2, 2},
		{pgPool{maxConns: 8}, 8, 2},
		{pgPool{maxConns: 64}, 64, 16},
		{pgPool{maxConns: 4*mainConns() + 3}, 4*mainConns() + 3, mainConns()},
	} {
		if got, side := c.pool.mainSize(), c.pool.sideSize(); got != c.main || side != c.side {
			t.Errorf("%+v: main %d, side %d; want %d, %d", c.pool, got, side, c.main, c.side)
		}
	}
}

// An engine's pools on Postgres take the URL's size: pgtest's 8, and a
// quarter of it, at least 2, for the buckets and the group commits; a
// size above 4 × GOMAXPROCS raises the main pool.
func TestPGPoolSize(t *testing.T) {
	url := pgtest.NewDB(t)
	pools := func(url string) (main, buckets, commits int) {
		t.Helper()
		e, err := Open(Options{Path: url, BlobDir: t.TempDir(), AuthDisabled: true})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		return e.db.Stats().MaxOpenConnections, e.rate.store.db.Stats().MaxOpenConnections, e.commits.db.Stats().MaxOpenConnections
	}
	if m, b, c := pools(url); m != 8 || b != 2 || c != 2 {
		t.Errorf("pgtest's pool_max_conns=8: main %d, buckets %d, commits %d; want 8, 2, 2", m, b, c)
	}
	big := 4*mainConns() + 8
	raised := strings.Replace(url, "pool_max_conns=8", fmt.Sprintf("pool_max_conns=%d", big), 1)
	if m, b, c := pools(raised); m != big || b != big/4 || c != big/4 {
		t.Errorf("pool_max_conns=%d: main %d, buckets %d, commits %d; want %d, %d, %d", big, m, b, c, big, big/4, big/4)
	}
	bad := strings.Replace(url, "pool_max_conns=8", "pool_max_conns=1", 1)
	if _, err := Open(Options{Path: bad, BlobDir: t.TempDir(), AuthDisabled: true}); err == nil || !strings.Contains(err.Error(), "pool_max_conns") {
		t.Errorf("pool_max_conns=1: %v, want refused", err)
	}
}
