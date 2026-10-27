package core

import (
	"strings"
	"testing"
	"time"
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
