package core

import (
	"database/sql"
	"fmt"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Connection pools on Postgres (D.8).
//
// An instance opens two pools on the database: the main one, of up to
// 4 × GOMAXPROCS connections (mainConns), and the rate buckets', of a
// quarter of that, at least 2 (bucketConns, ratebuckets.go). Each keeps
// the connections it opened, idle, for the next request. Two query
// parameters of the URL, the names pgxpool gives them, change that; they
// are removed from the URL before it reaches pgx, which would send them
// to the server as settings:
//
//   - pool_max_conns=N caps the main pool at N connections, at least 2
//     (it holds one for the background loops' leader lock, pglock.go),
//     and the bucket pool at a quarter of N, at least 2;
//   - pool_max_conn_idle_time=D (a Go duration such as 5m) closes a
//     connection that has been idle for longer than D.
//
// The test suite's databases carry both (pgtest): it starts hundreds of
// engines, dozens at once, whose pools would otherwise grow with the
// runner's CPUs and keep every connection they opened.
type pgPool struct {
	maxConns    int
	maxIdleTime time.Duration
}

// The pool parameters of a Postgres URL.
const (
	poolMaxConns    = "pool_max_conns"
	poolMaxIdleTime = "pool_max_conn_idle_time"
)

// parsePGPool returns the URL without its pool parameters, and their
// values. A URL without them is returned as it is.
func parsePGPool(raw string) (string, pgPool, error) {
	var p pgPool
	if !strings.Contains(raw, "pool_") {
		return raw, p, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", p, err
	}
	q := u.Query()
	if !q.Has(poolMaxConns) && !q.Has(poolMaxIdleTime) {
		return raw, p, nil
	}
	if q.Has(poolMaxConns) {
		v := q.Get(poolMaxConns)
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 {
			return "", p, fmt.Errorf("%s=%q: want an integer of at least 2", poolMaxConns, v)
		}
		p.maxConns = n
	}
	if q.Has(poolMaxIdleTime) {
		v := q.Get(poolMaxIdleTime)
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return "", p, fmt.Errorf("%s=%q: want a positive duration, such as 5m", poolMaxIdleTime, v)
		}
		p.maxIdleTime = d
	}
	q.Del(poolMaxConns)
	q.Del(poolMaxIdleTime)
	u.RawQuery = q.Encode()
	return u.String(), p, nil
}

// sizeMain sizes the main pool (mainConns).
func (p pgPool) sizeMain(db *sql.DB) {
	p.size(db, mainConns(), p.maxConns)
}

// sizeBuckets sizes the bucket pool (bucketConns).
func (p pgPool) sizeBuckets(db *sql.DB) {
	limit := 0
	if p.maxConns > 0 {
		limit = max(2, p.maxConns/4)
	}
	p.size(db, bucketConns(), limit)
}

// size sets db's pool to n connections, or limit if lower (and not 0),
// all kept idle until the idle time, if any, passes.
func (p pgPool) size(db *sql.DB, n, limit int) {
	if limit > 0 {
		n = min(n, limit)
	}
	db.SetMaxOpenConns(n)
	db.SetMaxIdleConns(n)
	if p.maxIdleTime > 0 {
		db.SetConnMaxIdleTime(p.maxIdleTime)
	}
}

// mainConns is the size of the main pool on Postgres, as of a SQLite
// file's (openSQLite).
func mainConns() int { return 4 * runtime.GOMAXPROCS(0) }
