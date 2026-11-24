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
// An instance opens three pools on the database: the main one, of
// 4 × GOMAXPROCS connections by default (mainConns), and two small ones of
// a quarter of the main pool's size, at least 2 (sideConns): the rate
// buckets' (ratebuckets.go) and the group commits' (commitPool,
// groupcommit.go). Each keeps the connections it opened, idle, for the
// next request. Two query parameters of the URL, the names pgxpool gives
// them, change that; they are removed from the URL before it reaches pgx,
// which would send them to the server as settings:
//
//   - pool_max_conns=N sets the main pool to N connections, at least 2
//     (it holds one for the background loops' leader lock, pglock.go),
//     whatever the CPUs, and each small pool to a quarter of N, at least
//     2. A connection mostly waits on a round trip to the server, not on
//     the instance's CPU: on RDS a 4-vCPU instance's 16 connections
//     limited it to about 3,000 writes a second while Postgres sat mostly
//     idle, and 64 took it to about 4,600 (docs/CAPACITY.md, "Several
//     namespaces on one database"). Raise it for a database far from the
//     instance; keep the sum of every instance's pools under the
//     server's max_connections;
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
// values. A URL without them is returned as it is, but for a Spanner
// URL's scheme, which becomes postgres:// (pgxURL).
func parsePGPool(raw string) (string, pgPool, error) {
	var p pgPool
	raw = pgxURL(raw)
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

// mainSize is the size of the main pool: pool_max_conns, or mainConns.
func (p pgPool) mainSize() int {
	if p.maxConns > 0 {
		return p.maxConns
	}
	return mainConns()
}

// sideSize is the size of the bucket pool and of the commit pool: a
// quarter of the main pool's, at least 2 (sideConns).
func (p pgPool) sideSize() int { return sideConns(p.mainSize()) }

// sizeMain sizes the main pool (mainSize).
func (p pgPool) sizeMain(db *sql.DB) { p.size(db, p.mainSize()) }

// sizeSide sizes a bucket or commit pool (sideSize).
func (p pgPool) sizeSide(db *sql.DB) { p.size(db, p.sideSize()) }

// size sets db's pool to n connections, all kept idle until the idle
// time, if any, passes.
func (p pgPool) size(db *sql.DB, n int) {
	db.SetMaxOpenConns(n)
	db.SetMaxIdleConns(n)
	if p.maxIdleTime > 0 {
		db.SetConnMaxIdleTime(p.maxIdleTime)
	}
}

// mainConns is the size of the main pool on Postgres without
// pool_max_conns, as of a SQLite file's (openSQLite).
func mainConns() int { return 4 * runtime.GOMAXPROCS(0) }

// sideConns is the size of a small pool beside a main pool of main
// connections: a quarter of it, at least two (a bucket sweep holds one).
// A draw is one short statement, and a group commit one transaction for
// up to GroupCommit writes: a fraction of the round trips of the checks
// on the main pool.
func sideConns(main int) int { return max(2, main/4) }
