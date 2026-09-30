package core

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
)

// maxStmts bounds the prepared statements kept: queries are constant
// strings, except a few built with a variable number of placeholders.
const maxStmts = 512

// stmtCache keeps one prepared statement per query text. database/sql
// prepares it once per connection and a transaction reuses that, so a
// query is parsed once rather than on every execution (parsing was most of
// the cost of a small read).
//
// Statements are prepared between transactions, never inside one: an
// in-memory database has a single connection, which the transaction holds,
// so preparing on the database from inside it would wait forever. A query
// first seen in a transaction runs unprepared and is prepared before the
// next transaction begins.
type stmtCache struct {
	mu      sync.Mutex
	m       map[string]*sql.Stmt
	wanted  map[string]bool
	pending atomic.Bool
	closed  bool
}

// get returns the statement for q, or nil (and notes q) if it isn't
// prepared yet.
func (c *stmtCache) get(q string) *sql.Stmt {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.m[q]; s != nil || c.closed || len(c.m)+len(c.wanted) >= maxStmts {
		return s
	}
	if c.wanted == nil {
		c.wanted = map[string]bool{}
	}
	c.wanted[q] = true
	c.pending.Store(true)
	return nil
}

// prepare prepares the queries noted since the last call. It must be called
// outside any transaction, and doesn't hold the lock while preparing, so
// transactions of other goroutines keep using the cache meanwhile.
func (c *stmtCache) prepare(db *sql.DB) {
	if !c.pending.Load() {
		return
	}
	c.mu.Lock()
	qs := make([]string, 0, len(c.wanted))
	for q := range c.wanted {
		qs = append(qs, q)
	}
	c.wanted = nil
	c.pending.Store(false)
	c.mu.Unlock()
	for _, q := range qs {
		s, err := db.Prepare(q)
		if err != nil {
			// Left unprepared: the query reports its own error.
			continue
		}
		c.mu.Lock()
		if c.closed || c.m[q] != nil {
			s.Close()
		} else {
			if c.m == nil {
				c.m = map[string]*sql.Stmt{}
			}
			c.m[q] = s
		}
		c.mu.Unlock()
	}
}

func (c *stmtCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.m {
		s.Close()
	}
	c.m, c.wanted, c.closed = nil, nil, true
}

// QueryRow, Query and Exec shadow the embedded *sql.Tx's, running cached
// prepared statements within the transaction. Like sql.Tx's, they use no
// context of their own: the transaction's context already ends it.

func (t *tx) QueryRow(q string, args ...any) *sql.Row {
	if s := t.e.stmts.get(q); s != nil {
		return t.Tx.StmtContext(context.Background(), s).QueryRow(args...)
	}
	return t.Tx.QueryRow(q, args...)
}

func (t *tx) Query(q string, args ...any) (*sql.Rows, error) {
	if s := t.e.stmts.get(q); s != nil {
		return t.Tx.StmtContext(context.Background(), s).Query(args...)
	}
	return t.Tx.Query(q, args...)
}

func (t *tx) Exec(q string, args ...any) (sql.Result, error) {
	if s := t.e.stmts.get(q); s != nil {
		return t.Tx.StmtContext(context.Background(), s).Exec(args...)
	}
	return t.Tx.Exec(q, args...)
}
