package derived

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
)

// Stored is one sealed view as it is served: the JWE (application/jose),
// or JSON carrying per-entry sealed values, with its Cache-Tag.
type Stored struct {
	Body []byte
	JSON bool   // Content-Type application/json rather than application/jose
	Tags string // Cache-Tag, comma-separated
}

// Execer runs statements (a *sql.DB or *sql.Tx).
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Cache stores sealed views, so that a view is sealed once and then served
// unchanged (§E.2.6 "stored once, served forever"), across restarts: every
// view is kept in the service's database (ciphertext only), keyed by view,
// with an in-memory front of at most max entries. A view carries the cache
// tags of its response, and Purge removes the views a CDN purge of the same
// tags removes, so purges reach the stored views exactly as they reach
// cached copies. Views are retired when their scope's at moves on (the
// services only serve the current at).
//
// Tables:
//
//	sealed_views(view, scope, at, body, json, tags)
//	sealed_view_tags(tag, view)
type Cache struct {
	db *sql.DB // nil: memory only

	mu    sync.Mutex
	max   int
	m     map[string]cacheEntry
	order []string
}

type cacheEntry struct {
	scope, at string
	tags      map[string]bool
	s         Stored
}

var cacheCreate = []string{
	`CREATE TABLE IF NOT EXISTS sealed_views (view TEXT PRIMARY KEY, scope TEXT NOT NULL, at TEXT NOT NULL,
		body BLOB NOT NULL, json INTEGER NOT NULL, tags TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS sealed_views_scope ON sealed_views (scope, at)`,
	`CREATE TABLE IF NOT EXISTS sealed_view_tags (tag TEXT NOT NULL, view TEXT NOT NULL, PRIMARY KEY (tag, view)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS sealed_view_tags_view ON sealed_view_tags (view)`,
}

// CacheDropStmts drop the cache's tables (a service's rebuild).
var CacheDropStmts = []string{`DROP TABLE IF EXISTS sealed_views`, `DROP TABLE IF EXISTS sealed_view_tags`}

// NewCache returns a cache persisting to db (nil: memory only) with an
// in-memory front of at most max entries (default 4096). Call Init before
// use.
func NewCache(max int, db *sql.DB) *Cache {
	if max <= 0 {
		max = 4096
	}
	return &Cache{db: db, max: max, m: map[string]cacheEntry{}}
}

// Init creates the tables.
func (c *Cache) Init(ctx context.Context) error {
	if c.db == nil {
		return nil
	}
	for _, q := range cacheCreate {
		if _, err := c.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func splitTags(tags string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Split(tags, ",") {
		if t != "" {
			out[t] = true
		}
	}
	return out
}

// Get returns the stored view.
func (c *Cache) Get(ctx context.Context, view string) (Stored, bool) {
	c.mu.Lock()
	e, ok := c.m[view]
	c.mu.Unlock()
	if ok || c.db == nil {
		return e.s, ok
	}
	var s Stored
	var scope, at string
	err := c.db.QueryRowContext(ctx, `SELECT scope, at, body, json, tags FROM sealed_views WHERE view = ?`, view).
		Scan(&scope, &at, &s.Body, &s.JSON, &s.Tags)
	if err != nil {
		return Stored{}, false
	}
	c.remember(view, cacheEntry{scope: scope, at: at, tags: splitTags(s.Tags), s: s})
	return s, true
}

// Put stores s as view (of scope, as of at) unless the view is already
// stored, and returns what is stored: the first writer wins, so every
// reader gets the same bytes. A failure to persist is returned with s,
// which is still served.
func (c *Cache) Put(ctx context.Context, view, scope, at string, s Stored) (Stored, error) {
	if old, ok := c.Get(ctx, view); ok {
		return old, nil
	}
	if c.db != nil {
		tx, err := c.db.BeginTx(ctx, nil)
		if err != nil {
			return s, err
		}
		defer tx.Rollback()
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sealed_views (view, scope, at, body, json, tags) VALUES (?, ?, ?, ?, ?, ?)`,
			view, scope, at, s.Body, s.JSON, s.Tags)
		if err != nil {
			return s, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// A concurrent writer won.
			tx.Rollback()
			if old, ok := c.Get(ctx, view); ok {
				return old, nil
			}
			return s, errors.New("derived: stored view vanished")
		}
		for t := range splitTags(s.Tags) {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sealed_view_tags (tag, view) VALUES (?, ?)`, t, view); err != nil {
				return s, err
			}
		}
		if err := tx.Commit(); err != nil {
			return s, err
		}
	}
	c.remember(view, cacheEntry{scope: scope, at: at, tags: splitTags(s.Tags), s: s})
	return s, nil
}

func (c *Cache) remember(view string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[view]; ok {
		return
	}
	for len(c.m) >= c.max && len(c.order) > 0 {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
	c.m[view] = e
	c.order = append(c.order, view)
}

// Purge removes every view carrying any of tags, in memory and through ex
// (the purge's apply transaction, or the database).
func (c *Cache) Purge(ctx context.Context, ex Execer, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, t := range tags {
		set[t] = true
	}
	c.drop(func(e cacheEntry) bool {
		for t := range e.tags {
			if set[t] {
				return true
			}
		}
		return false
	})
	if c.db == nil {
		return nil
	}
	for t := range set {
		if _, err := ex.ExecContext(ctx, `DELETE FROM sealed_views WHERE view IN (SELECT view FROM sealed_view_tags WHERE tag = ?)`, t); err != nil {
			return err
		}
		if _, err := ex.ExecContext(ctx, `DELETE FROM sealed_view_tags WHERE view IN (SELECT view FROM sealed_view_tags WHERE tag = ?)`, t); err != nil {
			return err
		}
	}
	return nil
}

// Retire removes the views of scope that aren't as of at.
func (c *Cache) Retire(ctx context.Context, ex Execer, scope, at string) error {
	c.drop(func(e cacheEntry) bool { return e.scope == scope && e.at != at })
	if c.db == nil {
		return nil
	}
	if _, err := ex.ExecContext(ctx, `DELETE FROM sealed_view_tags WHERE view IN (SELECT view FROM sealed_views WHERE scope = ? AND at <> ?)`, scope, at); err != nil {
		return err
	}
	_, err := ex.ExecContext(ctx, `DELETE FROM sealed_views WHERE scope = ? AND at <> ?`, scope, at)
	return err
}

func (c *Cache) drop(match func(cacheEntry) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := c.order[:0]
	for _, v := range c.order {
		e, ok := c.m[v]
		if !ok {
			continue
		}
		if match(e) {
			delete(c.m, v)
			continue
		}
		keep = append(keep, v)
	}
	c.order = keep
}
