package derived

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/dbmigrate"
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
// A purge can change what a view shows at an unchanged at (a service's
// backfill), so a view read or computed before a purge must not outlive
// it, as kept.Store has it: a view read from the database is remembered,
// and one computed since Generation is stored (PutSince), only if no
// purge since then carried one of its tags. Purge runs in the purging
// transaction, so a read of the database may still see, until it commits,
// the rows it deletes: a caller purging in a transaction calls Purged
// once it commits.
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
	// gen counts the purges so far (Generation), and purges holds the
	// tags of the last ones, oldest first, at most maxPurges.
	gen    uint64
	purges []map[string]bool
}

// maxPurges is how many purges a Cache recalls the tags of: a view read
// or computed before more purges than that counts as purged.
const maxPurges = 1024

type cacheEntry struct {
	scope, at string
	tags      map[string]bool
	s         Stored
}

// migrations holds the cache's tables, applied under the namespace
// "derived" (package dbmigrate).
//
//go:embed migrations
var migrations embed.FS

// CacheResetStmts empty the cache's tables (a service's rebuild).
var CacheResetStmts = []string{`DELETE FROM sealed_views`, `DELETE FROM sealed_view_tags`}

// NewCache returns a cache persisting to db (nil: memory only) with an
// in-memory front of at most max entries (default 4096). Call Init before
// use.
func NewCache(max int, db *sql.DB) *Cache {
	if max <= 0 {
		max = 4096
	}
	return &Cache{db: db, max: max, m: map[string]cacheEntry{}}
}

// Init creates or migrates the tables.
func (c *Cache) Init(ctx context.Context) error {
	if c.db == nil {
		return nil
	}
	return dbmigrate.Migrate(ctx, c.db, migrations, "derived")
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

// Generation is the number of purges so far. Take it before reading what a
// view shows, and store the view with PutSince.
func (c *Cache) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// Get returns the stored view.
func (c *Cache) Get(ctx context.Context, view string) (Stored, bool) {
	c.mu.Lock()
	e, ok := c.m[view]
	gen := c.gen
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
	// A purge since may not have committed when the row was read: it is
	// served this once, and read again next time.
	c.remember(view, gen, cacheEntry{scope: scope, at: at, tags: splitTags(s.Tags), s: s})
	return s, true
}

// Put stores s as view (of scope, as of at) unless the view is already
// stored, and returns what is stored: the first writer wins, so every
// reader gets the same bytes. A failure to persist is returned with s,
// which is still served.
func (c *Cache) Put(ctx context.Context, view, scope, at string, s Stored) (Stored, error) {
	return c.PutSince(ctx, view, scope, at, c.Generation(), s)
}

// PutSince is Put for a view computed from what was read after gen
// (Generation): one that a purge since then may have changed, one carrying
// any of its tags, isn't stored, and is returned to be served as it is.
func (c *Cache) PutSince(ctx context.Context, view, scope, at string, gen uint64, s Stored) (Stored, error) {
	if old, ok := c.Get(ctx, view); ok {
		return old, nil
	}
	tags := splitTags(s.Tags)
	if c.purgedSince(gen, tags) {
		return s, nil
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
		for t := range tags {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sealed_view_tags (tag, view) VALUES (?, ?)`, t, view); err != nil {
				return s, err
			}
		}
		// The insert holds the database's write lock until the commit, so
		// a purge whose deletes are still to come (Purge counts it before
		// them) deletes this row after the commit, and one that has
		// committed is counted by now.
		if c.purgedSince(gen, tags) {
			return s, nil
		}
		if err := tx.Commit(); err != nil {
			return s, err
		}
	}
	c.remember(view, gen, cacheEntry{scope: scope, at: at, tags: tags, s: s})
	return s, nil
}

// remember keeps e as view in memory unless a purge since gen carried one
// of its tags.
func (c *Cache) remember(view string, gen uint64, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.purgedSinceLocked(gen, e.tags) {
		return
	}
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

func (c *Cache) purgedSince(gen uint64, tags map[string]bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.purgedSinceLocked(gen, tags)
}

// purgedSinceLocked reports whether a purge since generation gen carried
// one of tags, or may have: one no longer recalled (maxPurges) is taken
// to. Called with mu held.
func (c *Cache) purgedSinceLocked(gen uint64, tags map[string]bool) bool {
	n := c.gen - gen
	if n > uint64(len(c.purges)) {
		return true
	}
	for _, p := range c.purges[uint64(len(c.purges))-n:] {
		for t := range tags {
			if p[t] {
				return true
			}
		}
	}
	return false
}

// Purge removes every view carrying any of tags, in memory and through ex
// (the purge's apply transaction, or the database). With a transaction,
// call Purged once it commits: until then the rows it deletes are still
// read, and remembered.
func (c *Cache) Purge(ctx context.Context, ex Execer, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, t := range tags {
		set[t] = true
	}
	c.forget(set)
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
	// What was read before the deletes (committed already through the
	// database) and remembered since goes too.
	c.forget(set)
	return nil
}

// Purged drops from memory, again, the views carrying any of tags once the
// transaction Purge removed them in has committed: one read from the
// database meanwhile, or stored by a Put that committed before the
// purge's deletes, would otherwise be kept in memory, and served, after
// the purge (§E.2.6).
func (c *Cache) Purged(tags []string) {
	if len(tags) == 0 {
		return
	}
	set := map[string]bool{}
	for _, t := range tags {
		set[t] = true
	}
	c.forget(set)
}

// forget counts a purge of tags (Generation) and drops the views in memory
// carrying any of them.
func (c *Cache) forget(tags map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.purges = append(c.purges, tags)
	if len(c.purges) > maxPurges {
		c.purges = slices.Delete(c.purges, 0, len(c.purges)-maxPurges)
	}
	c.dropLocked(func(e cacheEntry) bool {
		for t := range e.tags {
			if tags[t] {
				return true
			}
		}
		return false
	})
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

// Drop removes, in memory and from the database, the stored views that
// match: by view, scope and form (json, as Stored.JSON). It is for a
// service's start, to drop views of a form a release no longer serves at
// their URLs (they would be served unchanged), and reads every stored
// view's key to decide.
func (c *Cache) Drop(ctx context.Context, match func(view, scope string, json bool) bool) error {
	c.mu.Lock()
	keep := c.order[:0]
	for _, v := range c.order {
		e, ok := c.m[v]
		if !ok {
			continue
		}
		if match(v, e.scope, e.s.JSON) {
			delete(c.m, v)
			continue
		}
		keep = append(keep, v)
	}
	c.order = keep
	c.mu.Unlock()
	if c.db == nil {
		return nil
	}
	rows, err := c.db.QueryContext(ctx, `SELECT view, scope, json FROM sealed_views`)
	if err != nil {
		return err
	}
	var views []string
	for rows.Next() {
		var view, scope string
		var json bool
		if err := rows.Scan(&view, &scope, &json); err != nil {
			rows.Close()
			return err
		}
		if match(view, scope, json) {
			views = append(views, view)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(views) == 0 {
		return nil
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, v := range views {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sealed_view_tags WHERE view = ?`, v); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sealed_views WHERE view = ?`, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c *Cache) drop(match func(cacheEntry) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropLocked(match)
}

func (c *Cache) dropLocked(match func(cacheEntry) bool) {
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
