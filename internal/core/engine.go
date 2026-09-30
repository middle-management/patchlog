// Package core implements the patch log: identity, the write gate of §6.2,
// namespaces, batches, branches, deletion, pruning and the reads the HTTP
// API serves. It stores everything in SQLite with the layout of Addendum D.2.
//
// Every write runs inside one BEGIN IMMEDIATE transaction, serialised by an
// in-process mutex as well. That keeps the gate simple and exact: the
// configuration, heads and revocations a write is checked against are the
// ones it is inserted against (invariant 6). The cost is that validation runs
// inside the write lock, which D.3 avoids by re-checking; see README.
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// Options configure an Engine.
type Options struct {
	// Path of the SQLite database, or ":memory:".
	Path string
	// Origin is the deployment's canonical origin (§G.1), e.g. https://cms.example.
	Origin string
	// AuthDisabled accepts every request (development only). The author is
	// taken from X-Author.
	AuthDisabled bool
	// OperatorKeys may create namespaces (§C.4 bootstrapping). They act as
	// keys with can ["*"] for namespace creation only.
	OperatorKeys []grant.Key
	// Limits are the namespace defaults of §6.6.
	Limits Limits
	// Maximums are the deployment maximums; a namespace can set its limits
	// up to them (and allowances too). Zero means equal to Limits.
	Maximums Limits
	// LongPollInterval is the interval of §7.7 (default 20s).
	LongPollInterval time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Purger receives cache-tag purges (§9). Nil logs them.
	Purger Purger
}

// Purger purges CDN cache tags.
type Purger interface{ PurgeTags(tags []string) }

type logPurger struct{}

func (logPurger) PurgeTags(tags []string) { log.Printf("cdn purge %v", tags) }

// Engine is the patch-log service.
type Engine struct {
	db        *sql.DB
	opt       Options
	mu        sync.Mutex // serialises write transactions
	validator *schema.Validator
	hub       *hub
	rate      *rateLimiter
	docs      *docCache
	cfgMu     sync.Mutex
	cfgCache  map[int64]*Config
}

// Open opens or creates the database.
func Open(opt Options) (*Engine, error) {
	if opt.Limits == (Limits{}) {
		opt.Limits = DefaultLimits()
	}
	if opt.Maximums == (Limits{}) {
		opt.Maximums = opt.Limits
	}
	if opt.LongPollInterval == 0 {
		opt.LongPollInterval = 20 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Purger == nil {
		opt.Purger = logPurger{}
	}
	db, err := openDB(opt.Path)
	if err != nil {
		return nil, err
	}
	return &Engine{
		db:        db,
		opt:       opt,
		validator: schema.NewValidator(),
		hub:       newHub(),
		rate:      newRateLimiter(),
		docs:      newDocCache(4096),
		cfgCache:  map[int64]*Config{},
	}, nil
}

// Close closes the database.
func (e *Engine) Close() error { return e.db.Close() }

// Origin is the deployment origin.
func (e *Engine) Origin() string { return e.opt.Origin }

// LongPollInterval is the §7.7 interval.
func (e *Engine) LongPollInterval() time.Duration { return e.opt.LongPollInterval }

// Limits are the deployment maximums, which bound request bodies.
func (e *Engine) Limits() Limits { return e.opt.Maximums }

// parseConfig parses a namespace document with this deployment's limits.
func (e *Engine) parseConfig(doc any) (*Config, error) {
	return parseConfig(doc, e.opt.Limits, e.opt.Maximums)
}

func (e *Engine) now() time.Time { return e.opt.Now().UTC() }

// Error is an API error: an HTTP status and the JSON body of §12.
type Error struct {
	Status int
	Body   map[string]any
	Header http.Header
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d %v", e.Status, e.Body)
}

// Code is the body's code.
func (e *Error) Code() string { s, _ := e.Body["code"].(string); return s }

func apiErr(status int, code string, kv ...any) *Error {
	b := map[string]any{"code": code}
	for i := 0; i+1 < len(kv); i += 2 {
		b[kv[i].(string)] = kv[i+1]
	}
	return &Error{Status: status, Body: b}
}

func badInput(msg string) *Error  { return apiErr(400, "bad_input", "message", msg) }
func notFound() *Error            { return apiErr(404, "not_found") }
func gone(kv ...any) *Error       { return apiErr(410, "gone", kv...) }
func invalid(msg string) *Error   { return apiErr(422, "invalid", "message", msg) }
func forbidden(msg string) *Error { return apiErr(403, "forbidden", "message", msg) }
func limitErr(status int, msg string) *Error {
	return apiErr(status, "limit", "message", msg)
}

// tx is one database transaction with the engine's helpers.
type tx struct {
	*sql.Tx
	e         *Engine
	now       time.Time
	write     bool
	notify    map[string]bool // namespaces whose logs changed
	tags      []string        // cache tags to purge after commit
	flushDocs bool
}

// read runs f in a read transaction.
func (e *Engine) read(ctx context.Context, f func(t *tx) error) (err error) {
	sqlTx, err := e.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer sqlTx.Rollback()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error: %v", p)
		}
	}()
	return f(&tx{Tx: sqlTx, e: e, now: e.now()})
}

// update runs f in a write transaction and commits if it returns nil. A
// panic (t.must) rolls back and is returned as an error, so a failed write
// never leaves its transaction, and the connection, open.
func (e *Engine) update(ctx context.Context, f func(t *tx) error) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sqlTx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			sqlTx.Rollback()
			err = fmt.Errorf("internal error: %v", p)
		}
	}()
	t := &tx{Tx: sqlTx, e: e, now: e.now(), write: true, notify: map[string]bool{}}
	if err := f(t); err != nil {
		sqlTx.Rollback()
		return err
	}
	if err := sqlTx.Commit(); err != nil {
		return err
	}
	if t.flushDocs {
		e.docs.flush()
	}
	if len(t.tags) > 0 {
		e.opt.Purger.PurgeTags(t.tags)
	}
	for ns := range t.notify {
		e.hub.publish(ns)
	}
	return nil
}

func (t *tx) must(err error) {
	if err != nil {
		panic(err)
	}
}

func (t *tx) authorID(name string) int64 {
	var id int64
	err := t.QueryRow(`SELECT author FROM authors WHERE name = ?`, name).Scan(&id)
	if err == nil {
		return id
	}
	res, err := t.Exec(`INSERT INTO authors (name) VALUES (?)`, name)
	t.must(err)
	id, _ = res.LastInsertId()
	return id
}

func (t *tx) authorName(id int64) string {
	var s string
	t.must(t.QueryRow(`SELECT name FROM authors WHERE author = ?`, id).Scan(&s))
	return s
}

// nsRow is a namespace.
type nsRow struct {
	id            int64
	name          string
	base          sql.NullInt64
	baseAt        sql.NullInt64
	baseConfigSeq sql.NullInt64
	frozen        bool
	purged        bool
	headSeq       sql.NullInt64
	configSeq     int64
}

func (n *nsRow) isBranch() bool { return n.base.Valid }

const nsCols = `ns, name, base, base_at, base_config_seq, frozen, purged, head_seq, config_seq`

func scanNS(row interface{ Scan(...any) error }) (*nsRow, error) {
	n := &nsRow{}
	var cfg sql.NullInt64
	err := row.Scan(&n.id, &n.name, &n.base, &n.baseAt, &n.baseConfigSeq, &n.frozen, &n.purged, &n.headSeq, &cfg)
	n.configSeq = cfg.Int64
	return n, err
}

// nsByName returns the namespace or nil.
func (t *tx) nsByName(name string) *nsRow {
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	return n
}

func (t *tx) nsByID(id int64) *nsRow {
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE ns = ?`, id))
	t.must(err)
	return n
}

// config returns the parsed namespace document of an ns_config row.
func (t *tx) config(seq int64) *Config {
	t.e.cfgMu.Lock()
	c, ok := t.e.cfgCache[seq]
	t.e.cfgMu.Unlock()
	if ok {
		return c
	}
	var doc string
	t.must(t.QueryRow(`SELECT doc FROM ns_config WHERE seq = ?`, seq).Scan(&doc))
	c, err := t.e.parseConfig(jsonv.MustParse([]byte(doc)))
	if err != nil {
		panic(fmt.Errorf("stored namespace document %d is invalid: %w", seq, err))
	}
	t.e.cfgMu.Lock()
	t.e.cfgCache[seq] = c
	t.e.cfgMu.Unlock()
	return c
}

func (t *tx) configID(seq int64) ids.ID {
	var b []byte
	t.must(t.QueryRow(`SELECT id FROM ns_config WHERE seq = ?`, seq).Scan(&b))
	return ids.FromBytes(b)
}

func (t *tx) nsLogID(seq int64) ids.ID {
	var b []byte
	t.must(t.QueryRow(`SELECT id FROM ns_log WHERE seq = ?`, seq).Scan(&b))
	return ids.FromBytes(b)
}

// nsLogSeq finds an ns_log entry of a namespace by id.
func (t *tx) nsLogSeq(ns int64, id ids.ID) (int64, bool) {
	var seq int64
	err := t.QueryRow(`SELECT seq FROM ns_log WHERE ns = ? AND id = ?`, ns, id[:]).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false
	}
	t.must(err)
	return seq, true
}

// appendNS appends an entry to a namespace chain (§3.5) and returns its seq
// and id.
func (t *tx) appendNS(n *nsRow, entry map[string]any, res *int64, targetSeq *int64, configSeq int64, author int64) (int64, ids.ID) {
	var prev *ids.ID
	var prevSeq any
	if n.headSeq.Valid {
		p := t.nsLogID(n.headSeq.Int64)
		prev = &p
		prevSeq = n.headSeq.Int64
	}
	body := jsonv.Canonical(entry)
	id := ids.Hash(prev, body)
	kind := nsKindCode(entry["kind"].(string))
	r, err := t.Exec(`INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		n.id, id[:], prevSeq, kind, nullInt(res), nullInt(targetSeq), string(body), configSeq, author, t.now.UnixMilli())
	t.must(err)
	seq, _ := r.LastInsertId()
	_, err = t.Exec(`UPDATE namespaces SET head_seq = ?, config_seq = ? WHERE ns = ?`, seq, configSeq, n.id)
	t.must(err)
	n.headSeq = sql.NullInt64{Int64: seq, Valid: true}
	n.configSeq = configSeq
	t.notify[n.name] = true
	return seq, id
}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func formatTime(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// docCache caches documents by revision id: an id determines its document
// everywhere (§3.3). Values are canonical bytes.
type docCache struct {
	mu  sync.Mutex
	max int
	m   map[ids.ID][]byte
}

func newDocCache(max int) *docCache { return &docCache{max: max, m: map[ids.ID][]byte{}} }

func (c *docCache) get(id ids.ID) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.m[id]
	return b, ok
}

func (c *docCache) put(id ids.ID, b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for k := range c.m { // random eviction
			delete(c.m, k)
			if len(c.m) < c.max*3/4 {
				break
			}
		}
	}
	c.m[id] = b
}

func (c *docCache) flush() {
	c.mu.Lock()
	c.m = map[ids.ID][]byte{}
	c.mu.Unlock()
}
