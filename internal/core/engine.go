// Package core implements the patch log: identity, the write gate of §6.2,
// namespaces, batches, branches, deletion, pruning and the reads the HTTP
// API serves. It stores everything in SQLite with the layout of Addendum D.2.
//
// Resource writes and batches follow D.3: steps 1–6 of the gate run in a
// read transaction, outside the write lock; then one BEGIN IMMEDIATE
// transaction, serialised by an in-process mutex as well, re-checks that
// everything the decision depended on is unchanged and inserts (write.go
// writeOptimistic). That keeps invariant 6 exact: the configuration, heads
// and revocations a write is checked against are the ones it is inserted
// against. The rarer writes (config, branches, purges, prunes) still run
// their whole gate inside the write transaction; see README.
package core

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
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
	// HeadSnapshotMax is the largest head document kept as a head snapshot
	// (D.4, default 16 KiB). Larger heads are folded from snapshots.
	HeadSnapshotMax int
	// SnapshotEveryRevisions and SnapshotEveryBytes decide when an
	// intermediate snapshot is written (D.4, defaults 100 and 64 KiB).
	SnapshotEveryRevisions int
	SnapshotEveryBytes     int
	// Archiver stores pruning archives (§8.6). Nil means no destination is
	// configured: pruning then needs a * key and writes no archive, and
	// retention rules can't name an archive.
	Archiver Archiver
	// RetentionInterval is how often the retention applier runs (§8.6).
	// Zero means one hour; negative disables it.
	RetentionInterval time.Duration
	// Remote configures remote branches of this deployment (§G.3).
	Remote RemoteOptions
	// KeyStore wraps the data keys of encryption at rest (Addendum E.1).
	// Nil means none: a namespace document can't set encryption (422), and
	// content stored encrypted answers 500.
	KeyStore KeyStore
	// RotateEpochs, if positive, rotates every sealed namespace whose
	// current epoch is at least that old (§E.2.1), as RotateAuthor.
	RotateEpochs time.Duration
	// RotateOnRevoke rotates a sealed namespace's epoch (and its sealed
	// branches') right after a committed config write that adds a
	// revocation or removes or changes a key (§E.2.4).
	RotateOnRevoke bool
	// BeforeWriteLock is called by resource writes and batches after the
	// check phase (steps 1–6, outside the write lock) and before they take
	// the write lock and re-check (D.3). Tests use it to inject concurrent
	// writes deterministically; it may itself write through the engine.
	BeforeWriteLock func()
}

// RemoteOptions configure the branch side of remote branches (§G.3): how
// this deployment reaches the deployments holding their bases.
type RemoteOptions struct {
	// Resolve maps a base's origin to the endpoint requests go to. Nil
	// means the origin itself, http.DefaultClient and no bearer grant.
	Resolve func(origin string) (RemoteEndpoint, error)
	// IgnorePurges records purges in a base's log as notices only
	// (RemoteNotices) instead of applying them (§G.3 SHOULD follow).
	IgnorePurges bool
	// FollowInterval is how often bases' logs are followed and
	// registrations renewed. Zero means five minutes; negative disables the
	// background follower (SyncRemotes still works).
	FollowInterval time.Duration
	// Register registers each remote branch with its base (optional in
	// §G.3) when it is created, and renews the registration before it
	// expires. It needs read and export at the base.
	Register bool
	// RenewBefore is how long before expiry a registration is renewed.
	// Zero means seven days.
	RenewBefore time.Duration
}

// RemoteEndpoint is where and how a remote origin is reached.
type RemoteEndpoint struct {
	BaseURL    string       // e.g. https://cms.example; defaults to the origin
	HTTPClient *http.Client // nil: http.DefaultClient
	Bearer     string       // grant for the base namespace (read, and export to register)
	// Identity unwraps the keys of a sealed base (Addendum E.2) that the
	// base wraps to the grant's enc (§E.2.3, §G.5). Nil: raw keys only.
	Identity *ecdh.PrivateKey
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
	deks      *dekCache
	ekeys     epochKeyCache
	cfgMu     sync.Mutex
	cfgCache  map[int64]*Config
	stmts     stmtCache
	rc        readCache
	stop      chan struct{}
	bg        sync.WaitGroup
	closeOnce sync.Once
	// retentionSkipped remembers retention rules already logged as
	// skipped for lack of an archive (§8.6), so each is logged once.
	retentionSkipped sync.Map
}

// Open opens or creates the database.
func Open(opt Options) (*Engine, error) {
	if opt.Limits == (Limits{}) {
		opt.Limits = DefaultLimits()
	}
	if opt.HeadSnapshotMax == 0 {
		opt.HeadSnapshotMax = 16 << 10
	}
	if opt.SnapshotEveryRevisions == 0 {
		opt.SnapshotEveryRevisions = 100
	}
	if opt.SnapshotEveryBytes == 0 {
		opt.SnapshotEveryBytes = 64 << 10
	}
	if opt.Maximums == (Limits{}) {
		opt.Maximums = opt.Limits
	}
	if opt.Limits.RemoteRegistration == 0 {
		opt.Limits.RemoteRegistration = DefaultLimits().RemoteRegistration
	}
	if opt.Maximums.RemoteRegistration == 0 {
		opt.Maximums.RemoteRegistration = opt.Limits.RemoteRegistration
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
	if opt.RetentionInterval == 0 {
		opt.RetentionInterval = time.Hour
	}
	e := &Engine{
		db:        db,
		opt:       opt,
		validator: schema.NewValidator(),
		hub:       newHub(),
		rate:      newRateLimiter(),
		docs:      newDocCache(4096),
		deks:      newDEKCache(4096),
		cfgCache:  map[int64]*Config{},
		stop:      make(chan struct{}),
	}
	if err := e.checkKeyStore(); err != nil {
		db.Close()
		return nil, err
	}
	if opt.RetentionInterval > 0 {
		e.bg.Add(1)
		go e.retentionLoop(opt.RetentionInterval)
	}
	if e.opt.Remote.FollowInterval == 0 {
		e.opt.Remote.FollowInterval = 5 * time.Minute
	}
	if e.opt.Remote.RenewBefore == 0 {
		e.opt.Remote.RenewBefore = 7 * 24 * time.Hour
	}
	if opt.RotateEpochs > 0 {
		e.bg.Add(1)
		go e.rotateLoop(opt.RotateEpochs)
	}
	if e.opt.Remote.FollowInterval > 0 {
		e.bg.Add(1)
		go e.remoteLoop(e.opt.Remote.FollowInterval)
	}
	return e, nil
}

// Close stops the retention applier and closes the database.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() { close(e.stop) })
	e.bg.Wait()
	e.stmts.close()
	return e.db.Close()
}

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
	ctx       context.Context
	e         *Engine
	now       time.Time
	write     bool
	notify    map[string]bool // namespaces whose logs changed
	tags      []string        // cache tags to purge after commit
	flushDocs bool
	// metaChanged marks a write that changes what reads may return beyond
	// a namespace's log: its configuration, or a purge (readcache.go).
	metaChanged bool
	docPuts     []docPut // documents to cache after commit
	// deps, when set, records what a write's check phase read that a
	// concurrent write could change (D.3 re-check).
	deps *writeDeps
	// kids maps an author written in this transaction to the key that
	// signed its grant's root block (actorID), recorded with namespace
	// entries (§F.3).
	kids map[int64]string
	// Encryption at rest (crypt.go): data keys created in this
	// transaction (cached once committed), whether a purge destroyed keys,
	// resources' levels, and the levels of shadows being created.
	newDEKs      map[int64][]byte
	flushDEKs    bool
	resLevels    map[int64]int
	shadowLevels map[string]int
	// Sealed namespaces (sealed.go): epoch keys created in this
	// transaction, whether a namespace purge destroyed some, and the
	// namespaces whose config change revoked access (rotate-on-revoke).
	newEpochKeys   map[epochRef][]byte
	flushEpochKeys bool
	rotate         []string
}

type docPut struct {
	id  ids.ID
	doc []byte
}

// read runs f in a read transaction.
func (e *Engine) read(ctx context.Context, f func(t *tx) error) (err error) {
	e.stmts.prepare(e.db)
	sqlTx, err := e.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer sqlTx.Rollback()
	defer func() {
		if p := recover(); p != nil {
			err = panicErr(p)
		}
		err = ctxErr(ctx, err)
	}()
	return f(&tx{Tx: sqlTx, ctx: ctx, e: e, now: e.now()})
}

// ctxErr reports a failure after ctx ended as the context's error: database/sql
// rolls a transaction back when its context is cancelled, so later statements
// fail with sql.ErrTxDone, which is not an internal error.
func ctxErr(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("%w (%v)", ctx.Err(), err)
	}
	return err
}

// panicErr turns a recovered panic (t.must) into an error, keeping a panicked
// error wrapped so constraint violations can be recognised (D.3).
func panicErr(p any) error {
	if pe, ok := p.(error); ok {
		return fmt.Errorf("internal error: %w", pe)
	}
	return fmt.Errorf("internal error: %v", p)
}

// update runs f in a write transaction and commits if it returns nil. A
// panic (t.must) rolls back and is returned as an error, so a failed write
// never leaves its transaction, and the connection, open.
func (e *Engine) update(ctx context.Context, f func(t *tx) error) error {
	rotate, err := e.update1(ctx, f)
	if err == nil && len(rotate) > 0 && e.opt.RotateOnRevoke {
		e.rotateAfterRevoke(rotate)
	}
	return err
}

func (e *Engine) update1(ctx context.Context, f func(t *tx) error) (rotate []string, err error) {
	e.stmts.prepare(e.db)
	e.mu.Lock()
	defer e.mu.Unlock()
	sqlTx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			sqlTx.Rollback()
			err = panicErr(p)
		}
		err = ctxErr(ctx, err)
	}()
	t := &tx{Tx: sqlTx, ctx: ctx, e: e, now: e.now(), write: true, notify: map[string]bool{}}
	if err := f(t); err != nil {
		sqlTx.Rollback()
		return nil, err
	}
	done := e.rc.commit(t)
	err = sqlTx.Commit()
	done()
	if err != nil {
		return nil, err
	}
	if t.flushEpochKeys {
		e.ekeys.flush()
	} else {
		for r, k := range t.newEpochKeys {
			e.ekeys.put(r, k)
		}
	}
	if t.flushDEKs {
		e.deks.flush()
	}
	if !t.flushDEKs {
		for res, k := range t.newDEKs {
			e.deks.put(res, k)
		}
	}
	// Caches, CDN purges and live readers learn of a write only once it has
	// committed.
	if t.flushDocs {
		e.docs.flush()
	} else {
		for _, d := range t.docPuts {
			e.docs.put(d.id, d.doc)
		}
	}
	if len(t.tags) > 0 {
		e.opt.Purger.PurgeTags(t.tags)
	}
	for ns := range t.notify {
		e.hub.publish(ns)
	}
	return t.rotate, nil
}

func (t *tx) must(err error) {
	if err != nil {
		panic(err)
	}
}

// authorID returns an author's row, inserting it in a write transaction. A
// read transaction (a write's check phase, a dry run) never writes: an
// unknown author is -1, which matches no row.
func (t *tx) authorID(name string) int64 {
	var id int64
	err := t.QueryRow(`SELECT author FROM authors WHERE name = ?`, name).Scan(&id)
	if err == nil {
		return id
	}
	if !t.write {
		if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
		return -1
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

// isShadow reports whether n is the hidden shadow of a remote branch
// (§G.3), holding the remote base's mirrored content. Its name starts with
// "~", which the §3.6 grammar excludes, so it can never be addressed or
// collide with a namespace.
func (n *nsRow) isShadow() bool { return strings.HasPrefix(n.name, "~") }

const nsCols = `ns, name, base, base_at, base_config_seq, frozen, purged, head_seq, config_seq`

func scanNS(row interface{ Scan(...any) error }) (*nsRow, error) {
	n := &nsRow{}
	var cfg sql.NullInt64
	err := row.Scan(&n.id, &n.name, &n.base, &n.baseAt, &n.baseConfigSeq, &n.frozen, &n.purged, &n.headSeq, &cfg)
	n.configSeq = cfg.Int64
	return n, err
}

// nsByName returns the namespace or nil. Shadows (§G.3) have no name that
// can be looked up: they are reached only through their remote branch.
func (t *tx) nsByName(name string) *nsRow {
	if strings.HasPrefix(name, "~") {
		return nil
	}
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	t.deps.addNS(n)
	return n
}

func (t *tx) nsByID(id int64) *nsRow {
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE ns = ?`, id))
	t.must(err)
	t.deps.addNS(n)
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
	var kid any
	if k, ok := t.kids[author]; ok {
		kid = k
	}
	r, err := t.Exec(`INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, kid) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		n.id, id[:], prevSeq, kind, nullInt(res), nullInt(targetSeq), string(body), configSeq, author, t.now.UnixMilli(), kid)
	t.must(err)
	seq, _ := r.LastInsertId()
	_, err = t.Exec(`UPDATE namespaces SET head_seq = ?, config_seq = ? WHERE ns = ?`, seq, configSeq, n.id)
	t.must(err)
	n.headSeq = sql.NullInt64{Int64: seq, Valid: true}
	if n.configSeq != configSeq {
		t.metaChanged = true
	}
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

// cacheDoc caches a document by revision id: at once in a read transaction,
// after commit in a write transaction, so a write that rolls back never
// reaches the cache.
func (t *tx) cacheDoc(id ids.ID, doc []byte) {
	if t.write {
		t.docPuts = append(t.docPuts, docPut{id, doc})
		return
	}
	t.e.docs.put(id, doc)
}

func (c *docCache) flush() {
	c.mu.Lock()
	c.m = map[ids.ID][]byte{}
	c.mu.Unlock()
}

// FlushCaches drops in-memory document caches, so reads fold from storage
// (tests, and after restoring archived history).
func (e *Engine) FlushCaches() { e.docs.flush() }
