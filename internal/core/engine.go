// Package core implements the patch log: identity, the write gate of §6.2,
// namespaces, batches, branches, deletion, pruning and the reads the HTTP
// API serves. It stores everything in SQLite with the layout of Addendum D.2,
// or in Postgres with the equivalent of Addendum D.8 (dialect.go).
//
// Resource writes and batches follow D.3: steps 1–6 of the gate run in a
// read transaction, outside the write lock; then one BEGIN IMMEDIATE
// transaction, serialised by an in-process mutex as well, re-checks that
// everything the decision depended on is unchanged and inserts (write.go
// writeOptimistic). That keeps invariant 6 exact: the configuration, heads
// and revocations a write is checked against are the ones it is inserted
// against. The rarer writes (config, branches, purges, prunes) still run
// their whole gate inside the write transaction; see README.
//
// On Postgres several instances may share the database: advisory locks
// per namespace replace the mutex (pglock.go), held shared by the writers
// of a namespace's resources, which check inside them and serialise only
// to append to the namespace chain; and a tailer tells each instance of
// every commit, for its live readers and caches (tailer.go).
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
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// Options configure an Engine.
type Options struct {
	// Path of the SQLite database, or ":memory:", or a Postgres URL
	// (postgres://…, Addendum D.8).
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
	// BeforeCommit is called by every write transaction, with its
	// context, after its work and right before it commits. Tests use it to
	// hold a write in flight (graceful shutdown); it must not write.
	BeforeCommit func(ctx context.Context)
	// LockedCheckBytes: on Postgres, a resource write or batch whose
	// patches are smaller than this, roughly as JSON, runs its check
	// inside its namespace's (shared) lock rather than first in a
	// transaction of its own (D.3), saving that transaction's and the
	// re-check's round trips. Zero means every write; negative, none.
	LockedCheckBytes int
	// BlobSweepInterval is how often pending blobs past blobGrace are
	// deleted (§7.8, SweepBlobs), and orphan blob files (SweepBlobFiles),
	// on the leader. Zero means ten minutes; negative disables it.
	BlobSweepInterval time.Duration
	// BlobDir is the directory blob bytes are stored in (blobstore.go).
	// Empty means "<Path>.blobs" for a SQLite file, and the database itself
	// for ":memory:" and Postgres. Instances sharing a Postgres database
	// must share the directory too.
	BlobDir string
	// TailInterval is how often the tailer polls the namespace logs on
	// Postgres (tailer.go, default 100 ms): it wakes live readers for
	// writes of other instances and invalidates in-memory caches.
	TailInterval time.Duration
	// RepurgeDelay is how long after a CDN tag purge (§8.3) it is sent
	// again, by a durable job on the leader (repurge.go, D.8): longer than
	// the read caches' staleness bound, the longest replica lag allowed and
	// the hard deadline of a response. Zero means three tail intervals plus
	// two minutes; negative disables the second purge.
	RepurgeDelay time.Duration
	// RepurgeInterval is how often the leader looks for second purges that
	// are due. Zero means ten seconds; negative disables the loop
	// (Repurge still sends them).
	RepurgeInterval time.Duration
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
	pg        bool // Postgres (Addendum D.8), not SQLite
	opt       Options
	mu        sync.Mutex // serialises write transactions
	blobs     blobStore
	validator *schema.Validator
	hub       *hub
	rate      *rateLimiter
	docs      *docCache
	ids       idCache
	deks      *dekCache
	ekeys     epochKeyCache
	cfgMu     sync.Mutex
	cfgCache  map[int64]*Config
	stmts     stmtCache
	rc        readCache
	stop      chan struct{}
	bg        sync.WaitGroup
	closeOnce sync.Once
	// grantRoots are the root sub and kid of stored grants (grantref.go).
	grantRoots grantRootCache
	// retentionSkipped remembers retention rules already logged as
	// skipped for lack of an archive (§8.6), so each is logged once.
	retentionSkipped sync.Map
	// Postgres: when the tailer's last successful poll started (since
	// epoch, plus one; tailer.go), and the leader connection of the
	// background loops (pglock.go).
	epoch      time.Time
	lastPoll   atomic.Int64
	leaderMu   sync.Mutex
	leaderConn *sql.Conn
	// afterWriteLock, if set, is called by resource writes and batches
	// once they hold the write lock, with the namespace (tests).
	afterWriteLock func(ns string)
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
	// Options from before blobs (§7.8) leave their limits zero.
	defaultBlobLimits(&opt.Limits, DefaultLimits())
	defaultBlobLimits(&opt.Maximums, opt.Limits)
	if opt.LongPollInterval == 0 {
		opt.LongPollInterval = 20 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Purger == nil {
		opt.Purger = logPurger{}
	}
	db, pg, err := openDB(opt.Path)
	if err != nil {
		return nil, err
	}
	blobs, err := openBlobStore(opt.BlobDir, opt.Path, pg)
	if err != nil {
		db.Close()
		return nil, err
	}
	if opt.RetentionInterval == 0 {
		opt.RetentionInterval = time.Hour
	}
	e := &Engine{
		db:        db,
		pg:        pg,
		opt:       opt,
		blobs:     blobs,
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
	if pg {
		if e.opt.TailInterval <= 0 {
			e.opt.TailInterval = 100 * time.Millisecond
		}
		s, err := e.tailStart(context.Background())
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("starting the tailer: %w", err)
		}
		e.epoch = time.Now()
		e.rc.fresh, e.rc.headTTL = e.fresh, e.freshFor()
		e.bg.Add(1)
		go e.tailLoop(s)
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
	if e.opt.BlobSweepInterval == 0 {
		e.opt.BlobSweepInterval = 10 * time.Minute
	}
	if e.opt.BlobSweepInterval > 0 {
		e.bg.Add(1)
		go e.blobSweepLoop(e.opt.BlobSweepInterval)
	}
	if opt.RotateEpochs > 0 {
		e.bg.Add(1)
		go e.rotateLoop(opt.RotateEpochs)
	}
	if e.opt.RepurgeDelay == 0 {
		e.opt.RepurgeDelay = 3*e.opt.TailInterval + 2*time.Minute
	}
	if e.opt.RepurgeInterval == 0 {
		e.opt.RepurgeInterval = 10 * time.Second
	}
	if e.opt.RepurgeDelay > 0 && e.opt.RepurgeInterval > 0 {
		e.bg.Add(1)
		go e.repurgeLoop(e.opt.RepurgeInterval)
	}
	if e.opt.Remote.FollowInterval > 0 {
		e.bg.Add(1)
		go e.remoteLoop(e.opt.Remote.FollowInterval)
	}
	return e, nil
}

// Close stops the background loops and closes the database.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() { close(e.stop) })
	e.bg.Wait()
	e.resign()
	e.stmts.close()
	return e.db.Close()
}

// Ping checks that the database is reachable (the /_ready check).
func (e *Engine) Ping(ctx context.Context) error { return e.db.PingContext(ctx) }

// SpecVersion is the version of the Patch Log specification this
// implementation follows, published at GET / as { "spec" } (§7.4), so tools
// that copy namespace documents between deployments can check it first.
const SpecVersion = "0.37"

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
	ctx    context.Context
	e      *Engine
	now    time.Time
	write  bool
	notify map[string]bool // namespaces whose logs changed
	tags   []string        // cache tags to purge after commit
	// lastNS is the seq of the last namespace entry this transaction
	// appended: what a CDN purge it sends is keyed on (repurge.go).
	lastNS    int64
	flushDocs bool
	// metaChanged marks a write that changes what reads may return beyond
	// a namespace's log: its configuration, or a purge (readcache.go).
	metaChanged bool
	docPuts     []docPut // documents to cache after commit
	// reqCreds are the request's grant and those of Source-Authorization,
	// for an in_use answer's referencing list (§6.1, the rule for other
	// namespaces of §7.5).
	reqCreds []Credentials
	// deps, when set, records what a write's check phase read that a
	// concurrent write could change (D.3 re-check).
	deps *writeDeps
	// rateDrawn, when set, records that a write drew its rate-limit tokens,
	// so a transaction run again doesn't draw them twice.
	rateDrawn *bool
	// memo and dirty: rows read in this transaction, and whether it has
	// written (memo.go).
	memo    memo
	dirty   bool
	ownRevs map[int64]revRow
	revIDs  map[int64]ids.ID
	// grants maps an author authenticated in this transaction under a
	// grant to that grant (actorID): the namespace entries written for it
	// record the grant's id (§5, §7.4, §C.3), unless serverWrites > 0,
	// while the transaction writes entries of its own, such as propagated
	// purges (§8.3), which record none. storedGrants are the grants stored
	// in it, and whether encrypted (storeGrant).
	grants       map[int64]*grant.Grant
	serverWrites int
	storedGrants map[ids.ID]bool
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
	// Postgres: the advisory locks held (pglock.go), the largest key among
	// them, and whether reading namespaces locks them (noLock > 0: no).
	locks  map[int32]lockMode
	maxKey int32
	// logLocks are the log locks held (logClass, D.8), maxLogKey the
	// largest, and logPlan the ones a restarted transaction takes in
	// ascending order at its first append (errRelock).
	logLocks  map[int32]bool
	maxLogKey int32
	logPlan   map[int32]bool
	noLock    int
	// sharedNS is the namespace a resource write or batch appends to
	// holding its lock only shared (pglock.go); 0 if none.
	sharedNS int64
	// exclusive makes a resource write or batch lock its namespace
	// exclusively, as other writes do (writeLocked's last attempt).
	exclusive bool
	// Blob files (blobstore.go): those this transaction stored, deleted
	// if it rolls back, and those whose rows it deleted, deleted once it
	// has committed.
	newFiles  []string
	dropFiles []string
}

type docPut struct {
	id  ids.ID
	doc []byte
}

// read runs f in a read transaction.
func (e *Engine) read(ctx context.Context, f func(t *tx) error) (err error) {
	e.stmts.prepare(e.db)
	opts := &sql.TxOptions{ReadOnly: true}
	if e.pg {
		// A read sees one snapshot, as in SQLite's WAL mode: READ
		// COMMITTED would see each statement's own.
		opts.Isolation = sql.LevelRepeatableRead
	}
	sqlTx, err := e.db.BeginTx(ctx, opts)
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
	if !e.pg {
		e.stmts.prepare(e.db)
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.updateOnce(ctx, f, nil, nil)
	}
	// Postgres: advisory locks instead of the mutex (pglock.go). A
	// transaction that rolled back to take its locks in order, or on a
	// deadlock or a shared row's unique violation, runs again.
	var want map[int32]lockMode
	var logs map[int32]bool
	for attempt := 1; ; attempt++ {
		rotate, err = e.updateOnce(ctx, f, want, logs)
		if err == nil || attempt == maxWriteAttempts || !retryable(err) || ctx.Err() != nil {
			return rotate, err
		}
		var rl *errRelock
		if errors.As(err, &rl) {
			want, logs = rl.want, rl.logs
		}
	}
}

// updateOnce runs f in one write transaction, first taking the advisory
// locks of want (Postgres), and the log locks of logs at its first append.
func (e *Engine) updateOnce(ctx context.Context, f func(t *tx) error, want map[int32]lockMode, logs map[int32]bool) (rotate []string, err error) {
	sqlTx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	t := &tx{Tx: sqlTx, ctx: ctx, e: e, now: e.now(), write: true, notify: map[string]bool{}}
	committing := false
	defer func() {
		if p := recover(); p != nil {
			sqlTx.Rollback()
			if !committing {
				e.removeFiles(t.newFiles)
			}
			err = panicErr(p)
		}
		err = ctxErr(ctx, err)
	}()
	t.lockAll(want)
	t.logPlan = logs
	if err := f(t); err != nil {
		sqlTx.Rollback()
		e.removeFiles(t.newFiles)
		return nil, err
	}
	if h := e.opt.BeforeCommit; h != nil {
		h(ctx)
	}
	if len(t.tags) > 0 {
		// The second purge, durable with the commit (repurge.go).
		t.queueRepurge()
	}
	inv := t.invalidation()
	if e.pg && inv.meta {
		// Other instances' tailers learn of it at their next poll, however
		// long older transactions hold back the log they follow (tailer.go).
		_, err := t.Tx.Exec(`UPDATE cache_gen SET gen = gen + 1 WHERE id = 1`)
		t.must(err)
	}
	e.rc.begin(inv)
	committing = true
	err = sqlTx.Commit()
	if err != nil {
		// Whether it committed may be unknown (a lost connection): the
		// files it stored are left to the sweep.
		e.rc.bump(inv)
		return nil, err
	}
	e.removeFiles(t.dropFiles)
	// Caches, CDN purges and live readers learn of a write only once it has
	// committed.
	e.invalidate(inv, false)
	if !t.flushEpochKeys {
		for r, k := range t.newEpochKeys {
			e.ekeys.put(r, k)
		}
	}
	if !t.flushDEKs {
		for res, k := range t.newDEKs {
			e.deks.put(res, k)
		}
	}
	if !t.flushDocs {
		for _, d := range t.docPuts {
			e.docs.put(d.id, d.doc)
		}
	}
	if len(t.tags) > 0 {
		e.opt.Purger.PurgeTags(t.tags)
	}
	return t.rotate, nil
}

// invalidation is what a committed write changed that in-memory state must
// learn of: the namespaces whose logs moved, and whether what reads may
// return changed beyond them (readcache.go), with the caches to flush.
type invalidation struct {
	nss                                  []string
	meta                                 bool
	flushDocs, flushDEKs, flushEpochKeys bool
}

func (t *tx) invalidation() invalidation {
	inv := invalidation{flushDocs: t.flushDocs, flushDEKs: t.flushDEKs, flushEpochKeys: t.flushEpochKeys}
	inv.meta = t.metaChanged || t.flushDocs || t.flushDEKs || t.flushEpochKeys
	for ns := range t.notify {
		inv.nss = append(inv.nss, ns)
	}
	return inv
}

// invalidate applies a committed write's invalidation: the read cache's
// generations, the document, data key and epoch key caches, and the live
// readers waiting on its namespaces. A local commit calls it right after
// committing, closing the read cache's bracket; on Postgres the tailer
// calls it (seen) for every commit of any instance it sees (tailer.go).
func (e *Engine) invalidate(inv invalidation, seen bool) {
	if seen {
		e.rc.see(inv)
	} else {
		e.rc.bump(inv)
	}
	if inv.flushEpochKeys {
		e.ekeys.flush()
	}
	if inv.flushDEKs {
		e.deks.flush()
	}
	if inv.flushDocs {
		e.docs.flush()
	}
	for _, ns := range inv.nss {
		e.hub.publish(ns)
	}
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
	if v, ok := t.e.ids.authors.Load(name); ok {
		return v.(int64)
	}
	var id int64
	err := t.QueryRow(`SELECT author FROM authors WHERE name = ?`, name).Scan(&id)
	if err == nil {
		t.learnAuthor(name, id)
		return id
	}
	if !t.write {
		if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
		return -1
	}
	// Authors are shared by all namespaces: a concurrent writer on
	// Postgres may insert the same one first.
	t.wrote()
	err = t.QueryRow(`INSERT INTO authors (name) VALUES (?) ON CONFLICT DO NOTHING RETURNING author`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = t.QueryRow(`SELECT author FROM authors WHERE name = ?`, name).Scan(&id)
	}
	t.must(err)
	return id
}

func (t *tx) authorName(id int64) string {
	if v, ok := t.e.ids.authorNames.Load(id); ok {
		return v.(string)
	}
	var s string
	t.must(t.QueryRow(`SELECT name FROM authors WHERE author = ?`, id).Scan(&s))
	t.learnAuthor(s, id)
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
// can be looked up: they are reached only through their remote branch. In
// a write transaction on Postgres it takes the namespace's lock shared
// (pglock.go).
func (t *tx) nsByName(name string) *nsRow {
	return t.nsByNameLocked(name, lockShared)
}

// nsForWrite is nsByName for a namespace the transaction will change: on
// Postgres it takes the namespace's lock exclusively, not shared
// (pglock.go), before reading it.
func (t *tx) nsForWrite(name string) *nsRow {
	return t.nsByNameLocked(name, lockExclusive)
}

// nsForResources is nsByName for the namespace a resource write or batch
// appends to: on Postgres it takes the namespace's lock shared, so writers
// of other resources run alongside, and the entry is appended under the
// namespace row's lock (appendNS, pglock.go).
func (t *tx) nsForResources(name string) *nsRow {
	n := t.nsByNameLocked(name, lockShared)
	if n != nil && t.locking() {
		t.sharedNS = n.id
	}
	return n
}

func (t *tx) nsByNameLocked(name string, mode lockMode) *nsRow {
	if strings.HasPrefix(name, "~") {
		return nil
	}
	if t.locking() {
		// The lock first, then the row as of the lock.
		var id int64
		if v, ok := t.e.ids.nss.Load(name); ok {
			id = v.(int64)
		} else {
			err := t.QueryRow(`SELECT ns FROM namespaces WHERE name = ?`, name).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			t.must(err)
			if !t.dirty {
				t.e.ids.nss.Store(name, id)
			}
		}
		t.lockNS(id, mode)
	}
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	t.deps.addNS(n)
	return n
}

// nsByID returns a namespace, taking its lock shared on Postgres.
func (t *tx) nsByID(id int64) *nsRow {
	return t.nsByIDLocked(id, lockShared)
}

func (t *tx) nsByIDLocked(id int64, mode lockMode) *nsRow {
	t.lockNS(id, mode)
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

// histRow is a head_history row an entry records: res's head is target as
// of the entry.
type histRow struct{ res, target int64 }

// appendNS appends an entry to a namespace chain (§3.5) and returns its seq
// and id, recording the resource heads it moves (head_history).
//
// On Postgres the chain is appended to at its head as of the namespace's
// log lock (D.8), an advisory lock in a class of its own taken last, just
// before the append, and held through commit: under the namespace's
// exclusive state lock it is never contended; a resource write or batch
// holds that lock only shared (sharedNS), and the log lock orders its
// entry with those of the other resources' writers. Entries therefore
// commit, and their seqs grow, in chain order (pglock.go).
func (t *tx) appendNS(n *nsRow, entry map[string]any, res *int64, targetSeq *int64, configSeq int64, author int64, hist ...histRow) (int64, ids.ID) {
	if t.locking() && t.sharedNS != n.id {
		t.lockNS(n.id, lockExclusive)
	}
	// What doesn't depend on the head first, outside the row's lock.
	body := jsonv.Canonical(entry)
	kind := nsKindCode(entry["kind"].(string))
	var grantID any
	if g := t.grants[author]; g != nil && t.serverWrites == 0 {
		// Encrypted if the configuration in force after the entry
		// encrypts at rest: a namespace's first entry has none before it.
		grantID = t.storeGrant(g, t.config(configSeq).level >= levelAtRest)
	}
	rs, ts := make([]int64, len(hist)), make([]int64, len(hist))
	for i, h := range hist {
		rs[i], ts[i] = h.res, h.target
	}
	t.lockLog(n.id)
	var headID []byte
	t.must(t.QueryRow(`SELECT head_seq, head_id FROM namespaces WHERE ns = ?`, n.id).Scan(&n.headSeq, &headID))
	t.forget() // read after the log lock
	var prev *ids.ID
	var prevSeq any
	if n.headSeq.Valid {
		// head_id is NULL in rows from before the column, and in remote
		// shadows, whose chains are mirrored.
		p := ids.FromBytes(headID)
		if headID == nil {
			p = t.nsLogID(n.headSeq.Int64)
		}
		prev = &p
		prevSeq = n.headSeq.Int64
	}
	id := ids.Hash(prev, body)
	var seq int64
	if t.e.pg {
		// One statement: the entry, the namespace's head and the heads it
		// moves, so the log lock is held for a single round trip and the
		// commit.
		seq = t.mustInsert(`WITH l AS (INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id)
				VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING seq),
			u AS (UPDATE namespaces SET head_seq = (SELECT seq FROM l), head_id = ?, config_seq = ? WHERE ns = ?),
			h AS (INSERT INTO head_history (res, ns_seq, target_seq) SELECT v.res, l.seq, v.target FROM l, unnest(?::bigint[], ?::bigint[]) AS v(res, target))
			SELECT seq FROM l`,
			n.id, id[:], prevSeq, kind, nullInt(res), nullInt(targetSeq), string(body), configSeq, author, t.now.UnixMilli(), grantID,
			id[:], configSeq, n.id, rs, ts)
	} else {
		seq = t.mustInsert(`INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id) VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING seq`,
			n.id, id[:], prevSeq, kind, nullInt(res), nullInt(targetSeq), string(body), configSeq, author, t.now.UnixMilli(), grantID)
		_, err := t.Exec(`UPDATE namespaces SET head_seq = ?, head_id = ?, config_seq = ? WHERE ns = ?`, seq, id[:], configSeq, n.id)
		t.must(err)
		for _, h := range hist {
			_, err := t.Exec(`INSERT INTO head_history (res, ns_seq, target_seq) VALUES (?,?,?)`, h.res, seq, h.target)
			t.must(err)
		}
	}
	n.headSeq = sql.NullInt64{Int64: seq, Valid: true}
	t.lastNS = seq
	if n.configSeq != configSeq {
		t.metaChanged = true
	}
	n.configSeq = configSeq
	t.notify[n.name] = true
	return seq, id
}

// asServer runs f, whose namespace entries are the server's own, such as
// propagated purges (§8.3): they record no grant (§7.4).
func (t *tx) asServer(f func()) {
	t.serverWrites++
	defer func() { t.serverWrites-- }()
	f()
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
