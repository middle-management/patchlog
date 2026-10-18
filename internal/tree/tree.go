// Package tree is the tree service of Addendum B (§B.2–§B.9): a namespace
// consumer (§10) that follows a catalog namespace and every content
// namespace its catalog.trust lists (§B.6), keeps folders, placements and
// their edges in SQLite (§B.5) with the checkpoints of all followed
// namespaces committed in the same transaction as the rows derived from
// them, and serves listings on its own origin.
//
// One database holds every followed namespace, and the serving view is an
// in-memory graph replaced only after a commit, so a listing is always
// consistent as of the recorded checkpoints of the catalog and the content
// namespaces together.
//
// Nodes (§B.2): a catalog document whose name has no dot is a folder; a
// name {ns}.{name} is a placement of /r/{ns}/{name}. parents are live links
// to folders of the same catalog. Walks go up only through "walkable"
// edges: the parent exists, is a folder, and neither end is in a cycle.
// Cycles are the strongly connected components of the folder graph (every
// edge inside one is flagged, rather than an arbitrary "closing" edge, so
// the result does not depend on traversal order). Walks are bounded at
// depth 64 and deeper nodes are flagged (§B.5).
//
// A Hook (the catalog of §B.11) can keep more derived tables in the same
// transactions, and a RoleView can widen what a reader may see.
//
// Encrypted namespaces (Addendum E, package derived). Sealed (E2)
// namespaces are followed with keys from POST /ns/{ns}/keys (the Client
// must be built WithKeys; Recipient unwraps keys wrapped to the grant's
// enc). An e2e (E3) catalog is followed only with a keyring Recipient key,
// otherwise it is skipped (listings answer 503 "skipped"); an e2e content
// namespace without one is still followed for its items' heads (plaintext
// ids), but its documents are not read, so it contributes no implicit
// placements. GET /_status reports each namespace's state and why any is
// skipped. Listings of a sealed or e2e catalog are served sealed (see
// Handler); content namespaces contribute names, heads and structure,
// which stay in the clear, and in a file tree the file metadata of their
// items' heads, sealed per entry under the item's K_r for a sealed
// namespace and left out for an e2e one (§E.2.6, §H.3, files.go).
//
// Stored plaintext. The database holds what the service derives from its
// namespaces in the clear (titles, file metadata, $parents, $access, and the catalog's
// acl/effective tables), as the origin does at E2: it is protected only by
// the service's own storage, which must be encrypted at least like the
// core at E1. A purge or purge-ns deletes the derived rows (with
// secure_delete on, and the WAL truncated after a purge), and a purge-ns
// also drops the namespace's epoch keys from memory.
package tree

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/kept"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/repurge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// Purger purges the tree service's own cache tags.
type Purger interface{ PurgeTags(tags []string) }

// Hook keeps derived data of its own in the tree service's database, in
// the same transactions as the graph (used by internal/catalog).
type Hook interface {
	// Init creates the hook's tables.
	Init(ctx context.Context, db *sql.DB) error
	// Rebuild recomputes everything from g (on start, and after a failed
	// apply was rolled back and the graph reloaded).
	Rebuild(ctx context.Context, tx *sql.Tx, g *Graph) error
	// Update is called inside an apply transaction with the names of the
	// nodes that changed (added, removed, or with changed document or
	// derived state).
	Update(ctx context.Context, tx *sql.Tx, g *Graph, changed map[string]bool) error
}

// Options configure a Service.
type Options struct {
	// Client reads the core API. It needs read on the catalog and on every
	// trusted content namespace (§C.6). For sealed namespaces build it
	// WithKeys (client.NewKeys(Recipient)); for a sealed catalog its grant
	// must get epoch keys (read on the whole catalog), which seal listings.
	Client *client.Client
	// Recipient is the service's X25519 private key: it unwraps keys
	// POST /keys wraps to the grant's enc, and makes e2e namespaces
	// readable when their keyring names its public key (§E.3.2).
	Recipient *ecdh.PrivateKey
	// Catalog is the catalog namespace.
	Catalog string
	// DB is the SQLite database path.
	DB string
	// Rebuild drops the database and replays from "".
	Rebuild bool
	// SelfPlacing accepts $parents in trusted content documents as implicit
	// placements (§B.9). An explicit placement for the same item wins.
	SelfPlacing bool
	// MinWait bounds how long ?min= waits (default 2s).
	MinWait time.Duration
	// Now is the clock for grant checks, kept listings and the due times
	// of second purges (default time.Now).
	Now func() time.Time
	// CheckerTTL is how long namespace documents are cached for grant
	// checks (default 30s).
	CheckerTTL time.Duration
	// Purger receives cache-tag purges (default: log).
	Purger Purger
	// RepurgeDelay is how long after a cache-tag purge it is sent again,
	// queued with the transaction that commits it (package repurge, D.8,
	// as the core's RepurgeDelay): longer than a response under way at
	// the commit can take to reach the CDN, which is the CDN's first-byte
	// timeout, as the service sets no response deadline. Zero means two
	// minutes (repurge.DefaultDelay); negative disables the second purge.
	RepurgeDelay time.Duration
	// RepurgeInterval is how often second purges that are due are sent.
	// Zero means ten seconds; negative disables the loop, and second
	// purges stay queued until a start with it.
	RepurgeInterval time.Duration
	// Edge is the verifying edge in front of the service (§9): private
	// listings get edge lifetimes only when it verified the read itself,
	// carrying its secret and a prefix covering the URL and no other
	// credential, which only a read under the service's own edge grant
	// (EdgeGrants) can be. Other such listings, and all of them when nil,
	// are no-store for shared caches. They are served either way.
	Edge *edge.Verifier
	// Logf logs (default log.Printf).
	Logf func(format string, args ...any)
	// OnApply is called after each batch commits.
	OnApply func(b *follow.Batch)
	// FollowOptions are passed to every follower.
	FollowOptions []follow.Option
	// Hook, if set, keeps derived tables in the same transactions.
	Hook Hook
	// RoleView, if set, lets readers see nodes through roles (§B.11.5).
	RoleView RoleView
	// EdgeGrants, if set, mints and verifies the service's own edge grants
	// (§B.11.5, §C.5; edgegrants.go): cookies for /{catalog}/g/{gs},
	// under a key and kid of the service's own, never the origin's. Open
	// sets its Vouches to those prefixes. It needs a RoleView: only a
	// catalog service's listings depend on the subject set alone.
	EdgeGrants *edge.Cookies
	// EdgeGrantsOwnKey says EdgeGrants' key was made for this Service
	// alone (a random one, -edge-grant-key not given): no cookie under it
	// was minted before Open or by another instance, so the record of
	// when each g/all cookie was first issued is exact. Otherwise a g/all
	// cookie counts as issued at its exp less the longest lifetime
	// (allNotBefore).
	EdgeGrantsOwnKey bool
	// ExchangeRate is the exchangeRate bucket each principal draws one
	// token from per exchange at POST /edge-grants (§C.5, §6.6; default
	// DefaultExchangeRate). It is a deployment's limit, so the service
	// has its own, per process.
	ExchangeRate Rate
	// Branches makes the service a release preview (§B.5, §F.9): it maps
	// a namespace (the catalog, or a content namespace it trusts) to the
	// release's branch of it, which is followed in its place. Documents
	// keep naming the bases (placements say matches.final, parents say
	// /r/{catalog}/…), so the graph is keyed by the bases' names, while
	// checkpoints, the combined checkpoint, cache tags, item links and
	// read checks use the branches. A preview issues no grants: it can't
	// be combined with a catalog service (RoleView, Hook). Branches are
	// fixed for a Service; a Preview (OpenPreview) follows the release
	// document and replaces its Service when the branches change.
	Branches map[string]string
}

// Service is a running tree service.
type Service struct {
	opt     Options
	c       *client.Client
	db      *sql.DB
	cps     follow.SQLCheckpoints
	origin  string
	checker *grantcheck.Checker
	keys    *derived.Keys  // encryption of followed namespaces
	sealed  *derived.Cache // sealed listings
	kept    *kept.Store    // listings kept past their at
	repurge *repurge.Queue // second CDN purges

	amu sync.Mutex
	ats map[string]atRecord // the checkpoints behind the ats of kept listings (atIncludes)

	wmu     sync.Mutex // serialises applies across followers
	pmu     sync.Mutex
	pending map[string][]follow.Unit // pages of unfinished snapshots (stage)

	mu  sync.RWMutex // guards g, cur, purged
	g   *Graph
	cur map[string]string
	// purged is when the service applied the purge of each namespace it
	// holds as purged (meta "purged:{ns}", Unix nanoseconds; trustList).
	purged  map[string]time.Time
	changed chan struct{}

	// trusted is when each namespace the catalog trusts became trusted,
	// as far as the service knows (meta "trusted:{ns}"), guarded by mu;
	// kept with EdgeGrants only (edgegrants.go).
	trusted map[string]time.Time

	emu       sync.Mutex
	edgeSubs  map[string]edgeSubjects // gs → its subjects, for its edge grants
	allIssued map[int64]time.Time     // exp → the first issue of a g/all edge grant expiring then
	exchanges exchangeBuckets         // exchangeRate, per principal

	// siblings are the services of the other catalogs behind the same
	// Multi, set before it serves (awaitMins).
	siblings []*Service

	fmu     sync.Mutex
	runCtx  context.Context
	running map[string]context.CancelFunc
	fwg     sync.WaitGroup
}

// Open opens (creating) the database, reads the core's origin and loads
// the graph.
func Open(ctx context.Context, opt Options) (*Service, error) {
	if opt.Client == nil {
		return nil, errors.New("tree: no client")
	}
	if !client.ValidNSName(opt.Catalog) {
		return nil, fmt.Errorf("tree: invalid catalog namespace %q", opt.Catalog)
	}
	if len(opt.Branches) > 0 && (opt.RoleView != nil || opt.Hook != nil) {
		return nil, errors.New("tree: a release preview (Branches) serves previews only and issues no grants (§B.5); it can't be a catalog service")
	}
	seenBr := map[string]bool{}
	for ns, br := range opt.Branches {
		if !client.ValidNSName(ns) || !client.ValidNSName(br) || ns == br || seenBr[br] {
			return nil, fmt.Errorf("tree: invalid preview branch %q for %q", br, ns)
		}
		seenBr[br] = true
	}
	if opt.EdgeGrants != nil && opt.RoleView == nil {
		return nil, errors.New("tree: edge grants are bound to a subject set (§B.11.5), which only a catalog service's listings depend on alone")
	}
	if opt.EdgeGrants != nil && (opt.Catalog == "r" || opt.Catalog == "ns") {
		// A service's prefixes lie under a root of its own, which never
		// overlaps /r/ or /ns/ (§C.5.3).
		return nil, fmt.Errorf("tree: catalog %q can't have edge grants: /%s/g/{gs} would overlap the core's prefixes", opt.Catalog, opt.Catalog)
	}
	if opt.MinWait == 0 {
		opt.MinWait = 2 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.CheckerTTL == 0 {
		opt.CheckerTTL = 30 * time.Second
	}
	if opt.ExchangeRate.Rate <= 0 || opt.ExchangeRate.Burst < 1 {
		opt.ExchangeRate = DefaultExchangeRate
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	if opt.Purger == nil {
		opt.Purger = logPurger{opt.Logf}
	}
	origin, err := opt.Client.Origin(ctx)
	if err != nil {
		return nil, fmt.Errorf("tree: reading the core's origin: %w", err)
	}
	// A database that an earlier release kept under another name (see
	// sqlitedsn.Legacy) must be moved first, not replayed into a new one.
	if err := sqlitedsn.CheckLegacy(opt.DB); err != nil {
		return nil, fmt.Errorf("tree: %w", err)
	}
	// secure_delete: rows deleted by a purge are overwritten, not left in
	// free pages (see the package doc).
	dsn := sqlitedsn.DSN(opt.DB, "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Service{
		keys: derived.NewKeys(opt.Client, opt.Recipient), sealed: derived.NewCache(0, db), kept: kept.New(opt.Now, keepBytes),
		opt: opt, c: opt.Client, db: db, cps: follow.SQLCheckpoints{DB: db}, origin: origin,
		checker: grantcheck.New(opt.Client, grantcheck.WithClock(opt.Now), grantcheck.WithTTL(opt.CheckerTTL)),
		cur:     map[string]string{}, purged: map[string]time.Time{}, changed: make(chan struct{}),
		running: map[string]context.CancelFunc{},
	}
	s.repurge = repurge.New(db, opt.Purger, repurge.Options{Delay: opt.RepurgeDelay, Interval: opt.RepurgeInterval,
		Now: opt.Now, Lock: &s.wmu, Name: "tree", Logf: opt.Logf})
	if opt.EdgeGrants != nil {
		opt.EdgeGrants.Vouches = func(p string) bool { _, ok := s.edgeGS(p); return ok }
	}
	if err := s.init(ctx); err != nil {
		db.Close()
		return nil, err
	}
	s.repurge.Start()
	return s, nil
}

func (s *Service) init(ctx context.Context) error {
	if s.opt.Rebuild {
		for _, q := range dropStmts {
			if _, err := s.db.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("tree: rebuild: %w", err)
			}
		}
	}
	if err := s.cps.Init(ctx); err != nil {
		return err
	}
	for _, q := range createStmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("tree: schema: %w", err)
		}
	}
	// A database from before item titles (§B.5), or created times and file
	// metadata (§H.3), which backfillFiles fills in for a file tree.
	for _, col := range []string{"title", "created", "file"} {
		var has int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('items') WHERE name = ?`, col).Scan(&has); err != nil {
			return fmt.Errorf("tree: schema: %w", err)
		}
		if has == 0 {
			if _, err := s.db.ExecContext(ctx, `ALTER TABLE items ADD COLUMN `+col+` TEXT`); err != nil {
				return fmt.Errorf("tree: schema: %w", err)
			}
		}
	}
	if err := s.sealed.Init(ctx); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	if err := repurge.Init(ctx, s.db); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	if s.opt.Hook != nil {
		if err := s.opt.Hook.Init(ctx, s.db); err != nil {
			return err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ns, ns_id FROM checkpoints WHERE origin = ?`, s.origin)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns, id string
		if err := rows.Scan(&ns, &id); err != nil {
			rows.Close()
			return err
		}
		s.cur[s.logical(ns)] = id
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT substr(k, 8), v FROM meta WHERE k LIKE 'purged:%'`)
	if err != nil {
		return err
	}
	var undated []string
	for rows.Next() {
		var ns, v string
		if err := rows.Scan(&ns, &v); err != nil {
			rows.Close()
			return err
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && v != "1" {
			s.purged[ns] = time.Unix(0, n)
		} else {
			undated = append(undated, ns)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// A purge recorded by an earlier release has no time ("1"): it counts
	// as applied now, the later, so edge copies from before it have
	// expired before trustList counts it (more refusals, never fewer).
	for _, ns := range undated {
		now := s.opt.Now()
		s.purged[ns] = now
		if _, err := s.db.ExecContext(ctx, `UPDATE meta SET v = ? WHERE k = ?`, strconv.FormatInt(now.UnixNano(), 10), "purged:"+ns); err != nil {
			return err
		}
	}
	if err := s.reload(ctx); err != nil {
		return err
	}
	return s.loadTrusted(ctx)
}

// reload rebuilds the graph from the database, fixes any drift in the
// derived rows and lets the hook rebuild. Called with mu held (or before
// the service is shared).
func (s *Service) reload(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	g, err := s.loadGraph(ctx, s.db)
	if err != nil {
		return fmt.Errorf("tree: loading the graph: %w", err)
	}
	changed := g.analyze()
	// Drift changes listings at an unchanged combined checkpoint, which
	// cached listings take never to go stale (apply's cache tags), as for
	// placements of a purged namespace's names that an earlier release
	// held as missing (itemStateTitle): every listing of the catalog
	// carries ns:{catalog}, so they all go, stored sealed ones too.
	var tags []string
	if len(changed) > 0 {
		tags = []string{"ns:" + s.actual(s.opt.Catalog)}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for name := range changed {
		if err := s.persistNode(ctx, tx, g, name); err != nil {
			return err
		}
	}
	if s.opt.Hook != nil {
		if err := s.opt.Hook.Rebuild(ctx, tx, g); err != nil {
			return err
		}
	}
	if err := s.sealed.Purge(ctx, tx, tags); err != nil {
		return err
	}
	// The second purge, durable with the commit (package repurge).
	if err := s.repurge.Add(ctx, tx, tags); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.kept.Purge(s.opt.Catalog, tags)
	if len(tags) > 0 {
		s.opt.Purger.PurgeTags(tags)
	}
	s.g = g
	return nil
}

// Close stops sending second purges and closes the database.
func (s *Service) Close() error {
	s.repurge.Stop()
	return s.db.Close()
}

// actual is the namespace followed for ns: its branch in a release preview
// (Options.Branches), otherwise ns.
func (s *Service) actual(ns string) string {
	if a := s.opt.Branches[ns]; a != "" {
		return a
	}
	return ns
}

// logical is the namespace a followed namespace stands for: the base whose
// branch it is in a release preview, otherwise ns itself.
func (s *Service) logical(ns string) string {
	for k, v := range s.opt.Branches {
		if v == ns {
			return k
		}
	}
	return ns
}

// Branches is the release preview's namespace -> branch map (nil if the
// service is no preview).
func (s *Service) Branches() map[string]string { return s.opt.Branches }

// Origin is the core's canonical origin.
func (s *Service) Origin() string { return s.origin }

// Catalog is the catalog namespace.
func (s *Service) Catalog() string { return s.opt.Catalog }

// Checker is the grant checker the service verifies readers with.
func (s *Service) Checker() *grantcheck.Checker { return s.checker }

// Keys is the encryption state and keys of the followed namespaces
// (Addendum E).
func (s *Service) Keys() *derived.Keys { return s.keys }

// Client is the core client.
func (s *Service) Client() *client.Client { return s.c }

// DB is the service's database (for hooks' queries).
func (s *Service) DB() *sql.DB { return s.db }

// Checkpoint returns the ns_id the service reflects for ns ("" if none).
func (s *Service) Checkpoint(ns string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur[ns]
}

// View calls fn with the graph and the checkpoints under the read lock;
// fn must not keep references past its return.
func (s *Service) View(fn func(g *Graph, cur map[string]string)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.g, s.cur)
}

func (s *Service) state() (cur string, purged bool, changed <-chan struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, purged = s.purged[s.opt.Catalog]
	return s.cur[s.opt.Catalog], purged, s.changed
}

// Run follows the catalog and its trusted namespaces until ctx is done.
// Followers of content namespaces start and stop as catalog.trust changes.
func (s *Service) Run(ctx context.Context) error {
	s.fmu.Lock()
	s.runCtx = ctx
	s.fmu.Unlock()
	if err := s.backfillFiles(ctx); err != nil && ctx.Err() == nil {
		s.opt.Logf("tree: file metadata: %v", err)
	}
	s.ensureFollowers()
	<-ctx.Done()
	s.fwg.Wait()
	return ctx.Err()
}

// followed is the set of namespaces that should be followed.
func (s *Service) followed() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{s.opt.Catalog}
	for ns := range s.g.Trust {
		out = append(out, ns)
	}
	sort.Strings(out[1:])
	return out
}

func (s *Service) ensureFollowers() {
	want := map[string]bool{}
	for _, ns := range s.followed() {
		want[ns] = true
	}
	s.fmu.Lock()
	defer s.fmu.Unlock()
	if s.runCtx == nil || s.runCtx.Err() != nil {
		return
	}
	for ns, cancel := range s.running {
		if !want[ns] {
			cancel()
			delete(s.running, ns)
		}
	}
	for ns := range want {
		if _, ok := s.running[ns]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(s.runCtx)
		s.running[ns] = cancel
		s.fwg.Add(1)
		go func() {
			defer s.fwg.Done()
			s.follow(ctx, ns)
		}()
	}
}

func (s *Service) follow(ctx context.Context, ns string) {
	s.mu.RLock()
	_, purged := s.purged[ns]
	s.mu.RUnlock()
	if purged {
		s.opt.Logf("tree: %s was purged; not following", ns)
		return
	}
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) { s.opt.Logf("tree: %s: %v", n, err) }),
	}
	opts = append(opts, s.opt.FollowOptions...)
	pause := time.Second
	real := s.actual(ns) // a release preview follows the branch
	if real != ns {
		// Its read-through content comes from its /heads at its first
		// entry (§10 Branches).
		opts = append(opts, follow.AsBranch())
	}
	for {
		var err error
		// Addendum E: never consume what can't be decrypted (or, for the
		// catalog, whose listings can't be sealed); skip it and say why. A
		// content namespace is followed for heads even if its e2e
		// documents can't be read.
		if reason, permanent := s.keys.Check(ctx, real, ns != s.opt.Catalog); reason != "" {
			if permanent {
				s.opt.Logf("tree: skipping %s: %s", real, reason)
				return
			}
			err = fmt.Errorf("skipped: %s", reason)
		} else if ns != s.opt.Catalog && s.opt.RoleView != nil {
			if err = s.ensureContent(ctx, ns); err == nil {
				err = follow.New(s.c, real, s.cps, s, opts...).Run(ctx)
			}
		} else {
			err = follow.New(s.c, real, s.cps, s, opts...).Run(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, follow.ErrPurged) {
			s.opt.Logf("tree: %s was purged", real)
			return
		}
		s.opt.Logf("tree: following %s stopped: %v; restarting in %s", real, err, pause)
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if pause < 30*time.Second {
			pause *= 2
		}
	}
}

// prep is one coalesced change with its fetched content.
type prep struct {
	name  string
	kind  string // head, tombstone or purge
	head  string
	doc   any
	title string // the item's title at the catalog's pointer (§B.5)
	// created is the head's created as the log gives it, file its file
	// metadata in a file tree (§H.3).
	created string
	file    *FileMeta
	purged  bool
}

// Apply implements follow.Handler. The batch's units are coalesced and
// fetched outside the locks, then applied to the graph, the derived rows,
// the hook's tables and the checkpoint in one transaction (§A.1, §B.11.7).
func (s *Service) Apply(ctx context.Context, fb *follow.Batch) error {
	if fb.Snapshot {
		whole, ok := s.stage(fb)
		if !ok {
			return nil
		}
		fb = whole
	}
	// In a release preview the followed namespace is a branch, and the
	// graph is keyed by the namespace it stands for (Options.Branches): b
	// is the batch under that name, fb the batch as followed.
	b := fb
	if lg := s.logical(fb.NS); lg != fb.NS {
		c := *fb
		c.NS = lg
		b = &c
	}
	co := b.Coalesce()
	isCat := b.NS == s.opt.Catalog
	var cfg *client.NSDoc
	for _, u := range b.Units {
		if u.Config != nil {
			cfg = u.Config
			s.keys.Observe(fb.NS, u.Config.Value)
		}
	}
	// A content namespace's document as of the new checkpoint, which a
	// catalog's visibility is pinned to (§B.11.5): a config entry's, or,
	// when the batch has none and the service doesn't hold it (a snapshot,
	// or a database from before it was kept), read at the checkpoint.
	var content *client.NSDoc
	if !isCat && !co.PurgedNS && s.opt.RoleView != nil {
		content = cfg
		if content == nil && (b.Replaces() || !s.hasContent(b.NS)) {
			d, err := s.c.NSDoc(ctx, fb.NS, b.NewCheckpoint)
			switch {
			case client.IsPurged(err):
				// A sealed namespace purged since: its documents are 410
				// (§8.5), and the follower delivers the purge next.
			case err != nil:
				return fmt.Errorf("tree: reading the document of %s at %s: %w", fb.NS, b.NewCheckpoint, err)
			default:
				content = d
			}
		}
	}
	// Item titles (§B.5): read from the heads of items in namespaces that
	// aren't sealed or end-to-end, when the catalog names a pointer.
	s.mu.RLock()
	tptr, hasTitle, fileTree := s.g.TitlePtr, s.g.HasTitle, s.g.Files
	s.mu.RUnlock()
	var retitle map[[2]string]string
	if isCat && cfg != nil {
		np, nh := titlePointer(cfg.Value)
		if nh != hasTitle || nh && np.String() != tptr.String() {
			var err error
			if retitle, err = s.retitle(ctx, np, nh); err != nil {
				return err
			}
		}
	}
	titled := false
	if !isCat && hasTitle {
		if in, err := s.keys.Info(ctx, fb.NS); err == nil && !in.Protected() {
			titled = true
		}
	}
	// File metadata (§H.3): every head of a content namespace in a file
	// tree is read for it, with keys in a sealed one; at E3 it is left out.
	filed := false
	if !isCat && fileTree {
		in, err := s.keys.Info(ctx, fb.NS)
		if err != nil {
			return fmt.Errorf("tree: the encryption of %s: %w", fb.NS, err)
		}
		filed = in.Level != derived.LevelE2E
	}
	var preps []prep
	for _, ch := range co.Changes {
		p := prep{name: ch.Resource, kind: ch.Kind, head: ch.Target, purged: ch.Purged, created: ch.Created}
		if ch.Kind == "head" && (isCat || s.opt.SelfPlacing || titled || filed) {
			doc, err := s.keys.FetchDoc(ctx, fb.NS, ch.Resource, ch.Target, func(f client.Flag) {
				s.opt.Logf("tree: %s/%s: revision %s by %s is flagged and left out: %s", fb.NS, ch.Resource, f.ID, f.Author, f.Message)
			})
			switch {
			case err == nil:
				if doc.ID != ch.Target {
					// The head since, the revision being pruned: the
					// entry's created isn't its (follow.FetchDoc).
					p.created = ""
				}
				p.head, p.doc = doc.ID, doc.Value
				if titled {
					p.title = titleAt(doc.Value, tptr)
				}
				if filed {
					p.file = fileMetaOf(doc, p.created)
				}
			case errors.Is(err, derived.ErrSkip) && !isCat:
				// A live item whose document isn't readable content (an
				// e2e keyring, or e2e without keys): no implicit placement.
			case errors.Is(err, derived.ErrSkip):
				// Not a catalog node (the keyring of an e2e catalog).
				p.kind, p.head = "tombstone", ""
			case errors.Is(err, follow.ErrNotLive) || client.IsGone(err) || client.IsNotFound(err):
				// Gone since: a later entry says so too.
				p.kind, p.head = "tombstone", ""
			default:
				return err
			}
		}
		preps = append(preps, p)
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Whether the catalog is a file tree changes only under wmu: a content
	// batch fetched before it changed is fetched again (the follower
	// retries), and a catalog change reads the items for it here, where
	// no other apply commits meanwhile (refile).
	s.mu.RLock()
	nowFiles := s.g.Files
	s.mu.RUnlock()
	if !isCat && nowFiles != fileTree {
		return fmt.Errorf("tree: %s fetched while the catalog's catalog.files changed; fetching again", fb.NS)
	}
	var fr *refiling
	if isCat && cfg != nil && isFileTree(cfg.Value) != nowFiles {
		var err error
		if fr, err = s.refile(ctx, !nowFiles); err != nil {
			return err
		}
	}
	s.mu.Lock()
	oldTrust := s.g.Trust
	res, err := s.applyLocked(context.WithoutCancel(ctx), b, co, preps, cfg, content, retitle, fr)
	if err != nil {
		if rerr := s.reload(context.Background()); rerr != nil {
			s.opt.Logf("tree: reloading after a failed apply: %v", rerr)
		}
		s.mu.Unlock()
		return err
	}
	// Purge before the new checkpoint is out, so nobody who learns of it
	// can still be served what it removed. Purgers don't block. Kept
	// listings go first: one read before it that carries a tag it purges
	// is then not kept (kept.Store.Generation).
	s.kept.Purge(s.opt.Catalog, res.tags)
	if len(res.tags) > 0 {
		s.opt.Purger.PurgeTags(res.tags)
	}
	s.cur[b.NS] = b.NewCheckpoint
	if co.PurgedNS {
		s.purged[b.NS] = res.purgedAt
	}
	trustChanged := !sameSet(oldTrust, s.g.Trust)
	if trustChanged {
		s.noteTrust(context.WithoutCancel(ctx))
	}
	s.mu.Unlock()

	if len(res.tags) > 0 {
		// The purged rows' traces in the WAL go too (secure_delete zeroes
		// the freed pages of the database itself).
		if _, err := s.db.ExecContext(context.WithoutCancel(ctx), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			s.opt.Logf("tree: checkpointing the WAL after a purge: %v", err)
		}
	}
	if co.PurgedNS {
		s.keys.Forget(fb.NS)
	}
	s.mu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
	if cfg != nil {
		s.checker.Observe(fb.NS, b.NewCheckpoint)
	}
	if trustChanged {
		s.ensureFollowers()
	}
	if s.opt.OnApply != nil {
		s.opt.OnApply(fb)
	}
	// Only listings at the current at are served.
	if err := s.sealed.Retire(context.WithoutCancel(ctx), s.db, s.opt.Catalog, s.At()); err != nil {
		s.opt.Logf("tree: retiring sealed listings: %v", err)
	}
	return nil
}

// stage collects the pages of a snapshot listed by pages
// (follow.Batch.Partial) and returns it whole at its last page, as one
// Snapshot batch: listings are cached by the combined checkpoint, which
// moves only once the snapshot is complete, so its pages can't change
// what listings show one by one. The units are a page's names, kinds and
// heads, held as the graph holds every item anyway; nothing is applied or
// recorded before the last page, so a restart starts the snapshot again.
func (s *Service) stage(b *follow.Batch) (*follow.Batch, bool) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if b.Replaces() {
		delete(s.pending, b.NS)
	}
	if b.Partial() {
		if s.pending == nil {
			s.pending = map[string][]follow.Unit{}
		}
		s.pending[b.NS] = append(s.pending[b.NS], b.Units...)
		return nil, false
	}
	earlier, ok := s.pending[b.NS]
	if !ok {
		return b, true
	}
	delete(s.pending, b.NS)
	whole := *b
	whole.Units = append(earlier, b.Units...)
	whole.After, whole.More = "", ""
	return &whole, true
}

type applyResult struct {
	tags     []string
	purgedAt time.Time // when the purge of the batch's namespace was applied
}

func (s *Service) applyLocked(ctx context.Context, b *follow.Batch, co follow.Coalesced, preps []prep, cfg, content *client.NSDoc, retitle map[[2]string]string, fr *refiling) (*applyResult, error) {
	g := s.g
	cat := s.opt.Catalog
	oldTrust := g.Trust // setConfig replaces it
	res := &applyResult{}
	changed := map[string]bool{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if b.NS == cat {
		if b.Replaces() || co.PurgedNS {
			for name := range g.explicit {
				g.removeExplicit(name)
				changed[name] = true
			}
		}
		if cfg != nil {
			g.setConfig(cfg.Value)
			if err := saveMeta(ctx, tx, "config", canonJSON(cfg.Value)); err != nil {
				return nil, err
			}
			// The title pointer changed: every live item's title is read
			// again (retitle), and listings move to the new checkpoint.
			for k, title := range retitle {
				var col any
				if title != "" {
					col = title
				}
				if _, err := tx.ExecContext(ctx, `UPDATE items SET title = ? WHERE ns = ? AND name = ?`, col, k[0], k[1]); err != nil {
					return nil, err
				}
				pl := k[0] + "." + k[1]
				for _, n := range []*Node{g.explicit[pl], g.self[pl]} {
					if n != nil {
						n.ItemTitle = title
						changed[pl] = true
					}
				}
			}
			// catalog.files came or went: every live item's file
			// metadata is set or dropped, and listings move to the new
			// checkpoint.
			if fr != nil {
				if err := fr.apply(ctx, tx, g, changed); err != nil {
					return nil, err
				}
			}
		}
		for _, p := range preps {
			changed[p.name] = true
			if p.kind == "head" && p.doc != nil {
				n := ParseNode(cat, p.name, p.head, p.doc)
				g.setExplicit(n)
				if n.ItemNS != "" {
					// A new placement: its item's state is in the items table.
					it, err := itemInfo(ctx, tx, n.ItemNS, n.ItemName)
					if err != nil {
						return nil, err
					}
					g.setItem(p.name, it)
				}
			} else {
				g.removeExplicit(p.name)
			}
		}
	} else {
		ns := b.NS
		if b.Replaces() || co.PurgedNS {
			if b.Replaces() {
				if _, err := tx.ExecContext(ctx, `DELETE FROM items WHERE ns = ?`, ns); err != nil {
					return nil, err
				}
			} else if _, err := tx.ExecContext(ctx, `UPDATE items SET state = ?, head = NULL, title = NULL, created = NULL, file = NULL WHERE ns = ?`, ItemPurged, ns); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM self_parents WHERE ns = ?`, ns); err != nil {
				return nil, err
			}
			st := ItemUnknown
			if co.PurgedNS {
				st = ItemPurged
			}
			for _, m := range []map[string]*Node{g.explicit, g.self} {
				for name, n := range m {
					if n.ItemNS == ns {
						g.setItem(name, itemData{state: st})
						changed[name] = true
					}
				}
			}
			for name, n := range g.self {
				if n.ItemNS == ns {
					g.removeSelf(name)
					changed[name] = true
				}
			}
		}
		for _, p := range preps {
			st, head := ItemLive, p.head
			switch p.kind {
			case "tombstone":
				st, head = ItemTombstoned, ""
			case "purge":
				st, head = ItemPurged, ""
			}
			var headCol, titleCol, createdCol, fileCol any
			title, file := p.title, p.file
			if head != "" {
				headCol = head
			}
			if st != ItemLive {
				title, file = "", nil
			}
			if title != "" {
				titleCol = title
			}
			if p.created != "" && st == ItemLive {
				createdCol = p.created
			}
			if file != nil {
				fileCol = file.encode()
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO items (ns, name, state, head, title, created, file) VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (ns, name) DO UPDATE SET state = excluded.state, head = excluded.head, title = excluded.title,
				created = excluded.created, file = excluded.file`, ns, p.name, st, headCol, titleCol, createdCol, fileCol); err != nil {
				return nil, err
			}
			pl := ns + "." + p.name
			if g.setItem(pl, itemData{state: st, head: head, title: title, file: file}) {
				changed[pl] = true
			}
			if !s.opt.SelfPlacing {
				continue
			}
			var sn *Node
			if st == ItemLive && p.doc != nil {
				sn = parseSelf(cat, ns, p.name, p.doc)
			}
			if sn != nil {
				m, _ := p.doc.(map[string]any)
				if _, err := tx.ExecContext(ctx, `INSERT INTO self_parents (ns, name, parents) VALUES (?, ?, ?)
					ON CONFLICT (ns, name) DO UPDATE SET parents = excluded.parents`, ns, p.name, canonJSON(m["$parents"])); err != nil {
					return nil, err
				}
				sn.ItemState, sn.ItemHead, sn.ItemTitle, sn.ItemFile = st, head, title, file
				g.setSelf(sn)
				changed[pl] = true
			} else if g.self[pl] != nil {
				if _, err := tx.ExecContext(ctx, `DELETE FROM self_parents WHERE ns = ? AND name = ?`, ns, p.name); err != nil {
					return nil, err
				}
				g.removeSelf(pl)
				changed[pl] = true
			}
		}
		if co.PurgedNS {
			res.purgedAt = s.opt.Now()
			if err := saveMeta(ctx, tx, "purged:"+ns, strconv.FormatInt(res.purgedAt.UnixNano(), 10)); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE k = ?`, "config:"+ns); err != nil {
				return nil, err
			}
			delete(g.Content, ns)
		} else if content != nil {
			if err := g.setContent(ctx, tx, ns, content.Value); err != nil {
				return nil, err
			}
		}
	}
	if b.NS == cat && co.PurgedNS {
		res.purgedAt = s.opt.Now()
		if err := saveMeta(ctx, tx, "purged:"+cat, strconv.FormatInt(res.purgedAt.UnixNano(), 10)); err != nil {
			return nil, err
		}
	}

	// Cache tags (§B.5). Every change a listing depends on moves the
	// combined checkpoint, so cached listings never go stale and need no
	// purge (but for drift a start finds, reload); purges remove content: a purged resource from every cached
	// listing showing it (r:{ns}/{name}, and rs:{catalog} for listings too
	// large to name all they show), a purged namespace from every cached
	// listing whose checkpoint covers it (ns:{ns}).
	if co.PurgedNS {
		res.tags = append(res.tags, "ns:"+s.actual(b.NS))
	}
	nr := 0
	for _, p := range preps {
		if p.purged {
			res.tags = append(res.tags, "r:"+s.actual(b.NS)+"/"+p.name)
			nr++
		}
	}
	if nr > 0 || co.PurgedNS {
		res.tags = append(res.tags, ManyTag(cat))
	}

	derived := g.analyze()
	for name := range derived {
		changed[name] = true
	}
	names := make([]string, 0, len(changed))
	for name := range changed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := s.persistNode(ctx, tx, g, name); err != nil {
			return nil, err
		}
	}
	if s.opt.Hook != nil {
		if err := s.opt.Hook.Update(ctx, tx, g, changed); err != nil {
			return nil, err
		}
	}
	for _, u := range b.Units {
		if u.Entry.ID != "" {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, u.Entry.ID); err != nil {
				return nil, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, b.NewCheckpoint); err != nil {
		return nil, err
	}
	// Stored sealed listings go by the same tags as cached copies.
	if err := s.sealed.Purge(ctx, tx, res.tags); err != nil {
		return nil, err
	}
	// A namespace the catalog no longer trusts leaves every cached listing
	// of the catalog (ns:{catalog}, which every listing carries), with
	// edge grants: a g/all cookie issued from now on isn't checked against
	// it, and an edge serves the g/all listings it holds to every g/all
	// cookie (§B.11.5). Not ns:{ns}, which would evict all every service
	// caches of the namespace. Should the purge not land, their edge
	// lifetime is capped (cdnAll).
	if s.opt.EdgeGrants != nil {
		for ns := range oldTrust {
			if !g.Trust[ns] {
				res.tags = append(res.tags, "ns:"+s.actual(cat))
				break
			}
		}
	}
	// The second purge, durable with the commit (package repurge): a read
	// before the commit may reach the CDN after the first.
	if err := s.repurge.Add(ctx, tx, res.tags); err != nil {
		return nil, err
	}
	if err := s.cps.SaveBatch(ctx, tx, b.Origin, s.actual(b.NS), b); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

type logPurger struct{ logf func(string, ...any) }

func (l logPurger) PurgeTags(tags []string) { l.logf("tree: purge cache tags %v", tags) }

// hasContent reports whether the service holds a content namespace's
// document (Graph.Content).
func (s *Service) hasContent(ns string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.g.Content[ns] != nil
}

// setContent records a content namespace's document as of the checkpoint
// being applied in tx.
func (g *Graph) setContent(ctx context.Context, tx *sql.Tx, ns string, doc map[string]any) error {
	if err := saveMeta(ctx, tx, "config:"+ns, canonJSON(doc)); err != nil {
		return err
	}
	g.Content[ns] = &NSConfig{NS: ns, Doc: doc}
	return nil
}

// ensureContent reads the document of a content namespace the service
// has a checkpoint for but no document (a database from before documents
// were kept), so visibility doesn't wait for its next entry.
func (s *Service) ensureContent(ctx context.Context, ns string) error {
	s.mu.RLock()
	cp, have := s.cur[ns], s.g.Content[ns] != nil
	s.mu.RUnlock()
	if have || cp == "" {
		return nil
	}
	doc, err := s.c.NSDoc(ctx, s.actual(ns), cp)
	if client.IsPurged(err) {
		// A sealed namespace purged since: its follower learns of it
		// from the same 410 (§8.5).
		return nil
	}
	if err != nil {
		return fmt.Errorf("tree: reading the document of %s at %s: %w", s.actual(ns), cp, err)
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, purged := s.purged[ns]; s.cur[ns] != cp || s.g.Content[ns] != nil || purged {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.g.setContent(ctx, tx, ns, doc.Value); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		delete(s.g.Content, ns)
		return err
	}
	return nil
}

// ItemState returns the recorded state and head of a content resource
// (ItemUnknown if the service has never seen it, ItemPurged if it hasn't
// and the service holds its namespace as purged, §8.5).
func (s *Service) ItemState(ctx context.Context, ns, name string) (int, string, error) {
	return itemState(ctx, s.db, ns, name)
}

// Seen reports whether the service has applied ns_id (of any followed
// namespace).
func (s *Service) Seen(ctx context.Context, nsID string) bool {
	var one int
	return s.db.QueryRowContext(ctx, `SELECT 1 FROM seen WHERE ns_id = ? LIMIT 1`, nsID).Scan(&one) == nil
}

// retitle reads, for the new title pointer of the catalog (§B.5), the
// title of every live item of a trusted namespace that is neither sealed
// nor end-to-end; items it doesn't list get none.
func (s *Service) retitle(ctx context.Context, p pointer.Pointer, has bool) (map[[2]string]string, error) {
	out := map[[2]string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT ns, name, head FROM items WHERE state = ? AND head IS NOT NULL`, ItemLive)
	if err != nil {
		return nil, err
	}
	type it struct{ ns, name, head string }
	var all []it
	for rows.Next() {
		var i it
		if err := rows.Scan(&i.ns, &i.name, &i.head); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	open := map[string]bool{}
	for _, i := range all {
		k := [2]string{i.ns, i.name}
		out[k] = ""
		if !has {
			continue
		}
		ok, seen := open[i.ns]
		if !seen {
			in, err := s.keys.Info(ctx, s.actual(i.ns))
			ok = err == nil && !in.Protected()
			open[i.ns] = ok
		}
		if !ok {
			continue
		}
		doc, err := s.keys.FetchDoc(ctx, s.actual(i.ns), i.name, i.head, nil)
		if err != nil {
			// Gone or unreadable since: no title; its own entry follows.
			continue
		}
		out[k] = titleAt(doc.Value, p)
	}
	return out, nil
}
