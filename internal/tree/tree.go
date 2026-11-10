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
// transactions, and a RoleView filters listings by subject set (§B.11.5).
// Without one, a tree service serves only unfiltered listings: in the
// public URL space while everything is public, else g/all (Handler).
//
// Encrypted namespaces (Addendum E, package derived). Sealed (E2)
// namespaces are followed with keys from POST /ns/{ns}/keys (the Client
// must be built WithKeys; Recipient unwraps keys wrapped to the grant's
// enc). An e2e (E3) catalog is followed only with a keyring Recipient key,
// otherwise it is skipped (listings answer 404, as for a catalog the
// service doesn't serve); an e2e content
// namespace without one is still followed for its items' heads (plaintext
// ids), but its documents are not read, so it contributes no implicit
// placements. GET /_status reports each namespace's state and why any is
// skipped. Listings of a sealed or e2e catalog are served sealed (see
// Handler); content namespaces contribute names, heads and structure,
// which stay in the clear, and in a file tree the file metadata of their
// items' heads, sealed per entry under the item's K_r for a sealed
// namespace and absent for an e2e one (§E.2.6, §H.3, files.go).
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
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/kept"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/repurge"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/svcedge"
	"golang.org/x/sync/errgroup"
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
	// RoleView, if set, lets readers see nodes through roles (§B.11.5):
	// listings of each subject set, under /{catalog}/g/{gs}/. Without
	// one, the service serves only g/all, and no filtered listings.
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
	// has its own buckets, shared by every instance on its database DB
	// (§B.11.5, svcedge.Store).
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

	// beforeListing, if set, runs as a listing starts, outside the
	// graph's lock (tests: a checkpoint that moves meanwhile).
	beforeListing atomic.Pointer[func()]
	// afterGeneration, if set, runs as a listing has taken its kept
	// generation, before it reads the graph, outside the graph's lock
	// (tests: a purge applied meanwhile).
	afterGeneration atomic.Pointer[func()]
	// afterFileSealing, if set, runs as a listing has read its file
	// metadata's sealing (fileSealing), before it reads the graph,
	// outside the graph's lock (tests: a config change applied
	// meanwhile).
	afterFileSealing atomic.Pointer[func()]
	// beforeJudge, if set, runs as a listing records what it judged
	// (judgeEpochs), outside the graph's lock (tests: a head applied
	// meanwhile).
	beforeJudge atomic.Pointer[func()]
	// verifyHook, if set, fails the verification of a grant in each
	// namespace it returns an error for (tests: a requireAt chain the
	// checker can't read).
	verifyHook atomic.Pointer[func(ns string) error]

	wmu     sync.Mutex // serialises applies across followers
	pmu     sync.Mutex
	pending map[string][]follow.Unit // pages of unfinished snapshots (stage)

	mu  sync.RWMutex // guards g, cur, purged, caught, target, unfollowed
	g   *Graph
	cur map[string]string
	// purged is when the service applied the purge of each namespace it
	// holds as purged (meta "purged:{ns}", Unix nanoseconds; trustList).
	purged  map[string]time.Time
	changed chan struct{}
	// caught are the namespaces the service has once caught up with, to
	// the head their follower read when it started (target; meta
	// "caught:{ns}"): until then listings wait for them (behind).
	caught map[string]bool
	target map[string]string
	// unfollowed are the trusted namespaces the service can't follow,
	// and why: skipped for their keys (Addendum E), or refused or absent
	// at the core (a 401, 403 or 404); listings don't wait for them
	// (behind), nor ?min= naming them (awaitMins). Cleared once the core
	// serves the namespace's head to its follower again.
	unfollowed map[string]string
	// epochsPending is whether the heads' epochs are still being read in
	// (meta "epochs", backfillEpochs): until then a Node.Epoch of 0 may be
	// one not read in yet rather than a pending judgement, so a listing
	// judges none (unjudged; §E.2.6, §E.3.1).
	epochsPending bool
	// unjudged is whether a listing sealed a head under the current epoch
	// without judging it while epochsPending: the fill then drops the
	// stored listings, as for an epoch it changes.
	unjudged atomic.Bool

	// entered is when each namespace in the combined checkpoint entered
	// it while trusted, as far as the service knows (meta "inckpt:{ns}"),
	// guarded by mu; kept with EdgeGrants only (edgegrants.go, §B.11.5
	// g/all).
	entered map[string]time.Time

	// edge keeps the subjects behind each gs the service minted edge
	// grants for, and the exchangeRate buckets, shared with the instances
	// on its database (edgegrants.go).
	edge      *svcedge.Store
	emu       sync.Mutex
	allIssued map[int64]time.Time // exp → the first issue of a g/all edge grant expiring then

	// siblings are the services of the other catalogs behind the same
	// Multi, set before it serves (awaitMins).
	siblings []*Service

	fmu     sync.Mutex
	runCtx  context.Context
	running map[string]context.CancelFunc
	fwg     sync.WaitGroup
	// runs stops the running follower of a followed namespace, by the
	// name it follows (runFollower), which Apply does once a config
	// change leaves the service without its keys (derived.Keys.Recheck).
	runs map[string]context.CancelFunc
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
		cur:     map[string]string{}, purged: map[string]time.Time{}, changed: make(chan struct{}), unfollowed: map[string]string{},
		caught: map[string]bool{}, target: map[string]string{},
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
	if err := dbmigrate.Migrate(ctx, s.db, migrations, "tree"); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	var err error
	if s.edge, err = svcedge.NewStore(ctx, s.db); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	if err := s.sealed.Init(ctx); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	if err := s.dropWholeViews(ctx); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	if err := repurge.Init(ctx, s.db); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	if s.opt.Rebuild {
		if err := reset(ctx, s.db); err != nil {
			return fmt.Errorf("tree: rebuild: %w", err)
		}
	}
	if err := s.markBornEpochs(ctx); err != nil {
		return fmt.Errorf("tree: schema: %w", err)
	}
	var epochs string
	switch err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'epochs'`).Scan(&epochs); {
	case err == nil:
		s.epochsPending = true
	case !errors.Is(err, sql.ErrNoRows):
		return err
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
	rows, err = s.db.QueryContext(ctx, `SELECT substr(k, 8) FROM meta WHERE k LIKE 'caught:%'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			rows.Close()
			return err
		}
		s.caught[ns] = true
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
	// A catch-up recorded of a namespace the catalog doesn't trust (its
	// DELETE in forgetUntrusted failed, or the service stopped between the
	// apply that untrusted it and that DELETE) is dropped, so that trusted
	// again it is waited for (more 503s, never a listing short of files).
	s.mu.Lock()
	s.forgetUntrusted(ctx)
	s.mu.Unlock()
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
	s.sealed.Purged(tags)
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

// PurgeEntry reports whether the service holds ns as purged as of the
// checkpoints a View's fn is given, and then ns's purge-ns entry: its
// checkpoint for ns, since a purge-ns entry is the log's last (§8.5), so
// the head a 410 purged names (§12.1), as a catalog service answers for
// every name of a purged content namespace (§B.11.4). Call it from a
// View's fn, which holds the lock it reads under.
func (s *Service) PurgeEntry(ns string) (head string, purged bool) {
	if _, purged = s.purged[ns]; purged {
		head = s.cur[ns]
	}
	return head, purged
}

func (s *Service) state() (cur string, purged bool, changed <-chan struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, purged = s.purged[s.opt.Catalog]
	return s.cur[s.opt.Catalog], purged, s.changed
}

// behind returns a namespace the service follows that it hasn't caught
// up with yet, "" if there is none: the catalog, or a namespace the
// catalog trusts (the service started with a fresh database, rebuilt, or
// trusting it lately). Until its follower has replayed the log to the
// head it read when it started (caught), every placement of an item in a
// page not applied yet is missing (dangling, §B.3), and a listing would
// show folders empty or part filled that aren't, which a sync tool
// mirrors as files deleted (§H.3); listings answer 503 behind instead. A
// checkpoint isn't enough: a log longer than a page is applied a page at
// a time, and the first sets one (§10 Catch up). Once caught up, a
// restart doesn't wait again: what it holds is the namespace as of a
// checkpoint, as any follower lags. A namespace purged, or one it can't
// follow (unfollowed), isn't waited for: its placements dangle meanwhile.
func (s *Service) behind() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.caught[s.opt.Catalog] {
		return s.opt.Catalog
	}
	var out []string
	for ns := range s.g.Trust {
		if _, purged := s.purged[ns]; !s.caught[ns] && !purged && s.unfollowed[ns] == "" {
			out = append(out, ns)
		}
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	return out[0]
}

// setUnfollowed records why the service can't follow ns ("" when it can
// again).
func (s *Service) setUnfollowed(ns, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if why == "" {
		delete(s.unfollowed, ns)
	} else {
		s.unfollowed[ns] = why
	}
}

// onCatchUp is the follower of ns reporting its catch-up (follow.
// WithOnCatchUp): once the core serves ns's head, the service follows it
// again (unfollowed cleared), and listings wait for it until it is caught
// up (behind); once the checkpoint reaches that head (target), the
// service has caught up with ns: Apply marks it so as it publishes that
// checkpoint, and done marks it where nothing was left to apply. A
// report for a namespace the catalog no longer trusts is dropped: its
// follower is stopped only after the apply that untrusted it
// (forgetUntrusted), and a report on its way meanwhile would mark it
// caught, so that trusted again it wasn't waited for while its follower
// replays what was placed in between. So is a report of a follower
// stopped (ctx, cancelled by ensureFollowers at the end of that apply,
// before the catalog's next apply can trust the namespace again), which
// may come once it is trusted again, with a head read before what was
// placed in between, while the new follower is still catching up.
func (s *Service) onCatchUp(ctx context.Context, ns, head string, done bool) {
	s.mu.Lock()
	if ctx.Err() != nil || ns != s.opt.Catalog && !s.g.Trust[ns] {
		s.mu.Unlock()
		return
	}
	if !done {
		delete(s.unfollowed, ns)
		s.target[ns] = head
		s.mu.Unlock()
		return
	}
	mark := !s.caught[ns]
	s.caught[ns] = true
	s.mu.Unlock()
	if mark {
		s.recordCaught(ctx, ns, head)
	}
}

// recordCaught records that the service caught up with ns at head (meta
// "caught:{ns}"). Unrecorded, a restart waits for the catch-up again:
// more 503s, never a listing short of files.
func (s *Service) recordCaught(ctx context.Context, ns, head string) {
	if _, err := s.db.ExecContext(context.WithoutCancel(ctx), `INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
		"caught:"+ns, head); err != nil {
		s.opt.Logf("tree: recording the catch-up with %s: %v", ns, err)
	}
}

// forgetUntrusted drops what the service knows of following each
// namespace the catalog no longer trusts (caught, target, unfollowed): trusted
// again, it is waited for until caught up again, from the checkpoint it
// stopped at. Called with mu held for writing.
func (s *Service) forgetUntrusted(ctx context.Context) {
	for ns := range s.caught {
		if ns != s.opt.Catalog && !s.g.Trust[ns] {
			delete(s.caught, ns)
			if _, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE k = ?`, "caught:"+ns); err != nil {
				s.opt.Logf("tree: forgetting the catch-up with %s: %v", ns, err)
			}
		}
	}
	for ns := range s.unfollowed {
		if !s.g.Trust[ns] {
			delete(s.unfollowed, ns)
		}
	}
	for ns := range s.target {
		if ns != s.opt.Catalog && !s.g.Trust[ns] {
			delete(s.target, ns)
		}
	}
}

// Run follows the catalog and its trusted namespaces until ctx is done.
// Followers of content namespaces start and stop as catalog.trust changes.
func (s *Service) Run(ctx context.Context) error {
	s.fmu.Lock()
	s.runCtx = ctx
	s.fmu.Unlock()
	if err := s.backfillFiles(ctx); err != nil && ctx.Err() == nil {
		// Made again beside the followers until it succeeds.
		s.opt.Logf("tree: file metadata: %v; retrying", err)
		s.fwg.Add(1)
		go func() {
			defer s.fwg.Done()
			s.retryBackfill(ctx, "file metadata", s.backfillFiles)
		}()
	}
	// Born and deleted explicit placements, one log or page per node of a
	// database from before them, and the epochs heads are served under,
	// are read beside the followers, which don't wait for them.
	s.fwg.Add(1)
	go func() {
		defer s.fwg.Done()
		if err := s.backfillNodes(ctx); err != nil && ctx.Err() == nil {
			s.opt.Logf("tree: nodes: %v; retrying", err)
			s.retryBackfill(ctx, "nodes", s.backfillNodes)
		}
		if err := s.backfillEpochs(ctx); err != nil && ctx.Err() == nil {
			s.opt.Logf("tree: epochs: %v; retrying", err)
			s.retryBackfill(ctx, "epochs", s.backfillEpochs)
		}
	}()
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
	// A namespace it stops following, or can't follow past an entry, for
	// lack of keys, at a start or meanwhile, purges ns:{ns} (purgeStopped)
	// once per checkpoint it is held at: the config entry that took the
	// keys away (a raise, an epoch the service can't have) is never
	// applied, so never purges what it narrows.
	var (
		smu       sync.Mutex
		stopped   bool
		stoppedAt string
	)
	stop := func() {
		s.mu.RLock()
		cp := s.cur[ns]
		s.mu.RUnlock()
		smu.Lock()
		again := !stopped || cp != stoppedAt
		stopped, stoppedAt = true, cp
		smu.Unlock()
		if again {
			s.purgeStopped(context.WithoutCancel(ctx), ns)
		}
	}
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) {
			s.opt.Logf("tree: %s: %v", n, err)
			if n == s.actual(ns) && follow.LacksKey(ctx, err) {
				stop()
			}
		}),
		follow.WithOnCatchUp(func(_, head string, done bool) { s.onCatchUp(ctx, ns, head, done) }),
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
		// Skipped for its keys as configured, it isn't waited for (behind)
		// until its keys come and the core serves its head again
		// (onCatchUp). Skipped because its epoch key couldn't be fetched
		// for the moment (the core briefly unreachable, a 5xx, a 408 or 429:
		// retry), it is still waited for, as a namespace being caught up
		// with is: listings are 503 behind, never short of its items, and
		// a ?min= naming it waits.
		if reason, permanent, retry := s.keys.Check(ctx, real, ns != s.opt.Catalog); reason != "" {
			if !retry {
				s.setUnfollowed(ns, reason)
				stop()
			}
			if permanent {
				s.opt.Logf("tree: skipping %s: %s", real, reason)
				return
			}
			err = fmt.Errorf("skipped: %s", reason)
		} else {
			if ns == s.opt.Catalog || s.opt.RoleView == nil {
				err = s.runFollower(ctx, real, opts)
			} else if err = s.ensureContent(ctx, ns); err == nil {
				err = s.runFollower(ctx, real, opts)
			}
			if _, lacks := s.keys.Skip(real); lacks && ctx.Err() == nil {
				// Apply stopped it: a config change (a raise to e2e, an
				// epoch) left the service without its keys. Decided as
				// when it starts, at once.
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, follow.ErrPurged) {
			s.opt.Logf("tree: %s was purged", real)
			return
		}
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound) {
			s.setUnfollowed(ns, err.Error())
		}
		if follow.LacksKey(ctx, err) {
			// Its log can't be read past an entry whose keys the service
			// lacks: retried, but what that entry narrows is purged now.
			stop()
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

// runFollower runs a follower of real until it ends, or until Apply stops
// it (stopRun).
func (s *Service) runFollower(ctx context.Context, real string, opts []follow.Option) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.fmu.Lock()
	if s.runs == nil {
		s.runs = map[string]context.CancelFunc{}
	}
	s.runs[real] = cancel
	s.fmu.Unlock()
	defer func() {
		s.fmu.Lock()
		delete(s.runs, real)
		s.fmu.Unlock()
	}()
	return follow.New(s.c, real, s.cps, s, opts...).Run(ctx)
}

// hasRun reports whether real has a running follower of its own
// (runFollower).
func (s *Service) hasRun(real string) bool {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	_, ok := s.runs[real]
	return ok
}

// stopRun stops the running follower of real, reporting whether it had
// one.
func (s *Service) stopRun(real string) bool {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	cancel, ok := s.runs[real]
	if ok {
		cancel()
	}
	return ok
}

// prep is one coalesced change with its fetched content.
type prep struct {
	name  string
	kind  string // head, tombstone or purge
	head  string
	epoch int // the epoch head is served under (derived.EpochOf), 0 if not known
	doc   any
	title string // the item's title at the catalog's pointer (§B.5)
	// created is the head's created as the log gives it, file its file
	// metadata in a file tree (§H.3).
	created string
	file    *FileMeta
	purged  bool
	// born is the node's born (§B.5): of a catalog node, or of the
	// implicit placement a content document makes; bornUnknown that it
	// can't be known, or isn't read (Node.BornUnknown).
	born        string
	bornUnknown bool
	// bornEpoch is the epoch born's revision is served under in a sealed
	// or e2e catalog (Node.BornEpoch), 0 if not known.
	bornEpoch int
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
	if cfg != nil {
		// The grant checker drops the document it holds now, before the
		// graph moves: who reads public (publicViewer) is decided from
		// it, and one made private must not be read public at the
		// checkpoint that makes it so (§9, §B.11.5). Told again once
		// applied (below).
		s.checker.Observe(fb.NS, b.NewCheckpoint)
	}
	if cfg != nil && s.hasRun(fb.NS) {
		// A raise (to e2e from none or at-rest, Addendum E Levels) or an
		// epoch whose keys the service lacks as configured: skipped as
		// when its follower starts (the catalog's listings are 404,
		// §E.2.6; a content namespace is still followed for heads), and
		// not followed. The batch isn't applied: once the keys come, a
		// restart resumes at it.
		if reason, lacks := s.keys.Recheck(ctx, fb.NS, !isCat); lacks && s.stopRun(fb.NS) {
			s.opt.Logf("tree: skipping %s: %s", fb.NS, reason)
			s.purgeStopped(context.WithoutCancel(ctx), b.NS)
			return fmt.Errorf("tree: %s skipped: %s", fb.NS, reason)
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
	// tree is read for it, with keys in a sealed one; at E3 it is absent.
	filed := false
	if !isCat && fileTree {
		in, err := s.keys.Info(ctx, fb.NS)
		if err != nil {
			return fmt.Errorf("tree: the encryption of %s: %w", fb.NS, err)
		}
		filed = in.Level != derived.LevelE2E
	}
	// An implicit placement's born is a value of its item (§B.9, §B.5):
	// read only for items of namespaces that are neither sealed nor e2e,
	// whose logs give the created of each revision in the clear (§E.2.2,
	// §E.2.6), as titles are.
	bornable := false
	if !isCat && s.opt.SelfPlacing {
		in, err := s.keys.Info(ctx, fb.NS)
		if err != nil {
			return fmt.Errorf("tree: the encryption of %s: %w", fb.NS, err)
		}
		bornable = !in.Protected()
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
				p.head, p.doc, p.epoch = doc.ID, doc.Value, derived.EpochOf(fb.NS, doc.Kid)
				if titled {
					p.title = titleAt(doc.Value, tptr)
				}
				if filed {
					p.file = fileMetaOf(doc, p.created, fb.NS)
				}
				// A node's born (§B.5): a catalog node's, or that of the
				// implicit placement a content document makes (§B.9).
				self := !isCat && s.opt.SelfPlacing && parseSelf(s.opt.Catalog, b.NS, ch.Resource, doc.Value) != nil
				switch {
				case isCat || self && bornable:
					if p.born, p.bornUnknown, p.bornEpoch, err = s.nodeBorn(ctx, fb.NS, ch.Resource, p.head, self, ch.Purged); err != nil {
						return err
					}
				case self:
					p.bornUnknown = true
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
	// is then not kept (kept.Store.Generation). Stored sealed ones read
	// meanwhile go again (derived.Cache.Purged).
	s.sealed.Purged(res.tags)
	s.kept.Purge(s.opt.Catalog, res.tags)
	if len(res.tags) > 0 {
		s.opt.Purger.PurgeTags(res.tags)
	}
	s.cur[b.NS] = b.NewCheckpoint
	// The catch-up's head reached: caught up as this checkpoint is out
	// (if still trusted, and by a follower not stopped since, onCatchUp).
	caughtNow := !s.caught[b.NS] && s.target[b.NS] == b.NewCheckpoint && (b.NS == s.opt.Catalog || s.g.Trust[b.NS]) && ctx.Err() == nil
	if caughtNow {
		s.caught[b.NS] = true
	}
	if co.PurgedNS {
		s.purged[b.NS] = res.purgedAt
	}
	// A namespace enters the combined checkpoint with its first
	// checkpoint while trusted, or when trusted again holding one, and
	// leaves it when untrusted or purged (noteTrust).
	s.noteTrust(context.WithoutCancel(ctx))
	trustChanged := !sameSet(oldTrust, s.g.Trust)
	if trustChanged {
		s.forgetUntrusted(context.WithoutCancel(ctx))
	}
	s.mu.Unlock()
	if caughtNow {
		s.recordCaught(ctx, b.NS, b.NewCheckpoint)
	}

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

// purgedNames is Graph.Purged for an apply of a batch of the catalog
// (isCat) or of a content namespace: the catalog names the batch purged,
// or every one if it purged the catalog.
func purgedNames(isCat, all bool, preps []prep) func(string) bool {
	set := map[string]bool{}
	if isCat {
		for _, p := range preps {
			if p.purged {
				set[p.name] = true
			}
		}
	}
	return func(name string) bool { return isCat && all || set[name] }
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
		if b.Replaces() {
			// A snapshot lists every tombstone and purge again (/heads).
			if _, err := tx.ExecContext(ctx, `DELETE FROM explicit_gone`); err != nil {
				return nil, err
			}
			for name := range g.explicitGone {
				delete(g.explicitGone, name)
				g.refresh(name)
				changed[name] = true
			}
		}
		if b.Replaces() || co.PurgedNS {
			for name := range g.explicit {
				if co.PurgedNS && g.retireExplicit(name) {
					if err := saveGone(ctx, tx, name, true); err != nil {
						return nil, err
					}
				} else {
					g.removeExplicit(name)
				}
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
				n.Born, n.BornUnknown, n.Epoch, n.BornEpoch = p.born, p.bornUnknown, p.epoch, carryBornEpoch(g.explicit[p.name], p)
				if g.explicitGone[p.name] {
					if err := saveGone(ctx, tx, p.name, false); err != nil {
						return nil, err
					}
				}
				g.setExplicit(n)
				if n.ItemNS != "" {
					// A new placement: its item's state is in the items table.
					it, err := itemInfo(ctx, tx, n.ItemNS, n.ItemName)
					if err != nil {
						return nil, err
					}
					g.setItem(p.name, it)
				}
			} else if g.retireExplicit(p.name) {
				// Deleted or purged, it still wins over $parents (§B.9).
				if err := saveGone(ctx, tx, p.name, true); err != nil {
					return nil, err
				}
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
		if cfg != nil && derived.InfoOf(cfg.Value).Protected() {
			// Sealed or e2e as of this batch, maybe raised by it (levels
			// only rise, §E.2.1): the values listings took from its items
			// go, titles (§B.5) and implicit placements' born (§B.9), which
			// Apply no longer reads (§E.2.2, §E.2.6). Once gone, a later
			// config entry (a rotation) changes nothing.
			if _, err := tx.ExecContext(ctx, `UPDATE items SET title = NULL WHERE ns = ? AND title IS NOT NULL`, ns); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE self_parents SET born = '' WHERE ns = ?`, ns); err != nil {
				return nil, err
			}
			for _, m := range []map[string]*Node{g.explicit, g.self} {
				for name, n := range m {
					if n.ItemNS == ns && (n.ItemTitle != "" || n.Self && !n.BornUnknown) {
						n.ItemTitle = ""
						if n.Self {
							n.Born, n.BornUnknown = "", true
						}
						changed[name] = true
					}
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
				if _, err := tx.ExecContext(ctx, `INSERT INTO self_parents (ns, name, parents, born) VALUES (?, ?, ?, ?)
					ON CONFLICT (ns, name) DO UPDATE SET parents = excluded.parents, born = excluded.born`, ns, p.name, canonJSON(m["$parents"]), bornVal(p.born, p.bornUnknown)); err != nil {
					return nil, err
				}
				sn.ItemState, sn.ItemHead, sn.ItemTitle, sn.ItemFile = st, head, title, file
				sn.Born, sn.BornUnknown = p.born, p.bornUnknown
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
	// purge (but for drift a start finds, reload); purges remove content:
	// a purged resource from every cached listing showing it
	// (r:{ns}/{name}, and rs:{catalog} for listings too large to name all
	// they show), a purged namespace from every cached listing whose
	// checkpoint covers it (ns:{ns}). So does a config entry on which §9
	// purges ns:{ns}, one making the catalog or a namespace it trusts
	// private, or raising it to sealed or e2e (§A.1 via §B.5, §E.2.6):
	// listings at earlier ats, public or with its values in the clear,
	// are still served there, kept, stored or cached, and must go, as the
	// index's do (index.narrowed). Listings carry ns:{ns} for the catalog
	// and every namespace it trusts (tagSet.header).
	//
	// At a namespace's first batch this service shows nothing of it yet.
	// Against what an instance before it applied, the record a rebuild
	// keeps, a narrowing purges as any does; with no record, a genesis, it
	// purges nothing, but in a rebuild's replay (Options.Rebuild), which
	// may follow a database from a release that kept no record.
	narrowed, recorded, err := narrowedBy(ctx, tx, g, b, co.PurgedNS)
	if err != nil {
		return nil, err
	}
	narrowed = narrowed && (s.cur[b.NS] != "" || recorded || s.opt.Rebuild) && (b.NS == cat || g.Trust[b.NS] || oldTrust[b.NS])
	if co.PurgedNS || narrowed {
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
		g.Purged = purgedNames(b.NS == cat, co.PurgedNS, preps)
		err := s.opt.Hook.Update(ctx, tx, g, changed)
		g.Purged = nil
		if err != nil {
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
	// A namespace the catalog no longer trusts leaves every cached listing
	// of the catalog (ns:{catalog}, which every listing carries). Once
	// untrusted it is no longer followed, so a later config entry making
	// it private, sealed or e2e is never seen, and the listings showing it
	// public or in the clear must go now (§9, §B.5). With edge grants
	// also: a g/all cookie issued from now on isn't checked against it,
	// and an edge serves the g/all listings it holds to every g/all
	// cookie (§B.11.5); should the purge not land, their edge lifetime is
	// capped (cdnAll). Not ns:{ns}, which would evict all every service
	// caches of the namespace.
	for ns := range oldTrust {
		if !g.Trust[ns] {
			res.tags = append(res.tags, "ns:"+s.actual(cat))
			break
		}
	}
	// Stored sealed listings go by the same tags as cached copies.
	if err := s.sealed.Purge(ctx, tx, res.tags); err != nil {
		return nil, err
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

// purgeStopped purges ns:{ns}, as an apply of a config entry that
// narrows does (applyLocked), when the service stops following the
// catalog, or a namespace it trusts, at a config entry whose keys it
// lacks (a raise to e2e without a keyring recipient key, an epoch it
// can't have): that batch is never applied, and listings kept, stored or
// cached (its Purger) before it, public or in the clear, must not outlive
// it, though the service serves none of the catalog's now.
func (s *Service) purgeStopped(ctx context.Context, ns string) {
	s.mu.RLock()
	shown := ns == s.opt.Catalog || s.g.Trust[ns]
	s.mu.RUnlock()
	if !shown {
		return
	}
	tags := []string{"ns:" + s.actual(ns)}
	err := func() error {
		s.wmu.Lock()
		defer s.wmu.Unlock()
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := s.sealed.Purge(ctx, tx, tags); err != nil {
			return err
		}
		if err := s.repurge.Add(ctx, tx, tags); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil {
		s.opt.Logf("tree: purging %v for %s, no longer followed: %v", tags, ns, err)
	}
	s.sealed.Purged(tags)
	s.kept.Purge(s.opt.Catalog, tags)
	s.opt.Purger.PurgeTags(tags)
}

// narrowedBy reports whether a config unit of b makes its namespace
// private or raises it to sealed or e2e (§9), against the read mode and
// level the service last applied for it (meta "access:{ns}"), and
// whether there was such a record (recorded); it records the last unit's,
// in tx and in g (Graph.appliedPublic). A purge (purged) drops the
// record. Without a record, a namespace counts as public and unsealed,
// so the first private or sealed document applied counts too: at a
// genesis, and once after an upgrade from a release that kept no record
// (index.narrowed).
func narrowedBy(ctx context.Context, tx *sql.Tx, g *Graph, b *follow.Batch, purged bool) (narrowed, recorded bool, err error) {
	k := "access:" + b.NS
	if purged {
		delete(g.appliedPublic, b.NS)
		_, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE k = ?`, k)
		return false, false, err
	}
	public, level, read := true, "", false
	for _, u := range b.Units {
		if u.Config == nil {
			continue
		}
		if !read {
			var v string
			err := tx.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = ?`, k).Scan(&v)
			switch {
			case errors.Is(err, sql.ErrNoRows):
			case err != nil:
				return false, false, err
			default:
				recorded = true
				if m, ok := parseJSON(v).(map[string]any); ok {
					public, _ = m["public"].(bool)
					level, _ = m["level"].(string)
				}
			}
			read = true
		}
		mode, _ := u.Config.Value["read"].(string)
		lv := derived.InfoOf(u.Config.Value).Level
		if public && mode != "public" || levelRank(lv) > levelRank(level) && derived.Protected(lv) {
			narrowed = true
		}
		public, level = mode == "public", lv
	}
	if !read {
		return false, false, nil
	}
	g.appliedPublic[b.NS] = public
	return narrowed, recorded, saveMeta(ctx, tx, k, marshal(map[string]any{"public": public, "level": level}))
}

// levelRank orders encryption levels: none and at-rest, sealed, e2e
// (levels only rise, §E.2.1).
func levelRank(level string) int {
	switch level {
	case derived.LevelSealed:
		return 1
	case derived.LevelE2E:
		return 2
	}
	return 0
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

// nodeBorn is the born of a node (§B.5) whose document is ns/name, head
// head (ns as followed): a catalog node's, or with self an implicit
// placement's, which a content document makes (§B.9), whether it can't be
// known, and the epoch its revision is served under (Node.BornEpoch). The
// service keeps them with the node, so it reads the log only for a node
// it holds neither for, or whose chain a purge in this batch replaced
// (purged), never again for a chain whose born is unknown (bornOf).
func (s *Service) nodeBorn(ctx context.Context, ns, name, head string, self, purged bool) (string, bool, int, error) {
	node := name
	if self {
		node = s.logical(ns) + "." + name
	}
	s.mu.RLock()
	n := s.g.explicit[node]
	if self {
		n = s.g.self[node]
	}
	var born string
	var epoch int
	known := false
	if n != nil && !purged {
		born, known, epoch = n.Born, n.Born != "" || n.BornUnknown, n.BornEpoch
	}
	s.mu.RUnlock()
	if known {
		return born, born == "", epoch, nil
	}
	born, epoch, err := s.bornOf(ctx, ns, name, head)
	return born, err == nil && born == "", epoch, err
}

// carryBornEpoch is the BornEpoch of p's node, old the node as it was
// (nil for none): p's where its born was read again (bornOf); otherwise
// old's as it stands now, which a listing may have judged since p was
// read (judgeEpochs), and where it was its head's revision's judgement
// (bornWithHead) and the head moved on, that head's epoch, or pending on
// its own while that wasn't judged either (§E.2.6, §E.3.1).
func carryBornEpoch(old *Node, p prep) int {
	if old == nil || p.purged || old.Born != p.born || old.Born == "" {
		return p.bornEpoch
	}
	switch {
	case old.BornEpoch != bornWithHead || old.Head == p.head:
		return old.BornEpoch
	case old.Epoch > 0:
		return old.Epoch
	}
	return bornPending
}

// judgement is what a listing judged of a node's pending epochs in an e2e
// catalog (§E.2.6, §E.3.1), for the node's head and born as it read them:
// epoch, the head's (0 none); bornEpoch, the born's (0 none), on its own
// (bornPending) or, withHead, as the head's revision (bornWithHead),
// sealed with the head's values under the head's epoch.
type judgement struct {
	head, born       string
	epoch, bornEpoch int
	withHead         bool
}

// judgeEpochs records judged, by node name, in the nodes table and the
// graph: a value derived from a revision whose snapshot would carry the
// epoch in force is sealed under the epoch it was first sealed under,
// "judged once, when the service first seals a value derived from it"
// (§E.2.6), and born and head values from one revision share that
// judgement. The first writer wins, another listing of this service or
// of another on its database; lost reports that one recorded first
// differs from judged, so the listing must be computed again with it. A
// head's judgement is of that head: one that moved on meanwhile records
// none, its listing being of an at that is no longer the current one. A
// born's is of its revision, whatever the head: a head applied meanwhile
// carries a pending born over (carryBornEpoch), which takes it.
func (s *Service) judgeEpochs(ctx context.Context, judged map[string]*judgement) (lost bool, err error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	type stored struct {
		head, born       string
		epoch, bornEpoch int
	}
	got := map[string]stored{}
	for name, j := range judged {
		if j.epoch > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET epoch = ? WHERE name = ? AND head = ? AND self = 0 AND (epoch IS NULL OR epoch <= 0)`,
				j.epoch, name, j.head); err != nil {
				return false, err
			}
		}
		// A born of the head's revision takes the head's judgement, this
		// one or one recorded before.
		if j.withHead {
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET born_epoch = epoch WHERE name = ? AND head = ? AND self = 0 AND born_epoch = ? AND epoch > 0`,
				name, j.head, bornWithHead); err != nil {
				return false, err
			}
		}
		if j.bornEpoch > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET born_epoch = ? WHERE name = ? AND self = 0 AND born = ? AND born_epoch = ?`,
				j.bornEpoch, name, j.born, bornPending); err != nil {
				return false, err
			}
		}
		var h, b sql.NullString
		var e, be sql.NullInt64
		switch err := tx.QueryRowContext(ctx, `SELECT head, born, epoch, born_epoch FROM nodes WHERE name = ? AND self = 0`, name).Scan(&h, &b, &e, &be); {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return false, err
		default:
			got[name] = stored{h.String, b.String, int(e.Int64), int(be.Int64)}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	for name, j := range judged {
		n := s.g.explicit[name]
		if n == nil {
			continue
		}
		sameHead, sameBorn := n.Head == j.head, n.Born == j.born
		st, ok := got[name]
		if !ok || st.head != n.Head || st.born != n.Born {
			// Not stored as this node (the graph holds what the table
			// will): kept in the graph alone, as judged.
			st = stored{epoch: n.Epoch, bornEpoch: n.BornEpoch}
			if sameHead && st.epoch <= 0 && j.epoch > 0 {
				st.epoch = j.epoch
			}
			switch {
			case st.bornEpoch == bornWithHead && sameHead && st.epoch > 0:
				st.bornEpoch = st.epoch
			case st.bornEpoch == bornPending && sameBorn && j.bornEpoch > 0:
				st.bornEpoch = j.bornEpoch
			}
		}
		if sameHead && n.Epoch <= 0 && st.epoch > 0 {
			n.Epoch = st.epoch
		}
		if sameBorn && (n.BornEpoch == bornPending || n.BornEpoch == bornWithHead) && st.bornEpoch > 0 {
			n.BornEpoch = st.bornEpoch
		}
		if sameHead && j.epoch > 0 && n.Epoch > 0 && n.Epoch != j.epoch || sameBorn && j.bornEpoch > 0 && n.BornEpoch > 0 && n.BornEpoch != j.bornEpoch {
			lost = true
		}
	}
	return lost, nil
}

// bornOf is when ns/name was created (§B.5 born): the created of the first
// revision of its chain up to head, the first its log gives from genesis.
// A log that can't be read for the moment (Transient) is an error, so the
// apply is made again; otherwise, as for a resource gone since or a chain
// a prune cut (410 pruned, §7.1), the born is unknown (""), and only
// failures other than those are logged. epoch is the epoch that revision
// is served under in a sealed or e2e namespace (§E.2.6): at E2 its served
// kid's where that names ns (derived.EpochOf); at E3 the one a prune's
// snapshot of it would carry (snapshotBornEpoch, §E.3.1), never the
// served kid of an entry the log gives in the clear, and where that is
// the epoch in force, pending, judged once when a listing first seals it
// (bornPending, or bornWithHead where that revision is head); 0 if not
// known, which leaves born out of a sealed listing (Service.serve).
func (s *Service) bornOf(ctx context.Context, ns, name, head string) (born string, epoch int, err error) {
	es, _, err := s.c.LogPage(ctx, ns, name, head, "")
	switch {
	case err == nil:
	case client.Transient(err):
		return "", 0, fmt.Errorf("tree: the log of %s/%s: %w", ns, name, err)
	default:
		if !client.IsGone(err) && !client.IsPruned(err) && !client.IsNotFound(err) {
			s.opt.Logf("tree: the born of %s/%s is unknown: %v", ns, name, err)
		}
		return "", 0, nil
	}
	if len(es) == 0 {
		return "", 0, nil
	}
	in, err := s.keys.Info(ctx, ns)
	switch {
	case err == nil && in.Level == derived.LevelE2E:
		e := snapshotBornEpoch(ns, es[0])
		if e == bornPending && es[0].ID == head {
			e = bornWithHead
		}
		return es[0].Created, e, nil
	case err == nil || lastingKeyErr(err):
		return es[0].Created, derived.EpochOf(ns, es[0].Kid), nil
	default:
		return "", 0, fmt.Errorf("tree: the encryption of %s: %w", ns, err)
	}
}

// snapshotBornEpoch is the epoch of e2e namespace ns that a prune's
// snapshot of e, the first revision of a chain, would carry (§E.3.1), the
// epoch a value derived from it is sealed under (§E.2.6): a revision from
// before a raise from sealed, served sealed as at E2, its served kid's
// where that names ns; one whose sealed op is ns's own (its pl.ns names
// ns), the epoch its kid names; one whose op is a base's, read through, or
// in the clear from before a raise from none or at-rest, ns's epoch in
// force, judged once, when a value derived from it is first sealed
// (§E.2.6): bornPending, never the epoch current as it is applied. 0, not
// known, for one without its patch set (pruned or purged) or whose own
// op's kid doesn't name an epoch of ns.
func snapshotBornEpoch(ns string, e client.LogEntry) int {
	if e.Kid != "" {
		return derived.EpochOf(ns, e.Kid)
	}
	if !e.HasPatches {
		return 0
	}
	jwe, ok := seal.SealedJWE(e.Patches)
	if !ok {
		return bornPending
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return 0
	}
	if pns, _ := h.PL["ns"].(string); pns != ns {
		return bornPending
	}
	return derived.EpochOf(ns, h.Kid)
}

// bornReads bounds the logs backfillNodes reads at once.
const bornReads = 4

// backfillNodes fills in, on start, what a database from an earlier
// release lacks: born (§B.5) for every node that has neither it nor a
// record that it can't be known, read from its log (bornReads at a time;
// an implicit placement whose item is in a sealed or e2e namespace isn't
// read, as Apply doesn't read it), and once (meta "gone"), the deleted and
// purged explicit placements that win over $parents (§B.9), from the
// catalog's /heads at its checkpoint. It runs beside the followers (Run),
// reading outside the locks and taking wmu only to apply what it read: a
// node whose head moved meanwhile was read by the apply that moved it. A
// born that can't be known is recorded, so neither a later head nor the
// next start asks again. Listings change at an unchanged combined
// checkpoint, so every cached listing of the catalog goes (ns:{catalog}),
// as for the drift reload fixes. Should it fail, it is made again until it
// succeeds (retryBackfill).
func (s *Service) backfillNodes(ctx context.Context) error {
	cat := s.opt.Catalog
	var marked string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'gone'`).Scan(&marked)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	fillGone := err != nil
	type want struct {
		node, ns, name, head string
		self                 bool
	}
	var wants []want
	s.mu.RLock()
	cp, purged := s.cur[cat], false
	_, purged = s.purged[cat]
	for name, n := range s.g.explicit {
		if n.Born == "" && !n.BornUnknown && n.Head != "" {
			wants = append(wants, want{node: name, ns: s.actual(cat), name: name, head: n.Head})
		}
	}
	for name, n := range s.g.self {
		if n.Born == "" && !n.BornUnknown && n.ItemHead != "" {
			wants = append(wants, want{node: name, ns: s.actual(n.ItemNS), name: n.ItemName, head: n.ItemHead, self: true})
		}
	}
	s.mu.RUnlock()
	if !fillGone && len(wants) == 0 {
		return nil
	}
	// A database that starts empty records them as it applies the catalog.
	var gone []string
	if fillGone && cp != "" && !purged {
		for after := ""; ; {
			items, next, err := s.c.HeadsPage(ctx, s.actual(cat), cp, after)
			if client.IsPurged(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("tree: the deleted placements of %s: %w", cat, err)
			}
			for _, it := range items {
				if (it.Kind == "tombstone" || it.Kind == "purge") && strings.Contains(it.Resource, ".") {
					gone = append(gone, it.Resource)
				}
			}
			if next == "" || next == after {
				break
			}
			after = next
		}
	}
	open := map[string]bool{} // namespaces whose items' born listings show (Apply)
	for _, w := range wants {
		if _, seen := open[w.ns]; w.self && !seen {
			in, err := s.keys.Info(ctx, w.ns)
			if err != nil {
				return fmt.Errorf("tree: the encryption of %s: %w", w.ns, err)
			}
			open[w.ns] = !in.Protected()
		}
	}
	borns := make([]string, len(wants)) // "" where unknown
	bornEpochs := make([]int, len(wants))
	eg, ectx := errgroup.WithContext(ctx)
	eg.SetLimit(bornReads)
	for i, w := range wants {
		if w.self && !open[w.ns] {
			continue
		}
		eg.Go(func() error {
			b, e, err := s.bornOf(ectx, w.ns, w.name, w.head)
			borns[i], bornEpochs[i] = b, e
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g := s.g
	changed := map[string]bool{}
	for i, w := range wants {
		n, head := g.explicit[w.node], ""
		if w.self {
			n = g.self[w.node]
		}
		if n != nil {
			head = n.Head
			if w.self {
				head = n.ItemHead
			}
		}
		if n == nil || n.Born != "" || n.BornUnknown || head != w.head {
			continue
		}
		n.Born, n.BornUnknown = borns[i], borns[i] == ""
		if !w.self {
			n.BornEpoch = bornEpochs[i]
		}
		if w.self {
			if _, err := tx.ExecContext(ctx, `UPDATE self_parents SET born = ? WHERE ns = ? AND name = ?`, bornVal(n.Born, n.BornUnknown), n.ItemNS, n.ItemName); err != nil {
				return err
			}
		}
		switch {
		case g.nodes[w.node] != n:
		case n.BornUnknown:
			// Listings show nothing new: only the record that it can't be
			// known.
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET born = '' WHERE name = ?`, w.node); err != nil {
				return err
			}
		default:
			changed[w.node] = true
		}
	}
	for _, name := range gone {
		if g.explicit[name] != nil || g.explicitGone[name] {
			continue
		}
		g.retireExplicit(name)
		if err := saveGone(ctx, tx, name, true); err != nil {
			return err
		}
		changed[name] = true
	}
	if fillGone {
		if err := saveMeta(ctx, tx, "gone", "1"); err != nil {
			return err
		}
	}
	var tags []string
	if len(changed) > 0 {
		for name := range g.analyze() {
			changed[name] = true
		}
		for name := range changed {
			if err := s.persistNode(ctx, tx, g, name); err != nil {
				return err
			}
		}
		if s.opt.Hook != nil {
			if err := s.opt.Hook.Update(ctx, tx, g, changed); err != nil {
				return err
			}
		}
		tags = []string{"ns:" + s.actual(cat)}
		if err := s.sealed.Purge(ctx, tx, tags); err != nil {
			return err
		}
		if err := s.repurge.Add(ctx, tx, tags); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		if rerr := s.reload(context.WithoutCancel(ctx)); rerr != nil {
			s.opt.Logf("tree: reloading after a failed backfill: %v", rerr)
		}
		return err
	}
	if len(tags) > 0 {
		s.sealed.Purged(tags)
		s.kept.Purge(cat, tags)
		s.opt.Purger.PurgeTags(tags)
	}
	return nil
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
