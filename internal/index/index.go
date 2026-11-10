// Package index is the indexing service of Addendum A: a namespace consumer
// (§10) that follows one or more namespaces, indexes the fields their schemas
// annotate with x-index (§A.2, §6.5) into SQLite (§A.3), and answers queries
// on its own origin (§A.4) with checkpoint-addressed, cacheable URLs.
//
// Storage (§A.3, with additions):
//
//	checkpoints(origin, ns, ns_id)         follow.SQLCheckpoints, saved in the apply tx
//	seen(ns, ns_id)                        every ns_id applied, for ?min= (§A.5)
//	ns_state(ns, purged)                   purge-ns marks the namespace gone
//	ns_conf(ns, public, level)             the read mode and level last applied (narrowed)
//	docs(docid, ns, resource, head, schema, epoch) one row per live resource (untyped too, see
//	                                      UntypedListing); epoch, in a sealed or e2e namespace, the
//	                                      epoch its head is served under (derived.EpochOf), NULL or 0
//	                                      while pending, until the first answer sealing a value
//	                                      derived from it judges it (judgeEpochs)
//	text  fts5(ns, resource, schema, path, body)  rowid = docid<<20 | n, so a resource's rows are a rowid range
//	facet(ns, resource, schema, path, value, raw)  value: the string form (§A.2), raw: canonical JSON
//	sort (ns, resource, schema, path, value, raw)  value: the least value (sortColumn), raw: all, a JSON array
//	refs(ns, resource, schema, path, ref, target_ns, target, rev, entry)  x-ref references (§A.2, §A.3);
//	                                      path is the full instance pointer, indices included
//	sealed_views, sealed_view_tags   sealed results of sealed/e2e namespaces (derived.Cache)
//	cdn_repurge(id, tags, due)       second CDN purges (package repurge), kept by a rebuild
//	edge_subjects, edge_buckets      the markers of each subject set the service minted edge
//	                                 grants for, until the last of them expires, and its
//	                                 exchangeRate buckets (svcedge.Store, edgegrants.go)
//	edge_filters(marker, filter, exp) what each scope or g: marker of those stands for (markerRec)
//	edge_gs(marker, subjects, kid, roles, pub, exp)  and, for a g: marker (§B.11.9), its subjects;
//	                                      its kid, roles and pub are no longer read (edge_gs_keys)
//	edge_gs_keys(marker, kid, roles, pub, exp)  every key a g: marker's live cookies came from,
//	                                      with the read roles its scope digest covers (gsKey)
//	member_checkpoints(origin, ns, ns_id)  follow.SQLCheckpoints of the namespaces visibility reads
//	                                      that the index follows without serving them, while it
//	                                      follows them (members.go)
//	member_conf(ns, public, level)        as ns_conf, for those
//	ns_stopped(ns, ns_id)                 a namespace the index stopped following, or can't follow
//	                                      past an entry, and the checkpoint it was stopped at
//	                                      (purgeStopped)
//	catalog_trust(ns, trust)              the catalog.trust last applied, of either, kept past a
//	                                      purge-ns and a rebuild (recordTrust, fsTrust), read again
//	                                      at a snapshot, forgotten once ns is neither served nor
//	                                      followed, unless purged (dropUnfollowedTrust, forgetMember)
//
// Paths are instance pointers with array indices removed ("/players/2/name"
// is stored as "/players/name"), so they name a field of the schema rather
// than one position in one document.
//
// Encrypted namespaces (Addendum E, package derived). A sealed (E2)
// namespace is followed with keys from POST /ns/{ns}/keys (the Client must
// be built WithKeys, and Recipient unwraps keys wrapped to the grant's
// enc); an e2e (E3) namespace only with a keyring Recipient key, its
// documents folded client-side (the keyring itself is never indexed).
// Without keys a namespace is skipped: not followed, and reported with the
// reason at GET /_status. One whose keys the service lacks is answered 404
// as one it doesn't follow (§A.4); one whose keys it can't fetch for now,
// 503 behind. Results over a sealed or e2e namespace are sealed under the
// epochs their documents' heads are served under (§E.2.6, docs.epoch): see
// Handler.
//
// Stored plaintext. Full-text, facet and sort queries need the indexed
// values in the clear, so the database holds plaintext derived from
// sealed and e2e namespaces, as the origin itself does at E2: it is
// protected only by the service's own storage (run it on encrypted disks,
// like the core at E1), and it is exactly as long-lived as the source's
// readability: a purge or purge-ns deletes the rows (with secure_delete on,
// so freed pages are zeroed, and the WAL is truncated after a purge), and a
// purge-ns also drops the namespace's epoch keys from memory. An e2e
// namespace's rows are rows the operator could not read at the core; an
// indexer over it must be run by a key holder.
package index

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/kept"
	"github.com/middle-management/patchlog/internal/repurge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// Purger purges the index service's own cache tags (§A.1: a purge "also
// purge[s] the service's own cache tags").
type Purger interface{ PurgeTags(tags []string) }

// Options configure an Index.
type Options struct {
	// Client reads the core API; with a private namespace it needs a grant
	// with read on it (§C.6 least privilege). For sealed namespaces build it
	// WithKeys (client.NewKeys(Recipient)); its grant must get epoch keys
	// (read on the whole namespace), which seal the results. Where §B.11.9
	// covers a namespace, its grant must also read the namespaces
	// visibility reads there, which the index follows without serving them
	// (filtered.go, members.go): the trusted catalogs, their catalog.trust members and
	// a branch's bases. To tell whether §B.11.9 covers a namespace at all,
	// for readers it doesn't let read the namespace whole, it must read,
	// whether or not they turn out to cover it, every catalog a followed
	// namespace's catalogs names through a key whose requireAt names it,
	// every namespace a followed catalog's catalog.trust lists, and a
	// followed branch's bases; where it can't, such readers are answered
	// 502 and the log names the namespace (errGrantLacks), never as if the
	// namespace weren't covered.
	Client *client.Client
	// Recipient is the service's X25519 private key: it unwraps keys
	// POST /keys wraps to the grant's enc, and makes e2e namespaces
	// readable when their keyring names its public key (§E.3.2).
	Recipient *ecdh.PrivateKey
	// DB is the SQLite database path.
	DB string
	// Namespaces are the namespaces to follow (roots).
	Namespaces []string
	// Branches also follows branches of the roots, recursively, building a
	// preview index per branch (§F.8, §10 Branches). Off by default: the main
	// index follows only the base.
	Branches bool
	// UntypedListing keeps a docs row for documents without $schema, so they
	// appear in plain listings (no q, schema, facet or range filter) but in
	// no text, facet or sort query (resolution of §A.7's first question).
	UntypedListing bool
	// NoFTS forces the LIKE-based text table even where FTS5 is available
	// (for tests of the fallback; it applies when the table is created).
	NoFTS bool
	// Rebuild drops the index and replays from "" (§A.6).
	Rebuild bool
	// MinWait bounds how long ?min= waits (§A.5), and how long a query
	// waits for a namespace visibility reads to be followed up to its head
	// (members.go); default 2s.
	MinWait time.Duration
	// Purger receives cache tag purges; default: log.
	Purger Purger
	// RepurgeDelay is how long after a cache tag purge it is sent again,
	// queued with the apply that commits it (package repurge, D.8, as the
	// core's RepurgeDelay): longer than a response under way at the
	// commit can take to reach the CDN, which is the CDN's first-byte
	// timeout, as the index sets no response deadline. Zero means two
	// minutes (repurge.DefaultDelay); negative disables the second purge.
	RepurgeDelay time.Duration
	// RepurgeInterval is how often second purges that are due are sent.
	// Zero means ten seconds; negative disables the loop, and second
	// purges stay queued until a start with it.
	RepurgeInterval time.Duration
	// Edge is the verifying edge in front of the service (§9): private
	// results it verified itself, carrying its secret and a prefix covering
	// the URL and no other credential, get edge lifetimes. Other private
	// results, and all of them when nil, are no-store for shared caches.
	// They are served either way.
	Edge *edge.Verifier
	// EdgeGrants, if set, mints and verifies the service's own edge
	// grants (§A.4, §B.11.5, §C.5; edgegrants.go): cookies for
	// /{ns}/g/{gs} and /_refs/g/{gs}, under a key and kid of the
	// service's own, never the origin's. Open sets its Vouches to those
	// prefixes. Without it, POST and DELETE /edge-grants are 404
	// not_offered.
	EdgeGrants *edge.Cookies
	// ExchangeRate is the exchangeRate bucket each principal draws one
	// token from per exchange at POST /edge-grants (§C.5.2, §6.6; default
	// svcedge.DefaultExchangeRate). It is a deployment's limit, so the
	// service has its own buckets, shared by every instance on its
	// database DB (§B.11.5, svcedge.Store).
	ExchangeRate svcedge.Rate
	// Now is the clock for grant checks, kept results and the due times
	// of second purges (default time.Now).
	Now func() time.Time
	// CheckerTTL is how long namespace documents are cached for grant
	// checks before head pointers are re-read (default 30s).
	CheckerTTL time.Duration
	// Logf logs; default log.Printf.
	Logf func(format string, args ...any)
	// OnApply is called after each batch commits (tests, metrics).
	OnApply func(b *follow.Batch)
	// FollowOptions are passed to every follower (e.g. follow.WithSSE,
	// follow.WithBackoff).
	FollowOptions []follow.Option
	// FetchConcurrency is how many documents the index fetches at once,
	// across every followed namespace and branch (default 8); 1 fetches
	// them one by one. Rows are written in log order either way.
	FetchConcurrency int
}

// keepBytes bounds the results kept past their checkpoint (package kept).
const keepBytes = 64 << 20

// Index is a running indexing service.
type Index struct {
	opt     Options
	c       *client.Client
	db      *sql.DB
	cps     follow.SQLCheckpoints
	fts     bool
	origin  string
	checker *grantcheck.Checker
	schemas *SchemaCache
	refs    *kept.Store // answers of /_refs, kept past their at (refsall.go)
	roots   map[string]bool
	keys    *derived.Keys  // encryption of followed namespaces
	sealed  *derived.Cache // sealed results
	kept    *kept.Store    // results kept past their checkpoint
	repurge *repurge.Queue // second CDN purges
	edge    *svcedge.Store // the service's edge grants (EdgeGrants)

	fmu     sync.Mutex
	filters map[string]keptFilter // scope or g: marker -> what it stands for (edge_filters, edge_gs)

	fs  fstate  // the state of namespaces §B.11.9 covers (filtered.go)
	mem members // the namespaces visibility reads there that the index doesn't serve (members.go)
	// auth is the core's authentication mode as last read (authOff),
	// kept for CheckerTTL.
	auth struct {
		mu  sync.Mutex
		at  time.Time
		off bool
	}

	fetches *semaphore.Weighted // FetchConcurrency, shared by every follower's Apply
	wmu     sync.Mutex          // serialises Apply across followers

	mu     sync.Mutex
	cur    map[string]string // ns -> checkpoint
	purged map[string]bool
	// stopped are the namespaces the index stopped following, or can't
	// follow past an entry, each with the checkpoint it was stopped at
	// (purgeStopped, ns_stopped). ix.mu guards it.
	stopped map[string]string
	changed chan struct{} // closed and replaced after every commit
	// runs stops the running follower of a followed namespace (runFollower),
	// which Apply does once a config change leaves the service without
	// its keys (derived.Keys.Recheck).
	runs map[string]context.CancelFunc

	// testRefsRead, if set, is called once a /_refs answer's transaction
	// has read its hits (tests: refsCompute).
	testRefsRead func()
	// testAnswerRead, if set, is called once a query's answer has read
	// its rows, before it is built and kept (tests: answer).
	testAnswerRead func()
	// testBeforeJudge, if set, is called once a query's answer has read
	// its rows, before the pending epochs of its hits are judged (tests).
	testBeforeJudge func()
	// testJudge, if set, is called as pending epochs are about to be
	// judged, once the answer has read the encryption a last time
	// (judgeEpochsAt; tests).
	testJudge func()
	// epochMu orders judging pending epochs (judgeEpochsAt, read) with
	// Apply's keys.Observe (write), which moves the current epoch.
	epochMu sync.RWMutex
	// testMemberBootstrap, if set, is called before a member's follower
	// gives it its first checkpoint (tests: bootstrapMember).
	testMemberBootstrap func(ctx context.Context, m string)
	// testBeforeAnswer, if set, is called once a reader's views are
	// computed, before the answer is (tests: serve's head pointer,
	// /_refs).
	testBeforeAnswer func()
}

// Open opens (creating or, with Rebuild, recreating) the index database and
// reads the core's origin.
func Open(ctx context.Context, opt Options) (*Index, error) {
	if opt.Client == nil {
		return nil, errors.New("index: no client")
	}
	if opt.MinWait == 0 {
		opt.MinWait = 2 * time.Second
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.CheckerTTL == 0 {
		opt.CheckerTTL = 30 * time.Second
	}
	if opt.FetchConcurrency <= 0 {
		opt.FetchConcurrency = 8
	}
	if opt.Purger == nil {
		opt.Purger = logPurger{opt.Logf}
	}
	origin, err := opt.Client.Origin(ctx)
	if err != nil {
		return nil, fmt.Errorf("index: reading the core's origin: %w", err)
	}
	// A database that an earlier release kept under another name (see
	// sqlitedsn.Legacy) must be moved first, not replayed into a new one.
	if err := sqlitedsn.CheckLegacy(opt.DB); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	// secure_delete: rows deleted by a purge are overwritten, not left in
	// free pages (see the package doc).
	dsn := sqlitedsn.DSN(opt.DB, "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	ix := &Index{
		keys: derived.NewKeys(opt.Client, opt.Recipient), sealed: derived.NewCache(0, db),
		kept: kept.New(opt.Now, keepBytes), refs: kept.New(opt.Now, refsKeepBytes),
		opt: opt, c: opt.Client, db: db, cps: follow.SQLCheckpoints{DB: db}, origin: origin,
		checker: grantcheck.New(opt.Client, grantcheck.WithClock(opt.Now), grantcheck.WithTTL(opt.CheckerTTL)),
		schemas: NewSchemaCache(opt.Client),
		fetches: semaphore.NewWeighted(int64(opt.FetchConcurrency)),
		roots:   map[string]bool{}, cur: map[string]string{}, purged: map[string]bool{}, stopped: map[string]string{}, changed: make(chan struct{}),
	}
	ix.fs.init()
	ix.mem.init()
	ix.repurge = repurge.New(db, opt.Purger, repurge.Options{Delay: opt.RepurgeDelay, Interval: opt.RepurgeInterval,
		Now: opt.Now, Lock: &ix.wmu, Name: "index", Logf: opt.Logf})
	for _, ns := range opt.Namespaces {
		if !client.ValidNSName(ns) {
			db.Close()
			return nil, fmt.Errorf("index: invalid namespace name %q", ns)
		}
		ix.roots[ns] = true
	}
	if err := ix.initSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := ix.loadState(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := ix.loadMembers(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := ix.initEdge(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("index: edge grants: %w", err)
	}
	ix.repurge.Start()
	return ix, nil
}

// Close stops sending second purges and closes the database.
func (ix *Index) Close() error {
	ix.repurge.Stop()
	return ix.db.Close()
}

// FTS reports whether the text table is FTS5 (false: the LIKE fallback).
func (ix *Index) FTS() bool { return ix.fts }

// Origin is the core's canonical origin, used in hit URLs.
func (ix *Index) Origin() string { return ix.origin }

// migrations holds the index's tables but for text (initSchema), applied
// under the namespace "index" (package dbmigrate).
//
//go:embed migrations
var migrations embed.FS

// resetStmts empty what a rebuild replays (cdn_repurge stays, and so do
// the edge grants' tables, edge_filters, edge_gs and svcedge.Store's, and
// member_checkpoints and member_conf, whose followers derive no rows: one
// still needed resumes where it stopped, one no longer needed is forgotten
// with a purge of idx:{m}, so no purge is missed, members.go), in one
// transaction. checkpoints_bootstrap too: a snapshot left part-way would
// otherwise be resumed, not replayed from its first page. text, made by
// initSchema rather than a migration, is dropped, so a rebuild decides
// between FTS5 and the LIKE fallback again.
var resetStmts = []string{
	`DELETE FROM checkpoints`, `DELETE FROM checkpoints_bootstrap`, `DELETE FROM seen`, `DELETE FROM ns_state`, `DELETE FROM ns_conf`, `DELETE FROM ns_stopped`,
	`DELETE FROM docs`, `DROP TABLE IF EXISTS "text"`, `DELETE FROM facet`, `DELETE FROM "sort"`, `DELETE FROM refs`,
	derived.CacheResetStmts[0], derived.CacheResetStmts[1],
}

const ftsCreate = `CREATE VIRTUAL TABLE IF NOT EXISTS "text" USING fts5(ns UNINDEXED, resource UNINDEXED, schema UNINDEXED, path UNINDEXED, body, tokenize = '` + ftsTokenizer + `')`

// ftsTokenizer is the text table's tokenizer, which query words are
// tokenized with too (Index.ftsTokens). It has never changed.
const ftsTokenizer = "unicode61 remove_diacritics 2"

// The LIKE fallback, for SQLite builds without FTS5.
var likeCreate = []string{
	`CREATE TABLE IF NOT EXISTS "text" (docid INTEGER NOT NULL, ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, body TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS text_doc ON "text" (docid)`,
}

// reset runs resetStmts.
func (ix *Index) reset(ctx context.Context) error {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range resetStmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// indexFormat is the format of the rows, kept as the database's
// user_version: 1 since v0.73, whose x-index values come from a static walk
// (§A.2, valueWalk), whose sort rows hold each document's least value and
// every value as written, booleans included, and whose counts go by string
// form; 2 since v0.74, whose walk follows every dependentSchemas entry
// whatever the data (§A.4) and matches patternProperties as this version
// compiles every schema (§6.1). A database of an older format is rebuilt
// (§A.6).
const indexFormat = 2

func (ix *Index) initSchema(ctx context.Context) error {
	// What an existing database holds is read before the migrations bring
	// its tables up to date: whether it has docs at all (none: a new
	// database, with nothing to replay), and docs.epoch and ns_conf, which
	// migrations 003 and 002 add.
	var docs, epoch, conf int
	if err := ix.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'docs'),
		(SELECT count(*) FROM pragma_table_info('docs') WHERE name = 'epoch'),
		(SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'ns_conf')`).Scan(&docs, &epoch, &conf); err != nil {
		return err
	}
	if err := dbmigrate.Migrate(ctx, ix.db, migrations, "index"); err != nil {
		return fmt.Errorf("index: schema: %w", err)
	}
	if !ix.opt.Rebuild {
		// Before v0.73, x-index values were collected while validating, a
		// sort row held one value, not the least, and booleans none; before
		// v0.74, dependentSchemas were followed only for members present:
		// an older format is replayed (indexFormat).
		var format int
		if err := ix.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&format); err != nil {
			return err
		}
		if docs > 0 && format < indexFormat {
			ix.opt.Logf("index: the database predates the x-index walk and sort order of v0.74 (§A.2, §A.4); rebuilding it from the logs")
			ix.opt.Rebuild = true
		}
		// Before docs.epoch, the rows of sealed and e2e namespaces don't
		// say which epoch each head is served under, which their hits are
		// sealed under (§E.2.6): replay those namespaces, as a rebuild.
		// Otherwise the rows are kept, the column added.
		if docs > 0 && epoch == 0 && !ix.opt.Rebuild {
			protected := 1 // levels not recorded: any may be sealed
			if conf > 0 {
				if err := ix.db.QueryRowContext(ctx, `SELECT count(*) FROM ns_conf WHERE level IN (?, ?)`, derived.LevelSealed, derived.LevelE2E).Scan(&protected); err != nil {
					return err
				}
			}
			if protected > 0 {
				ix.opt.Logf("index: the database predates the epochs hits of sealed and e2e namespaces are sealed under (§E.2.6); rebuilding it from the logs")
				ix.opt.Rebuild = true
			}
		}
	}
	if err := ix.sealed.Init(ctx); err != nil {
		return fmt.Errorf("index: schema: %w", err)
	}
	if err := ix.dropWholePublic(ctx); err != nil {
		return fmt.Errorf("index: schema: %w", err)
	}
	if err := repurge.Init(ctx, ix.db); err != nil {
		return fmt.Errorf("index: schema: %w", err)
	}
	// Before a rebuild empties the checkpoints it goes by.
	if err := ix.dropUnfollowedTrust(ctx); err != nil {
		return fmt.Errorf("index: catalog trust: %w", err)
	}
	if ix.opt.Rebuild {
		if err := ix.reset(ctx); err != nil {
			return fmt.Errorf("index: rebuild: %w", err)
		}
	}
	if _, err := ix.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, indexFormat)); err != nil {
		return fmt.Errorf("index: schema: %w", err)
	}
	// An existing text table decides the mode; otherwise try FTS5.
	var sqlText string
	err := ix.db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'text'`).Scan(&sqlText)
	switch {
	case err == nil:
		ix.fts = containsFold(sqlText, "fts5")
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if !ix.opt.NoFTS {
		if _, err := ix.db.ExecContext(ctx, ftsCreate); err == nil {
			ix.fts = true
			return nil
		} else {
			ix.opt.Logf("index: FTS5 unavailable (%v); using the LIKE-based text table", err)
		}
	}
	for _, s := range likeCreate {
		if _, err := ix.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("index: schema: %w", err)
		}
	}
	return nil
}

// dropWholePublic drops stored results sealed whole at a public URL,
// /{ns}/at/…, where the view's scope is its namespace (answer). Before
// v0.73 a public sealed or e2e namespace's results were stored as one JWE
// under K_e at the URLs they are sealed per entry at now, with counts
// (ENC-33, §E.2.6: whole-response sealing only for a source that isn't
// public); a stored view is keyed by its URL and the shape of the reader's
// keys, so none of them may be served again, though the namespace's
// checkpoint, which retires them, may not move for long. A database of an
// older format is rebuilt anyway (indexFormat); this covers one written
// since. No URL of the shapes of v0.73 matches: a public URL's results are
// JSON, and a whole JWE's URL has /g/{gs}.
func (ix *Index) dropWholePublic(ctx context.Context) error {
	return ix.sealed.Drop(ctx, func(view, scope string, json bool) bool {
		return !json && strings.HasPrefix(view, "/"+scope+"/at/")
	})
}

func (ix *Index) loadState(ctx context.Context) error {
	rows, err := ix.db.QueryContext(ctx, `SELECT ns, ns_id FROM checkpoints WHERE origin = ?`, ix.origin)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns, id string
		if err := rows.Scan(&ns, &id); err != nil {
			rows.Close()
			return err
		}
		ix.cur[ns] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = ix.db.QueryContext(ctx, `SELECT ns, ns_id FROM ns_stopped`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns, id string
		if err := rows.Scan(&ns, &id); err != nil {
			rows.Close()
			return err
		}
		ix.stopped[ns] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = ix.db.QueryContext(ctx, `SELECT ns FROM ns_state WHERE purged = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return err
		}
		ix.purged[ns] = true
	}
	return rows.Err()
}

// Checkpoint returns the ns_id the index reflects for ns ("" if none).
func (ix *Index) Checkpoint(ns string) string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.cur[ns]
}

func (ix *Index) state(ns string) (cur string, purged bool, changed <-chan struct{}) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.cur[ns], ix.purged[ns], ix.changed
}

// known reports whether ns is served: a root, or (with Branches) a branch
// the index has reached.
func (ix *Index) known(ns string) bool {
	if ix.roots[ns] {
		return true
	}
	if !ix.opt.Branches {
		return false
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	_, ok := ix.cur[ns]
	return ok
}

// Run follows every namespace until ctx is done. A follower that stops on a
// permanent error is restarted after a pause; a purged namespace is not.
// It also follows, without serving them, the namespaces visibility reads
// for those §B.11.9 covers (members.go).
func (ix *Index) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ix.runMembers(ctx)
	}()
	for ns := range ix.roots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ix.follow(ctx, ns)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func (ix *Index) follow(ctx context.Context, ns string) {
	if _, purged, _ := ix.state(ns); purged {
		ix.opt.Logf("index: %s was purged; not following", ns)
		return
	}
	// A namespace it stops following, or can't follow past an entry, for
	// keys it lacks or a refusal (401, 403, 404), at a start or meanwhile,
	// is stopped (purgeStopped): the config entry that took the keys or
	// the read away is never applied, so never purges what it narrows.
	stop := func(n string) { ix.purgeStopped(context.WithoutCancel(ctx), n) }
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) {
			ix.opt.Logf("index: %s: %v", n, err)
			if ix.known(n) && follow.LacksKey(ctx, err) && (n != ns || !ix.lacksKeys(ctx, n)) {
				stop(n)
			}
		}),
		follow.WithOnCatchUp(func(n, head string, done bool) {
			if done {
				ix.unstopAt(context.WithoutCancel(ctx), n, head)
			}
		}),
	}
	if ix.opt.Branches {
		opts = append(opts, follow.WithBranches())
	}
	opts = append(opts, ix.opt.FollowOptions...)
	pause := time.Second
	for {
		var err error
		// Addendum E: never consume what can't be decrypted (or whose
		// results can't be sealed); skip it and say why.
		if reason, permanent, retry := ix.keys.Check(ctx, ns, false); reason != "" {
			if !retry {
				stop(ns)
			}
			if permanent {
				ix.opt.Logf("index: skipping %s: %s", ns, reason)
				return
			}
			err = fmt.Errorf("skipped: %s", reason)
		} else {
			if z, purged, cerr := ix.committed(ctx, ns); cerr == nil && !purged && z != "" {
				// Resumed from a checkpoint committed before catalog_trust
				// was (migration 009), or without a config entry since.
				ix.trustAt(ctx, ns, z)
			}
			err = ix.runFollower(ctx, ns, opts)
			if _, lacks := ix.keys.Skip(ns); lacks && ctx.Err() == nil {
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
			ix.opt.Logf("index: %s was purged", ns)
			return
		}
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound) {
			refused := ae.Status != http.StatusNotFound || ae.Path == "/ns/"+ns
			if !refused {
				// A 404 of a log range or a document may be a stale head
				// pointer's (a CDN's, §9); one the namespace's own head
				// answers alike is a refusal (§7 answers a namespace the
				// reader can't read as one that doesn't exist).
				_, herr := ix.c.NSHead(ctx, ns)
				he, ok := client.AsAPIError(herr)
				refused = ok && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden || he.Status == http.StatusNotFound)
			}
			if refused {
				stop(ns)
			}
		} else if follow.LacksKey(ctx, err) {
			// Its log can't be read past an entry whose keys the service
			// lacks: retried, but what that entry narrows is purged now.
			stop(ns)
		}
		ix.opt.Logf("index: following %s stopped: %v; restarting in %s", ns, err, pause)
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

// followsRoot reports whether ns has a follower of its own (runFollower).
func (ix *Index) followsRoot(ns string) bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	_, ok := ix.runs[ns]
	return ok
}

// runFollower runs a follower of ns until it ends, or until Apply stops it
// (stopRun).
func (ix *Index) runFollower(ctx context.Context, ns string, opts []follow.Option) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ix.mu.Lock()
	if ix.runs == nil {
		ix.runs = map[string]context.CancelFunc{}
	}
	ix.runs[ns] = cancel
	ix.mu.Unlock()
	defer func() {
		ix.mu.Lock()
		delete(ix.runs, ns)
		ix.mu.Unlock()
	}()
	return follow.New(ix.c, ns, ix.cps, ix, opts...).Run(ctx)
}

// lacksKeys decides again, as when its follower starts (Keys.Check), its
// encryption read anew, whether the index lacks the keys of ns, a
// namespace it follows, as configured, after a read of it failed for want
// of a key: an entry of its log, such as the config entry of a raise to
// sealed whose keys it can't have, which Apply never sees, or its
// document in a read check. Lacking them, ns is skipped (Keys.Skip): its
// queries are 404 as one the index doesn't follow, before the read check,
// and /_status says why (§A.4 Unavailable namespaces, §E.2.6), as after a
// restart; it is stopped (purgeStopped) and its follower too, so that it
// is checked again as at a start (follow). It reports whether it lacks
// them.
func (ix *Index) lacksKeys(ctx context.Context, ns string) bool {
	ix.keys.Forget(ns)
	if _, lacks := ix.keys.Recheck(ctx, ns, false); !lacks {
		return false
	}
	ix.purgeStopped(context.WithoutCancel(ctx), ns)
	ix.stopRun(ns)
	return true
}

// stopRun stops the running follower of ns, reporting whether ns has one
// (a branch a follower follows with its base has none of its own).
func (ix *Index) stopRun(ns string) bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cancel, ok := ix.runs[ns]
	if ok {
		cancel()
	}
	return ok
}

// prepared is one coalesced change with its fetched content, ready to write.
type prepared struct {
	resource string
	remove   bool
	head     string
	epoch    int    // the epoch head is served under, 0 if pending or not sealed (derived.EpochOf; judgeEpochs)
	schema   string // "" = untyped
	typed    bool
	rows     *docRows
	purged   bool
}

// Apply implements follow.Handler: the batch's units are coalesced, their
// documents fetched and their rows written, with the checkpoint, in one
// transaction, so a batch entry is never half-applied (§10).
func (ix *Index) Apply(ctx context.Context, b *follow.Batch) error {
	co := b.Coalesce()
	config := false
	ix.epochMu.Lock() // no pending epoch is judged under what this replaces (judgeEpochsAt)
	for _, u := range b.Units {
		if u.Config != nil {
			ix.keys.Observe(b.NS, u.Config.Value)
			config = true
		}
	}
	ix.epochMu.Unlock()
	root := ix.followsRoot(b.NS)
	if _, lacks := ix.keys.Skip(b.NS); lacks && !root {
		// A branch followed with its base whose keys the service lacks
		// since a config change of it (below): not consumed, its queries
		// 404. Its batches aren't applied: once the keys come, a restart
		// resumes at the first.
		return nil
	}
	if config {
		// A raise (to e2e from none or at-rest, Addendum E Levels) or an
		// epoch (a rotation, §E.2.4) whose keys the service lacks as
		// configured: skipped as when its follower starts (queries are
		// 404, §A.4, §E.2.6), and not followed, so nothing is consumed
		// that can't be read or sealed. The batch isn't applied: once the
		// keys come, a restart resumes at it. A branch followed with its
		// base (-branches) has no follower of its own to stop: its batches
		// are left unapplied from here on (above).
		reason, lacks := ix.keys.Recheck(ctx, b.NS, false)
		switch {
		case lacks && root && ix.stopRun(b.NS):
			ix.opt.Logf("index: skipping %s: %s", b.NS, reason)
			ix.purgeStopped(context.WithoutCancel(ctx), b.NS)
			return fmt.Errorf("index: %s skipped: %s", b.NS, reason)
		case lacks && !root:
			ix.opt.Logf("index: skipping branch %s: %s", b.NS, reason)
			ix.purgeStopped(context.WithoutCancel(ctx), b.NS)
			return nil
		}
	}
	// Fetch FetchConcurrency documents at a time (one GET each), counting
	// every follower's Apply: prepare holds one of ix.fetches. preps keeps
	// the coalesced order, which the writes follow. The first error fails
	// the batch, as one by one, and the follower retries it whole.
	preps := make([]prepared, len(co.Changes))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(ix.opt.FetchConcurrency)
	for i, ch := range co.Changes {
		preps[i] = prepared{resource: ch.Resource, purged: ch.Purged, remove: ch.Kind != "head"}
		if ch.Kind == "head" {
			g.Go(func() error { return ix.prepare(gctx, b.NS, ch.Target, &preps[i]) })
		}
	}
	if err := g.Wait(); err != nil {
		return err
	}
	// A snapshot carries no config entry (but a new branch's genesis,
	// which narrowed records), so the namespace document is read at its
	// checkpoint: the catalog.trust recorded before it (catalog_trust,
	// which a rebuild keeps) may be one config entries the snapshot
	// skipped have changed since, and fsTrust reads it once ns is purged.
	// A purge-ns in place of a listing (a namespace purged before it was
	// bootstrapped) has no document to read, and keeps it; a sealed one
	// purged since the listing was read, whose document is 410 too, is
	// forgotten (unknown: no catalog, which shows least).
	//
	// The document also decides, as a config entry's would, whether the
	// snapshot narrows ns against what ns_conf records (none after a
	// rebuild: public and unsealed, as narrowed has it), which purges
	// idx:{ns} (§9, §A.1): a namespace made private while the index was
	// down or behind leaves no public result kept or cached.
	var snapDoc *client.NSDoc
	forgetTrust := false
	if b.Replaces() && !config && !co.PurgedNS {
		doc, err := ix.c.NSDoc(ctx, b.NS, b.NewCheckpoint)
		switch {
		case client.IsPurged(err):
			forgetTrust = true
		case err != nil:
			return lacksRead(b.NS, fmt.Errorf("the document of %s at %s: %w", b.NS, b.NewCheckpoint, err))
		default:
			if doc.Value == nil {
				doc.Value = map[string]any{}
			}
			snapDoc = doc
		}
	}

	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if b.Replaces() || co.PurgedNS {
		// A snapshot is the complete state (its later pages add to the
		// first); a purge-ns drops everything (Coalesce keeps only the
		// changes after it).
		if err := ix.dropNS(ctx, tx, b.NS); err != nil {
			return err
		}
	}
	if forgetTrust {
		if _, err := tx.ExecContext(ctx, `DELETE FROM catalog_trust WHERE ns = ?`, b.NS); err != nil {
			return err
		}
	}
	for _, p := range preps {
		if err := ix.write(ctx, tx, b.NS, p); err != nil {
			return err
		}
	}
	for _, u := range b.Units {
		if u.Entry.ID != "" {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, u.Entry.ID); err != nil {
				return err
			}
		}
	}
	if !b.Partial() {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, b.NewCheckpoint); err != nil {
			return err
		}
	}
	if co.PurgedNS {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ns_state (ns, purged) VALUES (?, 1) ON CONFLICT (ns) DO UPDATE SET purged = 1`, b.NS); err != nil {
			return err
		}
	}
	// §A.1, §A.4: a purge, of a resource or of the namespace, purges
	// idx:{ns}, which every result of the namespace carries: results page
	// by position, count facets over every hit and may show any document,
	// so none may outlive a purge of one of them. It also purges
	// r:{ns}/{name}, which /_refs answers showing the resource carry, and
	// a purge-ns the namespace's pointers (ns:{ns}). So does a config
	// entry on which §9 purges ns:{ns}, one making the namespace private
	// or raising it to sealed or e2e: results computed before it, public
	// or in the clear, must go. Kept results, stored sealed ones (in this
	// transaction) and /_refs answers go by the same tags.
	docs := configDocs(b)
	if snapDoc != nil {
		docs = append(docs, snapDoc)
	}
	narrowed, err := ix.narrowed(ctx, tx, "ns_conf", b.NS, docs)
	if err != nil {
		return err
	}
	var tags []string
	for _, p := range preps {
		if p.purged {
			tags = append(tags, "r:"+b.NS+"/"+p.resource)
		}
	}
	if len(tags) > 0 || co.PurgedNS || narrowed {
		tags = append(tags, "idx:"+b.NS)
	}
	if co.PurgedNS {
		tags = append(tags, "ns:"+b.NS)
	}
	if err := ix.purgeTx(ctx, tx, tags); err != nil {
		return err
	}
	if err := ix.cps.SaveBatch(ctx, tx, b.Origin, b.NS, b); err != nil {
		return err
	}
	// A batch of ns applied ends a stop (purgeStopped): what it couldn't
	// apply is applied now, its narrowing with it.
	ix.mu.Lock()
	_, wasStopped := ix.stopped[b.NS]
	ix.mu.Unlock()
	if wasStopped {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ns_stopped WHERE ns = ?`, b.NS); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if wasStopped {
		ix.mu.Lock()
		delete(ix.stopped, b.NS)
		ix.mu.Unlock()
	}
	if config || snapDoc != nil {
		// Keys, revocations or the read mode may have changed: the grant
		// checker reads the namespace's document again before anything
		// is purged or the checkpoint published. Told later, it would
		// pass read checks on the document it cached meanwhile (for up to
		// CheckerTTL), a namespace made private still public there, and a
		// result computed at the new checkpoint after the purge would be
		// kept and served in the public URL space (answer re-checks the
		// read once gen is taken, accessChanged). So may a snapshot's.
		ix.checker.Observe(b.NS, b.NewCheckpoint)
	}
	ix.purgeStored(ctx, b.NS, tags, co.PurgedNS)
	if b.Partial() {
		// A page of a snapshot later pages complete: the index doesn't
		// reflect the namespace as of b.NewCheckpoint yet, so the
		// checkpoint isn't published. A snapshot has no resource purges
		// (Coalesce marks none in synthetic units), but its first page
		// may narrow (snapDoc): what that purges goes now, as below.
		ix.purgeKept(b.NS, tags)
		if ix.opt.OnApply != nil {
			ix.opt.OnApply(b)
		}
		return nil
	}
	// Purge before the new checkpoint is out, so nobody who learns of it
	// can still be served what it removed.
	ix.purgeKept(b.NS, tags)
	// Publish the checkpoint before any other work, waking ?min= waiters.
	// Redirects go by the committed checkpoint (Index.committed), so the
	// gap between the commit and this doesn't make them alternate.
	ix.mu.Lock()
	first := ix.cur[b.NS] == ""
	ix.cur[b.NS] = b.NewCheckpoint
	if co.PurgedNS {
		ix.purged[b.NS] = true
	}
	close(ix.changed)
	ix.changed = make(chan struct{})
	ix.mu.Unlock()
	if ix.opt.OnApply != nil {
		ix.opt.OnApply(b)
	}
	// Housekeeping, once the checkpoint is out: only the current
	// checkpoint's sealed results are stored, so older ones go (kept ones
	// stay kept a while, in memory).
	if err := ix.sealed.Retire(ctx, ix.db, b.NS, b.NewCheckpoint); err != nil {
		ix.opt.Logf("index: retiring sealed results of %s: %v", b.NS, err)
	}
	if len(tags) > 0 {
		// The purged rows' traces in the WAL go too (secure_delete zeroes
		// the freed pages of the database itself).
		if _, err := ix.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			ix.opt.Logf("index: checkpointing the WAL after a purge: %v", err)
		}
	}
	if co.PurgedNS {
		ix.keys.Forget(b.NS)
	}
	if config || co.PurgedNS || first {
		// What coverage reads may have changed: which namespaces the
		// index follows for it (members.go) is judged again.
		ix.kickMembers()
	}
	return nil
}

// purgeStopped stops ns, a namespace the index serves, when it stops
// following it, or can't follow it past an entry, for keys it lacks (a
// raise to e2e without a keyring recipient key, an epoch it can't have)
// or a refusal (made private with the index's grant no longer verifying):
// that entry is never applied, so never purges what it narrows (§9,
// §A.1), and the read mode the index applied predates it. It marks ns
// stopped at the checkpoint the index holds (ns_stopped), so it reads
// public to no one (appliedPublic), and has the grant checker drop what
// it holds of ns; then it purges idx:{ns}, as an apply of a config entry
// that narrows does: kept, stored and cached results (its Purger), with
// the second purge queued. Once per checkpoint: stopped again at the one
// it was stopped at, after a restart too, it purges nothing more. A batch
// of ns applied (Apply), or its follower catching up with that checkpoint
// (unstopAt), ends the stop. As the tree service's purgeStopped.
func (ix *Index) purgeStopped(ctx context.Context, ns string) {
	cp, purged, err := ix.committed(ctx, ns)
	if err != nil || purged {
		return
	}
	ix.mu.Lock()
	was, marked := ix.stopped[ns]
	ix.stopped[ns] = cp
	ix.mu.Unlock()
	ix.checker.Observe(ns, "")
	if marked && was == cp {
		return
	}
	ix.opt.Logf("index: %s can't be followed past %q: purging idx:%s, read as private until it is", ns, cp, ns)
	tags := []string{"idx:" + ns}
	err = func() error {
		ix.wmu.Lock()
		defer ix.wmu.Unlock()
		tx, err := ix.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `INSERT INTO ns_stopped (ns, ns_id) VALUES (?, ?) ON CONFLICT (ns) DO UPDATE SET ns_id = excluded.ns_id`, ns, cp); err != nil {
			return err
		}
		if err := ix.purgeTx(ctx, tx, tags); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil {
		ix.opt.Logf("index: purging %v for %s, no longer followed: %v", tags, ns, err)
	}
	ix.purgeStored(ctx, ns, tags, false)
	ix.purgeKept(ns, tags)
}

// isStopped reports whether ns is stopped (purgeStopped).
func (ix *Index) isStopped(ns string) bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	_, ok := ix.stopped[ns]
	return ok
}

// unstopAt ends ns's stop once its follower caught up with head at the
// checkpoint it was stopped at: nothing it couldn't follow is left
// unapplied (a refusal or a key that has passed, a stale head pointer).
func (ix *Index) unstopAt(ctx context.Context, ns, head string) {
	ix.mu.Lock()
	was, ok := ix.stopped[ns]
	unstop := ok && head != "" && was == head && ix.cur[ns] == head
	if unstop {
		delete(ix.stopped, ns)
	}
	ix.mu.Unlock()
	if !unstop {
		return
	}
	ix.checker.Observe(ns, "")
	if _, err := ix.db.ExecContext(ctx, `DELETE FROM ns_stopped WHERE ns = ?`, ns); err != nil {
		ix.opt.Logf("index: ending the stop of %s: %v", ns, err)
	}
}

// purgeTx purges tags, in tx, from the stored sealed results, and queues
// their second purge, durable with the commit (package repurge): a read
// before the commit may reach the CDN after the first (§A.1, D.8).
func (ix *Index) purgeTx(ctx context.Context, tx *sql.Tx, tags []string) error {
	if err := ix.sealed.Purge(ctx, tx, tags); err != nil {
		return err
	}
	return ix.repurge.Add(ctx, tx, tags)
}

// purgeStored drops, once the apply that purges tags in ns has committed,
// what fstate keeps of ns (fsForget) where tags purge idx:{ns}, first, then
// the sealed results stored since its own purge of them (purgeTx), and the
// /_refs answers they remove (refsPurged). fstate goes first: a view of
// another namespace that read ns's state before is then computed before
// any store counts the purge, and its answer isn't kept (fcp.gens).
func (ix *Index) purgeStored(ctx context.Context, ns string, tags []string, purgedNS bool) {
	if slices.Contains(tags, "idx:"+ns) {
		ix.fsForget(ns)
	}
	ix.sealed.Purged(tags)
	ix.refsPurged(ctx, ns, tags, purgedNS)
}

// purgeKept drops, once the apply that purges tags in ns has committed and
// before its checkpoint is published, the kept results they remove, and
// purges them from the service's cache (§A.1). Kept results go first: one
// read before the commit that carries a tag it purges is then not kept
// (kept.Store.Generation). Results at a combined checkpoint of another
// namespace that lists ns (§A.4, filtered.go) carry idx:{ns} too, whether
// ns is one the index serves or one it follows only for visibility
// (members.go); what fstate keeps of ns went before (purgeStored).
// Purgers don't block.
func (ix *Index) purgeKept(ns string, tags []string) {
	ix.kept.Purge(ns, tags)
	if slices.Contains(tags, "idx:"+ns) {
		for _, other := range ix.refsNamespaces() {
			if other != ns {
				ix.kept.Purge(other, []string{"idx:" + ns})
			}
		}
	}
	if len(tags) > 0 {
		ix.opt.Purger.PurgeTags(tags)
	}
}

// configDocs are the namespace documents b's config units bring, in order.
func configDocs(b *follow.Batch) []*client.NSDoc {
	var out []*client.NSDoc
	for _, u := range b.Units {
		if u.Config != nil {
			out = append(out, u.Config)
		}
	}
	return out
}

// narrowed reports whether one of docs, the namespace documents ns's
// config units bring, or the one a snapshot is taken at (Apply), makes
// ns private or raises it to sealed or e2e (§9), against the read mode
// and level the index last applied (table: ns_conf, or member_conf for a
// namespace it follows only for visibility, members.go), and records the
// last one's, in tx, with its catalog.trust (recordTrust). Before
// the first it records, the namespace counts as public and unsealed, so
// the first private or sealed document it applies counts too: once, at
// the genesis of a namespace followed from the start, when nothing is
// cached yet, and after an upgrade from a database without ns_conf, when
// there may be.
func (ix *Index) narrowed(ctx context.Context, tx *sql.Tx, table, ns string, docs []*client.NSDoc) (bool, error) {
	if table != "ns_conf" && table != "member_conf" {
		return false, fmt.Errorf("index: no table %q", table)
	}
	if len(docs) == 0 {
		return false, nil
	}
	public, level := true, ""
	err := tx.QueryRowContext(ctx, `SELECT public, level FROM `+table+` WHERE ns = ?`, ns).Scan(&public, &level)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	narrowed := false
	for _, d := range docs {
		read, _ := d.Value["read"].(string)
		lv := derived.InfoOf(d.Value).Level
		if public && read != "public" || levelRank(lv) > levelRank(level) && derived.Protected(lv) {
			narrowed = true
		}
		public, level = read == "public", lv
	}
	if err := recordTrust(ctx, tx, ns, docs[len(docs)-1].Value); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO `+table+` (ns, public, level) VALUES (?, ?, ?) ON CONFLICT (ns) DO UPDATE SET public = excluded.public, level = excluded.level`, ns, public, level)
	return narrowed, err
}

// recordTrust records, in tx, ns's catalog.trust as its document doc
// gives it (null for a namespace that is no catalog), the one fsTrust
// reads once ns is purged and its document 410 (catalog_trust).
func recordTrust(ctx context.Context, tx *sql.Tx, ns string, doc map[string]any) error {
	c, _ := doc["catalog"].(map[string]any)
	trust, err := json.Marshal(c["trust"])
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO catalog_trust (ns, trust) VALUES (?, ?) ON CONFLICT (ns) DO UPDATE SET trust = excluded.trust`, ns, string(trust))
	return err
}

// dropUnfollowedTrust forgets, at Open, the catalog.trust recorded for a
// namespace the index served (it holds a checkpoint of it) and no longer
// does (it isn't among the namespaces it serves now; with Branches, every
// namespace it holds a checkpoint of is served, known), unless the index
// applied its purge, whose last trust stays (fsTrust), or follows it as
// a member (members.go, which records it again at its bootstrap and its
// config entries): config entries the index no longer applies may change
// it unseen, and once that namespace is purged, its document 410, fsTrust
// would read the stale one, and may cover a namespace it no longer
// trusts. Without one, it counts as no catalog, the reading that shows
// least, as forgetMember leaves a live member it stops following.
func (ix *Index) dropUnfollowedTrust(ctx context.Context) error {
	if ix.opt.Branches {
		return nil
	}
	rows, err := ix.db.QueryContext(ctx, `SELECT t.ns FROM catalog_trust t
		WHERE EXISTS (SELECT 1 FROM checkpoints c WHERE c.ns = t.ns)
		AND NOT EXISTS (SELECT 1 FROM ns_state s WHERE s.ns = t.ns AND s.purged = 1)
		AND NOT EXISTS (SELECT 1 FROM member_checkpoints m WHERE m.ns = t.ns)`)
	if err != nil {
		return err
	}
	var drop []string
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			rows.Close()
			return err
		}
		if !ix.roots[ns] {
			drop = append(drop, ns)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, ns := range drop {
		ix.opt.Logf("index: %s is no longer served; forgetting its catalog.trust", ns)
		if _, err := ix.db.ExecContext(ctx, `DELETE FROM catalog_trust WHERE ns = ?`, ns); err != nil {
			return err
		}
	}
	return nil
}

// lastTrust is ns's catalog.trust as the namespace document last applied
// gave it (recordTrust), ok false if the index applied none of ns's
// documents, nil for one that is no catalog.
func (ix *Index) lastTrust(ctx context.Context, ns string) (trust []any, ok bool, err error) {
	var s string
	switch err := ix.db.QueryRowContext(ctx, `SELECT trust FROM catalog_trust WHERE ns = ?`, ns).Scan(&s); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	if err := json.Unmarshal([]byte(s), &trust); err != nil {
		return nil, false, err
	}
	return trust, true, nil
}

// levelRank orders encryption levels as raises go (Addendum E): at rest
// changes nothing a view shows.
func levelRank(level string) int {
	switch level {
	case derived.LevelSealed:
		return 1
	case derived.LevelE2E:
		return 2
	}
	return 0
}

// prepare fetches p.resource's document at revision id and extracts its
// rows into p, holding one of the index's FetchConcurrency fetches.
func (ix *Index) prepare(ctx context.Context, ns, id string, p *prepared) error {
	if err := ix.fetches.Acquire(ctx, 1); err != nil {
		return err
	}
	defer ix.fetches.Release(1)
	doc, err := ix.keys.FetchDoc(ctx, ns, p.resource, id, func(f client.Flag) {
		ix.opt.Logf("index: %s/%s: revision %s by %s is flagged and left out: %s", ns, p.resource, f.ID, f.Author, f.Message)
	})
	if err != nil {
		if errors.Is(err, derived.ErrSkip) && follow.LacksKey(ctx, err) {
			// Sealed under an epoch the index's grant gets no key for
			// (§E.2.3): it can't be read, so it isn't indexed (§A.4).
			ix.opt.Logf("index: %s/%s: left out: %v", ns, p.resource, err)
			p.remove = true
			return nil
		}
		if errors.Is(err, derived.ErrSkip) || errors.Is(err, follow.ErrNotLive) || client.IsGone(err) || client.IsNotFound(err) {
			// Gone since: a later entry of the log says so too.
			p.remove = true
			return nil
		}
		return err
	}
	p.head, p.epoch = doc.ID, derived.EpochOf(ns, doc.Kid)
	p.schema, p.typed, p.rows, err = ix.extract(ctx, ns, p.resource, doc.Value)
	return err
}

// dropNS deletes every row of a namespace.
func (ix *Index) dropNS(ctx context.Context, tx *sql.Tx, ns string) error {
	for _, q := range []string{`DELETE FROM "text" WHERE ns = ?`, `DELETE FROM facet WHERE ns = ?`, `DELETE FROM "sort" WHERE ns = ?`, `DELETE FROM refs WHERE ns = ?`, `DELETE FROM docs WHERE ns = ?`} {
		if _, err := tx.ExecContext(ctx, q, ns); err != nil {
			return err
		}
	}
	return nil
}

const textShift = 20 // text rowid = docid<<20 | n

// clearRows deletes a resource's text/facet/sort rows and returns its docid.
func (ix *Index) clearRows(ctx context.Context, tx *sql.Tx, ns, resource string) (int64, bool, error) {
	var docid int64
	err := tx.QueryRowContext(ctx, `SELECT docid FROM docs WHERE ns = ? AND resource = ?`, ns, resource).Scan(&docid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if ix.fts {
		_, err = tx.ExecContext(ctx, `DELETE FROM "text" WHERE rowid BETWEEN ? AND ?`, docid<<textShift, docid<<textShift|(1<<textShift-1))
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM "text" WHERE docid = ?`, docid)
	}
	if err != nil {
		return 0, false, err
	}
	for _, q := range []string{`DELETE FROM facet WHERE ns = ? AND resource = ?`, `DELETE FROM "sort" WHERE ns = ? AND resource = ?`, `DELETE FROM refs WHERE ns = ? AND resource = ?`} {
		if _, err := tx.ExecContext(ctx, q, ns, resource); err != nil {
			return 0, false, err
		}
	}
	return docid, true, nil
}

func (ix *Index) write(ctx context.Context, tx *sql.Tx, ns string, p prepared) error {
	docid, found, err := ix.clearRows(ctx, tx, ns, p.resource)
	if err != nil {
		return err
	}
	if p.remove || (!p.typed && !ix.opt.UntypedListing) {
		if found {
			_, err = tx.ExecContext(ctx, `DELETE FROM docs WHERE docid = ?`, docid)
		}
		return err
	}
	var schemaCol, epochCol any
	if p.schema != "" {
		schemaCol = p.schema
	}
	if p.epoch > 0 {
		epochCol = p.epoch
	}
	if found {
		// A head whose epoch is pending (NULL) keeps the epoch an answer
		// judged for it, where the row holds that head already (§E.2.6,
		// judgeEpochs): judged once.
		_, err = tx.ExecContext(ctx, `UPDATE docs SET epoch = CASE WHEN head = ?1 AND ?3 IS NULL THEN epoch ELSE ?3 END, head = ?1, schema = ?2 WHERE docid = ?4`, p.head, schemaCol, epochCol, docid)
	} else {
		var res sql.Result
		res, err = tx.ExecContext(ctx, `INSERT INTO docs (ns, resource, head, schema, epoch) VALUES (?, ?, ?, ?, ?)`, ns, p.resource, p.head, schemaCol, epochCol)
		if err == nil {
			docid, err = res.LastInsertId()
		}
	}
	if err != nil || p.rows == nil {
		return err
	}
	for n, t := range p.rows.text {
		if n >= 1<<textShift {
			break
		}
		if ix.fts {
			_, err = tx.ExecContext(ctx, `INSERT INTO "text" (rowid, ns, resource, schema, path, body) VALUES (?, ?, ?, ?, ?, ?)`,
				docid<<textShift|int64(n), ns, p.resource, schemaCol, t.path, t.body)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO "text" (docid, ns, resource, schema, path, body) VALUES (?, ?, ?, ?, ?, ?)`,
				docid, ns, p.resource, schemaCol, t.path, t.body)
		}
		if err != nil {
			return err
		}
	}
	for _, f := range p.rows.facet {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO facet (ns, resource, schema, path, value, raw) VALUES (?, ?, ?, ?, ?, ?)`,
			ns, p.resource, schemaCol, f.path, f.value, f.raw); err != nil {
			return err
		}
	}
	for _, r := range p.rows.refs {
		var rev, entry any
		if r.rev != "" {
			rev = r.rev
		}
		if r.entry != "" {
			entry = r.entry
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO refs (ns, resource, schema, path, ref, target_ns, target, rev, entry) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ns, p.resource, schemaCol, r.path, r.ref, r.targetNS, r.target, rev, entry); err != nil {
			return err
		}
	}
	for _, s := range p.rows.sort {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO "sort" (ns, resource, schema, path, value, raw) VALUES (?, ?, ?, ?, ?, ?)`,
			ns, p.resource, schemaCol, s.path, s.value, s.raw); err != nil {
			return err
		}
	}
	return nil
}

type logPurger struct{ logf func(string, ...any) }

func (l logPurger) PurgeTags(tags []string) { l.logf("index: purge cache tags %v", tags) }

// SetMinWait changes how long ?min= waits (§A.5).
func (ix *Index) SetMinWait(d time.Duration) {
	ix.mu.Lock()
	ix.opt.MinWait = d
	ix.mu.Unlock()
}
