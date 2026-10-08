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
//	docs(docid, ns, resource, head, schema) one row per live resource (untyped too, see UntypedListing)
//	text  fts5(ns, resource, schema, path, body)  rowid = docid<<20 | n, so a resource's rows are a rowid range
//	facet(ns, resource, schema, path, value, raw)
//	sort (ns, resource, schema, path, value)
//	refs(ns, resource, schema, path, ref, target_ns, target, rev, entry)  x-ref references (§A.2, §A.3);
//	                                      path is the full instance pointer, indices included
//	sealed_views, sealed_view_tags   sealed results of sealed/e2e namespaces (derived.Cache)
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
// Without keys a namespace is skipped: not followed, answered 503
// "skipped", and reported with the reason at GET /_status. Results over a
// sealed or e2e namespace are sealed under its current epoch key
// (§E.2.5): see Handler.
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
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// Purger purges the index service's own cache tags (§A.1: a purge "also
// purge[s] the service's own cache tags").
type Purger interface{ PurgeTags(tags []string) }

// Options configure an Index.
type Options struct {
	// Client reads the core API; with a private namespace it needs a grant
	// with read on it (§C.6 least privilege). For sealed namespaces build it
	// WithKeys (client.NewKeys(Recipient)); its grant must get epoch keys
	// (read on the whole namespace), which seal the results.
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
	// MinWait bounds how long ?min= waits (§A.5); default 2s.
	MinWait time.Duration
	// Purger receives cache tag purges; default: log.
	Purger Purger
	// Edge is the verifying edge in front of the service (§9): private
	// results are served only to requests carrying its secret, with edge
	// lifetimes. Nil: there is none, and private responses are no-store
	// for shared caches.
	Edge *edge.Verifier
	// Now is the clock for grant checks (default time.Now).
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
	// FetchConcurrency is how many documents Apply fetches at once
	// (default 8); 1 fetches them one by one. Rows are written in log
	// order either way.
	FetchConcurrency int
}

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
	roots   map[string]bool
	keys    *derived.Keys  // encryption of followed namespaces
	sealed  *derived.Cache // sealed results

	wmu sync.Mutex // serialises Apply across followers

	mu      sync.Mutex
	cur     map[string]string // ns -> checkpoint
	purged  map[string]bool
	changed chan struct{} // closed and replaced after every commit
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
	// secure_delete: rows deleted by a purge are overwritten, not left in
	// free pages (see the package doc).
	dsn := "file:" + opt.DB + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	ix := &Index{
		keys: derived.NewKeys(opt.Client, opt.Recipient), sealed: derived.NewCache(0, db),
		opt: opt, c: opt.Client, db: db, cps: follow.SQLCheckpoints{DB: db}, origin: origin,
		checker: grantcheck.New(opt.Client, grantcheck.WithClock(opt.Now), grantcheck.WithTTL(opt.CheckerTTL)),
		schemas: NewSchemaCache(opt.Client),
		roots:   map[string]bool{}, cur: map[string]string{}, purged: map[string]bool{}, changed: make(chan struct{}),
	}
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
	return ix, nil
}

// Close closes the database.
func (ix *Index) Close() error { return ix.db.Close() }

// FTS reports whether the text table is FTS5 (false: the LIKE fallback).
func (ix *Index) FTS() bool { return ix.fts }

// Origin is the core's canonical origin, used in hit URLs.
func (ix *Index) Origin() string { return ix.origin }

var dropStmts = []string{
	`DROP TABLE IF EXISTS checkpoints`, `DROP TABLE IF EXISTS seen`, `DROP TABLE IF EXISTS ns_state`,
	`DROP TABLE IF EXISTS docs`, `DROP TABLE IF EXISTS "text"`, `DROP TABLE IF EXISTS facet`, `DROP TABLE IF EXISTS "sort"`, `DROP TABLE IF EXISTS refs`,
	derived.CacheDropStmts[0], derived.CacheDropStmts[1],
}

var createStmts = []string{
	`CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS ns_state (ns TEXT PRIMARY KEY, purged INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS docs (docid INTEGER PRIMARY KEY, ns TEXT NOT NULL, resource TEXT NOT NULL, head TEXT NOT NULL, schema TEXT, UNIQUE (ns, resource))`,
	`CREATE TABLE IF NOT EXISTS facet (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value TEXT NOT NULL, raw TEXT NOT NULL, PRIMARY KEY (ns, resource, path, value))`,
	`CREATE TABLE IF NOT EXISTS "sort" (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value, raw TEXT, PRIMARY KEY (ns, resource, path))`,
	`CREATE TABLE IF NOT EXISTS refs (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, ref TEXT NOT NULL, target_ns TEXT NOT NULL, target TEXT NOT NULL, rev TEXT, entry TEXT, PRIMARY KEY (ns, resource, path))`,
	`CREATE INDEX IF NOT EXISTS docs_q ON docs (ns, schema)`,
	`CREATE INDEX IF NOT EXISTS refs_q ON refs (target_ns, target, rev, entry)`,
	`CREATE INDEX IF NOT EXISTS facet_q ON facet (ns, path, value)`,
	`CREATE INDEX IF NOT EXISTS sort_q ON "sort" (ns, path, value)`,
}

const ftsCreate = `CREATE VIRTUAL TABLE IF NOT EXISTS "text" USING fts5(ns UNINDEXED, resource UNINDEXED, schema UNINDEXED, path UNINDEXED, body, tokenize = 'unicode61 remove_diacritics 2')`

// The LIKE fallback, for SQLite builds without FTS5.
var likeCreate = []string{
	`CREATE TABLE IF NOT EXISTS "text" (docid INTEGER NOT NULL, ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, body TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS text_doc ON "text" (docid)`,
}

func (ix *Index) initSchema(ctx context.Context) error {
	if !ix.opt.Rebuild {
		// A database from before v0.44 has no refs table, so its documents'
		// references were never collected (§A.2): replay it, as a rebuild.
		var docs, refs int
		if err := ix.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'docs'`).Scan(&docs); err != nil {
			return err
		}
		if err := ix.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'refs'`).Scan(&refs); err != nil {
			return err
		}
		if docs > 0 && refs == 0 {
			ix.opt.Logf("index: the database predates reference indexing (§A.2); rebuilding it from the logs")
			ix.opt.Rebuild = true
		}
		// Before v0.46 the sort table kept no value as written, and schema
		// documents were not indexed: replay those too.
		var noRaw int
		if err := ix.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('sort') WHERE name = 'raw'`).Scan(&noRaw); err != nil {
			return err
		}
		var haveSort int
		if err := ix.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'sort'`).Scan(&haveSort); err != nil {
			return err
		}
		if haveSort > 0 && noRaw == 0 && !ix.opt.Rebuild {
			ix.opt.Logf("index: the database predates sort values in hits and indexed schema documents (§A.4); rebuilding it from the logs")
			ix.opt.Rebuild = true
		}
	}
	if ix.opt.Rebuild {
		for _, s := range dropStmts {
			if _, err := ix.db.ExecContext(ctx, s); err != nil {
				return fmt.Errorf("index: rebuild: %w", err)
			}
		}
	}
	if err := ix.cps.Init(ctx); err != nil {
		return err
	}
	for _, s := range createStmts {
		if _, err := ix.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("index: schema: %w", err)
		}
	}
	if err := ix.sealed.Init(ctx); err != nil {
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
func (ix *Index) Run(ctx context.Context) error {
	var wg sync.WaitGroup
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
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) { ix.opt.Logf("index: %s: %v", n, err) }),
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
		if reason, permanent := ix.keys.Check(ctx, ns, false); reason != "" {
			if permanent {
				ix.opt.Logf("index: skipping %s: %s", ns, reason)
				return
			}
			err = fmt.Errorf("skipped: %s", reason)
		} else {
			err = follow.New(ix.c, ns, ix.cps, ix, opts...).Run(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, follow.ErrPurged) {
			ix.opt.Logf("index: %s was purged", ns)
			return
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

// prepared is one coalesced change with its fetched content, ready to write.
type prepared struct {
	resource string
	remove   bool
	head     string
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
	for _, u := range b.Units {
		if u.Config != nil {
			ix.keys.Observe(b.NS, u.Config.Value)
		}
	}
	// Fetch FetchConcurrency documents at a time (one GET each); preps
	// keeps the coalesced order, which the writes follow. The first error
	// fails the batch, as one by one, and the follower retries it whole.
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

	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if b.Snapshot || co.PurgedNS {
		// A snapshot is the complete state; a purge-ns drops everything
		// (Coalesce keeps only the changes after it).
		if err := ix.dropNS(ctx, tx, b.NS); err != nil {
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
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, b.NewCheckpoint); err != nil {
		return err
	}
	if co.PurgedNS {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ns_state (ns, purged) VALUES (?, 1) ON CONFLICT (ns) DO UPDATE SET purged = 1`, b.NS); err != nil {
			return err
		}
	}
	// §A.1, §A.4: a purge removes every cached result that shows the
	// resource, through the r:{ns}/{name} tag each result carries per hit
	// (and results with facet counts, which may aggregate it); a purge-ns
	// removes every cached result and pointer of the namespace. Stored
	// sealed results go by the same tags, in this transaction.
	var tags []string
	if co.PurgedNS {
		tags = append(tags, "idx:"+b.NS, "ns:"+b.NS)
	}
	for _, p := range preps {
		if p.purged {
			tags = append(tags, "r:"+b.NS+"/"+p.resource)
		}
	}
	if len(tags) > 0 && !co.PurgedNS {
		tags = append(tags, countsTag(b.NS))
	}
	if err := ix.sealed.Purge(ctx, tx, tags); err != nil {
		return err
	}
	if err := ix.cps.Save(ctx, tx, b.Origin, b.NS, b.NewCheckpoint); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Purge before the new checkpoint is out, so nobody who learns of it
	// can still be served what it removed. Purgers don't block.
	if len(tags) > 0 {
		ix.opt.Purger.PurgeTags(tags)
	}
	// Publish the checkpoint before any other work, waking ?min= waiters.
	// Redirects go by the committed checkpoint (Index.committed), so the
	// gap between the commit and this doesn't make them alternate.
	ix.mu.Lock()
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
	// checkpoint's results are served, so older stored ones go.
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
	for _, u := range b.Units {
		if u.Config != nil {
			// Keys, revocations or the read mode may have changed.
			ix.checker.Observe(b.NS, b.NewCheckpoint)
			break
		}
	}
	return nil
}

// prepare fetches p.resource's document at revision id and extracts its
// rows into p.
func (ix *Index) prepare(ctx context.Context, ns, id string, p *prepared) error {
	doc, err := ix.keys.FetchDoc(ctx, ns, p.resource, id, func(f client.Flag) {
		ix.opt.Logf("index: %s/%s: revision %s by %s is flagged and left out: %s", ns, p.resource, f.ID, f.Author, f.Message)
	})
	if err != nil {
		if errors.Is(err, derived.ErrSkip) || errors.Is(err, follow.ErrNotLive) || client.IsGone(err) || client.IsNotFound(err) {
			// Gone since: a later entry of the log says so too.
			p.remove = true
			return nil
		}
		return err
	}
	p.head = doc.ID
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
	var schemaCol any
	if p.schema != "" {
		schemaCol = p.schema
	}
	if found {
		_, err = tx.ExecContext(ctx, `UPDATE docs SET head = ?, schema = ? WHERE docid = ?`, p.head, schemaCol, docid)
	} else {
		var res sql.Result
		res, err = tx.ExecContext(ctx, `INSERT INTO docs (ns, resource, head, schema) VALUES (?, ?, ?, ?)`, ns, p.resource, p.head, schemaCol)
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
