package core

// The DynamoDB backend (docs/DYNAMODB.md), §10's path C, one instance.
// ddbBackend implements the Engine's backend (backend.go) for -db
// dynamodb:// URLs (registerBackend): the gate's reads over the table
// (ddbreads.go), the commits of what the gate decided (ddbwrite.go,
// ddbblobs.go and the rest). Reads and the write checks are core's own
// code on the gate.
//
// Deliberate gaps, surfaced as 501 "unsupported" (ddbUnsupported, or a
// read that panics with it): the SQL write path's hooks; mirroring a
// schema revision the remote base pruned; raising a namespace from
// sealed to e2e, and mirroring a base raised so (ddblevels.go); a value
// over DynamoDB's 400 KB item (ddbAsErr). Intermediate snapshots aren't
// kept (revisions fold from the genesis, or from a pruning horizon).
// Everything else the SQL backends serve works here, multi-step items
// and batches bounded by the transaction's 100 actions (§7.5).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/schema"
)

// ddbBackend is the Engine's DynamoDB state: the store and what the
// engine keeps of it.
type ddbBackend struct {
	e     *Engine
	store ddb.Store
	cfgMu sync.Mutex
	// byID are the configurations the gate's reads parsed, by namespace
	// and id (ddbReads.config): a configuration never changes.
	byID map[string]*Config
	// cfgRows are the configuration items read (configAt), by namespace
	// and position: a configuration never changes.
	cfgRows map[string]*ddb.ConfigRow
	// entryPositions are entry ids' positions (entryPos), by namespace
	// and id: an entry's position never changes.
	entryPositions map[string]uint64
	// refsMarked are the schema references marked (schemaRefs).
	refsMarked markedSet
	// keys are the data keys unwrapped (ddbcrypt.go); grantsSealed the
	// grants stored encrypted.
	keys         ddbKeys
	grantsSealed markedSet
}

// markedSet is a bounded set of keys: when full it starts over (a key
// forgotten is only written again).
type markedSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *markedSet) has(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k]
}

func (s *markedSet) add(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil || len(s.m) >= 4096 {
		s.m = map[string]bool{}
	}
	s.m[k] = true
}

// ErrUnsupported wraps Open's refusal of an option the backend the path
// names doesn't implement (on DynamoDB: encryption at rest, blob storage,
// authentication — docs/DYNAMODB.md §13). Test harnesses skip on it; a
// deployment fixes its flags.
var ErrUnsupported = errors.New("not implemented on this backend")

// openDDB builds the engine on a DynamoDB table (Open's branch for
// dynamodb:// paths, after option normalization). The background loops of
// the SQL backends (tailer, retention, sweeps, repurge, rotation, remote
// follow) don't start: their features are phase 2+.
func openDDB(opt Options) (*Engine, error) {
	// What it would otherwise ignore: the SQL write path's test hooks,
	// which it never reaches — a caller waiting on one would wait for good.
	if opt.BeforeWriteLock != nil || opt.BeforeCommit != nil {
		return nil, fmt.Errorf("core: the SQL write path's hooks (BeforeWriteLock, BeforeCommit): %w (DynamoDB)", ErrUnsupported)
	}
	b := &ddbBackend{byID: map[string]*Config{}, cfgRows: map[string]*ddb.ConfigRow{}, entryPositions: map[string]uint64{}}
	store, err := ddb.Open(context.Background(), opt.Path, ddb.Options{
		// Group commit (docs/DYNAMODB.md §4): resource writes queue per
		// namespace; GroupCommitWait doesn't apply — a group forms from
		// the writes queued while the one before it commits.
		GroupCommit: opt.GroupCommit,
		// The engine's clock stamps what the store writes (created
		// times), as the SQL write path's opt.Now does: Last-Modified and
		// /heads' created are the revision's own time on the instance's
		// clock (§7.1).
		Now: opt.Now,
		// What core encrypted at rest, opened for the store's own folds.
		OpenValue: func(ctx context.Context, ns, name, kind, key, raw string) (string, error) {
			return b.openValue(ctx, ns, name, kind, key, raw)
		},
		OnGroup: observeGroup,
	})
	if err != nil {
		return nil, err
	}
	b.store = store
	// The table must answer before the server starts, as a SQL database
	// must open: a region, credentials or a table that is missing fail
	// here, by name, rather than as every request's error.
	pctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	err = store.Ping(pctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("dynamodb: the table of %s doesn't answer (does the URL name its region, are AWS credentials available, does the table exist?): %w", opt.Path, err)
	}
	// The deployment's batch maximum, lowered to what one transaction
	// holds (docs/DYNAMODB.md §10): namespaces learn it from their limits,
	// and a batch over it is §6.6's 413 itemsPerBatch, not the action cap.
	opt.Maximums.ItemsPerBatch = min(opt.Maximums.ItemsPerBatch, store.MaxBatchItems())
	opt.Limits.ItemsPerBatch = min(opt.Limits.ItemsPerBatch, opt.Maximums.ItemsPerBatch)
	// Blob bytes go to files under -blob-dir (one instance), or else into
	// their items, which bounds blobSize by an item's size.
	var blobs blobStore = tableStore{}
	if opt.BlobDir != "" {
		if blobs, err = openBlobStore(opt.BlobDir, "", false); err != nil {
			return nil, err
		}
	} else {
		opt.Maximums.BlobSize = min(opt.Maximums.BlobSize, ddb.MaxInlineBytes)
		opt.Limits.BlobSize = min(opt.Limits.BlobSize, opt.Maximums.BlobSize)
	}
	e := &Engine{
		blobs:      blobs,
		opt:        opt,
		validator:  schema.NewValidator(),
		hub:        newHub(),
		rate:       newRateLimiter(),
		docs:       newDocCache(opt.DocCacheBytes),
		schemaDocs: newParsedCache(4096),
		deks:       newDEKCache(4096),
		cfgCache:   map[int64]*Config{},
		stop:       make(chan struct{}),
		started:    opt.Now().UTC(),
	}
	e.rc.maxBytes = opt.ReadCacheBytes
	e.bearers.lru.MaxEntries, e.bearers.lru.MaxBytes = opt.GrantCacheEntries, maxGrantCacheBytes
	// Registrations are renewed within a week of expiring, as on SQL
	// (SyncRemotes).
	if e.opt.Remote.RenewBefore == 0 {
		e.opt.Remote.RenewBefore = 7 * 24 * time.Hour
	}
	b.e = e
	e.be = b
	if err := b.checkKeyStore(context.Background()); err != nil {
		return nil, err
	}
	if err := b.checkEpochKeys(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

func init() {
	registerBackend(ddb.IsURL, openDDB)
}

var _ backend = (*ddbBackend)(nil)

func (b *ddbBackend) orphanFiles(ctx context.Context, cands map[fileGroup][]string) ([]string, error) {
	// The BYTES items name the files (putBytes).
	_, _, bytes, err := b.store.ScanBlobs(ctx)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	named := map[string]bool{}
	for _, by := range bytes {
		named[by.File] = true
	}
	var orphans []string
	for _, files := range cands {
		for _, f := range files {
			if !named[f] {
				orphans = append(orphans, f)
			}
		}
	}
	return orphans, nil
}

func (b *ddbBackend) firstEntryTime(ctx context.Context) (int64, bool, error) {
	return b.store.FirstEntryTime(ctx)
}

func (b *ddbBackend) ping(ctx context.Context) error { return b.store.Ping(ctx) }
func (b *ddbBackend) close() error                   { return nil }
func (b *ddbBackend) dbSystem() string               { return "aws.dynamodb" }

// ddbUnsupported answers for an Engine method the phase doesn't cover.
func ddbUnsupported(what string) *Error {
	return apiErr(501, "unsupported", "message", what+" is not implemented on the DynamoDB backend (docs/DYNAMODB.md §13)")
}

// ddbAsErr maps the store's *ddb.Error onto *core.Error (same body
// shape) and anything else onto a 500.
func ddbAsErr(err error) *Error {
	var de *ddb.Error
	if errors.As(err, &de) {
		return &Error{Status: de.Status, Body: de.Body}
	}
	var ce *Error
	if errors.As(err, &ce) {
		return ce
	}
	if strings.Contains(err.Error(), "Item size has exceeded the maximum allowed size") {
		// Values over DynamoDB's 400 KB item limit go to S3 in the
		// design (docs/DYNAMODB.md §3), which the store doesn't do.
		return ddbUnsupported("a value larger than DynamoDB's 400 KB item")
	}
	return apiErr(500, "internal", "message", err.Error())
}

// commit commits c, bracketed for the read cache as a SQL commit is
// (commit of engine.go): its generations move before and after, so a read
// that overlapped it doesn't store what it read, and the namespace's live
// readers wake. A config change may change what any read answers (meta).
func (b *ddbBackend) commit(ctx context.Context, c *ddb.Commit) (*ddb.CommitResult, error) {
	e := b.e
	// A purge takes content away from every cached answer (flushDocs, as
	// purgeResource's).
	// So does a prune, from the documents below its horizon, which
	// cached answers to revision reads hold until the meta generation
	// moves (the SQL invalidation's: meta with every flush).
	flush := c.Purge != nil || c.PurgeNS || c.Prune != nil
	inv := invalidation{nss: []string{c.NS}, meta: c.Config != nil || flush, flushDocs: flush}
	if c.Branch != nil {
		// A namespace that now exists.
		inv.nss, inv.meta = append(inv.nss, c.Branch.Name), true
	}
	e.rc.begin(inv)
	defer e.invalidate(inv, false)
	return b.store.Commit(ctx, c)
}

// committed is the post-commit of a write: purge the cache tags the
// write's transaction would have collected on SQL (t.tags: none for
// resource writes; ns:{ns} when a config change ends public caching,
// insertConfig).
func (b *ddbBackend) committed(ns string, tags ...string) {
	e := b.e
	if len(tags) > 0 {
		e.opt.Purger.PurgeTags(tags)
	}
}

// --- reads ---

// repurgeOf is the second purge of tags a commit queues (repurge.go): nil
// for none, or with RepurgeDelay negative.
func (b *ddbBackend) repurgeOf(now time.Time, tags []string) *ddb.Repurge {
	if len(tags) == 0 || b.e.opt.RepurgeDelay < 0 {
		return nil
	}
	return &ddb.Repurge{Due: now.Add(b.e.opt.RepurgeDelay).UnixMilli(), Tags: tags}
}

func (b *ddbBackend) dueRepurges(ctx context.Context, now time.Time) ([]dueRepurge, error) {
	rs, err := b.store.DueRepurges(ctx, now.UnixMilli(), 100)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	out := make([]dueRepurge, len(rs))
	for i, r := range rs {
		out[i] = dueRepurge{key: r.Key, tags: r.Tags}
	}
	return out, nil
}

func (b *ddbBackend) doneRepurge(ctx context.Context, key any) error {
	return asErrOrNil(b.store.DoneRepurge(ctx, key.(string)))
}
