package core

// The DynamoDB backend (docs/DYNAMODB.md), phase 1 of §10's path C:
// plain namespaces, one instance. ddbBackend implements the Engine's
// backend (backend.go) for -db dynamodb:// URLs (registerBackend): the
// gate's reads over the table (ddbreads.go), the commits of what the gate
// decided (ddbwrite.go, ddbblobs.go). Reads and the write checks are
// core's own code on the gate.
//
// Deliberate gaps, all surfaced as 501 "unsupported" (lacks, or a read
// that panics with it): branches, purges and pruning, batch sources
// whose documents reference blobs, sealed and e2e namespaces,
// nonce-required namespaces, gestures listing, author signatures, head
// snapshots (revisions fold from the genesis). Grants, edge grants,
// blobs, $schema validation and schemaReads, tombstones and restores,
// multi-step items and batches (§7.5, bounded by the transaction's 100
// actions) work.

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/schema"
)

// ddbBackend is the Engine's DynamoDB state: the store and what the
// engine keeps of it.
type ddbBackend struct {
	e     *Engine
	store *ddb.Store
	cfgMu sync.Mutex
	// byID are the configurations the gate's reads parsed, by namespace
	// and id (ddbReads.config): a configuration never changes.
	byID map[string]*Config
	// refsMarked are the schema references marked (schemaRefs).
	refsMarked markedSet
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
	if opt.KeyStore != nil {
		return nil, fmt.Errorf("core: encryption at rest: %w (DynamoDB, docs/DYNAMODB.md phase 1)", ErrUnsupported)
	}
	// What it would otherwise ignore: an archive no retention loop writes,
	// and the SQL write path's test hooks, which it never reaches — a
	// caller waiting on one would wait for good.
	if opt.Archiver != nil {
		return nil, fmt.Errorf("core: archives: %w (DynamoDB, docs/DYNAMODB.md phase 2)", ErrUnsupported)
	}
	if opt.BeforeWriteLock != nil || opt.BeforeCommit != nil {
		return nil, fmt.Errorf("core: the SQL write path's hooks (BeforeWriteLock, BeforeCommit): %w (DynamoDB)", ErrUnsupported)
	}
	store, err := ddb.Open(context.Background(), opt.Path)
	if err != nil {
		return nil, err
	}
	// Group commit (docs/DYNAMODB.md §4): resource writes queue per
	// namespace; GroupCommitWait doesn't apply — a group forms from the
	// writes queued while the one before it commits.
	store.GroupCommit = opt.GroupCommit
	// The engine's clock stamps what the store writes (created times),
	// as the SQL write path's opt.Now does: Last-Modified and /heads'
	// created are the revision's own time on the instance's clock (§7.1).
	store.Now = opt.Now
	// The deployment's batch maximum, lowered to what one transaction
	// holds (docs/DYNAMODB.md §10): namespaces learn it from their limits,
	// and a batch over it is §6.6's 413 itemsPerBatch, not the action cap.
	opt.Maximums.ItemsPerBatch = min(opt.Maximums.ItemsPerBatch, ddb.MaxBatchItems)
	opt.Limits.ItemsPerBatch = min(opt.Limits.ItemsPerBatch, opt.Maximums.ItemsPerBatch)
	// Blob bytes go to the blob store (S3 for several instances; a
	// directory for one), or else into their items, which bounds blobSize
	// by an item's size.
	blobs := opt.BlobStore
	if blobs == nil {
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
	e.be = &ddbBackend{e: e, store: store, byID: map[string]*Config{}}
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

// lacks: the features phase 1 doesn't build answer 501 (ddbUnsupported).
func (b *ddbBackend) lacks(feature string) *Error { return ddbUnsupported(feature) }

// ddbUnsupported answers for an Engine method the phase doesn't cover.
func ddbUnsupported(what string) *Error {
	return apiErr(501, "unsupported", "message", what+" is not implemented on the DynamoDB backend (docs/DYNAMODB.md phase 1)")
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
	return apiErr(500, "internal", "message", err.Error())
}

// ddbRefusals are the configuration features phase 1 refuses, shared by
// creates and changes.
func ddbRefusals(cfg *Config) *Error {
	switch {
	case cfg.Encryption != "":
		return ddbUnsupported("encrypted namespaces")
	case cfg.NonceRequired:
		return ddbUnsupported("nonce-required namespaces")
	case cfg.Base != nil:
		return ddbUnsupported("branches")
	case cfg.Successor != "":
		return ddbUnsupported("namespace successors")
	case cfg.SignaturesRequired:
		// Writes can't carry signatures on this backend, so a
		// namespace requiring them would take unsigned ones (§C.3.1).
		return ddbUnsupported("author signatures")
	}
	return nil
}

// commit commits c, bracketed for the read cache as a SQL commit is
// (commit of engine.go): its generations move before and after, so a read
// that overlapped it doesn't store what it read, and the namespace's live
// readers wake. A config change may change what any read answers (meta).
func (b *ddbBackend) commit(ctx context.Context, c *ddb.Commit) (*ddb.CommitResult, error) {
	e := b.e
	inv := invalidation{nss: []string{c.NS}, meta: c.Config != nil}
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
