package core

// The DynamoDB backend (docs/DYNAMODB.md), phase 1 of §10's path C:
// plain namespaces, authentication disabled (-dev), one instance. The
// seam: Open keeps a *ddbBackend on the Engine when -db is a dynamodb://
// URL, and each Engine method of the phase-1 serving set delegates when
// it is set — writes through the store's check hook (the gate of §6.2,
// subset), reads mapped onto the store's items. What the phase doesn't
// cover answers 501 rather than falling through to SQL.
//
// Deliberate gaps, all surfaced as 501 "unsupported": grants and private
// reads (writes require -dev), multi-step items, branches, purges and
// pruning, blobs (batch sources with them), sealed and e2e namespaces,
// $schema validation, nonce-required namespaces, gestures listing, SSE
// events, author signatures, rate limiting, head snapshots (revisions
// fold from the genesis). Tombstones and restores work (§8.1), and
// batches (§7.5): single-step items, per-item failures, dry runs, an
// optional config change, bounded by the transaction's 100 actions.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
)

// ddbBackend is the Engine's DynamoDB state: the store and the
// configuration cache (configs change only through this instance in phase
// 1, so the cache invalidates on its own commits).
type ddbBackend struct {
	store *ddb.Store
	cfgMu sync.Mutex
	cfgs  map[string]*ddbCfgEntry
	// byID are the configurations the gate's reads parsed, by namespace
	// and id (ddbReads.config): a configuration never changes.
	byID map[string]*Config
}

type ddbCfgEntry struct {
	id  string
	cfg *Config
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
	if opt.BlobDir != "" {
		return nil, fmt.Errorf("core: blob storage: %w (DynamoDB, docs/DYNAMODB.md phase 1)", ErrUnsupported)
	}
	if !opt.AuthDisabled {
		return nil, fmt.Errorf("core: authentication: %w (DynamoDB writes in -dev mode only, docs/DYNAMODB.md phase 1); run with -dev", ErrUnsupported)
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
	e := &Engine{
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
	e.ddb = &ddbBackend{store: store, cfgs: map[string]*ddbCfgEntry{}, byID: map[string]*Config{}}
	return e, nil
}

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

// ddbConfig is the namespace's compiled configuration, cached by id.
func (e *Engine) ddbConfig(ctx context.Context, ns, cfgID string) (*Config, *Error) {
	b := e.ddb
	b.cfgMu.Lock()
	if c := b.cfgs[ns]; c != nil && c.id == cfgID {
		cfg := c.cfg
		b.cfgMu.Unlock()
		return cfg, nil
	}
	b.cfgMu.Unlock()
	doc, id, err := b.store.ReadConfig(ctx, ns)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	cfg, perr := e.newConfig(doc, nil, nil)
	if perr != nil {
		return nil, perr
	}
	b.cfgMu.Lock()
	b.cfgs[ns] = &ddbCfgEntry{id: id, cfg: cfg}
	b.cfgMu.Unlock()
	return cfg, nil
}

// ddbForgetConfig drops a namespace's cached configuration: the next read
// re-reads it (single instance; commits are this instance's).
func (e *Engine) ddbForgetConfig(ns string) {
	e.ddb.cfgMu.Lock()
	delete(e.ddb.cfgs, ns)
	e.ddb.cfgMu.Unlock()
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

// ddbAuthor is the dev-mode author (authenticate's AuthDisabled branch).
func ddbAuthor(cred Credentials) string {
	if cred.Author != "" {
		return cred.Author
	}
	return "anonymous"
}

// ddbCommitted is the post-commit of a write: wake the namespace's live
// readers and purge the cache tags the write's transaction would have
// collected on SQL (t.tags: none for resource writes; ns:{ns} when a
// config change ends public caching, insertConfig). The read cache holds
// no ddb entries in phase 1.
func (e *Engine) ddbCommitted(ns string, tags ...string) {
	e.hub.publish(ns)
	if len(tags) > 0 {
		e.opt.Purger.PurgeTags(tags)
	}
}

// --- writes: ddbwrite.go ---

// applyConfigPatches folds config patches into a namespace document, as
// createNamespace does (nsops.go).
func applyConfigPatches(doc any, exists bool, patches any) (any, *Error) {
	ops, err := patch.Parse(patches)
	if err != nil {
		return nil, patchErr(err)
	}
	out, _, err := patch.Apply(doc, exists, ops, patch.Options{})
	if err != nil {
		return nil, patchErr(err)
	}
	return out, nil
}

// ddbBatchBodyLimit is BatchBodyLimit's bound for a ddb namespace: the
// same formula over the configuration's batch limits (no allowances in
// dev mode).
func (e *Engine) ddbBatchBodyLimit(ctx context.Context, req Request) (bound, batchSize int, err error) {
	info, err := e.ddb.store.ReadNSInfo(ctx, req.NS)
	if err != nil {
		return 0, 0, ddbAsErr(err)
	}
	if !info.Exists {
		return 0, 0, apiErr(404, "not_found", "namespace", req.NS)
	}
	cfg, perr := e.ddbConfig(ctx, req.NS, info.ConfigID)
	if perr != nil {
		return 0, 0, perr
	}
	items, size := cfg.Limits.ItemsPerBatch, cfg.Limits.BatchSize
	bound = size + size/4 + 512*items + max(cfg.Limits.PatchSetSize, cfg.Limits.DocumentSize) + 64<<10
	return bound, size, nil
}

// --- reads ---

// ddbNS guards a read's namespace and answers whether it's public.
func (e *Engine) ddbNS(ctx context.Context, ns string) (*ddb.NSInfo, bool, *Error) {
	info, err := e.ddb.store.ReadNSInfo(ctx, ns)
	if err != nil {
		return nil, false, ddbAsErr(err)
	}
	if !info.Exists {
		return nil, false, apiErr(404, "not_found", "namespace", ns)
	}
	if info.Purged {
		return nil, false, apiErr(410, "purged", "namespace", ns)
	}
	cfg, perr := e.ddbConfig(ctx, ns, info.ConfigID)
	if perr != nil {
		return nil, false, perr
	}
	public := cfg.Read == "public"
	if !public && !e.opt.AuthDisabled {
		return nil, false, ddbUnsupported("private reads (grants)")
	}
	return info, public, nil
}

func (e *Engine) ddbResourceHead(ctx context.Context, ns, name string, cred Credentials) (*Head, error) {
	_, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	head, derr := e.ddb.store.ReadHead(ctx, ns, name)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	if head == nil {
		return &Head{State: NotFound, Public: public}, nil
	}
	if !head.Live {
		h := &Head{State: Tombstoned, Head: head.ID, Last: head.LastID, Public: public}
		// Successor is the last live document's well-formed top-level
		// $successor (§8.1, §6.5), as the SQL path serves it.
		if doc, _, err := e.ddb.store.FoldResource(ctx, ns, name, head.LastPos); err == nil {
			if m, ok := doc.(map[string]any); ok {
				if s, ok := m["$successor"]; ok && schema.Successor(s) {
					h.Successor, _ = s.(string)
				}
			}
		}
		return h, nil
	}
	return &Head{State: Live, Head: head.ID, Public: public}, nil
}

func (e *Engine) ddbResourceRev(ctx context.Context, ns, name, id string, cred Credentials) (*Rev, error) {
	_, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	if id == "" {
		head, herr := e.ddb.store.ReadHead(ctx, ns, name)
		if herr != nil {
			return nil, ddbAsErr(herr)
		}
		if head == nil {
			return &Rev{Status: 404, Public: public}, nil
		}
		if !head.Live {
			return &Rev{Status: 410, Code: "tombstone", Public: public}, nil
		}
		id = head.ID
	}
	// The resource's own chain (findInAncestry): a genesis twin's id
	// names a revision of each.
	rev, derr := e.ddb.store.ReadRevOf(ctx, ns, name, id)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	if rev == nil {
		return &Rev{Status: 404, Public: public}, nil
	}
	if rev.Kind == "tombstone" {
		return &Rev{Status: 410, Code: "tombstone", Public: public}, nil
	}
	_, canon, derr := e.ddb.store.FoldResource(ctx, ns, name, rev.Pos)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	return &Rev{Status: 200, Doc: canon, Public: public, Created: time.UnixMilli(rev.Created).UTC(), Digest: rev.Digest}, nil
}

func (e *Engine) ddbResourceRaw(ctx context.Context, ns, name, id string, cred Credentials) (*Raw, error) {
	head, err := e.ddbResourceHead(ctx, ns, name, cred)
	if err != nil {
		return nil, err
	}
	out := &Raw{Head: head, Public: head.Public}
	if head.State != Live {
		return out, nil
	}
	rev, err := e.ddbResourceRev(ctx, ns, name, id, cred)
	if err != nil {
		return nil, err
	}
	out.Rev = rev
	return out, nil
}

func (e *Engine) ddbResourceLog(ctx context.Context, ns, name, id, since string, limit int, cred Credentials) (*Log, error) {
	_, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	// The range (since, to] of ResourceLog (§7.1): to is the id's
	// position, or the head's for ""; since, when given, a revision of the
	// chain at or below it. The chain is linear, so every revision of it
	// is an ancestor of the head; anything else is 404, as is an absent
	// resource.
	headPos, derr := e.ddb.store.HeadPos(ctx, ns, name)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	if headPos == 0 {
		return &Log{Status: 404, Public: public}, nil
	}
	toPos := headPos
	if id != "" {
		if toPos, derr = e.ddb.store.RevPos(ctx, ns, name, id); derr != nil {
			return nil, ddbAsErr(derr)
		}
		if toPos == 0 || toPos > headPos {
			return &Log{Status: 404, Public: public}, nil
		}
	}
	var fromPos uint64
	if since != "" {
		if fromPos, derr = e.ddb.store.RevPos(ctx, ns, name, since); derr != nil {
			return nil, ddbAsErr(derr)
		}
		if fromPos == 0 || fromPos > toPos {
			return &Log{Status: 404, Public: public}, nil
		}
	}
	// A page (limit > 0) is also bounded by logPageBytes of patch sets,
	// though it always holds one entry (logBetween).
	maxBytes := 0
	if limit > 0 {
		maxBytes = e.opt.Maximums.LogPageBytes
	}
	entries, more, derr := e.ddb.store.ResourceLog(ctx, ns, name, fromPos, toPos, limit, maxBytes)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	out := &Log{Status: 200, Public: public, Last: since, More: more}
	for _, re := range entries {
		// LogEntry.value's shape: dev-mode writes carry no grant, so
		// resource entries serve none (only namespace entries mark
		// no_auth with "grant": null).
		le := LogEntry{
			ID: re.ID, Parent: re.ParentID, Kind: re.Kind, Patches: re.Patches,
			Author: re.Author, Created: formatTime(re.Created),
			Gesture: re.Gesture, Undoes: re.Undoes,
		}
		out.Entries = append(out.Entries, le.value())
		out.Last = re.ID
	}
	return out, nil
}

func (e *Engine) ddbNamespaceLog(ctx context.Context, ns, id, since string, limit int, cred Credentials) (*Log, error) {
	_, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	entries, next, derr := e.ddb.store.ReadLog(ctx, ns, id, since, limit)
	if derr != nil {
		var de *ddb.Error
		if errors.As(derr, &de) && de.Status == 404 {
			return &Log{Status: 404, Public: public}, nil
		}
		return nil, ddbAsErr(derr)
	}
	out := &Log{Status: 200, Public: public, Last: since}
	for _, e := range entries {
		e["grant"] = nil // dev mode: entries serve "grant": null (§1)
		out.Entries = append(out.Entries, e)
		out.Last = e["id"].(string)
	}
	out.More = next != ""
	return out, nil
}

func (e *Engine) ddbNamespaceHead(ctx context.Context, ns string, cred Credentials) (*NSInfo, error) {
	info, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	return &NSInfo{Head: info.HeadID, Config: info.ConfigID, Public: public}, nil
}

func (e *Engine) ddbNamespaceRev(ctx context.Context, ns, id string, cred Credentials) (*NSInfo, error) {
	_, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	doc, cfgID, derr := e.ddb.store.ReadDocAtEntry(ctx, ns, id)
	if derr != nil {
		// An id that is no entry of the log: the 404 of NamespaceRev,
		// not a document (nfNS).
		var de *ddb.Error
		if errors.As(derr, &de) && de.Status == 404 {
			return nil, nfNS(public)
		}
		return nil, ddbAsErr(derr)
	}
	return &NSInfo{Head: id, Config: cfgID, Public: public, Doc: jsonv.Canonical(doc)}, nil
}

func (e *Engine) ddbNamespaceHeads(ctx context.Context, ns, nsID, after string, cred Credentials) (*HeadsPage, error) {
	_, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	// The heads as of the entry nsID (§7.4): names created after it are
	// skipped, heads moved since are the ones it saw (HeadsAt). An id
	// that is no entry of the log is 404 (nfNS), "" included.
	if nsID == "" {
		return nil, nfNS(public)
	}
	page, next, found, derr := e.ddb.store.HeadsAt(ctx, ns, nsID, after, e.opt.Maximums.LogPageSize)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	if !found {
		return nil, nfNS(public)
	}
	out := &HeadsPage{Items: []map[string]any{}, Public: public, Next: next}
	for _, h := range page {
		kind := "head"
		if h.Tombstoned {
			kind = "tombstone"
		}
		item := map[string]any{"resource": h.Name, "kind": kind, "target": h.ID}
		// created, the target's created time as log entries give it, a
		// tombstone's too; size and digest, a live head's document's
		// (NamespaceHeads; plain namespaces only in phase 1).
		if h.Created != 0 {
			item["created"] = formatTime(h.Created)
		}
		if !h.Tombstoned && len(h.Digest) == sha256.Size {
			item["size"] = float64(h.Size)
			item["digest"] = ReprDigest(h.Digest)
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// ddbNamespaceLiveLog is NamespaceLog for the long-poll fetch: correct,
// without the SQL path's sharing of reads among waiters (live.go's
// collapse is an optimization; Streams are phase 3).
func (e *Engine) ddbNamespaceLiveLog(ctx context.Context, ns, since string, limit int, cred Credentials, pass *LivePass) (*Log, *LivePass, error) {
	lg, err := e.ddbNamespaceLog(ctx, ns, "", since, limit, cred)
	return lg, nil, err
}
