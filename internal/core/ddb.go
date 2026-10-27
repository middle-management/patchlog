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
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/rules"
	"github.com/middle-management/patchlog/internal/schema"
)

// ddbBackend is the Engine's DynamoDB state: the store and the
// configuration cache (configs change only through this instance in phase
// 1, so the cache invalidates on its own commits).
type ddbBackend struct {
	store *ddb.Store
	cfgMu sync.Mutex
	cfgs  map[string]*ddbCfgEntry
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
	e.ddb = &ddbBackend{store: store, cfgs: map[string]*ddbCfgEntry{}}
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

// --- the thin gate (§6.2, phase-1 subset) ---

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

// ddbGate is the write gate of §6.2 for a single patch-set step, phase-1
// subset: namespace state, unsupported features, limits (step 2), and
// namespace rules against the §6.4.1 envelope (step 6). Grants (steps 1,
// 3, and step 6's grant side), schemas (step 5) and rate limits are out
// of the phase; authentication is disabled, so the envelope's principal
// is null, as the SQL path's dev mode builds it (basicEnvelope).
func (e *Engine) ddbGate(ns, name string, patches any, st *ddb.WriteState) *Error {
	if !st.Exists {
		return apiErr(404, "not_found", "namespace", ns)
	}
	if st.Purged {
		return apiErr(410, "purged", "namespace", ns)
	}
	if st.Frozen {
		return apiErr(409, "frozen")
	}
	cfg, perr := e.ddbConfig(context.Background(), ns, st.ConfigID)
	if perr != nil {
		return perr
	}
	return ddbGateCfg(cfg, ns, name, patches, st, e.opt.Now().UnixMilli())
}

// ddbGateCfg is ddbGate with the configuration already loaded: a batch's
// items are gated under its config change's result (§7.5), not the one
// in force when the batch started.
func ddbGateCfg(cfg *Config, ns, name string, patches any, st *ddb.WriteState, nowMs int64) *Error {
	if err := ddbRefusals(cfg); err != nil {
		return err
	}

	// The envelope's document and patches: a write's result and its patch
	// set; a delete's last live document and none (stepEnvelope, §6.4.1).
	// The $schema refusal and the limits are a write's; a delete writes
	// no document.
	doc := st.Doc
	var canon []byte
	if st.Action == "delete" {
		doc = st.HeadDoc
	} else {
		// Step 4, the SQL path's own checkLimits on a one-step item:
		// sizes (a create, or an append that replaces the whole
		// document, against documentSize: fromScratch), counts, depth
		// and well-formed $blob references. A document that references
		// blobs then needs them resolved (checkBlobs), which this
		// backend can't do.
		canon = jsonv.Canonical(patches)
		step := &stepState{raw: patches, canon: canon, action: st.Action, doc: st.Doc}
		if err := checkLimits(cfg.Limits, &itemState{steps: []*stepState{step}}); err != nil {
			return err
		}
		if !step.noBlobs {
			return ddbUnsupported("blobs")
		}
		// Step 5.
		if d, ok := st.Doc.(map[string]any); ok {
			if _, typed := d["$schema"]; typed {
				return ddbUnsupported("$schema validation")
			}
		}
	}

	// Step 6, namespace rules: the §6.4.1 envelope, with patches only
	// when a rule reads them (rulesRead's shape), doc always
	// (stepEnvelope).
	env := map[string]any{
		"action":    st.Action,
		"now":       formatTime(nowMs),
		"principal": nil,
		"writes":    stringsToAny(st.Writes),
		"doc":       doc,
	}
	if name != "" {
		env["resource"] = name
	}
	if st.Action == "delete" {
		env["patches"] = []any{}
	} else {
		for _, r := range cfg.Rules {
			if refs := r.Refs(); refs["patches"] || refs["*"] {
				env["patches"] = jsonv.MustParse(canon)
				break
			}
		}
	}
	if i, path, ok := rules.EvalList(cfg.Rules, env); !ok {
		return apiErr(422, "rule", "rule", i, "path", path)
	}
	return nil
}

func stringsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// ddbAuthor is the dev-mode author (authenticate's AuthDisabled branch).
func ddbAuthor(cred Credentials) string {
	if cred.Author != "" {
		return cred.Author
	}
	return "anonymous"
}

// ddbDraw is a write's rate-limit draw (rateLimit of auth.go) for the
// -dev principal (devActor), allowances included: one draw a request,
// whichever comes first of the gate (a write that reaches it) and the
// store's answer before it (a replay, or a step-2 refusal). On the SQL
// path the draw precedes both (§6.6, §6.2 step 1), so they draw too, and
// an empty bucket answers 429 instead.
type ddbDraw struct {
	e     *Engine
	ns    string
	cred  Credentials
	names []string
	items int
	done  bool
}

func (d *ddbDraw) take(cfg *Config) *Error {
	if d.done || d.items == 0 {
		return nil
	}
	d.done = true
	a, now := devActor(d.cred), d.e.opt.Now()
	return d.e.admit(now, writeDraws(d.ns, cfg.Limits, principalDraw(d.ns, cfg, a, float64(d.items), now), a.bucketKey, d.names, d.items))
}

// late draws for an answer the store gave before the gate ran, once the
// namespace is known to exist: what SQL refuses before step 1 (absent,
// malformed) draws nothing.
func (d *ddbDraw) late(ctx context.Context, err error) *Error {
	if d.done {
		return nil
	}
	if err != nil {
		if ae := ddbAsErr(err); ae.Status == 404 || ae.Status == 400 || ae.Status >= 500 {
			return nil
		}
	}
	info, ierr := d.e.ddb.store.ReadNSInfo(ctx, d.ns)
	if ierr != nil || !info.Exists {
		return nil
	}
	cfg, perr := d.e.ddbConfig(ctx, d.ns, info.ConfigID)
	if perr != nil {
		return nil
	}
	return d.take(cfg)
}

// gate draws, then runs ddbGate.
func (d *ddbDraw) gate(ctx context.Context, name string, patches any, st *ddb.WriteState) *Error {
	if st.Exists && st.ConfigID != "" {
		cfg, perr := d.e.ddbConfig(ctx, d.ns, st.ConfigID)
		if perr != nil {
			return perr
		}
		if err := d.take(cfg); err != nil {
			return err
		}
	}
	return d.e.ddbGate(d.ns, name, patches, st)
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

// --- writes ---

func (e *Engine) ddbWriteResource(ctx context.Context, req Request, item Item) (*WriteResult, error) {
	if req.Signature != "" {
		return nil, ddbUnsupported("author signatures")
	}
	if item.Resource == KeyringName {
		return nil, ddbUnsupported("e2e keyrings")
	}
	if len(item.Steps) != 1 {
		return nil, ddbUnsupported("multi-step items")
	}
	step := item.Steps[0]
	if step.Signature != "" {
		return nil, ddbUnsupported("author signatures")
	}
	if err := checkGestures([]Item{item}); err != nil {
		return nil, err
	}
	author := ddbAuthor(req.Cred)
	if step.Delete {
		return e.ddbDelete(ctx, req, item, step, author)
	}
	rd := &ddbDraw{e: e, ns: req.NS, cred: req.Cred, names: []string{item.Resource}, items: 1}
	sctx, span := e.dbSpan(ctx, "core.db.update")
	res, err := e.ddb.store.WriteResource(sctx, req.NS, item.Resource, ddb.Pre{IfMatch: item.IfMatch, IfNoneMatch: item.IfNoneMatch}, step.Patches, step.Gesture, step.Undoes, author,
		func(st *ddb.WriteState) error {
			if perr := rd.gate(ctx, item.Resource, step.Patches, st); perr != nil {
				return perr
			}
			return nil
		})
	endDBSpan(span, err)
	if perr := rd.late(ctx, err); perr != nil {
		return nil, perr
	}
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !res.Replayed {
		e.ddbCommitted(req.NS)
	}
	return &WriteResult{
		Status:   res.Status,
		NSID:     res.NSID,
		Replayed: res.Replayed,
		Items:    []ItemResult{{Resource: item.Resource, IDs: []string{res.ID}}},
		Entry:    ddbRevEntry(res.Rev),
	}, nil
}

// ddbRevEntry is a revision's resource log entry as a write answers it,
// committed or replayed (logEntry of resolve.go): its id and parent, its
// canonical patches (none for a tombstone), author, time and gestures, as
// recorded. -dev writes carry no grant.
func ddbRevEntry(r ddb.RevInfo) *LogEntry {
	le := &LogEntry{ID: r.ID, Parent: r.ParentID, Kind: "rev", Author: r.Author, Created: formatTime(r.Created), Gesture: r.Gesture, Undoes: r.Undoes}
	if r.Kind == "tombstone" {
		le.Kind = "tombstone"
	} else if r.Patches != "" {
		le.Patches, le.size = jsonv.MustParse([]byte(r.Patches)), len(r.Patches)
	}
	return le
}

// ddbDelete is a tombstone write (§7.2's DELETE): the store pins the
// checked head, the gate sees the delete envelope (§6.4.1: the last live
// document, no patches).
func (e *Engine) ddbDelete(ctx context.Context, req Request, item Item, step Step, author string) (*WriteResult, error) {
	rd := &ddbDraw{e: e, ns: req.NS, cred: req.Cred, names: []string{item.Resource}, items: 1}
	sctx, span := e.dbSpan(ctx, "core.db.update")
	res, err := e.ddb.store.DeleteResource(sctx, req.NS, item.Resource, ddb.Pre{IfMatch: item.IfMatch, IfNoneMatch: item.IfNoneMatch}, step.Gesture, step.Undoes, author,
		func(st *ddb.WriteState) error {
			if perr := rd.gate(ctx, item.Resource, nil, st); perr != nil {
				return perr
			}
			return nil
		})
	endDBSpan(span, err)
	if perr := rd.late(ctx, err); perr != nil {
		return nil, perr
	}
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !res.Replayed {
		e.ddbCommitted(req.NS)
	}
	return &WriteResult{
		Status:   res.Status,
		NSID:     res.NSID,
		Replayed: res.Replayed,
		Items:    []ItemResult{{Resource: item.Resource, IDs: []string{res.ID}}},
		Entry:    ddbRevEntry(res.Rev),
	}, nil
}

func (e *Engine) ddbWriteConfig(ctx context.Context, req Request, cc ConfigChange) (*WriteResult, error) {
	author := ddbAuthor(req.Cred)
	if err := checkConfigGestures(&cc); err != nil {
		return nil, err
	}
	if cc.IfNoneMatch {
		// PUT /ns/{ns}: create (insertNamespace).
		if !ValidNSName(req.NS) {
			return nil, badInput("invalid namespace name")
		}
		doc, perr := applyConfigPatches(nil, false, cc.Patches)
		if perr != nil {
			return nil, perr
		}
		cfg, perr := e.newConfig(doc, nil, nil)
		if perr != nil {
			return nil, perr
		}
		if err := ddbRefusals(cfg); err != nil {
			return nil, err
		}
		sctx, span := e.dbSpan(ctx, "core.db.update")
		cfgID, nsID, err := e.ddb.store.CreateNamespace(sctx, req.NS, author, cc.Patches)
		endDBSpan(span, err)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		e.ddbCommitted(req.NS)
		return &WriteResult{Status: 201, NSID: nsID, ConfigID: cfgID, Entry: &LogEntry{Gesture: cc.Gesture, Undoes: cc.Undoes}}, nil
	}

	if cc.IfMatch == "" {
		return nil, apiErr(428, "precondition_required")
	}
	// Public copies at the edge must go when the change ends public
	// caching (§9, insertConfig): ns:{ns} is on every response.
	var endsPublic bool
	sctx, span := e.dbSpan(ctx, "core.db.update")
	res, err := e.ddb.store.WriteConfig(sctx, req.NS, author, cc.IfMatch, cc.Patches, cc.Gesture, cc.Undoes,
		func(doc any, exists bool, patches any) (any, error) {
			doc, perr := applyConfigPatches(doc, exists, patches)
			if perr != nil {
				return nil, perr
			}
			return doc, nil
		},
		func(st *ddb.ConfigState) error {
			// Steps 4 and 5 of planConfig (nsops.go): the current
			// configuration's limits on the change, then the new
			// document's schema against what it keeps. Rules don't
			// apply: the -dev principal is a * key (§6.6, checkRules).
			cur, perr := e.ddbConfig(ctx, req.NS, st.ConfigID)
			if perr != nil {
				return perr
			}
			if canon := jsonv.Canonical(cc.Patches); len(canon) > cur.Limits.PatchSetSize {
				return limitErr(413, "patchSetSize", int64(len(canon)), int64(cur.Limits.PatchSetSize), "patch set too large")
			}
			if n := len(jsonv.Canonical(st.Doc)); n > cur.Limits.DocumentSize {
				return limitErr(413, "documentSize", int64(n), int64(cur.Limits.DocumentSize), "document too large")
			}
			prev, _ := st.Cur.(map[string]any)
			cfg, perr := e.newConfig(st.Doc, prev, nil)
			if perr != nil {
				return perr
			}
			endsPublic = cur.cachePublic() && !cfg.cachePublic()
			if err := ddbRefusals(cfg); err != nil {
				return err
			}
			st.NewFrozen = cfg.Frozen
			return nil
		})
	endDBSpan(span, err)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !res.Replayed {
		// The new document replaces the cache and wakes readers;
		// insertConfig's CDN tag, simplified (single instance).
		e.ddbForgetConfig(req.NS)
		var tags []string
		if endsPublic {
			tags = append(tags, "ns:"+req.NS)
		}
		e.ddbCommitted(req.NS, tags...)
	}
	status, gesture, undoes := 201, cc.Gesture, cc.Undoes
	if res.Replayed {
		// A retry answers what was recorded, gestures included (§7.2).
		status, gesture, undoes = 200, res.Gesture, res.Undoes
	}
	return &WriteResult{Status: status, NSID: res.NSID, ConfigID: res.ConfigID, Replayed: res.Replayed,
		Entry: &LogEntry{ID: res.NSID, Kind: "config", Author: author, Created: formatTime(res.Created), Gesture: gesture, Undoes: undoes}}, nil
}

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

// ddbBatch is an atomic batch (§7.5), phase-2 subset: single-step items,
// no sources, an optional config change, per-item failures collected as
// §7.5's failure list. The budget is the transaction's 100 actions
// (batch.go), which lowers ItemsPerBatch's reach.
func (e *Engine) ddbBatch(ctx context.Context, req Request, items []Item, cc *ConfigChange, source any, dryRun bool) (*WriteResult, error) {
	if source != nil {
		return nil, ddbUnsupported("batch sources")
	}
	if req.Signature != "" {
		return nil, ddbUnsupported("author signatures")
	}
	if len(items) == 0 && cc == nil {
		return nil, badInput("empty batch")
	}
	seen := map[string]bool{}
	for i, it := range items {
		if !ValidResourceName(it.Resource) {
			return nil, badInput(fmt.Sprintf("item %d: invalid resource name", i))
		}
		if seen[it.Resource] {
			return nil, badInput(fmt.Sprintf("item %d: resource %q appears twice", i, it.Resource))
		}
		seen[it.Resource] = true
		if len(it.Steps) == 0 {
			return nil, badInput(fmt.Sprintf("item %d: no steps", i))
		}
		if len(it.Steps) != 1 {
			return nil, ddbUnsupported("multi-step items")
		}
		if it.Steps[0].Signature != "" {
			return nil, ddbUnsupported("author signatures")
		}
		if it.Resource == KeyringName {
			return nil, ddbUnsupported("e2e keyrings")
		}
	}
	if err := checkGestures(items); err != nil {
		return nil, err
	}
	if cc != nil && cc.IfNoneMatch {
		return nil, badInput("a batch's config change takes If-Match, not If-None-Match")
	}

	// The batch limits come from the configuration in force (§6.6, §7.5):
	// the items count, the action budget, the patch-set bytes total.
	info, err := e.ddb.store.ReadNSInfo(ctx, req.NS)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !info.Exists {
		return nil, apiErr(404, "not_found", "namespace", req.NS)
	}
	cfg, perr := e.ddbConfig(ctx, req.NS, info.ConfigID)
	if perr != nil {
		return nil, perr
	}
	// A token per item (§6.6), the config change exempt (the -dev
	// principal is a * key), drawn after step 1 as on the SQL path:
	// before the purged answer, the retry lookup and the limits.
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.Resource
	}
	if perr := (&ddbDraw{e: e, ns: req.NS, cred: req.Cred, names: names, items: len(items)}).take(cfg); perr != nil {
		return nil, perr
	}
	if info.Purged {
		return nil, apiErr(410, "purged", "namespace", req.NS)
	}
	if len(items) > cfg.Limits.ItemsPerBatch {
		return nil, limitErr(413, "itemsPerBatch", int64(len(items)), int64(cfg.Limits.ItemsPerBatch), fmt.Sprintf("more than %d items", cfg.Limits.ItemsPerBatch))
	}
	ddbItems := make([]ddb.BatchItem, len(items))
	size := 0
	for i, it := range items {
		st := it.Steps[0]
		ddbItems[i] = ddb.BatchItem{
			Name: it.Resource, IfMatch: it.IfMatch, IfNoneMatch: it.IfNoneMatch,
			Delete: st.Delete, Patches: st.Patches, Gesture: st.Gesture, Undoes: st.Undoes,
		}
		if !st.Delete {
			size += len(jsonv.Canonical(st.Patches))
		}
	}
	if acts := ddb.BatchActions(ddbItems, cc != nil); acts > 100 {
		return nil, limitErr(413, "itemsPerBatch", int64(acts), 100, "the batch's transaction exceeds 100 actions")
	}
	if size > cfg.Limits.BatchSize {
		return nil, limitErr(413, "batchSize", int64(size), int64(cfg.Limits.BatchSize), "batch too large")
	}

	// A batch's items are gated under its config change's result (§7.5):
	// the change's hook compiles it and hands it to the item hook.
	author := ddbAuthor(req.Cred)
	var gateCfg *Config
	var ccPatches any
	var applyCfg func(doc any, exists bool, patches any) (any, error)
	var checkCfg func(*ddb.ConfigState) error
	if cc != nil {
		ccPatches = cc.Patches
		applyCfg = func(doc any, exists bool, patches any) (any, error) {
			d, perr := applyConfigPatches(doc, exists, patches)
			if perr != nil {
				return nil, perr
			}
			return d, nil
		}
		checkCfg = func(st *ddb.ConfigState) error {
			// As a config write's (ddbWriteConfig): the limits of the
			// configuration in force, the new document against what it
			// keeps.
			if canon := jsonv.Canonical(cc.Patches); len(canon) > cfg.Limits.PatchSetSize {
				return limitErr(413, "patchSetSize", int64(len(canon)), int64(cfg.Limits.PatchSetSize), "patch set too large")
			}
			if n := len(jsonv.Canonical(st.Doc)); n > cfg.Limits.DocumentSize {
				return limitErr(413, "documentSize", int64(n), int64(cfg.Limits.DocumentSize), "document too large")
			}
			prev, _ := st.Cur.(map[string]any)
			ncfg, perr := e.newConfig(st.Doc, prev, nil)
			if perr != nil {
				return perr
			}
			if err := ddbRefusals(ncfg); err != nil {
				return err
			}
			st.NewFrozen = ncfg.Frozen
			gateCfg = ncfg
			return nil
		}
	}
	check := func(name string, st *ddb.WriteState) error {
		g := gateCfg
		if g == nil {
			var perr *Error
			g, perr = e.ddbConfig(ctx, req.NS, st.ConfigID)
			if perr != nil {
				return perr
			}
		}
		var patches any
		for i := range items {
			if items[i].Resource == name {
				patches = items[i].Steps[0].Patches
				break
			}
		}
		if perr := ddbGateCfg(g, req.NS, name, patches, st, e.opt.Now().UnixMilli()); perr != nil {
			return perr
		}
		return nil
	}

	ccIfMatch := ""
	if cc != nil {
		ccIfMatch = cc.IfMatch
	}
	sctx, span := e.dbSpan(ctx, "core.db.update")
	res, err := e.ddb.store.WriteBatch(sctx, req.NS, author, ddbItems, ccIfMatch, ccPatches, applyCfg, checkCfg, check, dryRun)
	endDBSpan(span, err)
	var fails []ddb.BatchItemError
	var bf *ddb.BatchFailure
	switch {
	case errors.As(err, &bf):
		fails = bf.Items
	case err != nil:
		return nil, ddbAsErr(err)
	default:
		fails = res.Fails
	}
	// An item refused for a feature this backend lacks refuses the
	// batch with it: the feature, not the item, is what's missing.
	for _, f := range fails {
		if fe := ddbAsErr(f.Err); fe.Status == 501 {
			return nil, fe
		}
	}
	if bf != nil {
		ifs := make([]itemErr, len(fails))
		for i, f := range fails {
			ifs[i] = itemErr{f.Index, ddbAsErr(f.Err)}
		}
		return nil, batchError(ifs)
	}
	if dryRun {
		// Every item reported (dryRunReport): the refused with the
		// status and code they failed with, the rest with their ids.
		failed := map[int]*Error{}
		for _, f := range fails {
			failed[f.Index] = ddbAsErr(f.Err)
		}
		var passed []*itemState
		for i, it := range items {
			if _, ok := failed[i]; ok {
				continue
			}
			id, perr := ids.Parse(res.IDs[it.Resource])
			if perr != nil {
				continue
			}
			passed = append(passed, &itemState{index: i, steps: []*stepState{{id: id}}})
		}
		return &WriteResult{Status: 200, ConfigID: res.ConfigID, Items: dryRunReport(items, passed, failed, nil)}, nil
	}
	if !res.Replayed && !dryRun {
		var tags []string
		if cc != nil && res.ConfigID != info.ConfigID {
			e.ddbForgetConfig(req.NS)
			if gateCfg != nil && cfg.cachePublic() && !gateCfg.cachePublic() {
				tags = append(tags, "ns:"+req.NS)
			}
		}
		e.ddbCommitted(req.NS, tags...)
	}
	out := &WriteResult{Status: res.Status, NSID: res.NSID, Replayed: res.Replayed, ConfigID: res.ConfigID}
	for _, it := range items {
		out.Items = append(out.Items, ItemResult{Resource: it.Resource, IDs: []string{res.IDs[it.Resource]}})
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
