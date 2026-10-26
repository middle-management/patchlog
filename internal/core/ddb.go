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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
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

// openDDB builds the engine on a DynamoDB table (Open's branch for
// dynamodb:// paths, after option normalization). The background loops of
// the SQL backends (tailer, retention, sweeps, repurge, rotation, remote
// follow) don't start: their features are phase 2+.
func openDDB(opt Options) (*Engine, error) {
	if opt.KeyStore != nil {
		return nil, fmt.Errorf("core: encryption at rest is not implemented on the DynamoDB backend (docs/DYNAMODB.md phase 1)")
	}
	if opt.BlobDir != "" {
		return nil, fmt.Errorf("core: blob storage is not implemented on the DynamoDB backend (docs/DYNAMODB.md phase 1)")
	}
	if !opt.AuthDisabled {
		return nil, fmt.Errorf("core: the DynamoDB backend writes in -dev mode only (docs/DYNAMODB.md phase 1); run with -dev")
	}
	store, err := ddb.Open(context.Background(), opt.Path)
	if err != nil {
		return nil, err
	}
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
		return apiErr(409, "frozen", "namespace", ns)
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
		if d, ok := st.Doc.(map[string]any); ok {
			if _, typed := d["$schema"]; typed {
				return ddbUnsupported("$schema validation")
			}
		}
		canon = jsonv.Canonical(patches)
		if err := ddbCheckLimits(cfg.Limits, patches, canon, st.DocCanon); err != nil {
			return err
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

// ddbCheckLimits is checkLimits for one patch-set step (write.go's, minus
// blobs and e2e).
func ddbCheckLimits(l Limits, patches any, canon, docCanon []byte) *Error {
	if len(canon) > l.PatchSetSize {
		return limitErr(413, "patchSetSize", int64(len(canon)), int64(l.PatchSetSize), "patch set too large")
	}
	if ops, ok := patches.([]any); ok && len(ops) > l.OpsPerSet {
		return limitErr(422, "opsPerSet", int64(len(ops)), int64(l.OpsPerSet), "too many operations")
	}
	if len(docCanon) > l.DocumentSize {
		return limitErr(413, "documentSize", int64(len(docCanon)), int64(l.DocumentSize), "document too large")
	}
	if sh := shapeOf(l, docCanon); sh.depth > l.NestingDepth {
		return limitErr(422, "nestingDepth", int64(sh.depth), int64(l.NestingDepth), "document nested too deeply")
	} else if sh.bad != nil {
		return sh.bad
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

// ddbCommitted is the post-commit of a write: wake the namespace's live
// readers and purge its cache tags (appendNS's notify + the write path's
// purges; the read cache holds no ddb entries in phase 1).
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
	res, err := e.ddb.store.WriteResource(ctx, req.NS, item.Resource, item.IfMatch, step.Patches, step.Gesture, step.Undoes, author,
		func(st *ddb.WriteState) error {
			if item.IfNoneMatch && st.ResExists {
				return apiErr(412, "stale", "head", st.HeadID)
			}
			if perr := e.ddbGate(req.NS, item.Resource, step.Patches, st); perr != nil {
				return perr
			}
			return nil
		})
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !res.Replayed {
		e.ddbCommitted(req.NS, "r:"+req.NS+"/"+item.Resource, "heads:"+req.NS)
	}
	return &WriteResult{
		Status:   res.Status,
		NSID:     res.NSID,
		Replayed: res.Replayed,
		Items:    []ItemResult{{Resource: item.Resource, IDs: []string{res.ID}}},
		Entry: &LogEntry{
			ID: res.NSID, Kind: "head", Author: author,
			Created: formatTime(res.Created),
			Gesture: step.Gesture, Undoes: step.Undoes,
		},
	}, nil
}

// ddbDelete is a tombstone write (§7.2's DELETE): the store pins the
// checked head, the gate sees the delete envelope (§6.4.1: the last live
// document, no patches).
func (e *Engine) ddbDelete(ctx context.Context, req Request, item Item, step Step, author string) (*WriteResult, error) {
	res, err := e.ddb.store.DeleteResource(ctx, req.NS, item.Resource, item.IfMatch, step.Gesture, step.Undoes, author,
		func(st *ddb.WriteState) error {
			if perr := e.ddbGate(req.NS, item.Resource, nil, st); perr != nil {
				return perr
			}
			return nil
		})
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !res.Replayed {
		e.ddbCommitted(req.NS, "r:"+req.NS+"/"+item.Resource, "heads:"+req.NS)
	}
	return &WriteResult{
		Status:   res.Status,
		NSID:     res.NSID,
		Replayed: res.Replayed,
		Items:    []ItemResult{{Resource: item.Resource, IDs: []string{res.ID}}},
		Entry: &LogEntry{
			ID: res.NSID, Kind: "tombstone", Author: author,
			Created: formatTime(res.Created),
			Gesture: step.Gesture, Undoes: step.Undoes,
		},
	}, nil
}

func (e *Engine) ddbWriteConfig(ctx context.Context, req Request, cc ConfigChange) (*WriteResult, error) {
	author := ddbAuthor(req.Cred)
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
		cfgID, nsID, err := e.ddb.store.CreateNamespace(ctx, req.NS, author, cc.Patches)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		e.ddbCommitted(req.NS)
		return &WriteResult{Status: 201, NSID: nsID, ConfigID: cfgID, Entry: &LogEntry{Gesture: cc.Gesture, Undoes: cc.Undoes}}, nil
	}

	res, err := e.ddb.store.WriteConfig(ctx, req.NS, author, cc.Patches,
		func(doc any, exists bool, patches any) (any, error) {
			doc, perr := applyConfigPatches(doc, exists, patches)
			if perr != nil {
				return nil, perr
			}
			return doc, nil
		},
		func(st *ddb.ConfigState) error {
			if st.Purged {
				return apiErr(410, "purged", "namespace", req.NS)
			}
			if cc.IfMatch != "" && cc.IfMatch != st.ConfigID {
				return apiErr(412, "stale", "config", st.ConfigID)
			}
			cfg, perr := e.newConfig(st.Doc, nil, nil)
			if perr != nil {
				return perr
			}
			if err := ddbRefusals(cfg); err != nil {
				return err
			}
			st.NewFrozen = cfg.Frozen
			return nil
		})
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if !res.Replayed {
		// The new document replaces the cache and wakes readers;
		// insertConfig's CDN tag, simplified (single instance).
		e.ddbForgetConfig(req.NS)
		e.ddbCommitted(req.NS, "ns:"+req.NS)
	}
	return &WriteResult{Status: 201, NSID: res.NSID, ConfigID: res.ConfigID, Replayed: res.Replayed,
		Entry: &LogEntry{ID: res.NSID, Kind: "config", Author: author, Created: formatTime(res.Created), Gesture: cc.Gesture, Undoes: cc.Undoes}}, nil
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
	if info.Purged {
		return nil, apiErr(410, "purged", "namespace", req.NS)
	}
	cfg, perr := e.ddbConfig(ctx, req.NS, info.ConfigID)
	if perr != nil {
		return nil, perr
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
			if st.Purged {
				return apiErr(410, "purged", "namespace", req.NS)
			}
			if cc.IfMatch != "" && cc.IfMatch != st.ConfigID {
				return apiErr(412, "stale", "config", st.ConfigID)
			}
			ncfg, perr := e.newConfig(st.Doc, nil, nil)
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

	res, err := e.ddb.store.WriteBatch(ctx, req.NS, author, ddbItems, ccPatches, applyCfg, checkCfg, check, dryRun)
	if err != nil {
		var bf *ddb.BatchFailure
		if errors.As(err, &bf) {
			fails := make([]itemErr, len(bf.Items))
			for i, f := range bf.Items {
				fails[i] = itemErr{f.Index, ddbAsErr(f.Err)}
			}
			return nil, batchError(fails)
		}
		return nil, ddbAsErr(err)
	}
	if !res.Replayed && !dryRun {
		if cc != nil && res.ConfigID != info.ConfigID {
			e.ddbForgetConfig(req.NS)
		}
		e.ddbCommitted(req.NS, "ns:"+req.NS)
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
	rev, derr := e.ddb.store.ReadRevByID(ctx, ns, id)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	if rev == nil || rev.Name != name {
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
	out := &Log{Status: 200, Public: public, Last: since}
	// The upper bound: the id's position, or the head's for "".
	var toPos uint64
	if id == "" {
		head, derr := e.ddb.store.ReadHead(ctx, ns, name)
		if derr != nil {
			return nil, ddbAsErr(derr)
		}
		if head == nil {
			return &Log{Status: 404, Public: public}, nil
		}
	} else {
		pos, err := e.ddb.store.RevPos(ctx, ns, name, id)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		if pos == 0 {
			return &Log{Status: 404, Public: public}, nil
		}
		toPos = pos
	}
	var fromPos uint64
	if since != "" {
		pos, err := e.ddb.store.RevPos(ctx, ns, name, since)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		if pos == 0 || (toPos > 0 && pos > toPos) {
			return &Log{Status: 404, Public: public}, nil
		}
		fromPos = pos
	}
	entries, derr := e.ddb.store.ResourceLogEntries(ctx, ns, name, fromPos, limit)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	for i, re := range entries {
		if toPos > 0 && re.Pos > toPos {
			break
		}
		if limit > 0 && i == limit {
			out.More = true
			break
		}
		e := map[string]any{
			"id": re.ID, "kind": re.Kind,
			"author": re.Author, "created": formatTime(re.Created),
			"grant": nil,
		}
		if re.Kind != "tombstone" {
			e["patches"] = re.Patches
		}
		if re.ParentID != "" {
			e["parent"] = re.ParentID
		}
		if re.Gesture != "" {
			e["gesture"] = re.Gesture
		}
		if re.Undoes != "" {
			e["undoes"] = re.Undoes
		}
		out.Entries = append(out.Entries, e)
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
	info, public, err := e.ddbNS(ctx, ns)
	if err != nil {
		return nil, err
	}
	doc, cfgID, derr := e.ddb.store.ReadDocAtEntry(ctx, ns, id)
	if derr != nil {
		var de *ddb.Error
		if errors.As(derr, &de) && de.Status == 404 {
			return &NSInfo{Head: info.HeadID, Public: public}, nil
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
	out := &HeadsPage{Items: []map[string]any{}, Public: public}
	// At any revision, once its resources are gone (§8.5): the id must be
	// an entry of the log. "" is the tip.
	if nsID != "" {
		ok, err := e.ddb.store.KnownEntry(ctx, ns, nsID)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		if !ok {
			return out, nil
		}
	}
	page, next, derr := e.ddb.store.ListHeads(ctx, ns, after, e.opt.Maximums.LogPageSize)
	if derr != nil {
		return nil, ddbAsErr(derr)
	}
	out.Next = next
	for _, h := range page {
		kind := "head"
		if h.Tombstoned {
			kind = "tombstone"
		}
		item := map[string]any{"resource": h.Name, "kind": kind, "target": h.ID}
		if !h.Tombstoned && h.Created != 0 {
			item["created"] = formatTime(h.Created)
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
