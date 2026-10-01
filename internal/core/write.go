package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
)

// Step is one step of a write: a patch set, or a delete.
type Step struct {
	Delete  bool
	Patches any // a JSON value (validated as a patch set at step 3)
}

// Item is a write to one resource: a precondition and its steps.
type Item struct {
	Resource    string
	IfMatch     string // text id; "" if absent
	IfNoneMatch bool
	Steps       []Step
}

// ConfigChange is a namespace-document change (§7.4), alone or in a batch.
type ConfigChange struct {
	IfMatch     string
	IfNoneMatch bool
	Patches     any
}

// Request carries what every write request has in common.
type Request struct {
	NS        string
	Cred      Credentials
	Signature string // optional author signature header (§C.3)
	// SourceCred is Source-Authorization: the grant a copy's source, or a
	// batch's local source, is read with (§7.8). Empty: Cred.
	SourceCred Credentials
}

// WriteResult is the outcome of a resource write or batch.
type WriteResult struct {
	Status   int // 200 (replayed or dry run) or 201
	NSID     string
	Items    []ItemResult
	Entry    *LogEntry // single writes: the resulting entry
	Replayed bool
	ConfigID string
}

// ItemResult lists the ids an item produced. In a dry-run report it also
// carries the item's index and status, and a failed item's error body.
type ItemResult struct {
	Resource string         `json:"resource"`
	IDs      []string       `json:"ids,omitempty"`
	Index    *int           `json:"index,omitempty"`
	Status   int            `json:"status,omitempty"`
	Err      map[string]any `json:"-"`
}

// Value is the item as a JSON value, a failed item's error body flattened
// into it as in §7.5 failure reports.
func (r ItemResult) Value() map[string]any {
	m := map[string]any{"resource": r.Resource}
	for k, v := range r.Err {
		m[k] = v
	}
	if r.IDs != nil {
		ids := make([]any, len(r.IDs))
		for i, id := range r.IDs {
			ids[i] = id
		}
		m["ids"] = ids
	}
	if r.Index != nil {
		m["index"] = *r.Index
	}
	if r.Status != 0 {
		m["status"] = r.Status
	}
	return m
}

// dropFailed records a dry run's failures and removes those items from
// the later steps.
func dropFailed(st []*itemState, fs []itemErr, fails map[int]*Error) []*itemState {
	for _, f := range fs {
		fails[f.index] = f.err
	}
	out := st[:0]
	for _, s := range st {
		if _, failed := fails[s.index]; !failed {
			out = append(out, s)
		}
	}
	return out
}

func dryRunReport(items []Item, passed []*itemState, fails map[int]*Error) []ItemResult {
	byIndex := map[int]*itemState{}
	for _, s := range passed {
		byIndex[s.index] = s
	}
	out := make([]ItemResult, len(items))
	for i, it := range items {
		idx := i
		r := ItemResult{Resource: it.Resource, Index: &idx}
		if err, failed := fails[i]; failed {
			r.Status, r.Err = err.Status, err.Body
		} else if s := byIndex[i]; s != nil {
			r.Status = 200
			for _, step := range s.steps {
				r.IDs = append(r.IDs, step.id.String())
			}
		}
		out[i] = r
	}
	return out
}

type stepState struct {
	del      bool
	raw      any
	canon    []byte
	action   string
	parentID *ids.ID
	id       ids.ID
	doc      any    // resulting (for a delete: the last live) document
	docCanon []byte // canonical(doc), once checkLimits computed it
	writes   []string
	typed    string // $schema of the resulting document
	// prevNonce is the $nonce of the document the step applied to, if
	// any (sealed namespaces refuse a repeated nonce, §E.2.5).
	prevNonce string
	// sealed marks a create, append or restore of an e2e resource: its
	// patch set is opaque and its document unknown (§6.2, §E.3).
	sealed bool
	// blobs are the blobs the resulting document references, with where
	// each is available from (step 4, §7.8), for step 7 to attach.
	blobs map[ids.ID]*blobRow
}

type itemState struct {
	Item
	index  int
	view   *view
	parent *revRow // the head the precondition matched; nil for a create
	steps  []*stepState
	// cands are the candidate verbs of an item whose first step is a patch
	// set under If-Match: those of append and restore that passed step 1
	// (§6.2). Nil for any other item, whose verbs are known from the request.
	cands []string
}

// itemErr is a failure of one item at one step.
type itemErr struct {
	index int
	err   *Error
}

// batchError builds the §7.5 failure body.
func batchError(fails []itemErr) *Error {
	status := fails[0].err.Status
	var items []any
	for _, f := range fails {
		m := map[string]any{}
		for k, v := range f.err.Body {
			m[k] = v
		}
		// "index" is the item's; a patch error's operation index moves to "op".
		if i, has := m["index"]; has {
			m["op"] = i
		}
		m["index"], m["status"] = f.index, f.err.Status
		items = append(items, m)
	}
	e := apiErr(status, "batch", "items", items)
	for _, f := range fails {
		if f.err.Header != nil {
			e.Header = f.err.Header
		}
	}
	return e
}

// WriteResource performs a single-resource write: create, append, restore
// (PATCH) or delete.
func (e *Engine) WriteResource(ctx context.Context, req Request, item Item) (*WriteResult, error) {
	res, err := e.writeOptimistic(ctx, req, []Item{item}, nil, false)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Batch performs an atomic batch (§7.5).
func (e *Engine) Batch(ctx context.Context, req Request, items []Item, cfg *ConfigChange, source any, dryRun bool) (*WriteResult, error) {
	if dryRun {
		// A dry run writes nothing: steps 1–6 in a read transaction.
		var res *WriteResult
		err := e.read(ctx, func(t *tx) error {
			r, err := t.writeItems(req, items, cfg, source, true, true, false)
			res = r
			return err
		})
		return res, err
	}
	if cfg != nil {
		// A batch that changes the configuration is rare, and its config
		// change reads more than the re-check covers (dependents, archive
		// destinations): it runs its whole gate inside the write lock.
		var res *WriteResult
		err := e.update(ctx, func(t *tx) error {
			r, err := t.writeItems(req, items, cfg, source, true, false, false)
			res = r
			return err
		})
		return res, err
	}
	return e.writeOptimistic(ctx, req, items, source, true)
}

// batchLimits are a principal's batch limits in a configuration: the
// namespace's, or its allowance's (§6.6).
func (t *tx) batchLimits(cfg *Config, a *actor) (items, size int) {
	items, size = cfg.Limits.ItemsPerBatch, cfg.Limits.BatchSize
	if al := t.allowanceOf(cfg, a); al != nil {
		if al.ItemsPerBatch > 0 {
			items = al.ItemsPerBatch
		}
		if al.BatchSize > 0 {
			size = al.BatchSize
		}
	}
	return items, size
}

// BatchBodyLimit authenticates a batch request and returns how many bytes
// of body the server reads for it: the principal's batchSize (§6.6), plus
// room for the batch's own JSON (items, preconditions, an optional config
// change). A larger body is refused with 413 without reading the rest,
// which reveals nothing about any item (§7.5). The batch itself
// authenticates again.
func (e *Engine) BatchBodyLimit(ctx context.Context, req Request) (int, error) {
	var limit int
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(req.NS)
		if n == nil {
			return t.absentNS(req.NS, req.Cred)
		}
		if n.purged {
			return gone()
		}
		cur := t.config(n.configSeq)
		a, aerr := t.authenticate(n.name, n, cur, req.Cred, nil)
		if aerr != nil {
			return aerr
		}
		items, size := t.batchLimits(cur, a)
		limit = size + size/4 + 512*items + max(cur.Limits.PatchSetSize, cur.Limits.DocumentSize) + 64<<10
		return nil
	})
	return limit, err
}

// asErr converts an *Error into error without the typed-nil trap.
func asErr(e *Error) error {
	if e == nil {
		return nil
	}
	return e
}

// writeItems runs the whole gate of §6.2 in one transaction: steps 1–6,
// then, unless this is a dry run, the insert. rateDrawn skips the rate-limit
// draw of step 1, for a request whose tokens an earlier attempt already drew.
func (t *tx) writeItems(req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun, rateDrawn bool) (*WriteResult, error) {
	p, res, err := t.checkItems(req, items, cc, source, isBatch, dryRun, rateDrawn)
	if err != nil || res != nil {
		return res, err
	}
	return t.insertPlan(req, p), nil
}

// writePlan is a write that passed steps 1–6 and waits for step 7.
type writePlan struct {
	n       *nsRow
	a       *actor
	st      []*itemState
	cplan   *configPlan
	src     any
	isBatch bool
	result  *WriteResult
	// req and source are the request and its raw batch source, which the
	// re-check of blob availability needs (recheck.go).
	req    Request
	source any
}

// checkItems runs steps 1–6 of §6.2 for a resource write or batch. It
// returns a plan to insert, or a final result (an idempotent retry, a dry
// run), or an error.
func (t *tx) checkItems(req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun, rateDrawn bool) (*writePlan, *WriteResult, error) {
	n := t.nsForWrite(req.NS)
	if n == nil {
		return nil, nil, t.absentNS(req.NS, req.Cred)
	}
	if h := t.e.afterWriteLock; h != nil && t.write && cc == nil {
		// The whole gate runs in the write lock (writeLocked).
		h(n.name)
	}
	if n.purged {
		return nil, nil, gone()
	}
	cur := t.config(n.configSeq)
	if isBatch {
		seen := map[string]bool{}
		for i, it := range items {
			if !ValidResourceName(it.Resource) {
				return nil, nil, badInput(fmt.Sprintf("item %d: invalid resource name", i))
			}
			if seen[it.Resource] {
				return nil, nil, badInput(fmt.Sprintf("item %d: resource %q appears twice", i, it.Resource))
			}
			seen[it.Resource] = true
			if len(it.Steps) == 0 {
				return nil, nil, badInput(fmt.Sprintf("item %d: no steps", i))
			}
		}
		if len(items) == 0 && cc == nil {
			return nil, nil, badInput("empty batch")
		}
	}

	a, aerr := t.authenticate(n.name, n, cur, req.Cred, nil)
	if aerr != nil {
		return nil, nil, aerr
	}
	// The batch limits come from the current configuration, raised by the
	// principal's allowance if it has one (§6.6), and are checked at step 4
	// (§7.5).
	maxItems, maxSize := t.batchLimits(cur, a)

	// The optional config change runs steps 1–6 first (§7.5).
	st := make([]*itemState, len(items))
	for i, it := range items {
		st[i] = &itemState{Item: it, index: i}
	}
	dryFails := map[int]*Error{}
	fail := func(fs []itemErr) error {
		if !isBatch {
			return fs[0].err
		}
		return batchError(fs)
	}
	// Step 1 for the items: authorisation.
	authorizeItems := func(a *actor) []itemErr {
		var fs []itemErr
		for _, s := range st {
			s.cands = nil
			for j := range s.Steps {
				if j == 0 && hasCandidates(s.Item) {
					// Append or restore, which only the resource's state
					// decides: both are tried, and step 2 settles it (§6.2).
					var first *Error
					for _, verb := range []string{"append", "restore"} {
						if err := t.authorize(a, verb, s.Resource); err != nil {
							if first == nil {
								first = err
							}
							continue
						}
						s.cands = append(s.cands, verb)
					}
					if len(s.cands) == 0 {
						fs = append(fs, itemErr{s.index, first})
						break
					}
					continue
				}
				if err := t.authorize(a, staticVerb(s.Item, j), s.Resource); err != nil {
					fs = append(fs, itemErr{s.index, err})
					break
				}
			}
		}
		return fs
	}

	cfg := cur
	var cplan *configPlan
	if cc != nil {
		p, err := t.planConfig(n, cur, a, cc, true)
		if err != nil {
			// A retried batch finds its config precondition stale: look
			// for the batch it would have produced first (§7.5, §7.2).
			var ae *Error
			if errors.As(err, &ae) && ae.Status == 412 && cc.IfMatch != "" {
				if pid, perr := ids.Parse(cc.IfMatch); perr == nil && len(authorizeItems(a)) == 0 {
					exp := ids.Revision(&pid, jsonv.Canonical(cc.Patches))
					if r := t.replay(n, a, st, &configPlan{expected: &exp}, true); r != nil {
						return nil, r, nil
					}
				}
			}
			return nil, nil, err
		}
		cplan = p
		cfg = p.cfg
		if len(items) > 0 {
			a, aerr = t.authenticate(n.name, n, cfg, req.Cred, nil)
			if aerr != nil {
				return nil, nil, aerr
			}
		}
	}

	// Step 1: authorisation.
	fs := authorizeItems(a)
	if len(fs) > 0 {
		return nil, nil, fail(fs)
	}
	if len(items) > 0 {
		names := make([]string, len(items))
		for i, it := range items {
			names[i] = it.Resource
		}
		if !rateDrawn && (t.rateDrawn == nil || !*t.rateDrawn) {
			if err := t.rateLimit(n, cfg, a, names, len(items)); err != nil {
				return nil, nil, err
			}
			if t.rateDrawn != nil {
				*t.rateDrawn = true
			}
		}
	}

	// Step 2: precondition — idempotent retry, settling the verb, frozen,
	// the precondition.
	if r := t.replay(n, a, st, cplan, isBatch); r != nil {
		return nil, r, nil
	}
	// Settling the verb completes authorisation: a 403 here is reported
	// like one of step 1, and a dry run answers it as a submit would
	// (§6.2, §7.5). It runs for every item before anything else of step 2.
	var denied []itemErr
	for _, s := range st {
		if err := t.settle(n, s); err != nil {
			if err.Status == 403 {
				denied = append(denied, itemErr{s.index, err})
			} else {
				fs = append(fs, itemErr{s.index, err})
			}
		}
	}
	if len(denied) > 0 {
		return nil, nil, fail(denied)
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}
	if cur.Frozen && len(items) > 0 {
		e := apiErr(409, "frozen")
		if cur.Successor != "" {
			e.Body["successor"] = cur.Successor
		}
		return nil, nil, e
	}
	for _, s := range st {
		if err := t.precondition(n, s); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}

	// Step 3: apply. Sealed namespaces also need a fresh $nonce in every
	// patch set (§C.7, §E.2.5). In an e2e namespace nothing is applied but
	// the keyring: patch sets are sealed and checked by their header
	// (§6.2, §E.3).
	for _, s := range st {
		var err *Error
		switch {
		case cfg.level == levelE2E && s.Resource != KeyringName:
			err = t.applyStepsE2E(n, cfg, s)
		default:
			err = t.applySteps(s)
			if err == nil && cfg.level == levelSealed {
				err = checkNonces(s)
			}
			if err == nil && cfg.level == levelE2E {
				err = t.checkKeyring(n, cfg, s)
			}
		}
		if err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}

	// Step 4: limits. The batch's item count and size first: they are the
	// batch's, not an item's.
	if isBatch {
		if len(items) > maxItems {
			return nil, nil, limitErr(413, fmt.Sprintf("more than %d items", maxItems))
		}
		size := 0
		for _, it := range items {
			for _, s := range it.Steps {
				if !s.Delete {
					size += len(jsonv.Canonical(s.Patches))
				}
			}
		}
		if size > maxSize {
			return nil, nil, limitErr(413, "batch too large")
		}
	}
	for _, s := range st {
		if err := checkLimits(cfg.Limits, s); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}
	// Blob references name available blobs (§7.8), also at step 4.
	bs := blobSourceOf(req, source, isBatch)
	for _, s := range st {
		if err := t.checkBlobs(n, s, a, bs); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}

	// Step 5: schema. Items may reference schema revisions created by
	// earlier items (§6.1).
	pending := map[string]any{}
	for _, s := range st {
		for _, step := range s.steps {
			if step.del || step.sealed {
				continue // e2e: validation moves to clients (§E.3.2)
			}
			typed, err := t.validateDoc(step.doc, a, pending)
			if err != nil {
				fs = append(fs, itemErr{s.index, err})
				break
			}
			step.typed = typed
			if !n.isBranch() {
				pending["/r/"+n.name+"/"+s.Resource+"/rev/"+step.id.String()] = step.doc
			}
		}
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}

	// Step 6: rules.
	for _, s := range st {
		for _, step := range s.steps {
			check := t.checkRules
			if step.sealed {
				check = func(cfg *Config, a *actor, env map[string]any, _ bool) *Error { return t.checkRulesE2E(cfg, a, env) }
			}
			if err := check(cfg, a, t.stepEnvelope(s, step, a), false); err != nil {
				fs = append(fs, itemErr{s.index, err})
				break
			}
		}
	}
	if len(fs) > 0 {
		if !dryRun {
			return nil, nil, fail(fs)
		}
		st, fs = dropFailed(st, fs, dryFails), nil
	}

	result := &WriteResult{Status: 201}
	for _, s := range st {
		ir := ItemResult{Resource: s.Resource}
		for _, step := range s.steps {
			ir.IDs = append(ir.IDs, step.id.String())
		}
		result.Items = append(result.Items, ir)
	}
	var src any
	if isBatch && source != nil {
		var err *Error
		src, err = t.checkSource(source)
		if err != nil {
			return nil, nil, err
		}
	}
	if dryRun {
		// A dry run reports every item (§7.5): its ids, or the error of the
		// step it failed at.
		result.Status = 200
		result.Items = dryRunReport(items, st, dryFails)
		return nil, result, nil
	}

	return &writePlan{n: n, a: a, st: st, cplan: cplan, src: src, isBatch: isBatch, result: result, req: req, source: source}, nil, nil
}

// insertPlan is step 7: insert a checked write atomically with its
// namespace entry. n must be the namespace as of this transaction.
func (t *tx) insertPlan(req Request, p *writePlan) *WriteResult {
	n, a, st, cplan, src, isBatch, result := p.n, p.a, p.st, p.cplan, p.src, p.isBatch, p.result
	// Step 7: insert atomically with the namespace entry.
	author := t.actorID(a)
	configSeq := n.configSeq
	var entries []any
	if cplan != nil {
		configSeq = t.insertConfig(n, cplan, author)
		entries = append(entries, map[string]any{"kind": "config", "target": cplan.id.String()})
		result.ConfigID = cplan.id.String()
	}
	// After the config change, which may have turned encryption on.
	grantID := t.storeGrant(n, a)
	type ins struct {
		res  int64
		last int64
	}
	var inserted []ins
	for _, s := range st {
		res, last := t.insertItem(n, s, a, author, grantID, req.Signature)
		inserted = append(inserted, ins{res, last})
		final := s.steps[len(s.steps)-1]
		kind := "head"
		if final.del {
			kind = "tombstone"
		}
		entries = append(entries, map[string]any{"resource": s.Resource, "kind": kind, "target": final.id.String()})
	}
	var nsSeq int64
	var nsID ids.ID
	if isBatch {
		entry := map[string]any{"kind": "batch", "entries": entries}
		if src != nil {
			entry["source"] = src
		}
		nsSeq, nsID = t.appendNS(n, entry, nil, nil, configSeq, author)
	} else {
		e := entries[0].(map[string]any)
		nsSeq, nsID = t.appendNS(n, e, &inserted[0].res, &inserted[0].last, configSeq, author)
	}
	for _, x := range inserted {
		_, err := t.Exec(`INSERT INTO head_history (res, ns_seq, target_seq) VALUES (?,?,?)`, x.res, nsSeq, x.last)
		t.must(err)
	}
	result.NSID = nsID.String()
	if !isBatch {
		le := t.logEntry(t.rev(inserted[0].last))
		result.Entry = &le
	}
	return result
}

// hasCandidates reports whether an item's first step may be an append or a
// restore, which only the resource's state decides (§6.2).
func hasCandidates(it Item) bool {
	return it.IfMatch != "" && !it.IfNoneMatch && len(it.Steps) > 0 && !it.Steps[0].Delete
}

// settle is the second sub-step of step 2 (§6.2): it settles the verb of
// an item with candidate verbs from the resource's state as the writer sees
// it (a branch's view, read-through included), and refuses one that isn't
// a candidate with 403, before the precondition is compared.
func (t *tx) settle(n *nsRow, s *itemState) *Error {
	if s.cands == nil {
		return nil
	}
	verb := "append"
	switch t.resolve(n, s.Resource, nil).state {
	case Purged:
		return gone()
	case Tombstoned:
		verb = "restore"
	}
	if !contains(s.cands, verb) {
		return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
	}
	return nil
}

// entryVerb is the verb an entry was written with: restore when its parent
// is a tombstone, append otherwise (§6.2).
func (t *tx) entryVerb(row *revRow) string {
	if row.parentSeq.Valid && t.rev(row.parentSeq.Int64).kind == kindTombstone {
		return "restore"
	}
	return "append"
}

// staticVerb is the verb of step j known from the request. The first patch
// step of an If-Match item has candidate verbs instead (hasCandidates).
func staticVerb(it Item, j int) string {
	s := it.Steps[j]
	if s.Delete {
		return "delete"
	}
	if j == 0 {
		if it.IfNoneMatch {
			return "create"
		}
		return "append"
	}
	if it.Steps[j-1].Delete {
		return "restore"
	}
	return "append"
}

// expectedIDs computes the ids an item would produce from its precondition
// alone (§3.3, §3.4). ok is false if it cannot be computed.
func expectedIDs(it Item) ([]ids.ID, bool) {
	var parent *ids.ID
	if it.IfMatch != "" {
		p, err := ids.Parse(it.IfMatch)
		if err != nil {
			return nil, false
		}
		parent = &p
	} else if !it.IfNoneMatch {
		return nil, false
	}
	var out []ids.ID
	for _, s := range it.Steps {
		var id ids.ID
		if s.Delete {
			if parent == nil {
				return nil, false
			}
			id = ids.Tombstone(*parent)
		} else {
			id = ids.Revision(parent, jsonv.Canonical(s.Patches))
		}
		out = append(out, id)
		p := id
		parent = &p
	}
	return out, true
}

// replay implements the idempotent-retry lookup (§7.2, §7.5).
func (t *tx) replay(n *nsRow, a *actor, st []*itemState, cp *configPlan, isBatch bool) *WriteResult {
	author := t.actorID(a)
	if !isBatch {
		if len(st) != 1 {
			return nil
		}
		s := st[0]
		want, ok := expectedIDs(s.Item)
		if !ok {
			return nil
		}
		own := t.resource(n.id, s.Resource)
		if own == nil || own.state == statePurged {
			return nil // a purged resource answers 410, never its content
		}
		last := want[len(want)-1]
		row, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ?`, own.id, last[:]))
		if err != nil || row.author != author {
			return nil
		}
		if s.cands != nil && !contains(s.cands, t.entryVerb(row)) {
			return nil // recorded with a verb this request may not use
		}
		var nsSeq int64
		t.QueryRow(`SELECT ns_seq FROM head_history WHERE res = ? AND target_seq = ?`, own.id, row.seq).Scan(&nsSeq)
		le := t.logEntry(row)
		r := &WriteResult{Status: 200, Replayed: true, Entry: &le,
			Items: []ItemResult{{Resource: s.Resource, IDs: []string{last.String()}}}}
		if nsSeq != 0 {
			r.NSID = t.nsLogID(nsSeq).String()
		}
		return r
	}
	var entries []any
	if cp != nil {
		if cp.expected == nil {
			return nil
		}
		entries = append(entries, map[string]any{"kind": "config", "target": cp.expected.String()})
	}
	var items []ItemResult
	for _, s := range st {
		want, ok := expectedIDs(s.Item)
		if !ok {
			return nil
		}
		kind := "head"
		if s.Steps[len(s.Steps)-1].Delete {
			kind = "tombstone"
		}
		entries = append(entries, map[string]any{"resource": s.Resource, "kind": kind, "target": want[len(want)-1].String()})
		ir := ItemResult{Resource: s.Resource}
		for _, id := range want {
			ir.IDs = append(ir.IDs, id.String())
		}
		items = append(items, ir)
	}
	want := string(jsonv.Canonical(entries))
	rows, err := t.Query(`SELECT id, body FROM ns_log WHERE ns = ? AND kind = ? AND author = ?`, n.id, nsKindCode("batch"), author)
	t.must(err)
	var match []byte
	for rows.Next() {
		var id []byte
		var body string
		t.must(rows.Scan(&id, &body))
		b := jsonv.MustParse([]byte(body)).(map[string]any)
		if string(jsonv.Canonical(b["entries"])) == want {
			match = id
			break
		}
	}
	// Closed before querying again: a Postgres connection runs one query
	// at a time.
	rows.Close()
	if match == nil || !t.candidateVerbsMatch(n, st) {
		return nil
	}
	r := &WriteResult{Status: 200, Replayed: true, NSID: ids.FromBytes(match).String(), Items: items}
	if cp != nil {
		r.ConfigID = cp.expected.String()
	}
	return r
}

// candidateVerbsMatch reports whether every item with candidate verbs
// recorded its first entry with one of them (§7.5 idempotent retry).
func (t *tx) candidateVerbsMatch(n *nsRow, st []*itemState) bool {
	for _, s := range st {
		if s.cands == nil {
			continue
		}
		want, ok := expectedIDs(s.Item)
		own := t.resource(n.id, s.Resource)
		if !ok || own == nil {
			return false
		}
		row, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ?`, own.id, want[0][:]))
		if err != nil || !contains(s.cands, t.entryVerb(row)) {
			return false
		}
	}
	return true
}

// precondition is step 2 for one item (§7.2, §7.6 first writes).
func (t *tx) precondition(n *nsRow, s *itemState) *Error {
	v := t.resolve(n, s.Resource, nil)
	s.view = v
	headErr := func() *Error {
		e := apiErr(412, "stale")
		if v.head != nil {
			e.Body["head"] = v.head.id.String()
		} else {
			e.Body["head"] = nil
		}
		return e
	}
	switch {
	case s.IfNoneMatch && s.IfMatch != "":
		return badInput("both If-Match and If-None-Match")
	case s.IfNoneMatch:
		switch v.state {
		case NotFound:
			return nil
		case Purged:
			return gone()
		default:
			return headErr()
		}
	case s.IfMatch != "":
		want, err := ids.Parse(s.IfMatch)
		if err != nil {
			return badInput("malformed If-Match")
		}
		switch v.state {
		case Purged:
			return gone()
		case NotFound:
			return headErr()
		case Tombstoned:
			if want != v.head.id || s.Steps[0].Delete {
				return gone("tombstone", v.head.id.String())
			}
		case Live:
			if want != v.head.id {
				return headErr()
			}
		}
		s.parent = v.head
		return nil
	default:
		return apiErr(428, "precondition_required")
	}
}

// applySteps is step 3: apply each step's patches in turn.
func (t *tx) applySteps(s *itemState) *Error {
	var doc any
	exists := false
	var parentID *ids.ID
	tomb := false
	if s.parent != nil {
		d, err := t.docAt(s.parent)
		if err != nil {
			var pe *prunedError
			if errors.As(err, &pe) {
				h, a := t.prunedInfo(pe)
				if a != "" {
					return apiErr(410, "pruned", "horizon", h, "archive", a)
				}
				return apiErr(410, "pruned", "horizon", h)
			}
			return gone()
		}
		doc, exists = d, true
		p := s.parent.id
		parentID = &p
		tomb = s.parent.kind == kindTombstone
	}
	for _, step := range s.Steps {
		ss := &stepState{del: step.Delete, raw: step.Patches, parentID: parentID}
		if step.Delete {
			if parentID == nil || tomb {
				return gone()
			}
			ss.action = "delete"
			ss.id = ids.Tombstone(*parentID)
			ss.doc = doc
			ss.writes = []string{}
			tomb = true
		} else {
			switch {
			case parentID == nil:
				ss.action = "create"
			case tomb:
				ss.action = "restore"
			default:
				ss.action = "append"
			}
			ops, err := patch.Parse(step.Patches)
			if err != nil {
				return patchErr(err)
			}
			nd, writes, err := patch.Apply(doc, exists, ops, patch.Options{ResourceEnvelope: true})
			if err != nil {
				return patchErr(err)
			}
			if m, ok := doc.(map[string]any); ok && exists {
				ss.prevNonce, _ = m["$nonce"].(string)
			}
			ss.canon = jsonv.Canonical(step.Patches)
			ss.id = ids.Revision(parentID, ss.canon)
			ss.doc = nd
			ss.writes = patch.WritesStrings(writes)
			doc, exists, tomb = nd, true, false
		}
		id := ss.id
		parentID = &id
		s.steps = append(s.steps, ss)
	}
	return nil
}

func patchErr(err error) *Error {
	var pe *patch.Error
	if errors.As(err, &pe) {
		return apiErr(422, "invalid", "message", pe.Message, "index", pe.Index, "pointer", pe.Pointer)
	}
	return invalid(err.Error())
}

// checkLimits is step 4 (§6.6).
func checkLimits(l Limits, s *itemState) *Error {
	for _, step := range s.steps {
		if step.del {
			continue
		}
		maxPatch := l.PatchSetSize
		if fromScratch(step) {
			maxPatch = l.DocumentSize
		}
		if len(step.canon) > maxPatch {
			return limitErr(413, "patch set too large")
		}
		if ops, ok := step.raw.([]any); ok && len(ops) > l.OpsPerSet {
			return limitErr(422, "too many operations")
		}
		step.docCanon = jsonv.Canonical(step.doc)
		if len(step.docCanon) > l.DocumentSize {
			return limitErr(413, "document too large")
		}
		if jsonv.Depth(step.doc) > l.NestingDepth {
			return limitErr(422, "document nested too deeply")
		}
		if step.sealed {
			continue // e2e: clients check the limits on documents (§E.3.2)
		}
		if err := checkValuesAndPaths(l, step.doc); err != nil {
			return err
		}
		if err := checkBlobRefs(l, step.doc); err != nil {
			return err
		}
	}
	return nil
}

// validateDoc is step 5: resolve $schema and validate (§6.1). It returns the
// document's $schema, if typed.
func (t *tx) validateDoc(doc any, a *actor, pending map[string]any) (string, *Error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return "", nil
	}
	sv, has := m["$schema"]
	if !has {
		return "", nil
	}
	s, _ := sv.(string)
	load := func(ref schema.Ref) (any, error) { return t.loadSchema(ref, a, pending) }
	// The validator caches compiled schemas forever, so availability and
	// read permission are checked here for the whole $ref closure.
	if r, ok := schema.ParseRef(s); ok {
		seen := map[string]bool{}
		queue := []schema.Ref{r}
		for len(queue) > 0 {
			r := queue[0]
			queue = queue[1:]
			if seen[r.Path()] {
				continue
			}
			seen[r.Path()] = true
			d, err := load(r)
			if err != nil {
				return "", schemaErr(err, r.Path())
			}
			queue = append(queue, schema.Refs(d)...)
		}
	}
	if err := t.e.validator.Validate(doc, load); err != nil {
		return "", schemaErr(err, s)
	}
	return s, nil
}

func schemaErr(err error, path string) *Error {
	var re *schema.RefError
	var ue *schema.UnavailableError
	var ve *schema.ValidationError
	var se *schema.SchemaError
	switch {
	case errors.As(err, &re):
		return apiErr(422, "schema_ref", "message", re.Msg)
	case errors.Is(err, schema.ErrBranch):
		return apiErr(422, "schema_ref", "message", "a schema reference must not name a branch")
	case errors.As(err, &ue):
		return apiErr(422, "schema_unavailable", "ref", ue.Ref)
	case errors.Is(err, schema.ErrUnavailable), errors.Is(err, schema.ErrForbidden):
		return apiErr(422, "schema_unavailable", "ref", path)
	case errors.As(err, &ve):
		var details []any
		for _, d := range ve.Errors {
			details = append(details, map[string]any{"pointer": d.Pointer, "message": d.Message})
		}
		return apiErr(422, "invalid", "errors", details)
	case errors.As(err, &se):
		return apiErr(422, "invalid", "message", "invalid schema: "+se.Msg)
	}
	return invalid(err.Error())
}

// loadSchema resolves a schema revision path for a writer (§6.1).
func (t *tx) loadSchema(ref schema.Ref, a *actor, pending map[string]any) (any, error) {
	if d, ok := pending[ref.Path()]; ok {
		return d, nil
	}
	t.deps.addSchema(ref)
	n := t.nsByName(ref.NS)
	if n == nil || n.purged {
		return nil, schema.ErrUnavailable
	}
	if n.isBranch() {
		return nil, schema.ErrBranch
	}
	if t.e2eContent(n, ref.Name) {
		// The server can't read schemas in an e2e namespace (§E.3.2).
		return nil, schema.ErrUnavailable
	}
	if !t.canRead(n, t.config(n.configSeq), a, ref.Name) {
		return nil, schema.ErrForbidden
	}
	v := t.resolve(n, ref.Name, nil)
	if v.head == nil || v.state == Purged || v.state == NotFound {
		return nil, schema.ErrUnavailable
	}
	id, err := ids.Parse(ref.Rev)
	if err != nil {
		return nil, schema.ErrUnavailable
	}
	row := t.findInAncestry(v.head, id)
	if row == nil || row.kind == kindTombstone {
		return nil, schema.ErrUnavailable
	}
	d, err := t.docAt(row)
	if err != nil {
		return nil, schema.ErrUnavailable
	}
	return d, nil
}

// stepEnvelope builds the change envelope of §6.4.1 for one step.
func (t *tx) stepEnvelope(s *itemState, step *stepState, a *actor) map[string]any {
	env := t.basicEnvelope(step.action, s.Resource, a)
	w := make([]any, len(step.writes))
	for i, x := range step.writes {
		w[i] = x
	}
	env["writes"] = w
	if step.del {
		env["doc"] = nil
		env["patches"] = []any{}
	} else {
		env["doc"] = step.doc
		env["patches"] = jsonv.MustParse(step.canon)
	}
	return env
}

// checkSource validates a batch's source (§7.5).
func (t *tx) checkSource(v any) (any, *Error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("source must be an object")
	}
	for k := range m {
		switch k {
		case "origin", "ns", "at", "bundle", "ids":
		default:
			return nil, invalid("unknown source member " + k)
		}
	}
	ns, _ := m["ns"].(string)
	at, _ := m["at"].(string)
	if !ValidNSName(ns) || at == "" {
		return nil, invalid("source needs ns and at")
	}
	if o, has := m["origin"]; has {
		if o == t.e.opt.Origin {
			return nil, invalid("source origin is this deployment")
		}
		return m, nil
	}
	sn := t.nsByName(ns)
	id, err := ids.Parse(at)
	if sn == nil || err != nil {
		return nil, invalid("source.at is not in the chain of source.ns")
	}
	if _, ok := t.nsLogSeq(sn.id, id); !ok {
		return nil, invalid("source.at is not in the chain of source.ns")
	}
	return m, nil
}

// actorID is authorID for an actor. Under a grant it also remembers the key
// that signed the root block, which the namespace entries this transaction
// writes for that author record (§F.3: merge tools and the janitor match
// author and kid against merge.authors).
func (t *tx) actorID(a *actor) int64 {
	id := t.authorID(a.id())
	if a.verified != nil && id >= 0 {
		if t.kids == nil {
			t.kids = map[int64]string{}
		}
		t.kids[id] = a.verified.Key.Kid
	}
	return id
}

// storeGrant records the non-bearer form of the actor's grant (§C.3).
func (t *tx) storeGrant(n *nsRow, a *actor) []byte {
	if a.grant == nil {
		return nil
	}
	id := a.grant.ID()
	t.storeGrantBlocks(id[:], a.grant.Stored(), t.nsLevel(n) >= levelAtRest)
	return id[:]
}

// insertItem is step 7 for one item. It returns the resource row and the
// seq of its final entry.
func (t *tx) insertItem(n *nsRow, s *itemState, a *actor, author int64, grantID []byte, signature string) (int64, int64) {
	own := t.resource(n.id, s.Resource)
	var res int64
	if own == nil {
		res = t.mustInsert(`INSERT INTO resources (ns, name) VALUES (?, ?) RETURNING res`, n.id, s.Resource)
	} else {
		res = own.id
	}
	// A resource with a head has revisions (a purge keeps their rows).
	hasRows := own != nil && own.headSeq.Valid
	if own != nil && !hasRows {
		t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ?)`, res).Scan(&hasRows))
	}
	if _, ok := t.resLevels[res]; !ok {
		if t.resLevels == nil {
			t.resLevels = map[int64]int{}
		}
		t.resLevels[res] = t.nsLevel(n)
	}
	var via any
	if len(a.principal.Via) > 0 {
		via = string(jsonv.Canonical(jsonv.FromGo(a.principal.Via)))
	}
	var parentSeq any
	if s.parent != nil {
		parentSeq = s.parent.seq
	}
	var last int64
	var lastLive *stepState
	var lastLiveSeq int64
	if s.parent != nil {
		ll := t.lastLive(s.parent)
		lastLiveSeq = ll.seq
	}
	// E2e content has no documents on the server (§E.3).
	e2e := t.config(n.configSeq).level == levelE2E && s.Resource != KeyringName
	for i, step := range s.steps {
		first := 0
		if !hasRows && i == 0 {
			first = 1
		}
		kind := kindRev
		var patches, typed, sig any
		if step.del {
			kind = kindTombstone
		} else {
			patches = t.putPatches(res, step.id, step.canon)
			if step.typed != "" {
				typed = step.typed
			}
		}
		if i == 0 && signature != "" {
			sig = signature
		}
		var err error
		last, err = t.insert(`INSERT INTO revisions (res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq`,
			res, step.id[:], parentSeq, first, kind, patches, author, via, grantID, sig, typed, t.now.UnixMilli())
		if err != nil {
			panic(fmt.Errorf("inserting revision: %w", err))
		}
		t.inserted(revRow{seq: last, res: res, id: step.id, parentSeq: anyInt(parentSeq), first: first == 1, kind: kind,
			patches: anyStr(patches), author: author, via: anyStr(via), grantID: grantID, signature: anyStr(sig), created: t.now.UnixMilli()})
		parentSeq = last
		if !step.del && !step.sealed {
			// The blobs the document references are attached with it
			// (§7.8, step 7).
			t.attachStep(res, step, last)
		}
		// TODO(blobs-e2e): a sealed step attaches the blobs its op declares
		// (§E.3.1), and records them in blob_refs for pruning and archives;
		// a restore with [] keeps the last live document's list.
		if cfg := t.config(n.configSeq); cfg.level == levelSealed {
			// The epoch that seals this entry forever (§E.2.1).
			_, err := t.Exec(`INSERT INTO rev_epochs (seq, epoch) VALUES (?, ?)`, last, cfg.Epoch)
			t.must(err)
		}
		if !step.del {
			lastLive = step
			lastLiveSeq = last
			if e2e {
				continue
			}
			canon := step.docCanon
			if canon == nil {
				canon = jsonv.Canonical(step.doc)
			}
			t.cacheDoc(step.id, canon)
			t.maybeSnapshot(res, last, canon)
		}
	}
	final := s.steps[len(s.steps)-1]
	state := stateLive
	if final.del {
		state = stateTombstoned
	}
	_, err := t.Exec(`UPDATE resources SET head_seq = ?, state = ? WHERE res = ?`, last, state, res)
	t.must(err)
	// heads caches the last live document, which reads and restores need,
	// but only for small documents (D.4): rewriting a large one on every
	// save costs its whole size each time. Larger ones fold from snapshots.
	var doc []byte
	if lastLive != nil {
		doc = jsonv.Canonical(lastLive.doc)
	} else {
		doc = jsonv.Canonical(final.doc)
	}
	if !e2e && len(doc) <= t.e.opt.HeadSnapshotMax {
		_, err = t.Exec(`INSERT INTO heads (res, seq, doc) VALUES (?,?,?) ON CONFLICT (res) DO UPDATE SET seq = excluded.seq, doc = excluded.doc`, res, lastLiveSeq, t.putDoc("heads", res, lastLiveSeq, doc))
	} else {
		_, err = t.Exec(`DELETE FROM heads WHERE res = ?`, res)
	}
	t.must(err)
	return res, last
}

// maybeSnapshot writes an intermediate snapshot at seq once enough patch
// sets have accumulated since the resource's last snapshot (D.4), so no
// read folds more than that.
func (t *tx) maybeSnapshot(res, seq int64, doc []byte) {
	var count, size int64
	t.must(t.QueryRow(`SELECT COUNT(*), COALESCE(SUM(octet_length(patches)), 0) FROM revisions
		WHERE res = ? AND kind = 0 AND seq > (SELECT COALESCE(MAX(seq), 0) FROM snapshots WHERE res = ?)`, res, res).Scan(&count, &size))
	if count >= int64(t.e.opt.SnapshotEveryRevisions) || size >= int64(t.e.opt.SnapshotEveryBytes) {
		_, err := t.Exec(`INSERT INTO snapshots (seq, res, doc) VALUES (?,?,?) ON CONFLICT (seq) DO UPDATE SET res = excluded.res, doc = excluded.doc`, seq, res, t.putDoc("snapshots", res, seq, doc))
		t.must(err)
	}
}

// sortedKeys is a helper for stable output.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = sql.ErrNoRows
