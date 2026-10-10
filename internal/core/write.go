package core

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/rules"
	"github.com/middle-management/patchlog/internal/schema"
)

// Step is one step of a write: a patch set, or a delete.
type Step struct {
	Delete  bool
	Patches any // a JSON value (validated as a patch set at step 3)
	// Gesture and Undoes are the step's gesture ids (§7.2), "" if absent:
	// stored with its revision or tombstone as metadata, like its author,
	// outside its id (§3.3), and never seen by rules. A batch's item and
	// batch defaults are resolved into each step before it gets here.
	Gesture, Undoes string
	// Signature is the step's author signature, "<alg>:<kid>:<sig>"
	// (§C.3.1), "" if absent: a batch step object's "signature" (§7.5),
	// or a single write's Signature header. Stored with the step's
	// revision or tombstone, outside its id.
	Signature string
}

// gestureRe is the form of a gesture id (§7.2): 26 base32 characters,
// 128 random bits the client chooses.
var gestureRe = regexp.MustCompile(`^[a-z2-7]{26}$`)

// ValidGesture reports whether s is a gesture id (§7.2).
func ValidGesture(s string) bool { return gestureRe.MatchString(s) }

// checkGestures answers 400 for a step whose Gesture or Undoes isn't a
// gesture id (§7.2).
func checkGestures(items []Item) *Error {
	for i, it := range items {
		for j, st := range it.Steps {
			for _, g := range [2]string{st.Gesture, st.Undoes} {
				if g != "" && !ValidGesture(g) {
					return badInput(fmt.Sprintf("item %d, step %d: a gesture id is 26 base32 characters", i, j))
				}
			}
		}
	}
	return nil
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
	// Gesture and Undoes are the single config write's gesture ids (§7.2,
	// §7.4), stored with the config entry, outside its id. "" if absent.
	Gesture, Undoes string
}

// Request carries what every write request has in common.
type Request struct {
	NS        string
	Cred      Credentials
	Signature string // optional author signature header (§C.3)
	// SourceCreds are the grants of Source-Authorization, which may be
	// repeated (§6.1, §7.8): any of them that verifies for a namespace
	// serves for it, to read a copy's source, a batch's local source, or a
	// branch holding draft schema revisions. Empty: Cred alone.
	SourceCreds []Credentials
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

// dryRunReport is a dry run's report (§7.5). An item whose only failure
// is a blob that isn't available reports that failure with the ids a
// submit would produce once the blob is; one that also fails a later step
// reports that step's failure, with the blob failure as its "blob" member.
func dryRunReport(items []Item, passed []*itemState, fails, blobFails map[int]*Error) []ItemResult {
	byIndex := map[int]*itemState{}
	for _, s := range passed {
		byIndex[s.index] = s
	}
	out := make([]ItemResult, len(items))
	for i, it := range items {
		idx := i
		r := ItemResult{Resource: it.Resource, Index: &idx}
		berr := blobFails[i]
		if err, failed := fails[i]; failed {
			r.Status, r.Err = err.Status, err.Body
			if berr != nil {
				body := map[string]any{}
				for k, v := range err.Body {
					body[k] = v
				}
				body["blob"] = berr.Body
				r.Err = body
			}
		} else if s := byIndex[i]; s != nil {
			r.Status = 200
			if berr != nil {
				r.Status, r.Err = berr.Status, berr.Body
			}
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
	// any (sealed namespaces and those that require nonces refuse a
	// repeated one, §C.7, §E.2.5).
	prevNonce string
	// sealed marks a create, append or restore of an e2e resource: its
	// patch set is opaque and its document unknown (§6.2, §E.3).
	sealed bool
	// blobs are the blobs the resulting document references, with where
	// each is available from (step 4, §7.8), for step 7 to attach.
	blobs map[ids.ID]*blobRow
	// declared is a sealed step's declared blob list (§E.3.1), in the order
	// sent; keepsList marks a sealed restore with [], which keeps the list
	// of the last live document instead.
	declared  []ids.ID
	keepsList bool
	// packed is canon compressed, if the check phase compressed it
	// (packPlan, compress.go).
	packed []byte
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
	// canons are the canonical forms of the steps' patch sets, once
	// computed (canon): the retry lookup, the batch size and step 3 each
	// need them, and a create's is its whole document.
	canons [][]byte
}

// canon returns the canonical form of step j's patch set.
func (s *itemState) canon(j int) []byte {
	if s.canons == nil {
		s.canons = make([][]byte, len(s.Steps))
	}
	if s.canons[j] == nil {
		s.canons[j] = jsonv.Canonical(s.Steps[j].Patches)
	}
	return s.canons[j]
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
		cur := t.config(n.configSeq)
		a, aerr := t.authenticate(n.name, n, cur, req.Cred, nil)
		if aerr != nil {
			return aerr
		}
		// No state checks here: the gate answers them in order after the
		// body is parsed (§6.2, §7.5). This only bounds how much is read.
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
	// level is the encryption level the write was checked under, which
	// the re-check confirms (the namespace's config_seq).
	level int
}

// checkItems runs steps 1–6 of §6.2 for a resource write or batch. It
// returns a plan to insert, or a final result (an idempotent retry, a dry
// run), or an error.
func (t *tx) checkItems(req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun, rateDrawn bool) (*writePlan, *WriteResult, error) {
	// A config change locks the namespace exclusively; resource writes
	// alone lock it shared (pglock.go).
	t.reqCreds = req.anyCreds()
	var n *nsRow
	if cc != nil || t.exclusive {
		n = t.nsForWrite(req.NS)
	} else {
		n = t.nsForResources(req.NS)
	}
	if n == nil {
		return nil, nil, t.absentNS(req.NS, req.Cred)
	}
	if h := t.e.afterWriteLock; h != nil && t.write && cc == nil {
		// The whole gate runs in the write lock (writeLocked).
		h(n.name)
	}
	cur := t.config(n.configSeq)
	if err := checkGestures(items); err != nil {
		return nil, nil, err
	}
	if err := checkSignatureShapes(req, items, isBatch); err != nil {
		return nil, nil, err
	}
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
	all := append([]*itemState(nil), st...) // a dry run drops failed items from st
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
				// Signatures aren't checked: they come after the retry
				// lookup (§6.2 step 2.3), which answers a retry as first
				// recorded whatever it carries. If the lookup finds
				// nothing, the batch fails with its config change's error,
				// so no item is ever judged under the wrong configuration
				// (§C.3.1 "Requiring signatures").
				if pid, perr := ids.Parse(cc.IfMatch); perr == nil && len(authorizeItems(a)) == 0 {
					// The request passed step 1, so it draws its tokens,
					// even though the replay lookup ends it (§6.6, §6.2).
					// Its config change costs a token unless a * key
					// made it (§6.6); whether it was only a freeze isn't
					// known once the precondition failed.
					cost := len(items)
					if !a.star {
						cost++
					}
					names := make([]string, len(items))
					for i, it := range items {
						names[i] = it.Resource
					}
					if err := t.rateLimit(n, cur, a, names, cost); err != nil {
						return nil, nil, err
					}
					if t.rateDrawn != nil {
						*t.rateDrawn = true
					}
					exp := ids.Revision(&pid, jsonv.Canonical(cc.Patches))
					if r := t.replay(n, a, st, &configPlan{expected: &exp}, true); r != nil {
						// It is that batch, but the lookup doesn't apply
						// to a purged resource (§6.2 step 2, §7.2): 410
						// for its items, not a 412 that would invite the
						// client to apply its config change again.
						if pf := t.purgedItems(n, st); len(pf) > 0 {
							return nil, nil, fail(pf)
						}
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
	// A batch costs a token per item, and one for its config change unless
	// that is exempt (§6.6), so only a batch with no items and an exempt
	// change costs nothing.
	cost := len(items)
	if cplan != nil && !cplan.exempt {
		cost++
	}
	if len(items) > 0 {
		names := make([]string, len(items))
		for i, it := range items {
			names[i] = it.Resource
		}
		t.prefetchResources(n.id, names)
	}
	if cost > 0 {
		var names []string
		for _, it := range items {
			names = append(names, it.Resource)
		}
		if !rateDrawn && (t.rateDrawn == nil || !*t.rateDrawn) {
			if err := t.rateLimit(n, cfg, a, names, cost); err != nil {
				return nil, nil, err
			}
			if t.rateDrawn != nil {
				*t.rateDrawn = true
			}
		}
	}
	// A purged namespace is 410 after authorisation and the rate limits,
	// a config change's included (§6.2 step 2, §8.5), before step 2.
	if n.purged {
		return nil, nil, t.purgedNS(n)
	}

	// Step 2: precondition — idempotent retry, settling the verb, frozen,
	// the precondition. The retry lookup doesn't apply to a purged
	// resource: the answer is 410, as for every URL of it, before the
	// frozen check (§6.2 step 2, §7.2, §8.3).
	if pf := t.purgedItems(n, st); len(pf) > 0 {
		if !dryRun {
			return nil, nil, fail(pf)
		}
		st = dropFailed(st, pf, dryFails)
	}
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
	// Author signatures, after the retry lookup and the verb, in the
	// configuration the write is checked against (§6.2 step 2.3, §C.3.1).
	if fs = t.checkSignatures(n, cfg, a, st); len(fs) > 0 {
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

	// Step 3: apply. Namespaces that require nonces need a fresh $nonce in
	// every resulting document, and sealed ones in every patch set (§C.7,
	// §E.2.5). In an e2e namespace nothing is applied but the keyring:
	// patch sets are sealed and checked by their header (§6.2, §E.3).
	for _, s := range st {
		var err *Error
		switch {
		case cfg.level == levelE2E && s.Resource != KeyringName:
			err = t.applyStepsE2E(n, cfg, s)
		default:
			err = t.applySteps(s)
			if err == nil && cfg.NonceRequired {
				err = checkRequiredNonces(s)
			}
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
		for _, s := range all {
			for j, step := range s.Steps {
				if !step.Delete {
					size += len(s.canon(j))
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
	// A batch's source, then blob references naming available blobs
	// (§7.5, §7.8), also at step 4: the blobs may depend on the source.
	var src any
	var bs *batchSource
	if isBatch && source != nil {
		var err *Error
		src, bs, err = t.checkSource(req, source)
		if err != nil {
			return nil, nil, err
		}
	}
	// A dry run reports a blob that isn't available, and runs the later
	// steps as if it were (§7.5).
	blobFails := map[int]*Error{}
	for _, s := range st {
		if err := t.checkBlobs(n, s, a, bs); err != nil {
			if dryRun {
				blobFails[s.index] = err
				continue
			}
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		return nil, nil, fail(fs)
	}

	// Step 5: schema. Items may reference schema revisions created by
	// earlier items (§6.1). In a branch, a path its namespace can't resolve
	// is looked up among drafts in branches of that namespace.
	pending := map[string]any{}
	sc := &schemaCtx{a: a, target: n, creds: req.anyCreds()}
	for _, s := range st {
		for _, step := range s.steps {
			if step.del || step.sealed {
				continue // e2e: validation moves to clients (§E.3.2)
			}
			typed, err := t.validateDoc(step.doc, sc, pending)
			if err != nil {
				fs = append(fs, itemErr{s.index, err})
				break
			}
			step.typed = typed
			if k := t.pendingKey(n, s.Resource, step.id); k != "" {
				pending[k] = step.doc
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
	readsPatches := map[string]bool{}
	for _, s := range st {
		for _, step := range s.steps {
			check := t.checkRules
			if step.sealed {
				check = func(cfg *Config, a *actor, env map[string]any, _ bool) *Error { return t.checkRulesE2E(cfg, a, env) }
			}
			reads, ok := readsPatches[step.action]
			if !ok {
				reads = rulesRead(cfg, a, step.action, "patches")
				readsPatches[step.action] = reads
			}
			if err := check(cfg, a, t.stepEnvelope(s, step, a, reads), false); err != nil {
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
	if dryRun {
		// A dry run reports every item (§7.5): its ids, or the error of the
		// step it failed at.
		result.Status = 200
		result.Items = dryRunReport(items, st, dryFails, blobFails)
		return nil, result, nil
	}

	return &writePlan{n: n, a: a, st: st, cplan: cplan, src: src, isBatch: isBatch, result: result, req: req, source: source, level: cfg.level}, nil, nil
}

// insertPlan is step 7: insert a checked write atomically with its
// namespace entry. n must be the namespace as of this transaction.
func (t *tx) insertPlan(req Request, p *writePlan) *WriteResult {
	n, a, cplan, result := p.n, p.a, p.cplan, p.result
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
	grantID := t.storeGrant(a.grant, t.nsLevel(n) >= levelAtRest)
	inserted := t.insertItems(n, p.st, a, author, grantID)
	// The namespace entry last: on Postgres it is appended under the
	// namespace row's lock, held until commit (appendNS).
	na := t.planEntry(p, author, entries, inserted)
	_, nsID := t.appendNSMeta(p.n, na.entry, na.meta, na.res, na.target, configSeq, author, na.hist...)
	p.result.NSID = nsID.String()
	return p.result
}

// planEntry is the namespace entry of a write whose rows are inserted
// (inserted, in its items' order), after the entries of its config change
// if any. It completes the write's result but for the entry's id.
func (t *tx) planEntry(p *writePlan, author int64, entries []any, inserted []histRow) nsAppend {
	for _, s := range p.st {
		final := s.steps[len(s.steps)-1]
		kind := "head"
		if final.del {
			kind = "tombstone"
		}
		entries = append(entries, map[string]any{"resource": s.Resource, "kind": kind, "target": final.id.String()})
	}
	if p.isBatch {
		entry := map[string]any{"kind": "batch", "entries": entries}
		if p.src != nil {
			entry["source"] = p.src
		}
		return nsAppend{entry: entry, meta: batchGestures(p.st), author: author, hist: inserted}
	}
	le := t.logEntry(t.rev(inserted[0].target))
	p.result.Entry = &le
	return nsAppend{entry: entries[0].(map[string]any), meta: stepGestures(p.st[0].Steps[0]), res: &inserted[0].res, target: &inserted[0].target, author: author, hist: inserted}
}

// stepGestures are a step's gesture members, { gesture?, undoes? } (§7.4),
// or nil if it has neither: a single write's entry carries them.
func stepGestures(st Step) map[string]any {
	var m map[string]any
	for k, v := range map[string]string{"gesture": st.Gesture, "undoes": st.Undoes} {
		if v != "" {
			if m == nil {
				m = map[string]any{}
			}
			m[k] = v
		}
	}
	return m
}

// batchGestures are a batch entry's gesture members (§7.4): "gestures"
// maps each resource of the batch to a list of { gesture?, undoes? }, one
// per step in order, {} for a step with neither. The member is left out
// when no step of the batch has one, so batches without gestures serve
// what they did before v0.39; when it is there, every resource is, so a
// step's position in its list is its position among the item's steps.
func batchGestures(st []*itemState) map[string]any {
	has := false
	out := map[string]any{}
	for _, s := range st {
		list := make([]any, len(s.Steps))
		for j, step := range s.Steps {
			g := stepGestures(step)
			if g == nil {
				g = map[string]any{}
			} else {
				has = true
			}
			list[j] = g
		}
		out[s.Resource] = list
	}
	if !has {
		return nil
	}
	return map[string]any{"gestures": out}
}

// gestureMeta is a single config write's gesture members (§7.2, §7.4), or
// nil when it carries neither: the config entry can carry them too.
func gestureMeta(gesture, undoes string) map[string]any {
	return stepGestures(Step{Gesture: gesture, Undoes: undoes})
}

// checkConfigGestures answers 400 for a config write whose Gesture or
// Undoes header isn't a gesture id (§7.2), like checkGestures for steps.
func checkConfigGestures(cc *ConfigChange) *Error {
	for _, g := range [2]string{cc.Gesture, cc.Undoes} {
		if g != "" && !ValidGesture(g) {
			return badInput("Gesture and Undoes must be one gesture id: 26 base32 characters")
		}
	}
	return nil
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
func expectedIDs(s *itemState) ([]ids.ID, bool) {
	it := s.Item
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
	for j, step := range it.Steps {
		var id ids.ID
		if step.Delete {
			if parent == nil {
				return nil, false
			}
			id = ids.Tombstone(*parent)
		} else {
			id = ids.Revision(parent, s.canon(j))
		}
		out = append(out, id)
		p := id
		parent = &p
	}
	return out, true
}

// purgedItems answers 410 for each item whose resource is purged, as the
// writer sees it (§7.6): the idempotent-retry lookup doesn't apply to it
// (§6.2 step 2, §7.2), and every URL of it is 410 (§8.3).
func (t *tx) purgedItems(n *nsRow, st []*itemState) []itemErr {
	var fs []itemErr
	for _, s := range st {
		if t.resolve(n, s.Resource, nil).state == Purged {
			fs = append(fs, itemErr{s.index, gone()})
		}
	}
	return fs
}

// replay implements the idempotent-retry lookup (§7.2, §7.5). Callers
// answer a purged resource first (purgedItems): the lookup doesn't apply
// to one.
func (t *tx) replay(n *nsRow, a *actor, st []*itemState, cp *configPlan, isBatch bool) *WriteResult {
	author := t.actorID(a)
	if !isBatch {
		if len(st) != 1 {
			return nil
		}
		s := st[0]
		want, ok := expectedIDs(s)
		if !ok {
			return nil
		}
		own := t.resource(n.id, s.Resource)
		if own == nil {
			return nil
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
		want, ok := expectedIDs(s)
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
	// The batch, if it was written, is an entry that moved the first item's
	// resource to its target, or, for a batch of only a config change, the
	// first entry with that config in force. Looking it up from there costs
	// that resource's history, not every batch the author ever wrote here,
	// which made each batch slower as the log grew.
	var cands []int64
	if len(st) > 0 {
		own := t.resource(n.id, st[0].Resource)
		if own == nil {
			return nil
		}
		target, err := ids.Parse(items[0].IDs[len(items[0].IDs)-1])
		if err != nil {
			return nil
		}
		var rseq int64
		if t.QueryRow(`SELECT seq FROM revisions WHERE res = ? AND id = ?`, own.id, target[:]).Scan(&rseq) != nil {
			return nil
		}
		rows, err := t.Query(`SELECT ns_seq FROM head_history WHERE res = ? AND target_seq = ?`, own.id, rseq)
		t.must(err)
		for rows.Next() {
			var s int64
			t.must(rows.Scan(&s))
			cands = append(cands, s)
		}
		// Closed before querying again: a Postgres connection runs one
		// query at a time.
		rows.Close()
	} else if cp != nil {
		var cseq, s int64
		if t.QueryRow(`SELECT seq FROM ns_config WHERE ns = ? AND id = ?`, n.id, cp.expected[:]).Scan(&cseq) != nil {
			return nil
		}
		if t.QueryRow(`SELECT MIN(seq) FROM ns_log WHERE ns = ? AND config_seq = ?`, n.id, cseq).Scan(&s) == nil && s != 0 {
			cands = append(cands, s)
		}
	}
	var match []byte
	for _, seq := range cands {
		var id []byte
		var body string
		if t.QueryRow(`SELECT id, body FROM ns_log WHERE seq = ? AND ns = ? AND kind = ? AND author = ?`, seq, n.id, nsKindCode("batch"), author).Scan(&id, &body) != nil {
			continue
		}
		b := jsonv.MustParse([]byte(body)).(map[string]any)
		if string(jsonv.Canonical(b["entries"])) == want {
			match = id
			break
		}
	}
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
		want, ok := expectedIDs(s)
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

// doubleDelete answers a delete step right after another (§7.5): 422, as a
// DELETE of a tombstoned resource is 410.
func doubleDelete() *Error {
	return apiErr(422, "invalid", "message", "a delete step can't follow another delete")
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
	for j, step := range s.Steps {
		ss := &stepState{del: step.Delete, raw: step.Patches, parentID: parentID}
		if step.Delete {
			if j > 0 && s.Steps[j-1].Delete {
				return doubleDelete()
			}
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
			ss.canon = s.canon(j)
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

// genesisPrefix begins the canonical form of a patch set that adds a whole
// document (§3.3); the document's own canonical form follows it.
var genesisPrefix = []byte(`[{"op":"add","path":"","value":`)

// genesisDocCanon is the canonical form of the document a step's lone
// whole-document add makes, cut from its patch set's (a create, as an
// import's are), or nil for any other step.
func genesisDocCanon(step *stepState) []byte {
	ops, _ := step.raw.([]any)
	if len(ops) != 1 {
		return nil
	}
	if op, _ := ops[0].(map[string]any); len(op) != 3 || !bytes.HasPrefix(step.canon, genesisPrefix) || !bytes.HasSuffix(step.canon, []byte("}]")) {
		return nil
	}
	return step.canon[len(genesisPrefix) : len(step.canon)-2 : len(step.canon)-2]
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
		if step.docCanon = genesisDocCanon(step); step.docCanon == nil {
			step.docCanon = jsonv.Canonical(step.doc)
		}
		if len(step.docCanon) > l.DocumentSize {
			return limitErr(413, "document too large")
		}
		if jsonv.Depth(step.doc) > l.NestingDepth {
			return limitErr(422, "document nested too deeply")
		}
		if step.sealed {
			// e2e: clients check the limits on documents (§E.3.2); the
			// server checks blobsPerDocument on the declared list (§E.3.1).
			if len(step.declared) > l.BlobsPerDocument {
				return limitErr(422, fmt.Sprintf("more than %d blobs declared", l.BlobsPerDocument))
			}
			continue
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
func (t *tx) validateDoc(doc any, sc *schemaCtx, pending map[string]any) (string, *Error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return "", nil
	}
	sv, has := m["$schema"]
	if !has {
		return "", nil
	}
	s, _ := sv.(string)
	load := func(ref schema.Ref) (any, error) { return t.loadSchema(ref, sc, pending) }
	// The validator caches compiled schemas forever, so availability and
	// read permission are checked here for the whole $ref closure.
	// A schema document (a dialect $schema) starts the closure at its own
	// $refs, so a cached revision the writer may not read is still refused,
	// and the error names the revision that didn't resolve, not the dialect.
	var queue []schema.Ref
	if r, ok := schema.ParseRef(s); ok {
		queue = []schema.Ref{r}
	} else if schema.IsDialect(s) {
		queue = schema.Refs(doc)
	}
	{
		seen := map[string]bool{}
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
	case schema.RefPath(err) != "":
		// The revision that didn't resolve, wherever in the closure it is,
		// never the document's own $schema (a dialect URL for a schema).
		return apiErr(422, "schema_unavailable", "ref", schema.RefPath(err))
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

// loadSchema resolves a schema revision path for a writer (§6.1): from the
// write's own earlier items, in the path's namespace, or, in a write to a
// branch, among the drafts in branches of that namespace (loadDraft). A
// path naming a branch is ErrBranch, whatever the drafts.
//
// Within a transaction, which reads one snapshot, a path resolves the same
// way for the same writer (sc) every time: the result is kept for the
// transaction (t.schemas), so a batch's documents typed by the same schemas
// resolve and parse each once, not once for every document and $ref.
func (t *tx) loadSchema(ref schema.Ref, sc *schemaCtx, pending map[string]any) (any, error) {
	if d, ok := pending[ref.Path()]; ok {
		return d, nil
	}
	t.deps.addSchema(ref)
	key := schemaKey{sc, ref.Path()}
	if r, ok := t.schemas[key]; ok {
		return r.doc, r.err
	}
	d, err := t.loadSchemaIn(ref, sc)
	if err != nil && !errors.Is(err, schema.ErrBranch) {
		if dd, ok := t.loadDraft(ref, sc); ok {
			d, err = dd, nil
		} else {
			d = nil
		}
	}
	if t.schemas == nil {
		t.schemas = map[schemaKey]schemaLoaded{}
	}
	t.schemas[key] = schemaLoaded{d, err}
	return d, err
}

// schemaKey and schemaLoaded are a transaction's resolved schema paths
// (loadSchema).
type schemaKey struct {
	sc   *schemaCtx
	path string
}

type schemaLoaded struct {
	doc any
	err error
}

// loadSchemaIn resolves a schema revision path in its own namespace. The
// writer needs read on the copy (§6.1 Read permission): in the namespace
// written, with the write's own grant; in any other, by the rule for other
// namespaces (§7.5). A revision it can't read there is ErrForbidden, which
// falls through to drafts in a branch (loadSchema), as an absent one does.
func (t *tx) loadSchemaIn(ref schema.Ref, sc *schemaCtx) (any, error) {
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
	// A namespace that opens its schemas with schemaReads lets writes to a
	// listed namespace resolve them without read (§6.1); only schema
	// documents, checked once loaded.
	var readable bool
	if sc.target != nil && n.id == sc.target.id {
		readable = t.canRead(n, t.config(n.configSeq), sc.a, ref.Name)
	} else {
		readable = t.credsRead(n, ref.Name, sc.creds)
	}
	if readable {
		return t.schemaRevIn(n, ref)
	}
	if sc.target == nil || !t.schemaReadsServe(n, sc.target) {
		return nil, schema.ErrForbidden
	}
	d, err := t.schemaRevIn(n, ref)
	if err != nil {
		return nil, err
	}
	if !schema.IsSchemaDoc(d) {
		return nil, schema.ErrForbidden
	}
	return d, nil
}

// schemaRevIn loads revision ref.Rev of resource ref.Name in n, a
// namespace that isn't a branch: ErrUnavailable if unknown, purged,
// pruned or a tombstone.
func (t *tx) schemaRevIn(n *nsRow, ref schema.Ref) (any, error) {
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
	// A revision with its patch set is the document its id determines:
	// parsed once, kept apart from the document cache, which a large write
	// fills with its own (docBytesAt).
	if row.patches.Valid {
		if d, ok := t.e.schemaDocs.get(row.id); ok {
			return d, nil
		}
	}
	d, err := t.docAt(row)
	if err != nil {
		return nil, schema.ErrUnavailable
	}
	if row.patches.Valid {
		t.e.schemaDocs.put(row.id, d)
	}
	return d, nil
}

// rulesRead reports whether a rule deciding a's verb in cfg may read the
// change envelope's member m (§6.4.1): one of the namespace's rules, or of
// the grant's key, block and role rules.
func rulesRead(cfg *Config, a *actor, verb, m string) bool {
	reads := func(r *rules.Rule) bool {
		refs := r.Refs()
		return refs[m] || refs["*"]
	}
	for _, r := range cfg.Rules {
		if reads(r) {
			return true
		}
	}
	if a == nil || a.verified == nil {
		return false
	}
	v := a.verified
	lists := [][]any{v.KeyRules, v.BlockRules}
	if v.HasRoles() {
		_, roles := v.Allows(verb)
		for _, role := range roles {
			lists = append(lists, v.RoleRules(role))
		}
	}
	for _, l := range lists {
		for _, rv := range l {
			if r, err := compileCached(rv); err != nil || reads(r) {
				return true
			}
		}
	}
	return false
}

// stepEnvelope builds the change envelope of §6.4.1 for one step. Its
// patches are a copy of the step's, parsed again only if a rule reads them
// (withPatches); otherwise the member is absent, which no rule sees.
func (t *tx) stepEnvelope(s *itemState, step *stepState, a *actor, withPatches bool) map[string]any {
	env := t.basicEnvelope(step.action, s.Resource, a)
	w := make([]any, len(step.writes))
	for i, x := range step.writes {
		w[i] = x
	}
	env["writes"] = w
	if step.del {
		// The document being deleted: the resource's last live document as
		// this namespace sees it (read through in a branch), so rules can
		// decide deletes by content, e.g. by an owner field. Null at E3,
		// where the server can't see it, so a rule reading doc fails there.
		env["doc"] = step.doc
		env["patches"] = []any{}
	} else {
		env["doc"] = step.doc
		if withPatches {
			env["patches"] = jsonv.MustParse(step.canon)
		}
	}
	return env
}

// checkSource validates a batch's source at step 4 (§7.5). It returns the
// source as recorded and, for a local source the caller may read
// unrestricted (with the grant in Source-Authorization, if given), whose
// source.at it checked, the source that makes blobs available (§7.8). Any
// other caller's local source is recorded unchecked and makes no blobs
// available, so the check reveals nothing about a namespace it can't read.
func (t *tx) checkSource(req Request, v any) (any, *batchSource, *Error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, invalid("source must be an object")
	}
	for k := range m {
		switch k {
		case "origin", "ns", "at", "bundle", "ids":
		default:
			return nil, nil, invalid("unknown source member " + k)
		}
	}
	ns, _ := m["ns"].(string)
	at, _ := m["at"].(string)
	if !ValidNSName(ns) || at == "" {
		return nil, nil, invalid("source needs ns and at")
	}
	if o, has := m["origin"]; has {
		if o == t.e.opt.Origin {
			return nil, nil, invalid("source origin is this deployment")
		}
		return m, nil, nil // another deployment's blobs are uploaded (§G.3)
	}
	sn := t.nsByName(ns)
	if sn == nil || sn.purged || !t.sourceUnrestricted(sn, req) {
		return m, nil, nil
	}
	id, err := ids.Parse(at)
	if err != nil {
		return nil, nil, apiErr(422, "source", "message", "source.at is not in the chain of source.ns")
	}
	seq, ok := t.nsLogSeq(sn.id, id)
	if !ok {
		return nil, nil, apiErr(422, "source", "message", "source.at is not in the chain of source.ns")
	}
	return m, &batchSource{n: sn, atSeq: seq}, nil
}

// actorID is authorID for an actor. Under a grant it also remembers the
// grant, whose id the namespace entries this transaction writes for that
// author on the request record (§5, §7.4): merge tools and the janitor
// match its root sub and kid against merge.authors (§F.3, §F.6). With
// authentication disabled there is no grant: the entries record
// "grant": null instead (§1, tx.noAuth), which those checks match on the
// author alone while the deployment runs disabled.
func (t *tx) actorID(a *actor) int64 {
	id := t.authorID(a.id())
	if a.grant != nil && id >= 0 {
		if t.grants == nil {
			t.grants = map[int64]*grant.Grant{}
		}
		t.grants[id] = a.grant
	}
	if a.noAuth && id >= 0 {
		if t.unauth == nil {
			t.unauth = map[int64]bool{}
		}
		t.unauth[id] = true
	}
	return id
}

// entryGrant is the grant a namespace entry by author, written by a,
// records (§7.4), or nil. Entries appended together (appendNSMany) take it
// per entry, since one author may write under several grants.
func entryGrant(a *actor, author int64) *grant.Grant {
	if a.grant == nil || author < 0 {
		return nil
	}
	return a.grant
}

// storeGrant records the non-bearer form of a grant (§C.3), encrypted at
// rest if encrypt is set (§E.1), and returns its id (nil for no grant). A
// grant is stored once per transaction, and again only to encrypt it.
func (t *tx) storeGrant(g *grant.Grant, encrypt bool) []byte {
	if g == nil {
		return nil
	}
	id := g.ID()
	if enc, ok := t.storedGrants[id]; !ok || (encrypt && !enc) {
		var root *grantRoot
		if len(g.Blocks) > 0 {
			root = &grantRoot{sub: g.Blocks[0].Sub, kid: g.Blocks[0].Kid}
		}
		t.storeGrantBlocks(id[:], g.Stored(), root, encrypt)
		if t.storedGrants == nil {
			t.storedGrants = map[ids.ID]bool{}
		}
		t.storedGrants[id] = encrypt
	}
	return id[:]
}

// The statements of step 7 (bulk.go).
var (
	insResources = bulkInsert("resources", "ns bigint, name text", "RETURNING res, name")
	insRevisions = bulkInsert("revisions", "res bigint, id bytea, parent_seq bigint, first smallint, kind smallint, patches bytea, author bigint, "+
		"via text, grant_id bytea, signature text, schema_ref text, created bigint, gesture text, undoes text", "RETURNING seq, res")
	insRevEpochs = bulkInsert("rev_epochs", "seq bigint, epoch bigint", "")
	insSnapshots = bulkInsert("snapshots", "seq bigint, res bigint, doc bytea", "ON CONFLICT (seq) DO UPDATE SET res = excluded.res, doc = excluded.doc")
	upsertHeads  = bulkInsert("heads", "res bigint, seq bigint, doc bytea", "ON CONFLICT (res) DO UPDATE SET seq = excluded.seq, doc = excluded.doc")
	delHeads     = bulkStmt{pg: `DELETE FROM heads WHERE res = ANY($1::bigint[])`, lite: `DELETE FROM heads WHERE res = ?`, types: []string{"bigint"}}
	openBlobRefs = bulkStmt{pg: `SELECT res, bid FROM blob_refs WHERE res = ANY($1::bigint[]) AND to_seq IS NULL`,
		lite: `SELECT res, bid FROM blob_refs WHERE res = ? AND to_seq IS NULL`, types: []string{"bigint"}}
	// moveHeads moves each resource's head from the one its precondition
	// matched (old, 0 for none), or not at all (insertItems), with its
	// snapshot counts.
	moveHeads = bulkStmt{
		pg: `UPDATE resources SET head_seq = v.h, state = v.st, snap_revs = v.sr, snap_bytes = v.sb
			FROM unnest($1::bigint[], $2::smallint[], $3::bigint[], $4::bigint[], $5::bigint[], $6::bigint[]) AS v(h, st, sr, sb, res, old)
			WHERE resources.res = v.res AND COALESCE(resources.head_seq, 0) = v.old`,
		lite:  `UPDATE resources SET head_seq = ?, state = ?, snap_revs = ?, snap_bytes = ? WHERE res = ? AND COALESCE(head_seq, 0) = ?`,
		types: []string{"bigint", "smallint", "bigint", "bigint", "bigint", "bigint"},
	}
)

// insertItems is step 7 for a write's items: their resources' rows,
// revisions, attached blobs, snapshots and heads, in a few statements
// whatever the number of items (bulk.go). It returns each item's resource
// row and the seq of its final entry, in the items' order.
//
// Rows go in resource order: two batches writing some of the same
// resources at once (Postgres, pglock.go) then wait for each other's rows
// in that order, never in a cycle.
func (t *tx) insertItems(n *nsRow, st []*itemState, a *actor, author int64, grantID []byte) []histRow {
	by := writtenBy(a, author, grantID)
	ws := make([]writer, len(st))
	for i := range ws {
		ws[i] = by
	}
	return t.insertItemsBy(n, st, ws)
}

// writer is who wrote an item, as its revisions record it.
type writer struct {
	author  int64
	via     any // the principal's delegation chain, canonical JSON, or nil
	grantID []byte
}

func writtenBy(a *actor, author int64, grantID []byte) writer {
	w := writer{author: author, grantID: grantID}
	if len(a.principal.Via) > 0 {
		w.via = string(jsonv.Canonical(jsonv.FromGo(a.principal.Via)))
	}
	return w
}

// insertItemsBy is insertItems for items of several writes of one
// namespace, each item written by ws[i] (group commit, groupcommit.go).
// The items' resources must be distinct.
func (t *tx) insertItemsBy(n *nsRow, st []*itemState, ws []writer) []histRow {
	cfg := t.config(n.configSeq)
	level := t.nsLevel(n)
	type item struct {
		*itemState
		writer
		own     *resRow // the row the precondition was checked against
		res     int64
		hasRows bool
		e2e     bool // e2e content has no documents on the server (§E.3)
		open    map[ids.ID]bool
		// The chain as inserted so far: the last entry, the last live
		// revision and its step.
		last, lastLiveSeq int64
		lastLive          *stepState
		// Revisions and their patch sets' bytes since the last snapshot.
		snapRevs, snapBytes int64
	}
	items := make([]*item, len(st))
	for i, s := range st {
		items[i] = &item{itemState: s, writer: ws[i], own: s.view.own, e2e: cfg.level == levelE2E && s.Resource != KeyringName}
	}
	sorted := append([]*item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Resource < sorted[j].Resource })

	// Resource rows for the items that have none.
	var newRows [][]any
	byName := map[string]*item{}
	for _, it := range sorted {
		if it.own == nil {
			newRows = append(newRows, []any{n.id, it.Resource})
			byName[it.Resource] = it
		}
	}
	t.bulkQuery(insResources, newRows, func(rs *sql.Rows) {
		var res int64
		var name string
		t.must(rs.Scan(&res, &name))
		byName[name].res = res
	})
	var existing [][]any
	byRes := map[int64]*item{}
	for _, it := range sorted {
		if it.own != nil {
			it.res = it.own.id
			// A resource with a head has revisions (a purge keeps their
			// rows); one without may have none yet (a pending blob's).
			it.hasRows = it.own.headSeq.Valid
			if !it.hasRows {
				t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ?)`, it.res).Scan(&it.hasRows))
			}
			existing = append(existing, []any{it.res})
			it.snapRevs, it.snapBytes = t.snapCounts(it.own)
		}
		byRes[it.res] = it
		it.open = map[ids.ID]bool{}
		if _, ok := t.resLevels[it.res]; !ok {
			if t.resLevels == nil {
				t.resLevels = map[int64]int{}
			}
			t.resLevels[it.res] = level
		}
		if it.parent != nil {
			it.last = it.parent.seq
			it.lastLiveSeq = t.lastLive(it.parent).seq
		}
	}
	// The blobs the existing resources' heads reference (blob_refs still
	// open), which a new revision ends or keeps (attachStep).
	t.bulkQuery(openBlobRefs, existing, func(rs *sql.Rows) {
		var res int64
		var bid []byte
		t.must(rs.Scan(&res, &bid))
		byRes[res].open[ids.FromBytes(bid)] = true
	})

	// The revisions, one statement per step index: a step's parent is the
	// step before it.
	var epochs, snaps [][]any
	for k := 0; ; k++ {
		var rows [][]any
		var stepItems []*item
		for _, it := range sorted {
			if k >= len(it.steps) {
				continue
			}
			step := it.steps[k]
			first := 0
			if !it.hasRows && k == 0 {
				first = 1
			}
			kind := kindRev
			var patches, typed, sig any
			if step.del {
				kind = kindTombstone
			} else {
				patches = t.putPatches(it.res, step.id, step.canon, step.packed)
				if step.typed != "" {
					typed = step.typed
				}
			}
			// Each step carries its own signature (§7.5, §C.3.1).
			if s := it.Steps[k].Signature; s != "" {
				sig = s
			}
			var parent any
			if it.last != 0 {
				parent = it.last
			}
			// The step's gestures (§7.2), as the request resolved them.
			gesture, undoes := nullStr(it.Steps[k].Gesture), nullStr(it.Steps[k].Undoes)
			rows = append(rows, []any{it.res, step.id[:], parent, first, kind, patches, it.author, it.via, it.grantID, sig, typed, t.now.UnixMilli(), gesture, undoes})
			stepItems = append(stepItems, it)
		}
		if len(rows) == 0 {
			break
		}
		t.bulkQuery(insRevisions, rows, func(rs *sql.Rows) {
			var seq, res int64
			t.must(rs.Scan(&seq, &res))
			byRes[res].last = seq
		})
		for i, it := range stepItems {
			step, row, seq := it.steps[k], rows[i], it.last
			t.inserted(revRow{seq: seq, res: it.res, id: step.id, parentSeq: anyInt(row[2]), first: row[3] == 1, kind: row[4].(int),
				patches: anyStr(row[5]), author: it.author, via: anyStr(it.via), grantID: it.grantID, signature: anyStr(row[9]), created: row[11].(int64),
				gesture: anyStr(row[12]), undoes: anyStr(row[13])})
			if !step.del {
				// The blobs the document references are attached with it
				// (§7.8, step 7); a sealed step's are those its op declares,
				// or for a restore with [] the last live document's (§E.3.1).
				t.attachStepFrom(it.res, step, seq, it.open)
				it.open = map[ids.ID]bool{}
				for bid := range step.blobs {
					it.open[bid] = true
				}
			}
			if cfg.level == levelSealed {
				// The epoch that seals this entry forever (§E.2.1).
				epochs = append(epochs, []any{seq, cfg.Epoch})
			}
			if step.del {
				continue
			}
			it.lastLive, it.lastLiveSeq = step, seq
			if it.e2e {
				continue
			}
			canon := step.docCanon
			if canon == nil {
				canon = jsonv.Canonical(step.doc)
			}
			t.cacheDoc(step.id, canon)
			if step.parentID == nil && genesisDocCanon(step) != nil {
				// A genesis that adds the whole document holds it as a
				// snapshot would (docBytesAt reads it as one): the count
				// starts after it, and a copy would double a create's
				// writes.
				it.snapRevs, it.snapBytes = 0, 0
				continue
			}
			// An intermediate snapshot once enough patch sets have
			// accumulated since the last one (D.4), so no read folds more:
			// their bytes as stored, a compressed one's decompressed.
			it.snapRevs++
			if step.packed != nil {
				it.snapBytes += int64(len(step.canon))
			} else {
				it.snapBytes += int64(storedLen(row[5]))
			}
			if it.snapRevs >= int64(t.e.opt.SnapshotEveryRevisions) || it.snapBytes >= int64(t.e.opt.SnapshotEveryBytes) {
				snaps = append(snaps, []any{seq, it.res, t.putDoc("snapshots", it.res, seq, canon)})
				it.snapRevs, it.snapBytes = 0, 0
			}
		}
	}
	t.bulkExec(insRevEpochs, epochs)
	t.bulkExec(insSnapshots, snaps)

	// The heads move, each from the one its precondition matched, or not
	// at all: on Postgres a writer of another resource holds the
	// namespace's lock too, and a concurrent writer of this one that
	// inserted first fails here, if not on the chain's unique constraints
	// (pglock.go).
	var moves, heads, dropHeads [][]any
	for _, it := range sorted {
		final := it.steps[len(it.steps)-1]
		state := stateLive
		if final.del {
			state = stateTombstoned
		}
		var old int64
		if it.own != nil {
			old = it.own.headSeq.Int64
		}
		moves = append(moves, []any{it.last, state, it.snapRevs, it.snapBytes, it.res, old})
		// heads caches the last live document, which reads and restores
		// need, but only for small documents (D.4): rewriting a large one on
		// every save costs its whole size each time. Larger ones fold from
		// snapshots. Nor for a whole-document genesis, which is its own
		// snapshot (docBytesAt): a create stores its document once.
		var doc []byte
		switch {
		case it.e2e:
		case it.lastLive != nil:
			doc = it.lastLive.docCanon
			if doc == nil {
				doc = jsonv.Canonical(it.lastLive.doc)
			}
		default:
			doc = jsonv.Canonical(final.doc)
		}
		genesis := it.lastLive != nil && it.lastLive.parentID == nil && genesisDocCanon(it.lastLive) != nil
		if !it.e2e && !genesis && len(doc) <= t.e.opt.HeadSnapshotMax {
			heads = append(heads, []any{it.res, it.lastLiveSeq, t.putDoc("heads", it.res, it.lastLiveSeq, doc)})
		} else if it.own != nil {
			dropHeads = append(dropHeads, []any{it.res})
		}
	}
	if t.bulkExec(moveHeads, moves) != int64(len(moves)) {
		panic(errChainRace)
	}
	t.bulkExec(upsertHeads, heads)
	t.bulkExec(delHeads, dropHeads)

	out := make([]histRow, len(items))
	for i, it := range items {
		out[i] = histRow{it.res, it.last}
	}
	return out
}

// countSinceSnapshot counts res's revisions since its last snapshot, and
// the bytes of their stored patch sets, a compressed one's decompressed
// (as step 7 counts them).
func (t *tx) countSinceSnapshot(res int64) (revs, size int64) {
	t.must(t.QueryRow(`SELECT COUNT(*), COALESCE(SUM(octet_length(patches)), 0) FROM revisions
		WHERE res = ? AND kind = 0 AND seq > (SELECT COALESCE(MAX(seq), 0) FROM snapshots WHERE res = ?)`, res, res).Scan(&revs, &size))
	return revs, size + t.packedExtra(res)
}

// snapCounts returns a resource row's snapshot counts, counted from its
// revisions if the row doesn't have them: a row from before the columns,
// or whose revisions another path inserted (maybeSnapshot). Snapshots
// written outside step 7 (pruning, restoring an archive) aren't counted
// from: the next one is then only due earlier.
func (t *tx) snapCounts(r *resRow) (revs, size int64) {
	if r.snapRevs.Valid && r.snapBytes.Valid {
		return r.snapRevs.Int64, r.snapBytes.Int64
	}
	return t.countSinceSnapshot(r.id)
}

// storedLen is the length of a stored patch set (putPatches).
func storedLen(v any) int {
	switch v := v.(type) {
	case string:
		return len(v)
	case []byte:
		return len(v)
	}
	return 0
}

// maybeSnapshot writes an intermediate snapshot at seq, res's latest
// revision, once enough patch sets have accumulated since its last one
// (D.4), counted from its revisions; the paths that insert revisions
// outside step 7 use it, and leave the row's counts unknown.
func (t *tx) maybeSnapshot(res, seq int64, doc []byte) {
	revs, size := t.countSinceSnapshot(res)
	if revs >= int64(t.e.opt.SnapshotEveryRevisions) || size >= int64(t.e.opt.SnapshotEveryBytes) {
		t.bulkExec(insSnapshots, [][]any{{seq, res, t.putDoc("snapshots", res, seq, doc)}})
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
