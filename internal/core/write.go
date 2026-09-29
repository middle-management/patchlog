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

// ItemResult lists the ids an item produced.
type ItemResult struct {
	Resource string   `json:"resource"`
	IDs      []string `json:"ids"`
}

type stepState struct {
	del      bool
	raw      any
	canon    []byte
	action   string
	parentID *ids.ID
	id       ids.ID
	doc      any // resulting (for a delete: the last live) document
	writes   []string
	typed    string // $schema of the resulting document
}

type itemState struct {
	Item
	index  int
	view   *view
	parent *revRow // the head the precondition matched; nil for a create
	steps  []*stepState
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
	var res *WriteResult
	err := e.update(ctx, func(t *tx) error {
		r, err := t.writeItems(req, []Item{item}, nil, nil, false, false)
		res = r
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Batch performs an atomic batch (§7.5).
func (e *Engine) Batch(ctx context.Context, req Request, items []Item, cfg *ConfigChange, source any, dryRun bool) (*WriteResult, error) {
	var res *WriteResult
	run := e.update
	if dryRun {
		run = e.read
	}
	err := run(ctx, func(t *tx) error {
		r, err := t.writeItems(req, items, cfg, source, true, dryRun)
		res = r
		if err != nil {
			return err
		}
		return nil
	})
	return res, err
}

// asErr converts an *Error into error without the typed-nil trap.
func asErr(e *Error) error {
	if e == nil {
		return nil
	}
	return e
}

func (t *tx) writeItems(req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun bool) (*WriteResult, error) {
	n := t.nsByName(req.NS)
	if n == nil {
		return nil, notFound()
	}
	if n.purged {
		return nil, gone()
	}
	cur := t.config(n.configSeq)
	lim := cur.Limits
	if isBatch {
		if len(items) > lim.ItemsPerBatch {
			return nil, limitErr(413, fmt.Sprintf("more than %d items", lim.ItemsPerBatch))
		}
		size := 0
		for _, it := range items {
			for _, s := range it.Steps {
				if !s.Delete {
					size += len(jsonv.Canonical(s.Patches))
				}
			}
		}
		if size > lim.BatchSize {
			return nil, limitErr(413, "batch too large")
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
		}
		if len(items) == 0 && cc == nil {
			return nil, badInput("empty batch")
		}
	}

	a, aerr := t.authenticate(n.name, n, cur, req.Cred, nil)
	if aerr != nil {
		return nil, aerr
	}

	// The optional config change runs steps 1–6 first (§7.5).
	st := make([]*itemState, len(items))
	for i, it := range items {
		st[i] = &itemState{Item: it, index: i}
	}
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
			for j := range s.Steps {
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
						return r, nil
					}
				}
			}
			return nil, err
		}
		cplan = p
		cfg = p.cfg
		if len(items) > 0 {
			a, aerr = t.authenticate(n.name, n, cfg, req.Cred, nil)
			if aerr != nil {
				return nil, aerr
			}
		}
	}

	// Step 1: authorisation.
	fs := authorizeItems(a)
	if len(fs) > 0 {
		return nil, fail(fs)
	}
	if len(items) > 0 {
		names := make([]string, len(items))
		for i, it := range items {
			names[i] = it.Resource
		}
		if err := t.rateLimit(n, cfg, a, names, len(items)); err != nil {
			return nil, err
		}
	}

	// Step 2: precondition — idempotent retry, frozen, the precondition.
	if r := t.replay(n, a, st, cplan, isBatch); r != nil {
		return r, nil
	}
	if cur.Frozen && len(items) > 0 {
		e := apiErr(409, "frozen")
		if cur.Successor != "" {
			e.Body["successor"] = cur.Successor
		}
		return nil, e
	}
	for _, s := range st {
		if err := t.precondition(n, s); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		return nil, fail(fs)
	}

	// Step 3: apply.
	for _, s := range st {
		if err := t.applySteps(s); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		return nil, fail(fs)
	}

	// Step 4: limits.
	for _, s := range st {
		if err := checkLimits(cfg.Limits, s); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	if len(fs) > 0 {
		return nil, fail(fs)
	}

	// Step 5: schema. Items may reference schema revisions created by
	// earlier items (§6.1).
	pending := map[string]any{}
	for _, s := range st {
		for _, step := range s.steps {
			if step.del {
				continue
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
		return nil, fail(fs)
	}

	// Step 6: rules.
	for _, s := range st {
		for _, step := range s.steps {
			if err := t.checkRules(cfg, a, t.stepEnvelope(s, step, a), false); err != nil {
				fs = append(fs, itemErr{s.index, err})
				break
			}
		}
	}
	if len(fs) > 0 {
		return nil, fail(fs)
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
			return nil, err
		}
	}
	if dryRun {
		result.Status = 200
		return result, nil
	}

	// Step 7: insert atomically with the namespace entry.
	author := t.authorID(a.id())
	grantID := t.storeGrant(a)
	configSeq := n.configSeq
	var entries []any
	if cplan != nil {
		configSeq = t.insertConfig(n, cplan, author)
		entries = append(entries, map[string]any{"kind": "config", "target": cplan.id.String()})
		result.ConfigID = cplan.id.String()
	}
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
	return result, nil
}

// staticVerb is the verb of step j known before looking at state. The
// first patch step of an If-Match item is authorised as append; whether it
// is a restore is checked at step 6 (§6.2).
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
	author := t.authorID(a.id())
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
	defer rows.Close()
	for rows.Next() {
		var id []byte
		var body string
		t.must(rows.Scan(&id, &body))
		b := jsonv.MustParse([]byte(body)).(map[string]any)
		if string(jsonv.Canonical(b["entries"])) == want {
			r := &WriteResult{Status: 200, Replayed: true, NSID: ids.FromBytes(id).String(), Items: items}
			if cp != nil {
				r.ConfigID = cp.expected.String()
			}
			return r
		}
	}
	return nil
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
				return apiErr(410, "pruned", "horizon", t.horizonID(pe.res))
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
		if len(step.canon) > l.PatchSetSize {
			return limitErr(413, "patch set too large")
		}
		if ops, ok := step.raw.([]any); ok && len(ops) > l.OpsPerSet {
			return limitErr(422, "too many operations")
		}
		if len(jsonv.Canonical(step.doc)) > l.DocumentSize {
			return limitErr(413, "document too large")
		}
		if jsonv.Depth(step.doc) > l.NestingDepth {
			return limitErr(422, "document nested too deeply")
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
	n := t.nsByName(ref.NS)
	if n == nil || n.purged {
		return nil, schema.ErrUnavailable
	}
	if n.isBranch() {
		return nil, schema.ErrBranch
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

// storeGrant records the non-bearer form of the actor's grant (§C.3).
func (t *tx) storeGrant(a *actor) []byte {
	if a.grant == nil {
		return nil
	}
	id := a.grant.ID()
	_, err := t.Exec(`INSERT OR IGNORE INTO grants (id, blocks) VALUES (?, ?)`, id[:], string(a.grant.Stored()))
	t.must(err)
	return id[:]
}

// insertItem is step 7 for one item. It returns the resource row and the
// seq of its final entry.
func (t *tx) insertItem(n *nsRow, s *itemState, a *actor, author int64, grantID []byte, signature string) (int64, int64) {
	own := t.resource(n.id, s.Resource)
	var res int64
	if own == nil {
		r, err := t.Exec(`INSERT INTO resources (ns, name) VALUES (?, ?)`, n.id, s.Resource)
		t.must(err)
		res, _ = r.LastInsertId()
	} else {
		res = own.id
	}
	var hasRows bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ?)`, res).Scan(&hasRows))
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
			patches = string(step.canon)
			if step.typed != "" {
				typed = step.typed
			}
		}
		if i == 0 && signature != "" {
			sig = signature
		}
		r, err := t.Exec(`INSERT INTO revisions (res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			res, step.id[:], parentSeq, first, kind, patches, author, via, grantID, sig, typed, t.now.UnixMilli())
		if err != nil {
			panic(fmt.Errorf("inserting revision: %w", err))
		}
		last, _ = r.LastInsertId()
		parentSeq = last
		if !step.del {
			lastLive = step
			lastLiveSeq = last
			t.e.docs.put(step.id, jsonv.Canonical(step.doc))
		}
	}
	final := s.steps[len(s.steps)-1]
	state := stateLive
	if final.del {
		state = stateTombstoned
	}
	_, err := t.Exec(`UPDATE resources SET head_seq = ?, state = ? WHERE res = ?`, last, state, res)
	t.must(err)
	// heads holds the last live document, which a restore needs.
	var doc []byte
	if lastLive != nil {
		doc = jsonv.Canonical(lastLive.doc)
	} else {
		doc = jsonv.Canonical(final.doc)
	}
	_, err = t.Exec(`INSERT INTO heads (res, seq, doc) VALUES (?,?,?) ON CONFLICT (res) DO UPDATE SET seq = excluded.seq, doc = excluded.doc`, res, lastLiveSeq, string(doc))
	t.must(err)
	return res, last
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
