package client

// Undo and redo (§11.2).
//
// Gestures (§7.2) group the revisions one user action produced, across
// saves and resources of a namespace. This file is the client procedure
// that undoes one from the log, so undo works after a reload, from another
// device and from a history view:
//
//   - Finding the gesture. GET /ns/{ns}/gestures/{gesture} where it is
//     offered (§7.4). Otherwise (sealed and e2e namespaces, deployments
//     without the endpoint, grants without unrestricted read) the namespace
//     log is scanned for entries carrying the gesture by the same author.
//     The scan covers the whole log, page by page, or the part after
//     UndoSince. Either way each resource's log is then read from the
//     latest point known to precede the gesture there (the resource's
//     previous head in the scanned namespace log, its head as of UndoSince,
//     else genesis), or from its pruning horizon when that is later.
//   - The inverse. For each resource, the gesture's own entries, newest
//     first, become steps of one batch item (§7.5): a revision the patch
//     set that sets the paths it wrote (§6.4.1, widened to the whole array
//     when the last segment addresses an array element, as merges do,
//     §F.3) back to its parent's values; a revision made only of moves
//     whose ends are unchanged since is inverted by moves back instead; a
//     tombstone a restore with []; a restore the inverse of its patches,
//     then "delete"; a genesis "delete". Consecutive patch sets are joined
//     and split again to stay within opsPerSet and patchSetSize (§6.6).
//     $nonce is never restored: every patch set gets a fresh one in sealed
//     namespaces, in those that require nonces or whose document the grant
//     can't read, so it doesn't know the setting, a tombstone's restore
//     then being a lone fresh $nonce, and where the current document has
//     one (§C.7).
//   - The guard. The log after the gesture's last entry in each resource is
//     compared with the paths the gesture wrote: an overlapping write, a
//     delete, a restore or an undo of the gesture is a conflict
//     (ConflictError). The batch names the heads that were checked in
//     ifMatch; a 412 re-plans and retries (UndoRetries).
//   - Writing. One batch for every resource, with a fresh Gesture and
//     Undoes naming the gesture. A pruned revision (410), a missing blob
//     (422 blob) or a document that no longer validates (422 invalid,
//     schema_unavailable) is an ImpossibleError, not a conflict.
//   - E3 (UndoE2E). Documents and logs are folded client-side through the
//     E2E view, the guard compares decrypted entries, every resulting
//     document is validated before sealing, and each step is sealed bound
//     to the id the step before produces.
//
// Redo undoes the undo. UndoStack rebuilds an author's stack from the log.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// ErrGestureNotFound reports a gesture with no revisions in the namespace
// (by the author, if one is given), in the range searched.
var ErrGestureNotFound = errors.New("client: the gesture has no revisions here")

// ErrNothingToUndo reports a gesture whose inverse writes nothing: every
// resource it touched is already as it was before, and tombstoned.
var ErrNothingToUndo = errors.New("client: the gesture's inverse writes nothing")

// ErrNotUndone reports a Redo of a gesture nobody undid.
var ErrNotUndone = errors.New("client: the gesture isn't undone")

// UndoOption configures PlanUndo, Undo, Redo and UndoStack.
type UndoOption func(*undoConfig)

type undoConfig struct {
	author   string
	since    string
	scanLog  bool
	e2e      *E2E
	retries  int
	gesture  string
	maxOps   int
	maxBytes int
}

// UndoAuthor names the author whose gesture it is: only that author's
// revisions with the gesture id are undone, since the id is the writer's
// own label (§7.2). By default it is the author of the gesture's first
// revision found. For UndoStack it is the author argument.
func UndoAuthor(author string) UndoOption { return func(c *undoConfig) { c.author = author } }

// UndoSince limits the search to the namespace log after nsID (exclusive):
// the namespace log scan, and the point each resource's log is read from.
// A gesture with revisions before it is undone only in part, and Undoes
// naming a gesture before it counts as naming a missing one. By default
// the whole log is searched, page by page.
func UndoSince(nsID string) UndoOption { return func(c *undoConfig) { c.since = nsID } }

// UndoScanLog skips GET /ns/{ns}/gestures/{gesture} and scans the
// namespace log, as in sealed namespaces.
func UndoScanLog() UndoOption { return func(c *undoConfig) { c.scanLog = true } }

// UndoE2E undoes in an e2e namespace (E3) through x: logs are opened and
// folded client-side and the inverse is sealed under the namespace's keys.
// Without it an e2e namespace is refused.
func UndoE2E(x *E2E) UndoOption { return func(c *undoConfig) { c.e2e = x } }

// UndoRetries is how often a batch that fails with 412 is re-planned and
// sent again (default 3).
func UndoRetries(n int) UndoOption { return func(c *undoConfig) { c.retries = n } }

// UndoGesture is the gesture id the undo is written with (default a fresh
// one, NewGesture).
func UndoGesture(id string) UndoOption { return func(c *undoConfig) { c.gesture = id } }

// UndoLimits overrides the namespace's opsPerSet and patchSetSize (§6.6)
// when splitting the inverse into steps; 0 keeps the namespace's value.
func UndoLimits(opsPerSet, patchSetSize int) UndoOption {
	return func(c *undoConfig) { c.maxOps, c.maxBytes = opsPerSet, patchSetSize }
}

func undoOptions(opts []UndoOption) *undoConfig {
	cfg := &undoConfig{retries: 3}
	for _, o := range opts {
		o(cfg)
	}
	return cfg
}

// UndoConflict is a later entry that stops an undo (§11.2 The guard).
type UndoConflict struct {
	Resource string
	// Entry is the later entry's id, Author and Gesture its author and
	// gesture ("" if none).
	Entry, Author, Gesture string
	// Kind is "overlap" (it writes paths the gesture wrote), "deleted",
	// "restored", "undone" (it undoes the gesture already), "unreadable"
	// (an e2e entry that doesn't open) or "apply" (the inverse doesn't
	// apply to the current document).
	Kind string
	// Paths are the overlapping paths, the gesture's and the entry's.
	Paths []string
}

func (c UndoConflict) String() string {
	s := fmt.Sprintf("%s: %s", c.Resource, c.Kind)
	if c.Entry != "" {
		s += " by " + c.Entry
		if c.Author != "" {
			s += " (" + c.Author + ")"
		}
	}
	if len(c.Paths) > 0 {
		s += " at " + strings.Join(c.Paths, ", ")
	}
	return s
}

// ConflictError is an undo stopped by later entries: a person decides, as
// for a merge (§11.2).
type ConflictError struct {
	NS, Gesture string
	Conflicts   []UndoConflict
}

func (e *ConflictError) Error() string {
	parts := make([]string, len(e.Conflicts))
	for i, c := range e.Conflicts {
		parts[i] = c.String()
	}
	return fmt.Sprintf("client: undo of %s in %s conflicts: %s", e.Gesture, e.NS, strings.Join(parts, "; "))
}

// ImpossibleError is an undo that can't be done (§11.2 When undo is
// impossible), as opposed to one that conflicts.
type ImpossibleError struct {
	NS, Gesture, Resource string
	// Reason is "pruned" (a revision the inverse needs lies below a
	// pruning horizon), "blob" (a blob the earlier document references is
	// gone), "invalid" (the earlier values no longer validate against the
	// document's $schema), or "purged".
	Reason string
	Err    error
}

func (e *ImpossibleError) Error() string {
	s := fmt.Sprintf("client: undo of %s in %s is impossible: %s", e.Gesture, e.NS, e.Reason)
	if e.Resource != "" {
		s += " (" + e.Resource + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *ImpossibleError) Unwrap() error { return e.Err }

// IsUndoConflict reports a ConflictError.
func IsUndoConflict(err error) bool {
	var ce *ConflictError
	return errors.As(err, &ce)
}

// IsUndoImpossible reports an ImpossibleError.
func IsUndoImpossible(err error) bool {
	var ie *ImpossibleError
	return errors.As(err, &ie)
}

// UndoResource is the inverse planned for one resource.
type UndoResource struct {
	Resource string
	// Head is the head the plan was checked against: the item's ifMatch.
	Head  string
	State State // Live or Tombstoned, at Head
	// Entries are the gesture's own entries in the resource, oldest first.
	Entries []string
	// Writes are the paths the gesture wrote, widened for arrays.
	Writes []string
	// Steps is the inverse, in plaintext (the batch carries them sealed in
	// an e2e namespace).
	Steps []Step
	// Doc is the document after the inverse; Deleted when it ends
	// tombstoned (Doc is then the last live document).
	Doc     any
	Deleted bool
}

// UndoPlan is the inverse of a gesture, checked but not written (§11.2).
type UndoPlan struct {
	NS string
	// Gesture is the gesture undone, Author its author.
	Gesture, Author string
	// Source says how the gesture was found: "gestures" (the endpoint) or
	// "log" (the namespace log scan).
	Source    string
	Resources []UndoResource
	// Conflicts, if any, stop the undo (Err).
	Conflicts []UndoConflict
	// Batch is what Undo submits: one item per resource, with ifMatch on
	// the checked heads, Undoes set and Gesture the undo's own id. With
	// conflicts it holds only the resources without any, and isn't sent.
	Batch BatchRequest
}

// Err is a *ConflictError when the plan has conflicts, else nil.
func (p *UndoPlan) Err() error {
	if len(p.Conflicts) == 0 {
		return nil
	}
	return &ConflictError{NS: p.NS, Gesture: p.Gesture, Conflicts: p.Conflicts}
}

// UndoResult is a written undo.
type UndoResult struct {
	Plan  *UndoPlan
	Batch *BatchResult
	// Gesture is the undo's own gesture id: undoing it redoes.
	Gesture string
	// Attempts counts the plans made (more than one after a 412).
	Attempts int
}

// Undo undoes gesture in ns (§11.2): it plans the inverse, stops on
// conflicts (*ConflictError), writes it as one batch with a fresh Gesture
// and Undoes: gesture, and re-plans after a 412 up to UndoRetries times.
// An undo that can't be done is an *ImpossibleError.
func (c *Client) Undo(ctx context.Context, ns, gesture string, opts ...UndoOption) (*UndoResult, error) {
	cfg := undoOptions(opts)
	if cfg.gesture == "" {
		cfg.gesture = NewGesture()
	}
	var last error
	for attempt := 1; attempt <= cfg.retries+1; attempt++ {
		plan, err := c.planUndo(ctx, ns, gesture, cfg)
		if err != nil {
			return nil, err
		}
		if err := plan.Err(); err != nil {
			return nil, err
		}
		if len(plan.Batch.Items) == 0 {
			return nil, ErrNothingToUndo
		}
		br, err := c.Batch(ctx, ns, plan.Batch, false)
		if err == nil {
			return &UndoResult{Plan: plan, Batch: br, Gesture: cfg.gesture, Attempts: attempt}, nil
		}
		if IsStale(err) {
			last = err
			continue
		}
		return nil, impossibleFromWrite(ns, gesture, err)
	}
	return nil, fmt.Errorf("client: undo of %s: the heads kept moving: %w", gesture, last)
}

// PlanUndo plans the undo of gesture without writing anything: the inverse
// per resource, the conflicts the guard found, and the batch Undo would
// send. A UI shows it before the person confirms. Conflicts are in the
// plan (Err), not an error; an undo that can't be done is an
// *ImpossibleError.
func (c *Client) PlanUndo(ctx context.Context, ns, gesture string, opts ...UndoOption) (*UndoPlan, error) {
	cfg := undoOptions(opts)
	if cfg.gesture == "" {
		cfg.gesture = NewGesture()
	}
	return c.planUndo(ctx, ns, gesture, cfg)
}

// Redo redoes gesture: it undoes the latest undo of it (§11.2 Redo), by
// UndoAuthor if given, else by anyone. Undoing the undo's own gesture
// with Undo does the same. A gesture nobody undid is ErrNotUndone.
func (c *Client) Redo(ctx context.Context, ns, gesture string, opts ...UndoOption) (*UndoResult, error) {
	cfg := undoOptions(opts)
	undo, err := c.latestUndo(ctx, ns, gesture, cfg)
	if err != nil {
		return nil, err
	}
	rest := append(append([]UndoOption{}, opts...), UndoAuthor(undo.author))
	return c.Undo(ctx, ns, undo.gesture, rest...)
}

type undoRef struct{ gesture, author string }

// latestUndo finds the latest gesture undoing gesture.
func (c *Client) latestUndo(ctx context.Context, ns, gesture string, cfg *undoConfig) (*undoRef, error) {
	if !ValidGesture(gesture) {
		return nil, fmt.Errorf("client: invalid gesture id %q", gesture)
	}
	if !cfg.scanLog {
		list, err := c.Gestures(ctx, ns, gesture)
		if err == nil {
			var found *undoRef
			for _, e := range list {
				if e.Undoes == gesture && e.Gesture != "" && (cfg.author == "" || e.Author == cfg.author) {
					found = &undoRef{e.Gesture, e.Author}
				}
			}
			if found == nil {
				return nil, ErrNotUndone
			}
			return found, nil
		}
		if !IsNotFound(err) && !IsAuth(err) {
			return nil, err
		}
	}
	recs, err := c.scanGestures(ctx, ns, cfg.since, false)
	if err != nil {
		return nil, err
	}
	var found *undoRef
	for _, r := range recs.list {
		if r.Undoes == gesture && (cfg.author == "" || r.Author == cfg.author) {
			found = &undoRef{r.Gesture, r.Author}
		}
	}
	if found == nil {
		return nil, ErrNotUndone
	}
	return found, nil
}

// impossibleFromWrite maps a failed undo batch to an ImpossibleError where
// §11.2 says so; other errors pass through.
func impossibleFromWrite(ns, gesture string, err error) error {
	ae, ok := AsAPIError(err)
	if !ok {
		return err
	}
	reason := ""
	switch {
	case ae.Status == 410 && ae.Code == "pruned":
		reason = "pruned"
	case ae.Status == 422:
		codes := []string{ae.Code}
		for _, it := range ae.Items() {
			codes = append(codes, str(it, "code"))
		}
		for _, code := range codes {
			switch code {
			case "blob":
				reason = "blob"
			case "invalid", "schema_unavailable":
				if reason == "" {
					reason = "invalid"
				}
			}
		}
	}
	if reason == "" {
		return err
	}
	return &ImpossibleError{NS: ns, Gesture: gesture, Reason: reason, Err: err}
}

// --- finding the gesture ---------------------------------------------------

// gestureSite is one resource a gesture touched.
type gestureSite struct {
	resource string
	// hint is a revision known to precede the gesture's entries there ("":
	// genesis), the since its log is read from.
	hint string
	// markers are ids that must be in the log after hint: the gesture's
	// entries (the endpoint) or the namespace entries' targets (the scan).
	markers []string
	// writer is the log author of the gesture's entries here when it
	// differs from the gesture's author: the merger of a counted merge
	// that carried it (§11.2). "" means the gesture's author.
	writer string
}

type gestureFind struct {
	author, source string
	sites          []*gestureSite
}

func (c *Client) findGesture(ctx context.Context, ns, gesture string, cfg *undoConfig) (*gestureFind, error) {
	var since map[string]string
	if cfg.since != "" {
		since = map[string]string{}
		heads, err := c.Heads(ctx, ns, cfg.since)
		if err != nil {
			return nil, err
		}
		for _, h := range heads {
			if h.Kind == "head" {
				since[h.Resource] = h.Target
			}
		}
	}
	f := &gestureFind{author: cfg.author}
	byRes := map[string]*gestureSite{}
	site := func(res, hint string) *gestureSite {
		s := byRes[res]
		if s == nil {
			s = &gestureSite{resource: res, hint: hint}
			byRes[res] = s
			f.sites = append(f.sites, s)
		}
		return s
	}
	if !cfg.scanLog {
		list, err := c.Gestures(ctx, ns, gesture)
		switch {
		case err == nil:
			f.source = "gestures"
			for _, e := range list {
				if e.Gesture != gesture {
					continue
				}
				if f.author == "" {
					f.author = e.Author
				}
				if e.Author != f.author {
					continue
				}
				s := site(e.Resource, since[e.Resource])
				s.markers = append(s.markers, e.ID)
			}
			if len(f.sites) > 0 {
				return f, nil
			}
			if cfg.author == "" {
				return nil, ErrGestureNotFound
			}
			// The listing names the batch's writer. A gesture a merge
			// carried into this namespace counts for its source author
			// (§11.2), which only the log shows: scan it.
			f = &gestureFind{author: cfg.author}
			byRes = map[string]*gestureSite{}
		case IsNotFound(err) || IsAuth(err):
			// Not offered: sealed, e2e, an older deployment, or a grant
			// without unrestricted read. The log is the place to look.
		default:
			return nil, err
		}
	}
	f.source = "log"
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	// With a named author, a counted merge's gestures count for whoever
	// wrote them in the branch (§11.2), as UndoStack attributes them.
	var merges *mergeResolver
	if cfg.author != "" {
		merges = c.newMergeResolver(ctx, ns, h.ID)
	}
	log, err := c.NSLog(ctx, ns, h.ID, cfg.since)
	if err != nil {
		return nil, err
	}
	last := map[string]string{}
	for k, v := range since {
		last[k] = v
	}
	note := func(res, target, author, writer string, match bool) {
		if match && (f.author == "" || f.author == author) {
			f.author = author
			s := site(res, last[res])
			s.markers = append(s.markers, target)
			if writer != author {
				s.writer = writer
			}
		}
	}
	// A tombstone keeps the last revision as the hint: it is still an
	// ancestor of everything after it.
	setLast := func(kind, res, target string) {
		if kind == "head" {
			last[res] = target
		}
	}
	for _, e := range log {
		switch e.Kind {
		case "head", "tombstone":
			note(e.Resource, e.Target, e.Author, e.Author, e.Gesture == gesture)
			setLast(e.Kind, e.Resource, e.Target)
		case "batch":
			for _, sub := range e.Entries {
				if sub.Resource == "" {
					continue
				}
				match := false
				for _, sg := range e.Gestures[sub.Resource] {
					match = match || sg.Gesture == gesture
				}
				author := e.Author
				if match && merges != nil && author != f.author {
					wrote, err := merges.authorsOf(e)
					if err != nil {
						return nil, err
					}
					for _, a := range wrote[sub.Resource+"\n"+gesture] {
						if a == f.author {
							author = a
						}
					}
				}
				note(sub.Resource, sub.Target, author, e.Author, match)
				setLast(sub.Kind, sub.Resource, sub.Target)
			}
		case "purge":
			delete(last, e.Resource)
		}
	}
	if len(f.sites) == 0 {
		return nil, ErrGestureNotFound
	}
	return f, nil
}

// --- planning --------------------------------------------------------------

// undoState is a resource's state while folding: the document (the last
// live one when deleted), whether it exists, whether it is tombstoned.
type undoState struct {
	doc             any
	exists, deleted bool
}

func (s undoState) clone() undoState {
	return undoState{doc: jsonv.Clone(s.doc), exists: s.exists, deleted: s.deleted}
}

// foldedEntry is a log entry with the states around it.
type foldedEntry struct {
	LogEntry
	pre, post undoState
	writes    []pointer.Pointer // widened, $nonce left out
	ops       []patch.Op
	flag      string // e2e: why it didn't open
	restore   bool   // a patch set on a tombstone
}

type undoEnv struct {
	ns, gesture string
	level       string // "", "at-rest", "sealed", "e2e"
	maxOps      int
	maxBytes    int
	nonces      bool // the namespace requires nonces, or its document can't be read (§C.7)
	cfg         *undoConfig
}

func (c *Client) planUndo(ctx context.Context, ns, gesture string, cfg *undoConfig) (*UndoPlan, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if !ValidGesture(gesture) {
		return nil, fmt.Errorf("client: invalid gesture id %q", gesture)
	}
	if !ValidGesture(cfg.gesture) {
		return nil, fmt.Errorf("client: invalid undo gesture id %q", cfg.gesture)
	}
	level, err := c.EncryptionLevel(ctx, ns)
	if IsNotFound(err) || IsAuth(err) {
		// A grant whose rules refer to /resource can't read the namespace
		// document (§C.5): its level and nonce setting are unknown, and
		// every patch set adds a fresh $nonce (undoLimits).
		level, err = "", nil
	}
	if err != nil {
		return nil, err
	}
	if level == "e2e" && cfg.e2e == nil {
		return nil, fmt.Errorf("client: undo in the e2e namespace %s needs UndoE2E: the inverse is folded and sealed client-side", ns)
	}
	env := &undoEnv{ns: ns, gesture: gesture, level: level, cfg: cfg}
	env.maxOps, env.maxBytes, env.nonces = c.undoLimits(ctx, ns, cfg)
	if level == "e2e" {
		// Sealing grows a patch set by about half (§6.6 Values).
		env.maxBytes = env.maxBytes*2/3 - 1024
	}
	f, err := c.findGesture(ctx, ns, gesture, cfg)
	if err != nil {
		return nil, err
	}
	plan := &UndoPlan{NS: ns, Gesture: gesture, Author: f.author, Source: f.source,
		Batch: BatchRequest{Gesture: cfg.gesture, Undoes: gesture}}
	for _, s := range f.sites {
		r, conflicts, item, err := c.planResource(ctx, env, f.author, s)
		if err != nil {
			return nil, err
		}
		plan.Conflicts = append(plan.Conflicts, conflicts...)
		if r == nil {
			continue
		}
		plan.Resources = append(plan.Resources, *r)
		if item != nil {
			plan.Batch.Items = append(plan.Batch.Items, *item)
		}
	}
	if len(plan.Resources) == 0 && len(plan.Conflicts) == 0 {
		return nil, ErrGestureNotFound
	}
	return plan, nil
}

// undoLimits reads opsPerSet and patchSetSize from the namespace document
// (§6.6), with the defaults when it doesn't say or can't be read, and
// whether patch sets add a fresh $nonce: it requires nonces, or it can't
// be read (§C.7, NeedsNonce).
func (c *Client) undoLimits(ctx context.Context, ns string, cfg *undoConfig) (ops, size int, nonces bool) {
	ops, size, nonces = 1000, 256<<10, true
	if h, err := c.NSHead(ctx, ns); err == nil {
		if d, err := c.NSDoc(ctx, ns, h.ID); err == nil {
			nonces = d.Value["nonce"] == "required"
			lim, _ := d.Value["limits"].(map[string]any)
			if n, ok := lim["opsPerSet"].(float64); ok && n >= 2 {
				ops = int(n)
			}
			if n, ok := lim["patchSetSize"].(float64); ok && n >= 1024 {
				size = int(n)
			}
		}
	}
	if cfg.maxOps > 0 {
		ops = cfg.maxOps
	}
	if cfg.maxBytes > 0 {
		size = cfg.maxBytes
	}
	return ops, size, nonces
}

func (env *undoEnv) impossible(res, reason string, err error) error {
	return &ImpossibleError{NS: env.ns, Gesture: env.gesture, Resource: res, Reason: reason, Err: err}
}

// readResource reads a resource's head, its log after the site's hint (or
// its pruning horizon) and the document there, opening e2e entries.
func (c *Client) readResource(ctx context.Context, env *undoEnv, s *gestureSite) (*Head, undoState, []LogEntry, []string, error) {
	name := s.resource
	head, err := c.Head(ctx, env.ns, name)
	if err != nil {
		return nil, undoState{}, nil, nil, err
	}
	switch head.State {
	case Purged:
		return nil, undoState{}, nil, nil, env.impossible(name, "purged", nil)
	case NotFound:
		return nil, undoState{}, nil, nil, &APIError{Status: 404, Code: "not_found", Method: "GET", Path: "/r/" + env.ns + "/" + name}
	}
	since := s.hint
	var log []LogEntry
	for tries := 0; ; tries++ {
		log, err = c.Log(ctx, env.ns, name, head.ID, since)
		if err == nil {
			break
		}
		if h := Horizon(err); IsPruned(err) && h != "" && h != since && tries < 3 {
			since = h
			continue
		}
		if IsNotFound(err) && since != "" && tries < 3 {
			since = ""
			continue
		}
		if IsPruned(err) {
			return nil, undoState{}, nil, nil, env.impossible(name, "pruned", err)
		}
		return nil, undoState{}, nil, nil, err
	}
	var start undoState
	if since != "" {
		doc, err := c.undoDoc(ctx, env, name, since)
		if err != nil {
			if IsPruned(err) || IsGone(err) {
				return nil, undoState{}, nil, nil, env.impossible(name, "pruned", err)
			}
			return nil, undoState{}, nil, nil, err
		}
		start = undoState{doc: doc, exists: true}
	}
	var flags []string
	if env.level == "e2e" {
		if log, flags, err = env.cfg.e2e.OpenLog(ctx, env.ns, name, log); err != nil {
			return nil, undoState{}, nil, nil, err
		}
	}
	return head, start, log, flags, nil
}

func (c *Client) undoDoc(ctx context.Context, env *undoEnv, name, id string) (any, error) {
	if env.level == "e2e" {
		d, err := env.cfg.e2e.DocE2E(ctx, env.ns, name, id)
		if err != nil {
			return nil, err
		}
		return d.Value, nil
	}
	d, err := c.Doc(ctx, env.ns, name, id)
	if err != nil {
		return nil, err
	}
	return d.Value, nil
}

// fold folds entries onto start. Entries before the first of the gesture's
// are applied whole; from there on each op is applied on its own, for the
// writes of §6.4.1 under the array rule.
func fold(start undoState, log []LogEntry, flags []string, firstGesture int) ([]foldedEntry, undoState, error) {
	st := start
	out := make([]foldedEntry, len(log))
	for i, e := range log {
		fe := foldedEntry{LogEntry: e}
		if flags != nil {
			fe.flag = flags[i]
		}
		fe.pre = st
		switch {
		case e.Kind == "tombstone":
			if !st.exists || st.deleted {
				return nil, st, fmt.Errorf("client: %s deletes a resource that isn't live", e.ID)
			}
			st.deleted = true
		case fe.flag != "":
			// Left out of the fold, as E2E folds do.
		case !e.HasPatches:
			return nil, st, &APIError{Status: 410, Code: "pruned", Method: "GET", Path: "log entry " + e.ID}
		default:
			v, err := ToValue(e.Patches)
			if err != nil {
				return nil, st, err
			}
			ops, err := patch.Parse(v)
			if err != nil {
				return nil, st, fmt.Errorf("client: entry %s: %w", e.ID, err)
			}
			fe.ops = ops
			fe.restore = st.deleted
			st.deleted = false
			if i < firstGesture {
				nd, _, err := patch.Apply(st.doc, st.exists, ops, patch.Options{ResourceEnvelope: true})
				if err != nil {
					return nil, st, fmt.Errorf("client: entry %s: %w", e.ID, err)
				}
				st.doc, st.exists = nd, true
				break
			}
			for j, op := range ops {
				pre := st.doc
				nd, ws, err := patch.Apply(st.doc, st.exists, []patch.Op{op}, patch.Options{ResourceEnvelope: true})
				if err != nil {
					return nil, st, fmt.Errorf("client: entry %s op %d: %w", e.ID, j, err)
				}
				st.doc, st.exists = nd, true
				switch op.Op {
				case "remove":
					for _, w := range ws {
						fe.writes = append(fe.writes, widen(pre, w))
					}
				case "move":
					if len(ws) == 2 {
						fe.writes = append(fe.writes, widen(pre, ws[0]), widen(nd, ws[1]))
					}
				default:
					for _, w := range ws {
						fe.writes = append(fe.writes, widen(nd, w))
					}
				}
			}
			fe.writes = dropNonce(fe.writes)
		}
		fe.post = st
		out[i] = fe
	}
	return out, st, nil
}

// widen widens a write whose last segment addresses an array element (an
// index, or "-") to the whole array (§11.2, as §F.3).
func widen(doc any, w pointer.Pointer) pointer.Pointer {
	if len(w) == 0 {
		return w
	}
	parent := w[:len(w)-1]
	if w[len(w)-1] == "-" {
		return append(pointer.Pointer{}, parent...)
	}
	if v, ok := pointer.Get(doc, parent); ok {
		if _, isArr := v.([]any); isArr {
			return append(pointer.Pointer{}, parent...)
		}
	}
	return append(pointer.Pointer{}, w...)
}

// dropNonce leaves out writes at or below /$nonce: an undo never restores
// an old nonce (§11.2, §C.7).
func dropNonce(ws []pointer.Pointer) []pointer.Pointer {
	out := ws[:0:0]
	for _, w := range ws {
		if len(w) > 0 && w[0] == "$nonce" {
			continue
		}
		out = append(out, w)
	}
	return out
}

// cover returns the topmost of ws: no path in it is below another, sorted.
func cover(ws []pointer.Pointer) []pointer.Pointer {
	sorted := append([]pointer.Pointer{}, ws...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) < len(sorted[j])
		}
		return sorted[i].String() < sorted[j].String()
	})
	var out []pointer.Pointer
	for _, w := range sorted {
		covered := false
		for _, k := range out {
			if w.HasPrefix(k) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func overlaps(a, b []pointer.Pointer) []string {
	set := map[string]bool{}
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				set[x.String()] = true
				set[y.String()] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// planResource plans the inverse for one resource: nil when the gesture
// has no entries left there (with conflicts, if any).
func (c *Client) planResource(ctx context.Context, env *undoEnv, author string, s *gestureSite) (*UndoResource, []UndoConflict, *BatchItem, error) {
	name := s.resource
	head, start, log, flags, err := c.readResource(ctx, env, s)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.writer != "" {
		author = s.writer // a merge carried the gesture here (§11.2)
	}
	isOwn := func(e LogEntry) bool { return e.Gesture == env.gesture && e.Author == author }
	first, last := -1, -1
	ids := map[string]bool{}
	for i, e := range log {
		ids[e.ID] = true
		if isOwn(e) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	for _, m := range s.markers {
		if !ids[m] {
			return nil, nil, nil, env.impossible(name, "pruned", fmt.Errorf("the gesture's entry %s lies below the resource's pruning horizon", m))
		}
	}
	if first < 0 {
		return nil, nil, nil, nil
	}
	folded, final, err := fold(start, log, flags, first)
	if err != nil {
		if IsPruned(err) {
			return nil, nil, nil, env.impossible(name, "pruned", err)
		}
		return nil, nil, nil, err
	}
	r := &UndoResource{Resource: name, Head: head.ID, State: head.State}
	var gw []pointer.Pointer
	var own []*foldedEntry
	for i := first; i <= last; i++ {
		fe := &folded[i]
		if !isOwn(fe.LogEntry) {
			continue
		}
		if fe.flag != "" {
			return nil, nil, nil, env.impossible(name, "invalid", fmt.Errorf("the gesture's revision %s doesn't open: %s", fe.ID, fe.flag))
		}
		own = append(own, fe)
		r.Entries = append(r.Entries, fe.ID)
		gw = append(gw, fe.writes...)
		if fe.Kind == "rev" && fe.Parent == "" {
			gw = append(gw, pointer.Pointer{})
		}
	}
	gw = cover(gw)
	r.Writes = make([]string, len(gw))
	for i, w := range gw {
		r.Writes[i] = w.String()
	}

	// The guard (§11.2): the log after the gesture's last entry.
	var conflicts []UndoConflict
	for _, fe := range folded[last+1:] {
		cf := UndoConflict{Resource: name, Entry: fe.ID, Author: fe.Author, Gesture: fe.Gesture}
		switch {
		case fe.Undoes == env.gesture:
			cf.Kind = "undone"
		case fe.Kind == "tombstone":
			cf.Kind = "deleted"
		case fe.flag != "":
			cf.Kind = "unreadable"
		case fe.restore:
			cf.Kind = "restored"
		default:
			if cf.Paths = overlaps(gw, fe.writes); len(cf.Paths) == 0 {
				continue
			}
			cf.Kind = "overlap"
		}
		conflicts = append(conflicts, cf)
	}
	if len(conflicts) > 0 {
		return r, conflicts, nil, nil
	}

	// The inverse, newest first, applied to the current state. Where nonces
	// are required, every patch-set step gets one, a restore that would be
	// [] and a step before a "delete" included (§11.2, §C.7).
	needNonce := env.level == "sealed" || env.nonces
	if m, ok := final.doc.(map[string]any); ok && env.level != "e2e" {
		if _, has := m["$nonce"]; has {
			needNonce = true
		}
	}
	b := &stepBuilder{env: env, nonce: needNonce}
	st := final.clone()
	for i := len(own) - 1; i >= 0; i-- {
		fe := own[i]
		switch {
		case fe.Kind == "tombstone":
			b.flush()
			b.restore = true
			st.deleted = false
		case fe.Parent == "":
			b.flush()
			b.del()
			st.deleted = true
		default:
			ops, cf := invertRevision(fe, &st)
			if cf != nil {
				cf.Resource = name
				return r, []UndoConflict{*cf}, nil, nil
			}
			b.pending = append(b.pending, ops...)
			if fe.restore {
				b.flush()
				b.del()
				st.deleted = true
			}
		}
	}
	b.flush()
	steps := b.steps
	if len(steps) == 0 && head.State == Live {
		// Nothing to change: record the undo with an empty patch set, so
		// the stack sees it (§11.2 Redo).
		b.restore = true
		b.flush()
		steps = b.steps
	}
	r.Steps, r.Doc, r.Deleted = steps, st.doc, st.deleted
	if len(steps) == 0 {
		return r, nil, nil, nil
	}
	item := &BatchItem{Resource: name, IfMatch: head.ID, Steps: steps}
	if env.level == "e2e" {
		sealed, err := c.sealUndoSteps(ctx, env, name, head, final, steps)
		if err != nil {
			return nil, nil, nil, err
		}
		item.Steps = sealed
	}
	return r, nil, item, nil
}

// invertRevision returns the ops turning fe's paths back into its parent's
// values on st, and applies them to st. A conflict reports an inverse that
// doesn't apply.
func invertRevision(fe *foldedEntry, st *undoState) ([]any, *UndoConflict) {
	paths := cover(fe.writes)
	d0 := fe.pre.doc
	if ops, ok := moveBack(fe, st, paths); ok {
		return ops, nil
	}
	var out []any
	for _, w := range paths {
		var target any
		var tok bool
		if len(w) == 0 {
			target, tok = withoutNonce(d0), fe.pre.exists
		} else {
			target, tok = pointer.Get(d0, w)
		}
		cur, cok := pointer.Get(st.doc, w)
		if len(w) == 0 {
			cur = withoutNonce(cur)
		}
		var op map[string]any
		switch {
		case tok && cok && jsonv.Equal(cur, target), !tok && !cok:
			continue
		case !tok:
			op = map[string]any{"op": "remove", "path": w.String()}
		case cok:
			op = map[string]any{"op": "replace", "path": w.String(), "value": jsonv.Clone(target)}
		default:
			op = map[string]any{"op": "add", "path": w.String(), "value": jsonv.Clone(target)}
		}
		ops, err := patch.Parse([]any{op})
		if err == nil {
			var nd any
			nd, _, err = patch.Apply(st.doc, st.exists, ops, patch.Options{})
			if err == nil {
				st.doc = nd
			}
		}
		if err != nil {
			return nil, &UndoConflict{Entry: fe.ID, Author: fe.Author, Gesture: fe.Gesture, Kind: "apply", Paths: []string{w.String()}}
		}
		out = append(out, op)
	}
	return out, nil
}

func withoutNonce(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if _, has := m["$nonce"]; !has {
		return v
	}
	cp := make(map[string]any, len(m))
	for k, x := range m {
		if k != "$nonce" {
			cp[k] = x
		}
	}
	return cp
}

// moveBack inverts a revision made only of moves (and fresh $nonce adds)
// by moves back, when both ends are unchanged since: st holds fe's values
// at its paths, and the moves back restore its parent's (§11.2).
func moveBack(fe *foldedEntry, st *undoState, paths []pointer.Pointer) ([]any, bool) {
	var moves []patch.Op
	for _, op := range fe.ops {
		if op.Op == "move" {
			moves = append(moves, op)
			continue
		}
		if len(op.Path) == 1 && op.Path[0] == "$nonce" && (op.Op == "add" || op.Op == "replace") {
			continue
		}
		return nil, false
	}
	if len(moves) == 0 || len(paths) == 0 {
		return nil, false
	}
	same := func(a, b any) bool {
		for _, w := range paths {
			x, xok := pointer.Get(a, w)
			y, yok := pointer.Get(b, w)
			if xok != yok || (xok && !jsonv.Equal(x, y)) {
				return false
			}
		}
		return true
	}
	if !same(st.doc, fe.post.doc) {
		return nil, false
	}
	// The resolved ends of each move, replayed on the parent's document.
	doc := fe.pre.doc
	back := make([]any, 0, len(moves))
	for _, op := range moves {
		nd, ws, err := patch.Apply(doc, true, []patch.Op{op}, patch.Options{})
		if err != nil || len(ws) != 2 {
			return nil, false
		}
		doc = nd
		back = append([]any{map[string]any{"op": "move", "from": ws[1].String(), "path": ws[0].String()}}, back...)
	}
	ops, err := patch.Parse(back)
	if err != nil {
		return nil, false
	}
	nd, _, err := patch.Apply(st.doc, st.exists, ops, patch.Options{})
	if err != nil || !same(nd, fe.pre.doc) {
		return nil, false
	}
	st.doc = nd
	return back, true
}

// stepBuilder joins the inverse's patch sets and splits them into steps
// within the namespace's limits (§6.6).
type stepBuilder struct {
	env     *undoEnv
	nonce   bool
	pending []any
	restore bool // the next patch set restores: [] is needed even if empty
	steps   []Step
}

func (b *stepBuilder) del() { b.steps = append(b.steps, DeleteStep()) }

func (b *stepBuilder) flush() {
	ops, restore := b.pending, b.restore
	b.pending, b.restore = nil, false
	if len(ops) == 0 {
		if restore {
			b.steps = append(b.steps, PatchStep(b.withNonce(nil)))
		}
		return
	}
	maxOps, maxBytes := b.env.maxOps, b.env.maxBytes
	if b.nonce {
		maxOps--
		maxBytes -= 64
	}
	var cur []any
	size := 2
	for _, op := range ops {
		n := len(jsonv.Canonical(op)) + 1
		if len(cur) > 0 && (len(cur)+1 > maxOps || size+n > maxBytes) {
			b.steps = append(b.steps, PatchStep(b.withNonce(cur)))
			cur, size = nil, 2
		}
		cur = append(cur, op)
		size += n
	}
	b.steps = append(b.steps, PatchStep(b.withNonce(cur)))
}

func (b *stepBuilder) withNonce(ops []any) []any {
	out := append([]any{}, ops...)
	if b.nonce {
		out = append(out, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	}
	return out
}

// sealUndoSteps validates and seals the inverse of an e2e resource (§E.3):
// each patch set bound to the id the step before produces, with the
// declared blob list of the document it produces.
func (c *Client) sealUndoSteps(ctx context.Context, env *undoEnv, name string, head *Head, st undoState, steps []Step) ([]Step, error) {
	x := env.cfg.e2e
	prev := head.ID
	out := make([]Step, 0, len(steps))
	for i, s := range steps {
		if s.Delete {
			id, err := ExpectedTombstone(prev)
			if err != nil {
				return nil, err
			}
			prev = id
			st.deleted = true
			out = append(out, s)
			continue
		}
		v, err := ToValue(s.Patches)
		if err != nil {
			return nil, err
		}
		ops, err := patch.Parse(v)
		if err != nil {
			return nil, err
		}
		nd, _, err := patch.Apply(st.doc, st.exists, ops, patch.Options{})
		if err != nil {
			return nil, fmt.Errorf("client: undo step %d of %s doesn't apply: %w", i, name, err)
		}
		if msg, err := x.ValidateIn(ctx, env.ns, nd); err != nil {
			return nil, err
		} else if msg != "" {
			return nil, env.impossible(name, "invalid", errors.New("the document doesn't validate against its $schema: "+msg))
		}
		body, err := x.SealPatchesBlobs(ctx, env.ns, name, prev, v, BlobIDs(nd))
		if err != nil {
			return nil, err
		}
		sealed, err := jsonv.Parse(body)
		if err != nil {
			return nil, err
		}
		if prev, err = ExpectedRevision(prev, sealed); err != nil {
			return nil, err
		}
		st = undoState{doc: nd, exists: true}
		out = append(out, PatchStep(sealed))
	}
	return out, nil
}

// --- the author's stack ------------------------------------------------------

// GestureRecord summarises one gesture of one author in a namespace log.
type GestureRecord struct {
	Gesture, Author string
	// Undoes is the gesture it undoes, "" if none.
	Undoes    string
	Resources []string
	// FirstNSID and LastNSID are the namespace entries of its first and
	// last writes, Created the time of its last.
	FirstNSID, LastNSID, Created string
	first, last                  int
}

type gestureIndex struct {
	list []*GestureRecord
	by   map[string]*GestureRecord // author "\n" gesture
	ids  map[string]bool           // gestures that exist, any author
}

// scanGestures reads the namespace log (after since) and groups its writes
// by author and gesture (§7.2: tools group by both).
//
// With attribute, a gesture a merge carried into ns (§F.3) is grouped under
// the author who wrote it in the branch instead of the merger's (§11.2).
func (c *Client) scanGestures(ctx context.Context, ns, since string, attribute bool) (*gestureIndex, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	log, err := c.NSLog(ctx, ns, h.ID, since)
	if err != nil {
		return nil, err
	}
	ix := &gestureIndex{by: map[string]*GestureRecord{}, ids: map[string]bool{}}
	add := func(i int, e NSEntry, author, res string, g StepGesture) {
		if g.Gesture == "" {
			return
		}
		k := author + "\n" + g.Gesture
		r := ix.by[k]
		if r == nil {
			r = &GestureRecord{Gesture: g.Gesture, Author: author, FirstNSID: e.ID, first: i}
			ix.by[k] = r
			ix.list = append(ix.list, r)
			ix.ids[g.Gesture] = true
		}
		if r.Undoes == "" {
			r.Undoes = g.Undoes
		}
		r.LastNSID, r.Created, r.last = e.ID, e.Created, i
		for _, x := range r.Resources {
			if x == res {
				return
			}
		}
		r.Resources = append(r.Resources, res)
	}
	var merges *mergeResolver
	if attribute {
		merges = c.newMergeResolver(ctx, ns, h.ID)
	}
	for i, e := range log {
		switch e.Kind {
		case "head", "tombstone":
			add(i, e, e.Author, e.Resource, StepGesture{e.Gesture, e.Undoes})
		case "batch":
			var wrote gestureAuthors
			if merges != nil && len(e.Gestures) > 0 {
				if wrote, err = merges.authorsOf(e); err != nil {
					return nil, err
				}
			}
			for _, sub := range e.Entries {
				for _, sg := range e.Gestures[sub.Resource] {
					if as := wrote[sub.Resource+"\n"+sg.Gesture]; len(as) > 0 {
						for _, a := range as {
							add(i, e, a, sub.Resource, sg)
						}
						continue
					}
					add(i, e, e.Author, sub.Resource, sg)
				}
			}
		}
	}
	return ix, nil
}

// StackItem is one action on an author's undo stack (§11.2 Redo).
type StackItem struct {
	// Gesture is the original action, Resources what it touched.
	GestureRecord
	// Target is the gesture to pass to Undo: for an action that is done,
	// the latest redo of it (or the action itself); for one undone, the
	// author's undo of it, whose undo is the redo.
	Target string
	// Chain is the author's undos and redos of the action, oldest first.
	Chain []string
	// UndoneBy lists other authors' undos of the action as it stands
	// (Target), which don't drop it from this author's stack.
	UndoneBy []GestureRecord
}

// UndoStack is an author's stack, rebuilt from the namespace log.
type UndoStack struct {
	Author string
	// Done are the author's actions that stand, the most recent last:
	// Undo(Done[len-1].Target) undoes the last.
	Done []StackItem
	// Undone are the actions the author undid and didn't redo, the most
	// recently undone last: Undo(Undone[len-1].Target) redoes it.
	Undone []StackItem
}

// UndoStack rebuilds author's undo stack in ns from the namespace log
// (after UndoSince, else all of it): the gestures that author made, minus
// those the same author undid and didn't redo (§11.2 Redo). Undos by other
// authors are listed in UndoneBy instead of dropping the action. An
// Undoes naming a gesture that isn't in the log (or another author's) is
// ignored: the gesture counts as an action of its own.
//
// A gesture a merge carried into ns counts for the author who wrote it in
// the merge's source.ns (§11.2), when the batch counts as a merge under
// §F.3: no origin, source.at in the branch's chain, and the merger's grant
// listed in merge.authors of ns's document. Otherwise, or when the branch
// can't be read, it counts for whoever wrote the batch.
func (c *Client) UndoStack(ctx context.Context, ns, author string, opts ...UndoOption) (*UndoStack, error) {
	cfg := undoOptions(opts)
	ix, err := c.scanGestures(ctx, ns, cfg.since, true)
	if err != nil {
		return nil, err
	}
	return ix.stack(author), nil
}

func (ix *gestureIndex) stack(author string) *UndoStack {
	undoers := map[string][]*GestureRecord{}
	for _, r := range ix.list {
		if r.Undoes != "" {
			undoers[r.Undoes] = append(undoers[r.Undoes], r)
		}
	}
	own := func(g string) *GestureRecord { return ix.by[author+"\n"+g] }
	out := &UndoStack{Author: author, Done: []StackItem{}, Undone: []StackItem{}}
	type sorted struct {
		item StackItem
		at   int
	}
	var done, undone []sorted
	for _, r := range ix.list {
		if r.Author != author {
			continue
		}
		if r.Undoes != "" && own(r.Undoes) != nil && own(r.Undoes).first < r.first {
			continue // an undo or redo: part of a chain
		}
		tip, depth := r, 0
		var chain []string
		for {
			var next *GestureRecord
			for _, y := range undoers[tip.Gesture] {
				if y.Author == author && y.first > tip.first {
					next = y
				}
			}
			if next == nil {
				break
			}
			tip, depth = next, depth+1
			chain = append(chain, next.Gesture)
		}
		it := StackItem{GestureRecord: *r, Target: tip.Gesture, Chain: chain}
		if depth%2 == 0 {
			for _, y := range undoers[tip.Gesture] {
				if y.Author != author && y.first > tip.first {
					it.UndoneBy = append(it.UndoneBy, *y)
				}
			}
			done = append(done, sorted{it, tip.last})
		} else {
			undone = append(undone, sorted{it, tip.last})
		}
	}
	sort.SliceStable(done, func(i, j int) bool { return done[i].at < done[j].at })
	sort.SliceStable(undone, func(i, j int) bool { return undone[i].at < undone[j].at })
	for _, d := range done {
		out.Done = append(out.Done, d.item)
	}
	for _, u := range undone {
		out.Undone = append(out.Undone, u.item)
	}
	return out
}
