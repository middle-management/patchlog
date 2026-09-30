// Package merge implements the merge and rebase procedures of Addendum F
// (§F.3–§F.5, §F.7) as a client of the public API. Nothing here is a server
// operation: a merge is one batch into the base (§7.5), built from the
// branch's changes and classified by ancestry using ids only (§3.3).
//
// A Plan collects the resources a branch changed from its namespace log,
// classifies each against the target namespace (the base for a merge, the
// successor branch for a rebase), and builds the batch items:
//
//   - fast-forward: the branch's entries after the target head B, with
//     ifMatch B (ifNoneMatch * for a resource absent in the target). The ids
//     are identical to the branch's; the plan checks that client-side.
//   - replay: the branch's entries after the latest common ancestor, onto B,
//     with new ids. Both sides' writes since the ancestor are computed under
//     the array rule, and overlaps are conflicts.
//   - nothing, when the target already has the branch head (or more), or the
//     resource was purged (reported).
//
// Merge points (§F.3): when the target's log already holds a merge batch of
// the branch (an earlier replayed merge, or the first pass of a rebase),
// the branch revision as of its source.at and the target revision it
// produced are treated as a common ancestor. Per resource, the pair comes
// from the most recent such batch with an entry for it. A second merge
// after a replay then picks up exactly the branch's new entries, instead of
// replaying the already merged ones again. source is asserted, not
// verified, so only batches without origin, whose source.ns is the branch
// and whose author (root sub and kid) is listed in the target's
// merge.authors count (see Listed). Without merge.authors there are no
// merge points: classification falls back to ancestry by ids, and a second
// merge after a replay conflicts; such a branch should be rebased (§F.5).
//
// A resource resolved by keeping the target's version (Resolve with no
// steps) is still recorded in the batch with an empty step [] (in a sealed
// namespace, a patch set that only adds a fresh $nonce), so the batch holds
// its pair, but only when the target's head is a live document. On a
// tombstone or an absent resource that would restore or fail, so the
// resource gets no item: it stays unmerged and is offered again.
//
// The batch's source.at is the branch revision the plan was classified
// from (BranchAt), never a later one: re-classification after a 412 only
// reads the target again, and a plan built later (NewPlan) reads the
// branch's new head and uses that as its source.at.
package merge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// Class is a resource's classification by ancestry (§F.3).
type Class string

const (
	// Merged: B = H, or H was merged into B by an earlier merge batch.
	Merged Class = "merged"
	// FastForward: B is an ancestor of H (or the resource is absent in the
	// target).
	FastForward Class = "fast-forward"
	// Behind: H is an ancestor of B; the target has it and more.
	Behind Class = "behind"
	// Replay: neither; replay the branch's entries after the common ancestor.
	Replay Class = "replay"
	// Purged: purged in the target or in the branch; reported, no item.
	Purged Class = "purged"
)

// Conflict kinds.
const (
	ConflictOverlap          = "overlap"            // both sides wrote overlapping paths
	ConflictPruned           = "pruned"             // needed history was pruned (§8.6)
	ConflictDeleteVsChange   = "delete_vs_change"   // the branch deletes a document the target changed since
	ConflictChangeVsDelete   = "change_vs_delete"   // the branch changes a document the target deleted since
	ConflictNoCommonAncestor = "no_common_ancestor" // e.g. created independently on both sides
	ConflictUnreadable       = "unreadable"         // writes could not be computed (patches don't fold)
	ConflictStaleResolution  = "stale_resolution"   // the target moved after a resolution was given
)

// Conflict is a reason a resource needs a person.
type Conflict struct {
	Kind    string   `json:"kind"`
	Paths   []string `json:"paths,omitempty"`
	Message string   `json:"message,omitempty"`
}

// Resource is one resource the branch changed, classified.
type Resource struct {
	Name string `json:"resource"`
	// Class is the classification by ancestry.
	Class Class `json:"class"`
	// Base is the target's head B ("" = absent), BaseState its state.
	Base      string `json:"base,omitempty"`
	BaseState string `json:"baseState"`
	// Branch is the branch's head H; BranchDeleted if it is a tombstone.
	Branch        string `json:"branch,omitempty"`
	BranchDeleted bool   `json:"branchDeleted,omitempty"`
	// Ancestor is the common ancestor a replay starts from (branch side),
	// and TargetAncestor the target revision equivalent to it (the same id,
	// or the result of an earlier merge batch).
	Ancestor       string `json:"ancestor,omitempty"`
	TargetAncestor string `json:"targetAncestor,omitempty"`

	// The batch item.
	IfMatch     string        `json:"ifMatch,omitempty"`
	IfNoneMatch bool          `json:"ifNoneMatch,omitempty"`
	Steps       []client.Step `json:"-"`
	// Expected are the ids the item must produce: the branch's own ids for a
	// fast-forward (nil for replays, resolutions and squashed items).
	Expected []string `json:"expected,omitempty"`

	BranchWrites []string   `json:"branchWrites,omitempty"`
	BaseWrites   []string   `json:"baseWrites,omitempty"`
	Conflicts    []Conflict `json:"conflicts,omitempty"`
	Resolved     bool       `json:"resolved,omitempty"`
	Dropped      bool       `json:"dropped,omitempty"` // resolved by keeping the target as is
	// Kept: dropped, and recorded in the batch with an empty step (a
	// nonce-only one in a sealed namespace), so the batch holds the pair.
	// A dropped resource that isn't Kept stays unmerged.
	Kept bool `json:"kept,omitempty"`
	// Pair is the common-ancestor pair from the most recent trusted merge
	// batch with an entry for the resource, if any (§F.3).
	Pair     *Pair  `json:"pair,omitempty"`
	Squashed bool   `json:"squashed,omitempty"`
	Note     string `json:"note,omitempty"`

	branchPurged bool
	resolution   []client.Step
	resolvedAt   string // B the resolution was written against
}

// Status is the §F.7 status of the resource: "merged" (nothing to do),
// "ahead" (fast-forwards), "behind" (the target has it and more), "clean"
// (replays without overlapping writes), "conflicting" or "purged".
func (r *Resource) Status() string {
	switch r.Class {
	case FastForward:
		if len(r.Conflicts) > 0 && !r.Resolved {
			return "conflicting"
		}
		return "ahead"
	case Replay:
		if len(r.Conflicts) > 0 && !r.Resolved {
			return "conflicting"
		}
		return "clean"
	case Behind:
		return "behind"
	case Purged:
		return "purged"
	}
	return "merged"
}

// NeedsPerson reports unresolved conflicts.
func (r *Resource) NeedsPerson() bool { return len(r.Conflicts) > 0 && !r.Resolved }

// HasItem reports whether the resource contributes a batch item.
func (r *Resource) HasItem() bool {
	if r.Dropped {
		return r.Kept && len(r.Steps) > 0
	}
	return (r.Class == FastForward || r.Class == Replay) && len(r.Steps) > 0
}

// MarshalJSON renders steps as in the batch body ("delete" or a patch set).
func (r *Resource) MarshalJSON() ([]byte, error) {
	type alias Resource
	out := struct {
		*alias
		Status string `json:"status"`
		Steps  []any  `json:"steps,omitempty"`
	}{alias: (*alias)(r), Status: r.Status(), Steps: StepsJSON(r.Steps)}
	return json.Marshal(out)
}

// StepsJSON renders steps as in a batch body.
func StepsJSON(steps []client.Step) []any {
	if len(steps) == 0 {
		return nil
	}
	out := make([]any, len(steps))
	for i, s := range steps {
		if s.Delete {
			out[i] = "delete"
		} else {
			out[i] = s.Patches
		}
	}
	return out
}

// Options configure a plan.
type Options struct {
	// Squash replaces each item's steps with one patch set with the same
	// effect (§F.3). Fast-forwards then get new ids.
	Squash bool
	// Config is an explicit config change for the target, as a patch set
	// (§F.3: configuration is never merged implicitly).
	Config any
	// MaxRetries bounds re-classification after 412 in Apply (default 3).
	MaxRetries int
	// Resources, if set, limits the plan to these resource names.
	Resources []string
}

// Plan is a classified merge of Branch into Target.
type Plan struct {
	c *client.Client

	Target string `json:"target"`
	Branch string `json:"branch"`
	// BranchAt is the branch's ns_id the plan reflects, the batch's
	// source.at.
	BranchAt string `json:"branchAt"`
	// TargetAt and TargetConfig are the target's ns_id and config id when
	// the plan was built.
	TargetAt     string `json:"targetAt"`
	TargetConfig string `json:"targetConfig"`

	Resources []*Resource `json:"resources"`

	// MergeAuthors is the target's merge.authors; AuthorsDeclared is false
	// when its namespace document has none (then there are no merge
	// points).
	MergeAuthors    []Author `json:"mergeAuthors,omitempty"`
	AuthorsDeclared bool     `json:"authorsDeclared"`
	// Ignored lists the earlier merge batches of the branch in the target
	// that don't count as merge points, with the reason.
	Ignored []MergeBatch `json:"ignoredMerges,omitempty"`
	// TargetLevel is the target's encryption level ("", "at-rest",
	// "sealed").
	TargetLevel string `json:"targetLevel,omitempty"`

	opt        Options
	points     map[string]Pair         // per resource: the most recent trusted pair
	ignoredFor map[string][]MergeBatch // per resource: untrusted batches with an entry for it
	logs       map[string]ancestry     // cache: ns/name@head
}

// Pair is a common ancestor from an earlier merge batch (§F.3): the branch
// revision as of the batch's source.at and the target revision the batch
// produced for the resource.
type Pair struct {
	Batch  string `json:"batch"`  // the batch entry's ns_id in the target
	Author string `json:"author"` // its root sub
	Kid    string `json:"kid,omitempty"`
	At     string `json:"at"`     // its source.at
	Branch string `json:"branch"` // branch revision as of At
	Target string `json:"target"` // target revision from the batch
	// Used: the pair is the common ancestor the classification started
	// from (a later common ancestor by ids wins).
	Used bool `json:"used,omitempty"`
}

// MergeBatch is an earlier merge batch of the branch that isn't trusted.
type MergeBatch struct {
	Batch  string `json:"batch"`
	Author string `json:"author"`
	Kid    string `json:"kid,omitempty"`
	Reason string `json:"reason"`
}

type ancestry struct {
	entries   []client.LogEntry
	truncated bool // starts at a pruning horizon
}

// ErrConflicts is returned by Apply when some resource needs a person.
var ErrConflicts = errors.New("merge: unresolved conflicts")

// NewPlan collects the resources branch changed and classifies them against
// target (usually the branch's base).
func NewPlan(ctx context.Context, c *client.Client, target, branch string, opt Options) (*Plan, error) {
	if opt.MaxRetries <= 0 {
		opt.MaxRetries = 3
	}
	p := &Plan{c: c, Target: target, Branch: branch, opt: opt, logs: map[string]ancestry{}}
	// Sealed patch sets bind their namespace (§E.3.1): merging an e2e
	// branch means decrypting and re-encrypting under the target's keys,
	// never a fast-forward (§F.8), which this tool doesn't do.
	for _, ns := range []string{branch, target} {
		lv, err := c.EncryptionLevel(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("merge: %s: %w", ns, err)
		}
		if ns == target {
			p.TargetLevel = lv
		}
		if lv == "e2e" {
			return nil, fmt.Errorf("merge: %s is an e2e namespace (Addendum E.3): its merges must decrypt and re-encrypt under the target's keys in a client holding both, never fast-forward (§F.8); this merge tool doesn't support that", ns)
		}
	}
	bh, err := c.NSHead(ctx, branch)
	if err != nil {
		return nil, fmt.Errorf("merge: branch %s: %w", branch, err)
	}
	p.BranchAt = bh.ID
	blog, err := c.NSLog(ctx, branch, bh.ID, "")
	if err != nil {
		return nil, fmt.Errorf("merge: branch %s log: %w", branch, err)
	}
	bdoc, err := c.NSDoc(ctx, branch, bh.ID)
	if err != nil {
		return nil, err
	}
	th, err := c.NSHead(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("merge: target %s: %w", target, err)
	}
	p.TargetAt, p.TargetConfig = th.ID, th.Config
	tdoc, err := c.NSDoc(ctx, target, th.ID)
	if err != nil {
		return nil, fmt.Errorf("merge: target %s: %w", target, err)
	}
	p.MergeAuthors, p.AuthorsDeclared = MergeAuthors(tdoc.Value)

	changed := Collect(blog)
	var only map[string]bool
	if len(opt.Resources) > 0 {
		only = map[string]bool{}
		for _, n := range opt.Resources {
			only[n] = true
		}
	}
	for _, ch := range changed {
		if only != nil && !only[ch.Resource] {
			continue
		}
		r := &Resource{Name: ch.Resource, Branch: ch.Target, BranchDeleted: ch.Kind == "tombstone", branchPurged: ch.Purged}
		p.Resources = append(p.Resources, r)
	}

	// Earlier merge batches of this branch into the target.
	since := ""
	if b, ok := bdoc.Value["base"].(map[string]any); ok {
		if ns, _ := b["ns"].(string); ns == target {
			since, _ = b["at"].(string)
		}
	}
	if err := p.loadMergePoints(ctx, blog, since); err != nil {
		return nil, err
	}

	for _, r := range p.Resources {
		if err := p.classify(ctx, r); err != nil {
			return nil, fmt.Errorf("merge: %s: %w", r.Name, err)
		}
	}
	return p, nil
}

// Change is a resource's latest entry in a branch log.
type Change struct {
	Resource string `json:"resource"`
	Kind     string `json:"kind"` // head or tombstone (the latest live entry)
	Target   string `json:"target"`
	Purged   bool   `json:"purged,omitempty"`
}

// Collect lists the resources a namespace log changed (head, tombstone and
// batch entries), with the latest entry of each, sorted by name. A purge
// (including one propagated from a base, §8.3) marks the resource purged,
// and a purge-ns entry marks every resource purged.
func Collect(log []client.NSEntry) []Change {
	m := map[string]*Change{}
	get := func(name string) *Change {
		c := m[name]
		if c == nil {
			c = &Change{Resource: name}
			m[name] = c
		}
		return c
	}
	var visit func(e client.NSEntry)
	visit = func(e client.NSEntry) {
		switch e.Kind {
		case "head", "tombstone":
			c := get(e.Resource)
			c.Kind, c.Target = e.Kind, e.Target
		case "purge":
			get(e.Resource).Purged = true
		case "purge-ns":
			for _, c := range m {
				c.Purged = true
			}
		case "batch":
			for _, s := range e.Entries {
				visit(s)
			}
		}
	}
	for _, e := range log {
		visit(e)
	}
	out := make([]Change, 0, len(m))
	for _, c := range m {
		if c.Target == "" && !c.Purged {
			continue
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

// headsAt returns each resource's latest entry in log up to and including
// the entry at.
func headsAt(log []client.NSEntry, at string) map[string]string {
	out := map[string]string{}
	var visit func(e client.NSEntry)
	visit = func(e client.NSEntry) {
		switch e.Kind {
		case "head", "tombstone":
			out[e.Resource] = e.Target
		case "batch":
			for _, s := range e.Entries {
				visit(s)
			}
		}
	}
	for _, e := range log {
		visit(e)
		if e.ID == at {
			return out
		}
	}
	return nil // at not in the log
}

func (p *Plan) loadMergePoints(ctx context.Context, blog []client.NSEntry, since string) error {
	p.points, p.ignoredFor = map[string]Pair{}, map[string][]MergeBatch{}
	tlog, err := p.c.NSLog(ctx, p.Target, p.TargetAt, since)
	if client.IsNotFound(err) && since != "" {
		tlog, err = p.c.NSLog(ctx, p.Target, p.TargetAt, "")
	}
	if err != nil {
		return fmt.Errorf("merge: target %s log: %w", p.Target, err)
	}
	// Oldest first, so a later batch's pair replaces an earlier one.
	for _, e := range tlog {
		if !IsMergeOf(e, p.Branch) {
			continue
		}
		mb := MergeBatch{Batch: e.ID, Author: e.Author, Kid: e.Kid}
		switch {
		case !p.AuthorsDeclared:
			mb.Reason = "the target declares no merge.authors"
		case !Listed(p.MergeAuthors, e.Author, e.Kid):
			mb.Reason = "its author " + principal(e.Author, e.Kid) + " is not in the target's merge.authors"
		}
		if mb.Reason != "" {
			p.Ignored = append(p.Ignored, mb)
			for _, s := range e.Entries {
				if s.Kind == "head" || s.Kind == "tombstone" {
					p.ignoredFor[s.Resource] = append(p.ignoredFor[s.Resource], mb)
				}
			}
			continue
		}
		at, _ := e.Source["at"].(string)
		heads := headsAt(blog, at)
		if heads == nil {
			continue
		}
		for _, s := range e.Entries {
			if s.Kind != "head" && s.Kind != "tombstone" {
				continue
			}
			if bid, ok := heads[s.Resource]; ok {
				p.points[s.Resource] = Pair{Batch: e.ID, Author: e.Author, Kid: e.Kid, At: at, Branch: bid, Target: s.Target}
			}
		}
	}
	return nil
}

func principal(sub, kid string) string {
	if kid == "" {
		return sub + " (no kid)"
	}
	return sub + "/" + kid
}

// Hints explains, in words, why earlier merge batches were or weren't used
// as common ancestors (§F.3).
func (p *Plan) Hints() []string {
	var out []string
	if !p.AuthorsDeclared {
		out = append(out, p.Target+" declares no merge.authors: earlier merge batches aren't used as common ancestors (§F.3), so after a replayed merge a second merge conflicts; rebase the branch (§F.5) before merging it again, or have a * key holder add \"merge\": { \"authors\": [{ \"sub\", \"kid\" }] } to "+p.Target)
	}
	for _, mb := range p.Ignored {
		if !p.AuthorsDeclared {
			break
		}
		out = append(out, "merge batch "+mb.Batch+" from "+p.Branch+" doesn't count as a common ancestor: "+mb.Reason+"; if it replayed resources, rebase the branch (§F.5) before merging it again")
	}
	return out
}

// IsMergeOf reports whether e is a batch entry without origin whose
// source.ns is branch (§F.6).
func IsMergeOf(e client.NSEntry, branch string) bool {
	if e.Kind != "batch" || !e.HasSource || e.Source == nil {
		return false
	}
	if _, remote := e.Source["origin"]; remote {
		return false
	}
	ns, _ := e.Source["ns"].(string)
	at, _ := e.Source["at"].(string)
	return ns == branch && at != ""
}

// ancestry returns the log of ns/name up to head, oldest first. If older
// history is pruned it starts at the horizon (a synthetic entry without
// patches) and truncated is set.
func (p *Plan) ancestry(ctx context.Context, ns, name, head string) (ancestry, error) {
	key := ns + "/" + name + "@" + head
	if a, ok := p.logs[key]; ok {
		return a, nil
	}
	es, err := p.c.Log(ctx, ns, name, head, "")
	var a ancestry
	switch {
	case err == nil:
		a = ancestry{entries: es}
	case client.IsPruned(err) && client.Horizon(err) != "":
		hz := client.Horizon(err)
		es, err = p.c.Log(ctx, ns, name, head, hz)
		if err != nil {
			return ancestry{}, err
		}
		a = ancestry{entries: append([]client.LogEntry{{ID: hz}}, es...), truncated: true}
	default:
		return ancestry{}, err
	}
	p.logs[key] = a
	return a, nil
}

func indexOf(es []client.LogEntry, id string) int {
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].ID == id {
			return i
		}
	}
	return -1
}

func (r *Resource) reset() {
	r.Class, r.Base, r.BaseState = "", "", ""
	r.Ancestor, r.TargetAncestor = "", ""
	r.IfMatch, r.IfNoneMatch, r.Steps, r.Expected = "", false, nil, nil
	r.BranchWrites, r.BaseWrites, r.Conflicts = nil, nil, nil
	r.Squashed, r.Note, r.Kept, r.Pair = false, "", false, nil
}

func (r *Resource) conflict(kind, msg string, paths ...string) {
	r.Conflicts = append(r.Conflicts, Conflict{Kind: kind, Message: msg, Paths: paths})
}

// classify (re)computes r's classification and item against the target's
// current head.
func (p *Plan) classify(ctx context.Context, r *Resource) error {
	resolution, resolvedAt, hadResolution := r.resolution, r.resolvedAt, r.Resolved || r.Dropped
	r.reset()
	r.Resolved, r.Dropped = false, false
	if r.branchPurged {
		r.Class, r.BaseState, r.Note = Purged, "unknown", "purged in the branch"
		return nil
	}
	h, err := p.c.Head(ctx, p.Target, r.Name)
	if err != nil {
		return err
	}
	r.BaseState = h.State.String()
	switch h.State {
	case client.Purged:
		r.Class, r.Note = Purged, "purged in the target"
		return nil
	case client.Live, client.Tombstoned:
		r.Base = h.ID
	}
	if err := p.classifyAncestry(ctx, r, h); err != nil {
		return err
	}
	if hadResolution {
		if resolvedAt == r.Base && (r.Class == FastForward || r.Class == Replay) {
			p.applyResolution(r, resolution)
		} else if r.Class == FastForward || r.Class == Replay {
			r.conflict(ConflictStaleResolution, "the target moved after the resolution was written; resolve again against "+orAbsent(r.Base))
			r.resolution, r.resolvedAt = nil, ""
		}
	}
	if p.opt.Squash && r.HasItem() && !r.NeedsPerson() && !r.Resolved {
		if err := p.squash(ctx, r, h); err != nil {
			return err
		}
	}
	return nil
}

func orAbsent(id string) string {
	if id == "" {
		return "(absent)"
	}
	return id
}

func (p *Plan) classifyAncestry(ctx context.Context, r *Resource, h *client.Head) error {
	B, H := r.Base, r.Branch
	if B == H {
		r.Class = Merged
		return nil
	}
	ha, err := p.ancestry(ctx, p.Branch, r.Name, H)
	if err != nil {
		return err
	}
	hes := ha.entries

	fastForward := func(after int, parent string) error {
		r.Class = FastForward
		entries := hes[after+1:]
		r.Steps = stepsOf(entries)
		if parent == "" {
			r.IfNoneMatch = true
		} else {
			r.IfMatch = parent
		}
		if hasPruned(r.Steps) {
			r.conflict(ConflictPruned, "a patch set the fast-forward needs was pruned")
			return nil
		}
		exp, err := expectedIDs(parent, r.Steps)
		if err != nil {
			return err
		}
		for i, e := range entries {
			if exp[i] != e.ID {
				return fmt.Errorf("fast-forward of %s: step %d would produce %s, the branch has %s", r.Name, i, exp[i], e.ID)
			}
		}
		r.Expected = exp
		return nil
	}

	if B == "" {
		// Absent in the target: an ancestor of everything, if the branch's
		// chain starts with its own genesis.
		if ha.truncated {
			r.Class = FastForward
			r.IfNoneMatch = true
			r.conflict(ConflictPruned, "the resource is absent in the target and the branch's early history was pruned")
			return nil
		}
		if len(hes) > 0 && hes[0].Parent != "" {
			r.Class = Replay
			r.IfNoneMatch = true
			r.conflict(ConflictNoCommonAncestor, "the branch's chain starts at "+hes[0].Parent+", which the target doesn't have")
			return nil
		}
		return fastForward(-1, "")
	}
	if i := indexOf(hes, B); i >= 0 {
		return fastForward(i, B)
	}
	ba, err := p.ancestry(ctx, p.Target, r.Name, B)
	if err != nil {
		return err
	}
	bes := ba.entries
	if indexOf(bes, H) >= 0 {
		r.Class = Behind
		return nil
	}

	// Latest common ancestor by id.
	inB := map[string]int{}
	for i, e := range bes {
		inB[e.ID] = i
	}
	hi, bi := -1, -1
	for i := len(hes) - 1; i >= 0; i-- {
		if j, ok := inB[hes[i].ID]; ok {
			hi, bi = i, j
			break
		}
	}
	// The pair from the most recent trusted merge batch, if it is later
	// than the common ancestor by ids.
	if mp, ok := p.points[r.Name]; ok {
		pair := mp
		r.Pair = &pair
		mh := indexOf(hes, mp.Branch)
		mb, ok := inB[mp.Target]
		if mh >= 0 && ok && mh > hi {
			hi, bi = mh, mb
			pair.Used = true
		}
	}
	r.Class = Replay
	r.IfMatch = B
	defer p.hintIgnored(r)
	if hi < 0 {
		if ha.truncated || ba.truncated {
			r.conflict(ConflictPruned, "no common ancestor in the history that is left (pruned)")
		} else {
			r.conflict(ConflictNoCommonAncestor, "the branch and the target have no common ancestor")
		}
		return nil
	}
	r.Ancestor, r.TargetAncestor = hes[hi].ID, bes[bi].ID
	if hi == len(hes)-1 {
		// H itself was merged earlier; the target moved on since.
		r.Class, r.IfMatch = Merged, ""
		r.Note = "merged earlier (" + r.TargetAncestor + ")"
		if B != r.TargetAncestor {
			r.Class = Behind
		}
		return nil
	}
	r.Steps = stepsOf(hes[hi+1:])
	baseSteps := stepsOf(bes[bi+1:])
	if hasPruned(r.Steps) || hasPruned(baseSteps) {
		r.conflict(ConflictPruned, "patch sets after the common ancestor were pruned")
		return nil
	}

	// Documents at the ancestor on each side.
	bstart, err := p.docAt(ctx, p.Branch, r.Name, hes, hi)
	if err != nil {
		return err
	}
	tstart := bstart
	if r.TargetAncestor != r.Ancestor {
		if tstart, err = p.docAt(ctx, p.Target, r.Name, bes, bi); err != nil {
			return err
		}
	}
	if bstart == nil || tstart == nil {
		r.conflict(ConflictPruned, "the common ancestor's document is not available (pruned)")
		return nil
	}
	bsc, err := foldWrites(*bstart, r.Steps)
	if err != nil {
		r.conflict(ConflictUnreadable, "branch side: "+err.Error())
		return nil
	}
	tsc, err := foldWrites(*tstart, baseSteps)
	if err != nil {
		r.conflict(ConflictUnreadable, "target side: "+err.Error())
		return nil
	}
	r.BranchWrites = stringsOf(bsc.writes)
	r.BaseWrites = stringsOf(tsc.writes)

	targetDeleted := h.State == client.Tombstoned
	switch {
	case targetDeleted && r.BranchDeleted:
		// Deleted on both sides: the target already has the outcome.
		r.Class, r.IfMatch, r.Steps = Merged, "", nil
		r.Note = "deleted on both sides"
		return nil
	case r.BranchDeleted && bsc.deletes && tsc.revs:
		r.conflict(ConflictDeleteVsChange, "the branch deletes a document the target changed since "+r.TargetAncestor)
	case targetDeleted && tsc.deletes && bsc.revs:
		r.conflict(ConflictChangeVsDelete, "the branch changes a document the target deleted since "+r.TargetAncestor)
	}
	if ov := Overlaps(bsc.writes, tsc.writes); len(ov) > 0 {
		r.conflict(ConflictOverlap, "both sides wrote these paths since the common ancestor", ov...)
	}
	return nil
}

// hintIgnored adds a note to a conflicting replay when an earlier merge
// batch with an entry for the resource didn't count as a merge point.
func (p *Plan) hintIgnored(r *Resource) {
	ig := p.ignoredFor[r.Name]
	if len(ig) == 0 || len(r.Conflicts) == 0 || (r.Pair != nil && r.Pair.Used) {
		return
	}
	mb := ig[len(ig)-1]
	note := "earlier merge batch " + mb.Batch + " by " + principal(mb.Author, mb.Kid) + " isn't a common ancestor (" + mb.Reason + "); rebase the branch (§F.5) before merging it again"
	if r.Note != "" {
		note = r.Note + "; " + note
	}
	r.Note = note
}

// keepStep is the step that records a resource kept at the target's live
// head (§F.3): an empty patch set, which writes a revision with identical
// content, or in a sealed namespace a patch set that only adds a fresh
// $nonce, since every patch set there must refresh it (§E.2.5).
func (p *Plan) keepStep() client.Step {
	if p.TargetLevel == "sealed" {
		return client.PatchStep([]any{map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()}})
	}
	return client.PatchStep([]any{})
}

// docAt returns the document state at es[i] (for a tombstone, the last live
// document, deleted). nil if the document was pruned.
func (p *Plan) docAt(ctx context.Context, ns, name string, es []client.LogEntry, i int) (*docState, error) {
	deleted := false
	j := i
	for j >= 0 && es[j].Kind == "tombstone" {
		deleted = true
		j--
	}
	if j < 0 {
		return nil, nil
	}
	d, err := p.c.Doc(ctx, ns, name, es[j].ID)
	if err != nil {
		if client.IsPruned(err) || client.IsGone(err) {
			return nil, nil
		}
		return nil, err
	}
	return &docState{doc: d.Value, exists: true, deleted: deleted}, nil
}
