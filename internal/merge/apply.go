package merge

import (
	"context"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Clean reports whether no resource needs a person (§F.7: every resource
// fast-forwards, or replays without overlapping writes, or is resolved).
func (p *Plan) Clean() bool {
	for _, r := range p.Resources {
		if r.NeedsPerson() {
			return false
		}
	}
	return true
}

// Items returns the resources that contribute batch items, in batch order.
func (p *Plan) Items() []*Resource {
	var out []*Resource
	for _, r := range p.Resources {
		if r.HasItem() {
			out = append(out, r)
		}
	}
	return out
}

// Conflicting returns the resources that need a person.
func (p *Plan) Conflicting() []*Resource {
	var out []*Resource
	for _, r := range p.Resources {
		if r.NeedsPerson() {
			out = append(out, r)
		}
	}
	return out
}

// Resource returns the named resource of the plan, or nil.
func (p *Plan) Resource(name string) *Resource {
	for _, r := range p.Resources {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// Resolve replaces a resource's steps with a resolution written against
// the target's current head B (§F.3), usually one patch set. With no steps
// the resource is dropped: the target is kept as it is. A resolution only
// holds while B stays the same; if Apply finds B moved, the resource
// becomes a stale_resolution conflict again.
func (p *Plan) Resolve(name string, steps ...client.Step) error {
	r := p.Resource(name)
	if r == nil {
		return fmt.Errorf("merge: %s is not in the plan", name)
	}
	if r.Class != FastForward && r.Class != Replay {
		return fmt.Errorf("merge: %s is %s; there is nothing to resolve", name, r.Class)
	}
	r.resolvedAt = r.Base
	r.resolution = append([]client.Step(nil), steps...)
	p.applyResolution(r, r.resolution)
	return nil
}

func (p *Plan) applyResolution(r *Resource, steps []client.Step) {
	r.resolution, r.resolvedAt = steps, r.Base
	r.Expected, r.Squashed = nil, false
	r.IfMatch, r.IfNoneMatch = r.Base, r.Base == ""
	if len(steps) == 0 {
		r.Dropped, r.Resolved, r.Steps = true, true, nil
		return
	}
	r.Steps = steps
	r.Resolved = true
}

// squash replaces r's steps with one set with the same effect (§F.3).
func (p *Plan) squash(ctx context.Context, r *Resource, h *client.Head) error {
	start := docState{}
	switch h.State {
	case client.Live:
		d, err := p.c.Doc(ctx, p.Target, r.Name, h.ID)
		if err != nil {
			return err
		}
		start = docState{doc: d.Value, exists: true}
	case client.Tombstoned:
		d, err := p.c.Doc(ctx, p.Target, r.Name, h.Last)
		if err != nil {
			return err
		}
		start = docState{doc: d.Value, exists: true, deleted: true}
	}
	sc, err := foldWrites(docState{doc: jsonv.Clone(start.doc), exists: start.exists, deleted: start.deleted}, r.Steps)
	if err != nil {
		r.conflict(ConflictUnreadable, "squash: "+err.Error())
		return nil
	}
	fin := sc.final
	r.Squashed, r.Expected = true, nil
	switch {
	case fin.deleted && start.exists && !start.deleted:
		r.Steps = []client.Step{client.DeleteStep()}
	case fin.deleted || !fin.exists:
		// Deleted in the end and not live in the target: nothing to do.
		r.Steps, r.Class, r.IfMatch, r.IfNoneMatch = nil, Merged, "", false
		r.Note = "squashed to no change"
	case !start.exists:
		r.Steps = []client.Step{client.PatchStep(client.GenesisPatches(fin.doc))}
	default:
		d := Diff(start.doc, fin.doc)
		if len(d) == 0 && !start.deleted {
			r.Steps, r.Class, r.IfMatch, r.IfNoneMatch = nil, Merged, "", false
			r.Note = "squashed to no change"
			return nil
		}
		if d == nil {
			d = []any{}
		}
		// A patch set on a tombstone restores (§8.2).
		r.Steps = []client.Step{client.PatchStep(d)}
	}
	return nil
}

// Batch builds the batch request: one item per resource with an item, the
// explicit config change if any, and source { ns: branch, at: branchAt }.
func (p *Plan) Batch() client.BatchRequest {
	req := client.BatchRequest{Source: map[string]any{"ns": p.Branch, "at": p.BranchAt}}
	for _, r := range p.Items() {
		req.Items = append(req.Items, client.BatchItem{Resource: r.Name, IfMatch: r.IfMatch, IfNoneMatch: r.IfNoneMatch, Steps: r.Steps})
	}
	if p.opt.Config != nil {
		req.Config = &client.BatchConfig{IfMatch: p.TargetConfig, Patches: p.opt.Config}
	}
	return req
}

func (p *Plan) empty(req client.BatchRequest) bool { return len(req.Items) == 0 && req.Config == nil }

// checkIDs verifies that fast-forwarded items produced (or would produce)
// exactly the branch's ids.
func (p *Plan) checkIDs(res *client.BatchResult) error {
	items := p.Items()
	for i, r := range items {
		if r.Expected == nil || i >= len(res.Items) {
			continue
		}
		got := res.Items[i].IDs
		if len(got) != len(r.Expected) {
			return fmt.Errorf("merge: %s: %d ids, expected %d", r.Name, len(got), len(r.Expected))
		}
		for j := range got {
			if got[j] != r.Expected[j] {
				return fmt.Errorf("merge: %s: fast-forward produced %s, the branch has %s", r.Name, got[j], r.Expected[j])
			}
		}
	}
	return nil
}

// DryRun submits the batch with ?dry-run=1 (§7.5) and returns the per-item
// report. A failing item is an *client.APIError with code "batch". An empty
// plan returns (nil, nil).
func (p *Plan) DryRun(ctx context.Context) (*client.BatchResult, error) {
	req := p.Batch()
	if p.empty(req) {
		return nil, nil
	}
	res, err := p.c.Batch(ctx, p.Target, req, true)
	if err != nil {
		return nil, err
	}
	return res, p.checkIDs(res)
}

// Result is the outcome of Apply.
type Result struct {
	// NSID is the batch entry in the target ("" if there was nothing to do).
	NSID  string                   `json:"ns_id,omitempty"`
	Items []client.BatchItemResult `json:"-"`
	// IDs maps each merged resource to the ids it got.
	IDs      map[string][]string `json:"ids,omitempty"`
	Attempts int                 `json:"attempts"`
	Noop     bool                `json:"noop,omitempty"`
}

// Apply submits the batch with source { ns: branch, at: branchAt }. If the
// target moved meanwhile, the failing items (412) are re-classified and the
// batch resubmitted, up to MaxRetries times. It returns ErrConflicts when a
// resource needs a person, before or after re-classification.
func (p *Plan) Apply(ctx context.Context) (*Result, error) {
	for attempt := 1; ; attempt++ {
		if !p.Clean() {
			return nil, ErrConflicts
		}
		req := p.Batch()
		if p.empty(req) {
			return &Result{Noop: true, Attempts: attempt}, nil
		}
		res, err := p.c.Batch(ctx, p.Target, req, false)
		if err == nil {
			out := &Result{NSID: res.NSID, Items: res.Items, Attempts: attempt, IDs: map[string][]string{}}
			for _, it := range res.Items {
				out.IDs[it.Resource] = it.IDs
			}
			return out, p.checkIDs(res)
		}
		ae, ok := client.AsAPIError(err)
		if !ok || ae.Status != 412 || attempt > p.opt.MaxRetries {
			return nil, err
		}
		items := p.Items()
		var stale []*Resource
		for _, it := range ae.Items() {
			idx, ok := it["index"].(float64)
			if ok && int(idx) >= 0 && int(idx) < len(items) {
				stale = append(stale, items[int(idx)])
			}
		}
		if len(stale) == 0 {
			return nil, err // e.g. the config precondition
		}
		if th, err := p.c.NSHead(ctx, p.Target); err == nil {
			p.TargetAt = th.ID
		}
		for _, r := range stale {
			if err := p.classify(ctx, r); err != nil {
				return nil, fmt.Errorf("merge: re-classify %s: %w", r.Name, err)
			}
		}
	}
}

// Freeze freezes a merged branch with one config write that also records
// "merged": { "at": mergedAt } (§F.3), the convention the janitor reads
// (§F.6). It retries if the branch's config id moves meanwhile.
func Freeze(ctx context.Context, c *client.Client, branch, mergedAt string) (*client.ConfigResult, error) {
	patches := []any{
		map[string]any{"op": "add", "path": "/frozen", "value": true},
		map[string]any{"op": "add", "path": "/merged", "value": map[string]any{"at": mergedAt}},
	}
	return configWrite(ctx, c, branch, patches)
}

func configWrite(ctx context.Context, c *client.Client, ns string, patches []any) (*client.ConfigResult, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		h, err := c.NSHead(ctx, ns)
		if err != nil {
			return nil, err
		}
		res, err := c.PatchConfig(ctx, ns, h.Config, patches)
		if err == nil {
			return res, nil
		}
		if !client.IsStale(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}
