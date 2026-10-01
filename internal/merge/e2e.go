package merge

import (
	"context"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// sealItems seals the items of an e2e target under its keys (§F.8): for
// each resource with an item that doesn't need a person, it folds the
// steps onto the target's document at B, validates every resulting
// document against its $schema (§E.3.2) and seals each patch set bound to
// the target and to the id the step before produces (the batch writes
// them in order). A document that doesn't validate makes the resource an
// "invalid" conflict (a resolution that produced it no longer counts).
// Sealed steps are kept while the item stays the same, so a resubmission
// sends the same bytes and ids (§E.3.1); a re-classification or a new
// resolution seals again.
func (p *Plan) sealItems(ctx context.Context) error {
	if p.TargetLevel != "e2e" {
		return nil
	}
	for _, r := range p.Resources {
		if !r.HasItem() || r.NeedsPerson() {
			continue
		}
		key := itemKey(r)
		if r.sealed != nil && r.sealedFor == key {
			continue
		}
		r.sealed, r.sealedFor = nil, ""
		r.dropConflicts(ConflictInvalid)
		steps, msg, err := p.sealSteps(ctx, r)
		if err != nil {
			return fmt.Errorf("merge: sealing %s for %s: %w", r.Name, p.Target, err)
		}
		if msg != "" {
			r.conflict(ConflictInvalid, msg)
			r.Resolved = false
			continue
		}
		r.sealed, r.sealedFor = steps, key
	}
	return nil
}

// itemKey identifies an item: its precondition and plaintext steps.
func itemKey(r *Resource) string {
	return fmt.Sprintf("%s\n%v\n%s", r.IfMatch, r.IfNoneMatch, jsonv.Canonical(jsonv.FromGo(StepsJSON(r.Steps))))
}

func (r *Resource) dropConflicts(kind string) {
	out := r.Conflicts[:0:0]
	for _, c := range r.Conflicts {
		if c.Kind != kind {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		out = nil
	}
	r.Conflicts = out
}

// sealSteps folds and seals r's steps onto the target's head (see
// sealItems). msg reports a step that doesn't apply or a document that
// doesn't validate.
func (p *Plan) sealSteps(ctx context.Context, r *Resource) (steps []client.Step, msg string, err error) {
	x := p.opt.E2E
	var doc any
	exists := false
	switch {
	case r.BaseState == client.Live.String():
		if doc, err = p.doc(ctx, p.Target, r.Name, r.Base); err != nil {
			return nil, "", err
		}
		exists = true
	case r.BaseState == client.Tombstoned.String() && r.baseLast != "":
		// A patch set on a tombstone restores the last live document.
		if doc, err = p.doc(ctx, p.Target, r.Name, r.baseLast); err != nil {
			return nil, "", err
		}
		exists = true
	}
	prev := r.Base
	if r.IfNoneMatch {
		prev = ""
	}
	for i, s := range r.Steps {
		if s.Delete {
			if prev, err = client.ExpectedTombstone(prev); err != nil {
				return nil, "", err
			}
			steps = append(steps, client.DeleteStep())
			continue
		}
		v, err := client.ToValue(s.Patches)
		if err != nil {
			return nil, "", err
		}
		ops, err := patch.Parse(v)
		if err != nil {
			return nil, fmt.Sprintf("step %d: %v", i, err), nil
		}
		nd, _, err := patch.Apply(jsonv.Clone(doc), exists, ops, patch.Options{})
		if err != nil {
			return nil, fmt.Sprintf("step %d doesn't apply: %v", i, err), nil
		}
		if m, err := x.ValidateIn(ctx, p.Target, nd); err != nil {
			return nil, "", err
		} else if m != "" {
			return nil, fmt.Sprintf("step %d: the document doesn't validate against its $schema: %s", i, m), nil
		}
		// The re-sealed op keeps its declared blob list: the blobs of the
		// document it produces (§E.3.1, §F.8.1).
		body, err := x.SealPatchesBlobs(ctx, p.Target, r.Name, prev, v, client.BlobIDs(nd))
		if err != nil {
			return nil, "", err
		}
		sealed, err := jsonv.Parse(body)
		if err != nil {
			return nil, "", err
		}
		if prev, err = client.ExpectedRevision(prev, sealed); err != nil {
			return nil, "", err
		}
		steps = append(steps, client.PatchStep(sealed))
		doc, exists = nd, true
	}
	return steps, "", nil
}
