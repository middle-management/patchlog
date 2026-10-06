package merge

import (
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"
)

// SignSteps returns steps with the writer's own author signature on each
// (§C.3.1), as a batch item of ns/name whose first step has parent
// ("" = genesis) is judged: the first step's parent is the item's
// If-Match, a later step's the id the step before it produces. origin is
// the target deployment's origin from GET /. Any signature the steps
// carried is replaced: a step's signature is always the writer's own,
// never a source revision's, which don't verify in the target (§C.3).
//
// Steps with nil Patches (pruned history) can't be signed and are an error.
func SignSteps(k sig.Key, origin, ns, name, parent string, steps []client.Step) ([]client.Step, error) {
	out := make([]client.Step, len(steps))
	var par *ids.ID
	if parent != "" {
		id, err := ids.Parse(parent)
		if err != nil {
			return nil, fmt.Errorf("merge: signing %s/%s: %w", ns, name, err)
		}
		par = &id
	}
	for i, s := range steps {
		if s.Delete {
			if par == nil {
				return nil, fmt.Errorf("merge: signing %s/%s: step %d deletes a resource with no parent", ns, name, i)
			}
			s.Signature = k.SignTombstone(origin, ns, name, *par)
			id := ids.Tombstone(*par)
			par = &id
		} else {
			if s.Patches == nil {
				return nil, fmt.Errorf("merge: signing %s/%s: step %d has no patch set", ns, name, i)
			}
			v, err := client.ToValue(s.Patches)
			if err != nil {
				return nil, fmt.Errorf("merge: signing %s/%s: step %d: %w", ns, name, i, err)
			}
			body := jsonv.Canonical(v)
			s.Signature = k.SignPatches(origin, ns, name, par, body)
			id := ids.Revision(par, body)
			par = &id
		}
		out[i] = s
	}
	return out, nil
}

// signItems signs the steps of req's items with the plan's signer, if it
// has one.
func (p *Plan) signItems(req *client.BatchRequest) error {
	if p.opt.Signer == nil {
		return nil
	}
	if p.origin == "" {
		return fmt.Errorf("merge: signing needs the origin of the target deployment")
	}
	for i, it := range req.Items {
		steps, err := SignSteps(*p.opt.Signer, p.origin, p.Target, it.Resource, it.IfMatch, it.Steps)
		if err != nil {
			return err
		}
		req.Items[i].Steps = steps
	}
	return nil
}
