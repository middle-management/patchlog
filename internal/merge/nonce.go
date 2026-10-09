package merge

import (
	"context"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// nonces reports whether the patch sets the plan builds for the target
// need a fresh $nonce: a sealed target refreshes it in every patch set
// (§E.2.5), and one that requires nonces checks every resulting document
// (§C.7).
func (p *Plan) nonces() bool { return p.TargetLevel == "sealed" || p.TargetNonce }

// noncePlan is a plan that knows only whether target needs a fresh $nonce
// (nonces), for steps built before the target can classify them: the
// planned second half of a split node (stepPlan).
func noncePlan(ctx context.Context, c *client.Client, target string) (*Plan, error) {
	p := &Plan{}
	var err error
	if p.TargetLevel, err = c.EncryptionLevel(ctx, target); err != nil {
		return nil, err
	}
	th, err := c.NSHead(ctx, target)
	if err != nil {
		return nil, err
	}
	tdoc, err := c.NSDoc(ctx, target, th.ID)
	if err != nil {
		return nil, err
	}
	p.TargetNonce = tdoc.Value["nonce"] == "required"
	return p, nil
}

// stateNonce returns patches, a write to a document of the release tool's
// state namespace ns (a stored plan or a lock), with a fresh $nonce added
// at the end where one is needed (§C.7): ns requires nonces, or the
// document as last read had one (had), which is all a merge service that
// can't read the namespace document has to go by. It reports whether it
// added one.
func stateNonce(ctx context.Context, c *client.Client, ns string, had bool, patches []any) ([]any, bool) {
	if !had {
		if req, err := c.NonceRequired(ctx, ns); err != nil || !req {
			return patches, false
		}
	}
	return append(patches, map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()}), true
}

// nonceless returns doc without its top-level $nonce where the target
// needs a fresh one, so a diff for it leaves the nonce out (§F.3 Nonces);
// doc itself otherwise.
func (p *Plan) nonceless(doc any) any {
	if !p.nonces() {
		return doc
	}
	return dropNonce(doc)
}

// dropNonce returns doc without its top-level $nonce, if it has one.
func dropNonce(doc any) any {
	m, ok := doc.(map[string]any)
	if _, has := m["$nonce"]; !ok || !has {
		return doc
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != "$nonce" {
			out[k] = v
		}
	}
	return out
}

// withNonces returns steps with a fresh $nonce added at the end of every
// patch set, where the target needs one: resolution and squash sets (§F.3,
// §C.7). Deletes are left as they are, and so are steps that already
// carry a signature, which a nonce added here would break.
func (p *Plan) withNonces(steps []client.Step) []client.Step {
	if !p.nonces() || len(steps) == 0 {
		return steps
	}
	out := make([]client.Step, len(steps))
	for i, s := range steps {
		out[i] = s
		if s.Delete || s.Signature != "" {
			continue
		}
		ps, err := client.ToValue(s.Patches)
		arr, ok := ps.([]any)
		if err != nil || !ok {
			continue // not a patch set: the server reports it
		}
		out[i].Patches = append(append([]any{}, arr...), map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
	}
	return out
}
