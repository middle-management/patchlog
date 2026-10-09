package merge

import (
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// nonces reports whether the patch sets the plan builds for the target
// need a fresh $nonce: a sealed target refreshes it in every patch set
// (§E.2.5), and one that requires nonces checks every resulting document
// (§C.7).
func (p *Plan) nonces() bool { return p.TargetLevel == "sealed" || p.TargetNonce }

// nonceless returns doc without its top-level $nonce where the target
// needs a fresh one, so a diff for it leaves the nonce out (§F.3 Nonces);
// doc itself otherwise.
func (p *Plan) nonceless(doc any) any {
	m, ok := doc.(map[string]any)
	if _, has := m["$nonce"]; !ok || !has || !p.nonces() {
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
