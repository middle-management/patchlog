package bundle

import (
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/verify"
)

// Targets that require nonces (§C.7). Their gate checks every patch set,
// whatever its origin, for a resulting document with a fresh $nonce that
// differs from its parent's. So the importer:
//
//   - creates a snapshot document's upstream namespace with its target's
//     setting, since the target fast-forwards from it (§G.4.4), and gives
//     the patch sets it generates there and in the target a fresh $nonce,
//     as for sealed targets (sealedT);
//   - refuses, before anything is written, full history whose revisions
//     don't carry one: it can be re-authored or imported as a snapshot.

// docNonce reports whether a namespace document requires nonces.
func docNonce(doc any) bool {
	m, _ := doc.(map[string]any)
	return m["nonce"] == "required"
}

// requireNonces applies the setting of the targets that require nonces
// (nonces, by target namespace) and returns the problems it finds.
func (im *importer) requireNonces(nonces map[string]bool) []string {
	for _, k := range im.keys {
		d := im.docs[k]
		if d.info.History != Snapshot || !nonces[d.tns] {
			continue
		}
		u := im.upstreamNS(d.ns)
		if doc, ok := im.create[u].(map[string]any); ok && doc["nonce"] == nil {
			c := make(map[string]any, len(doc)+1)
			for k, v := range doc {
				c[k] = v
			}
			c["nonce"] = "required"
			im.create[u] = c
		}
		nonces[u] = true
	}
	for ns, req := range nonces {
		if req {
			im.sealedT[ns] = true
		}
	}
	var problems []string
	for _, k := range im.keys {
		d := im.docs[k]
		if d.info.History != Full || !nonces[d.tns] {
			continue
		}
		if id := withoutNonces(d.lines); id != "" {
			problems = append(problems, fmt.Sprintf("%s requires nonces (§C.7), and the full history of %s has revision %s without a fresh $nonce differing from its parent's, "+
				"which its gate refuses: import the document as a snapshot (export it with --history snapshot), or re-author its history with a fresh $nonce per step", d.tns, k, id))
		}
	}
	return problems
}

// withoutNonces returns the first revision of a history whose resulting
// document lacks a $nonce of the fresh form that differs from the one of
// the document it applies to (the last live one for a restore), or "".
// History that doesn't start at genesis, or whose patch sets were pruned,
// is left to the target's gate.
func withoutNonces(lines []*Line) string {
	if len(lines) == 0 || lines[0].Parent != "" {
		return ""
	}
	var doc any
	live := false
	for _, l := range lines {
		prev, _ := doc.(map[string]any)
		was, _ := prev["$nonce"].(string)
		nd, nl, err := verify.Replay(doc, live, []client.LogEntry{l.LogEntry()})
		if err != nil {
			return ""
		}
		if l.Kind == "rev" {
			m, _ := nd.(map[string]any)
			if n, _ := m["$nonce"].(string); !seal.ValidNonce(n) || n == was {
				return l.ID
			}
		}
		doc, live = nd, nl
	}
	return ""
}
