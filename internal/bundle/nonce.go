package bundle

import (
	"context"
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
//     it would write don't carry one: it can be re-authored or imported
//     as a snapshot. A renamed import's rewritten steps are new content,
//     and get a fresh $nonce as generated ones do (rename.go).

// docNonce reports whether a namespace document requires nonces.
func docNonce(doc any) bool {
	m, _ := doc.(map[string]any)
	return m["nonce"] == "required"
}

// requireNonces applies the setting of the targets that require nonces
// (nonces, by target namespace); checkNonces checks the full history they
// receive, once rename knows what it rewrites.
func (im *importer) requireNonces(nonces map[string]bool) {
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
	im.nonces = nonces
}

// checkNonces refuses full history that a target requiring nonces would
// receive without them (unnonced), before anything is written.
func (im *importer) checkNonces(ctx context.Context) error {
	var problems []string
	for _, k := range im.keys {
		d := im.docs[k]
		if d.info.History != Full || !im.nonces[d.tns] || d.rw != nil {
			continue
		}
		id, err := im.unnonced(ctx, d)
		if err != nil {
			return fmt.Errorf("import: %s: %w", k, err)
		}
		if id != "" {
			problems = append(problems, fmt.Sprintf("%s requires nonces (§C.7), and the full history of %s has revision %s without a fresh $nonce differing from its parent's, "+
				"which its gate refuses: import the document as a snapshot (export it with --history snapshot), or re-author its history with a fresh $nonce per step", d.tns, k, id))
		}
	}
	if len(problems) > 0 {
		return &AccessError{Problems: problems}
	}
	return nil
}

// unnonced returns the first revision lacking a fresh $nonce
// (withoutNonces) among the lines a full-history import of d writes to
// create or fast-forward it, or "". Lines the target already holds aren't
// written again. Where it diverged, only a resolution writes: take
// generates nonced patch sets, and a replay is left to the target's gate.
// A requires the target lacks is check's to report.
func (im *importer) unnonced(ctx context.Context, d *bdoc) (string, error) {
	th, err := im.head(ctx, d.tns, d.name)
	if err != nil {
		return "", err
	}
	from := 0
	switch i, in := d.idx[th.ID]; {
	case in:
		from = i + 1
	case th.State == client.Purged, th.ID != d.requires:
		return "", nil
	}
	if from == len(d.lines) {
		return "", nil
	}
	var doc any
	live := false
	if d.requires != "" {
		if doc, live, err = im.targetState(ctx, d.tns, d.name, d.requires); err != nil {
			return "", err
		}
	}
	return withoutNonces(doc, live, d.lines, from), nil
}

// withoutNonces replays lines onto doc (live: not a tombstone) and returns
// the first revision from lines[from] on whose resulting document lacks a
// $nonce of the fresh form that differs from the one of the document it
// applies to (the last live one for a restore), or "". History whose
// patch sets were pruned is left to the target's gate.
func withoutNonces(doc any, live bool, lines []*Line, from int) string {
	for i, l := range lines {
		prev, _ := doc.(map[string]any)
		was, _ := prev["$nonce"].(string)
		nd, nl, err := verify.Replay(doc, live, []client.LogEntry{l.LogEntry()})
		if err != nil {
			return ""
		}
		if i >= from && l.Kind == "rev" {
			m, _ := nd.(map[string]any)
			if n, _ := m["$nonce"].(string); !seal.ValidNonce(n) || n == was {
				return l.ID
			}
		}
		doc, live = nd, nl
	}
	return ""
}
