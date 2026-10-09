package core

import (
	"context"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// Required nonces (§C.7). A namespace with "nonce": "required" has the
// server check what writers of guessable content would otherwise forget:
// every resource create, append and restore must result in a document
// whose top-level $nonce has the fresh form and differs from its parent's,
// whatever the patch set's origin (fast-forwards and imports included).
// Deletes, and config, branch and prune writes, are exempt. A branch
// copies the setting and can't turn it off, a base can't start requiring
// nonces while a dependent doesn't (§7.4), and a remote branch of a base
// whose current document requires them must be created requiring them
// (§G.3).

// checkRequiredNonces is the check of gate step 3 (§6.2) for an item of a
// namespace that requires nonces: each create, append or restore must
// result in a document with a top-level $nonce of the fresh form
// (seal.ValidNonce) that differs from the one of the document it applied
// to, the last live document for a restore. A fresh value can't be told
// from an old one coming back; differing from the parent is what is
// checked.
func checkRequiredNonces(s *itemState) *Error {
	for _, st := range s.steps {
		if st.del {
			continue
		}
		m, _ := st.doc.(map[string]any)
		if n, _ := m["$nonce"].(string); !seal.ValidNonce(n) || n == st.prevNonce {
			return apiErr(422, "nonce", "message", "this namespace requires nonces: a create, append or restore must result in a document whose top-level $nonce "+
				"is 128 fresh random bits as 26 base32 characters, differing from its parent's (the last live document's for a restore); add /$nonce in every patch set, "+
				"a restore that would be [] included. History written without nonces can be re-authored with a fresh $nonce per step, or imported as a snapshot (§C.7)")
		}
	}
	return nil
}

// checkNonceBase refuses a branch's namespace document that turns off a
// nonce requirement its base has (§7.6, §C.7). cur is the branch's config,
// nil for a branch being created, which copies the setting; a branch made
// before its base set it never had it on, so leaving it off turns nothing
// off. base is the branch's base, nil for a namespace that isn't a branch.
// A remote branch's shadow holds what its base required when the branch
// was created (insertShadow).
func (t *tx) checkNonceBase(cur, cfg *Config, base *nsRow) *Error {
	if base != nil && !cfg.NonceRequired && (cur == nil || cur.NonceRequired) && t.config(base.configSeq).NonceRequired {
		return invalid(`/nonce: a branch can't turn off the nonce requirement its base has (§7.6, §C.7)`)
	}
	return nil
}

// checkNonceDependents refuses a namespace document that starts requiring
// nonces while a dependent of n, a branch at any depth that isn't purged,
// doesn't: its history would no longer merge back (§7.4, §C.7). They are
// listed leaves first, the order to set them in.
func (t *tx) checkNonceDependents(n *nsRow, cur, cfg *Config) *Error {
	if !cfg.NonceRequired || cur.NonceRequired {
		return nil
	}
	if deps := t.nonceDependents(n); len(deps) > 0 {
		return apiErr(409, "in_use", "dependents", anyStrings(deps), "message", "require nonces in these branches first, leaves first (§7.4, §C.7)")
	}
	return nil
}

// nonceDependents lists the dependents of n that don't require nonces,
// leaves first.
func (t *tx) nonceDependents(n *nsRow) []string {
	var out []string
	for _, b := range t.branchesOf(n) {
		if b.purged {
			continue
		}
		out = append(out, t.nonceDependents(b)...)
		if !t.config(b.configSeq).NonceRequired {
			out = append(out, b.name)
		}
	}
	return out
}

// fetchSchemaNonces reads which namespaces of a remote branch's schema
// closure require nonces at the base's deployment, so a schema namespace
// created here for them takes its source's setting (requireNonces). A
// namespace document the endpoint can't read leaves the setting optional:
// mirroring writes nothing through the gate, so only later writes here
// would be checked.
func fetchSchemaNonces(ctx context.Context, c *client.Client, schemas []*remoteSchema) map[string]bool {
	out := map[string]bool{}
	for _, s := range schemas {
		if _, done := out[s.ns]; done {
			continue
		}
		req, err := c.NonceRequired(ctx, s.ns)
		out[s.ns] = err == nil && req
	}
	return out
}

// requireNonces turns on the nonce requirement of a schema namespace that
// mirrorSchemas created for a remote branch, whose source requires nonces:
// it starts optional, since its history keeps its ids, and takes the
// setting with a config write once that history is in, so later writes
// there stay exportable (§C.7, §G.3). author is the creating operator, as
// for the namespace's other entries.
func (t *tx) requireNonces(n *nsRow, author int64) {
	cur := t.config(n.configSeq)
	if cur.level == levelE2E {
		return // not allowed there (§C.7)
	}
	cc := &ConfigChange{IfMatch: t.configID(n.configSeq).String(), Patches: []any{map[string]any{"op": "add", "path": "/nonce", "value": "required"}}}
	p, err := t.planConfig(n, cur, &actor{star: true}, cc, false)
	t.must(err)
	seq := t.insertConfig(n, p, author)
	t.appendNS(n, map[string]any{"kind": "config", "target": p.id.String()}, nil, &seq, seq, author)
}
