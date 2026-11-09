package core

import "time"

// maxEdgeTTL is the longest an edge grant lives (§C.5.2), edge.MaxGrantTTL,
// which the core can't import (internal/edge's tests import the core).
const maxEdgeTTL = 15 * time.Minute

// filteredEdgeGrant is edgeGrant for a partial reader of a covered
// namespace whose grant doesn't fix /resource (§B.11.9 Edge grants): its
// edge grant covers /ns/{ns}/g/{gs} alone, gs its subject set at the
// current checkpoint. §C.5.2's refusals concerning /resource rules and
// qualifying roles don't apply, and of its check that rules pass now only
// the block and key-scope rules that don't refer to /resource are
// evaluated, item 2 judging the rest per resource; its refusals for no
// read (edgeGrant's, before this) and for /now (grantView's) still do.
// The issue carries the filtered_gs row IssueEdgeGrants records, with exp
// that of the cookie at the longest, never past the grant's.
func (t *tx) filteredEdgeGrant(n *nsRow, fs *fscope, a *actor, exp time.Time) (*edgeIssue, *Error) {
	env := t.basicEnvelope("read", "", a)
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil {
				return nil, forbidden("the grant's rules refuse reading " + n.name)
			}
			if refs := r.Refs(); refs["now"] || refs["*"] {
				continue // grantView refuses them
			}
			if !r.Refs()["resource"] && !r.Eval(env) {
				return nil, forbidden("the grant's rules refuse reading " + n.name)
			}
		}
	}
	fv, err := t.grantView(fs, t.filteredCurrent(fs), a)
	if err != nil {
		return nil, err
	}
	if n.purged {
		pe := t.purgedNS(n)
		pe.Body["ns"] = n.name
		return nil, pe
	}
	until := t.now.Add(maxEdgeTTL)
	if !exp.IsZero() && exp.Before(until) {
		until = exp
	}
	return &edgeIssue{gs: fv.gs, rec: gsRecordOf(fv, until.Unix()), bucket: a.bucketKey}, nil
}
