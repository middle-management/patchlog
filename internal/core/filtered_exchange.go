package core

import (
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// maxEdgeTTL is the longest an edge grant lives (§C.5.2), edge.MaxGrantTTL,
// which the core can't import (internal/edge's tests import the core).
const maxEdgeTTL = 15 * time.Minute

// filteredEdgeGrant is edgeGrant for a partial reader of a covered
// namespace whose grant doesn't fix /resource (§B.11.9 Edge grants): its
// edge grant covers /ns/{ns}/g/{gs} alone, gs its subject set at the
// current checkpoint. §C.5.2's refusals concerning /resource rules and
// qualifying roles don't apply, and of its check that rules pass now only
// the block and key-scope rules that don't refer to /resource are
// evaluated, item 2 judging the rest per resource; its refusal for no
// read still does. A rule there that refers to /now fails, as for any
// read, and a grant with roles needs one that lists read without a rule
// on /now (§C.2 item 5, §B.11.9 Partial reader).
// The issue carries the filtered_gs row IssueEdgeGrants records, with exp
// that of the cookie at the longest, never past the grant's.
func (t *tx) filteredEdgeGrant(n *nsRow, fs *fscope, a *actor, exp time.Time) (*edgeIssue, *Error) {
	if _, ok := readRoles(a); !ok {
		return nil, forbidden("no role of the grant lists read without a rule on /now, which no read passes (§C.2 item 5): " + n.name)
	}
	env := t.basicEnvelope("read", "", a)
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil {
				return nil, forbidden("the grant's rules refuse reading " + n.name)
			}
			if refersToNow(r) {
				return nil, forbidden("the grant's rules refuse reading " + n.name + ": a rule that refers to /now passes no read (§C.2 item 5)")
			}
			if !r.Refs()["resource"] && !t.readRule(r, env) {
				return nil, forbidden("the grant's rules refuse reading " + n.name)
			}
		}
	}
	// An exchange whose budget of validationSteps is spent, by the check
	// of unrestricted read that brought it here or by a rule above, fails
	// as a whole: no cookie for the subject set either (§6.6).
	if t.readSpent() {
		return nil, forbidden("the grant's rules take more than validationSteps steps for this exchange, which fails it (§6.6): " + n.name)
	}
	fv, err := t.grantView(fs, t.filteredCurrent(fs), a)
	if err != nil {
		return nil, err
	}
	if t.readSpent() {
		return nil, forbidden("the grant's rules take more than validationSteps steps for this exchange, which fails it (§6.6): " + n.name)
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
	// The record keeps the digest of the key's entry and the read roles'
	// definitions as of the checkpoint the view is at, which every read
	// under the cookie compares (§B.11.9 gs, gsDigestHolds).
	// It keeps that document's ns_config seq too: the cookie is held to
	// every document of {ns} after it (gsHeldSince, v0.86). Both are of
	// this read snapshot, so a change that commits before the record is
	// written is one after the exchange.
	rec := gsRecordOf(fv, until.Unix())
	rec.conf = t.fconfigSeqAt(fv.cp.seq)
	rec.entry = t.gsEntryDigest(n, t.config(rec.conf), rec.kid, rec.roles)
	return &edgeIssue{gs: fv.gs, rec: rec, bucket: a.bucketKey}, nil
}

// partialReader reports whether a, whose grant allows read in n without
// reading it unrestricted, is a partial reader there (§7.9 Partial
// reader): its blocks and key scope fix no /resource (fixesSomeResource);
// its read rules refer to /resource, those of its blocks or key scope or
// of a read role that tests no literal name; it has a read role without a
// rule on /now if it carries roles (readRoles); and its block and
// key-scope rules that refer neither to /resource nor to /now pass now,
// within its validationSteps. Any other such grant reads nothing of n
// but the resources its rules allow, at their own URLs.
func (t *tx) partialReader(a *actor) bool {
	if a == nil || a.verified == nil {
		return false
	}
	roles, ok := readRoles(a)
	if !ok || fixesSomeResource(a) {
		return false
	}
	refers := refersToResource(a.verified.KeyRules) || refersToResource(a.verified.BlockRules)
	for _, r := range roles {
		if rs := a.verified.RoleRules(r); refersToResource(rs) && !literalResource(rs) {
			refers = true
		}
	}
	if !refers {
		return false
	}
	env := t.basicEnvelope("read", "", a)
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil || refersToNow(r) {
				return false
			}
			if !r.Refs()["resource"] && !t.readRule(r, env) {
				return false
			}
		}
	}
	return !t.readSpent()
}

// literalResource reports whether a rule of rs, at top level or nested
// only in alls, tests /resource against literal names.
func literalResource(rs []any) bool {
	for _, rv := range rs {
		if m, ok := rv.(map[string]any); ok && len(m) == 1 {
			if all, ok := m["all"].([]any); ok && literalResource(all) {
				return true
			}
		}
		if _, ok := grant.ResourceLiterals(rv); ok {
			return true
		}
	}
	return false
}
