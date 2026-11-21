package core

import (
	"time"
)

// maxEdgeTTL is the longest an edge grant lives (§C.5.2), edge.MaxGrantTTL,
// which the core can't import (internal/edge's tests import the core).
const maxEdgeTTL = 15 * time.Minute

// filteredEdgeGrant is edgeGrant for a partial reader of a covered
// namespace (§7.9 Edge grants): its edge grant covers
// /ns/{ns}/view/{view} alone, view its view at the current checkpoint.
// §C.5.2's refusals concerning /resource and /doc rules and qualifying
// roles don't apply, and of its check that rules pass now only the block
// and key-scope rules that refer to neither are evaluated, Visible judging
// the rest per revision; its refusal for no read still does. A rule there
// that refers to /now fails, as for any read, and a grant with roles needs
// one that lists read without a rule on /now (§C.2 item 5, §7.9 Partial
// reader). The issue carries the filtered_views row IssueEdgeGrants
// records, with exp that of the cookie at the longest, never past the
// grant's.
func (t *tx) filteredEdgeGrant(n *nsRow, fs *fscope, a *actor, exp time.Time) (*edgeIssue, *Error) {
	if _, ok := readRoles(a); !ok {
		return nil, forbidden("no role of the grant lists read without a rule on /now, which no read passes (§C.2 item 5): " + n.name)
	}
	if !t.passesNow(a) {
		return nil, forbidden("the grant's rules refuse reading " + n.name)
	}
	// An exchange whose budget of validationSteps is spent, by the check
	// of unrestricted read that brought it here or by a rule above, fails
	// as a whole: no cookie for the view either (§6.6).
	if t.readSpent() {
		return nil, forbidden("the grant's rules take more than validationSteps steps for this exchange, which fails it (§6.6): " + n.name)
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
	// The record keeps the digest of the key's entry and of every role
	// that lists read as of the checkpoint the view is at, which every
	// read under the cookie compares (§7.9 view, viewDigestHolds), and
	// that document's ns_config seq: the cookie is held to every document
	// of {ns} after it (viewHeldSince). Both are of this read snapshot,
	// so a change that commits before the record is written is one after
	// the exchange.
	rec := viewRecordOf(fv, until.Unix())
	rec.conf = t.fconfigSeqAt(fv.cp.seq)
	rec.entry = t.viewEntryDigest(n, t.config(rec.conf), rec.kid)
	return &edgeIssue{view: fv.view, rec: rec, bucket: a.exchangeBucket()}, nil
}

// passesNow reports whether a's block and key-scope rules that refer
// neither to /resource nor to /doc pass now against a read envelope for
// its principal, within the exchange's validationSteps, none referring to
// /now (§7.9 Edge grants).
func (t *tx) passesNow(a *actor) bool {
	env := t.basicEnvelope("read", "", a)
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil || refersToNow(r) {
				return false
			}
			refs := r.Refs()
			if !refs["resource"] && !refs["doc"] && !t.readRule(r, env) {
				return false
			}
		}
	}
	return true
}

// partialReader reports whether a, whose grant verifies in a namespace
// and allows read there through its verbs and, if it carries roles, an
// effective role without a rule on /now (readRoles), and none of whose
// block and key-scope rules refers to /now (the read check refuses those
// before), is a partial reader there (§7.9 Partial reader): it lacks
// unrestricted read, its read rules referring to /doc, or to /resource
// without fixing it (§2.1). Any other grant that lacks unrestricted read
// reads nothing of the namespace but the resources it fixes, at their own
// URLs.
func (t *tx) partialReader(a *actor) bool {
	if a == nil || a.verified == nil || scopeReferToNow(a) {
		return false
	}
	roles, ok := readRoles(a)
	if !ok {
		return false
	}
	if _, unrestricted := a.unrestrictedRoles(); unrestricted {
		return false
	}
	lists := [][]any{a.verified.KeyRules, a.verified.BlockRules}
	for _, r := range roles {
		lists = append(lists, a.verified.RoleRules(r))
	}
	_, fixes := fixedNames(a)
	for _, rs := range lists {
		if refersToDoc(rs) || !fixes && refersToResource(rs) {
			return true
		}
	}
	return false
}
