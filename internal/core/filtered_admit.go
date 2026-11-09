package core

import (
	"fmt"
	"slices"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// grantView is the view of a partial reader's grant at cp (§B.11.9 gs):
// its subjects are catvis.FilteredSubjects over the deciding subjects of
// every deciding catalog's Profile at cp, the grant's groups and its
// ReadsScope digest, and its gs their grantcheck.SubjectSetID, never
// "all". A grant whose read rules refer to /now (or the whole envelope)
// can't read the namespace this way: 403.
func (t *tx) grantView(fs *fscope, cp *fcp, a *actor) (*fview, *Error) {
	digest, ok := grantcheck.ReadsScope(a.verified)
	if !ok {
		return nil, forbidden(fmt.Sprintf("rules referring to /now make %s unreadable this way (§B.11.9)", fs.n.name))
	}
	var deciding [][]string
	cats := make([]*catvis.Catalog, len(cp.cats))
	for i := range cp.cats {
		cats[i] = t.catalogAt(&cp.cats[i], cp)
		subs, _ := cats[i].Profile().Deciding(a.principal)
		deciding = append(deciding, subs)
	}
	subjects := catvis.FilteredSubjects(deciding, a.principal.Groups, digest)
	return t.newFview(fs, cp, grantcheck.SubjectSetID(subjects), subjects, grantcheck.FilterOf(a.verified), a), nil
}

// gsRecordOf is the filtered_gs row of fv, a grant's view, for edge grants
// expiring at exp (Unix seconds).
func gsRecordOf(fv *fview, exp int64) *gsRecord {
	v := fv.a.verified
	in := grantcheck.ScopeInputOf(v)
	digest, _ := grantcheck.ScopeDigest(in)
	roles := make([]string, 0, len(in.Roles))
	for r := range in.Roles {
		roles = append(roles, r)
	}
	slices.Sort(roles)
	return &gsRecord{gs: fv.gs, ns: fv.fs.n.name, subjects: fv.subjects, partial: slices.Contains(fv.subjects, catvis.Partial),
		kid: v.Key.Kid, roles: roles, blockRules: v.BlockRules, readScope: v.Key.ReadScopeResource, principal: in.Principal,
		digest: digest, filter: fv.filter.Encode(), exp: exp}
}

// filteredAdmit admits a request at a filtered URL of n, /ns/{ns}/g/{urlGS}
// with checkpoint cp (§B.11.9 URLs, design H), and returns the view it
// reads with:
//
//   - a grant in Authorization: an unrestricted reader's is 403 there,
//     where its unfiltered URLs serve it; a partial reader's reads at its
//     own gs as of cp, and any other gs is 403;
//   - a cookie for /ns/{ns}/g/{gs}: its gs must be urlGS (403), and is
//     judged from its filtered_gs row alone (a miss is 401): 403 where the
//     scope digest of its stored kid's scope rules and stored roles'
//     definitions, read from {ns}'s document at cp, with its stored block
//     rules and principal, differs from the stored one (a kid or role
//     gone counts as differing); 403 where it is partial and some
//     deciding catalog's Profile at cp keeps all groups; otherwise item 1
//     from the stored subjects and item 2 from the stored filter;
//   - a cookie for /ns/{ns}, which covers these URLs too, is judged as a
//     cookie for urlGS would be;
//   - no credentials, or an expired cookie, are 401.
func (t *tx) filteredAdmit(n *nsRow, fs *fscope, urlGS string, cp *fcp, cred Credentials) (*fview, *Error) {
	if cred.Bearer != "" {
		a, kind, _, err := t.nsAccess(n, cred)
		switch {
		case err != nil:
			return nil, err
		case kind == accessUnrestricted:
			return nil, forbidden("this grant reads " + n.name + " unrestricted, at its unfiltered URLs (§B.11.9 Partial reader)")
		case kind != accessPartial:
			return nil, forbidden("the grant does not allow this read in " + n.name)
		}
		fv, err := t.grantView(fs, cp, a)
		if err != nil {
			return nil, err
		}
		if fv.gs != urlGS {
			return nil, forbidden("the grant reads " + n.name + " at its own subject set, /ns/" + n.name + "/g/" + fv.gs + " (§B.11.9, §B.11.5)")
		}
		return fv, nil
	}
	eg := cred.Edge
	if eg == nil {
		return nil, apiErr(401, "unauthenticated", "message", "missing grant")
	}
	if !eg.Exp.IsZero() && !t.now.Before(eg.Exp) {
		return nil, apiErr(401, "unauthenticated", "message", "the edge grant has expired")
	}
	if eg.NS != n.name || eg.Resource != "" {
		return nil, nsNotNamed(n.name)
	}
	if eg.GS != "" && eg.GS != urlGS {
		return nil, forbidden("the edge grant is for another subject set (§B.11.9)")
	}
	rec := t.loadGS(n.name, urlGS)
	if rec == nil {
		return nil, apiErr(401, "unauthenticated", "message", "unknown subject set: exchange the grant again (§B.11.9)")
	}
	if !t.gsDigestHolds(n, cp, rec) {
		return nil, forbidden("the rules this subject set was issued under have changed: exchange the grant again (§B.11.9)")
	}
	var cats []*catvis.Catalog
	for i := range cp.cats {
		cats = append(cats, t.catalogAt(&cp.cats[i], cp))
	}
	if rec.partial {
		for _, c := range cats {
			if c.Profile().KeepAll {
				return nil, forbidden("this subject set leaves out groups that decide visibility at this checkpoint: exchange the grant again (§B.11.5, §B.11.9)")
			}
		}
	}
	filter, err := grantcheck.DecodeReadFilter(rec.filter)
	if err != nil {
		return nil, apiErr(401, "unauthenticated", "message", "unknown subject set: exchange the grant again (§B.11.9)")
	}
	a := &actor{principal: grant.Principal{ID: "edge:" + eg.Prefix}, bucketKey: "edge:" + eg.Prefix, gs: urlGS}
	return t.newFview(fs, cp, urlGS, rec.subjects, filter, a), nil
}

// gsDigestHolds reports whether rec's scope digest is the same with its
// kid's scope rules and its roles' definitions as of n's document at cp
// (§B.11.9 gs: "a gs cookie is 403 at an at where those rules differ").
// Keys follow the base (§C.4).
func (t *tx) gsDigestHolds(n *nsRow, cp *fcp, rec *gsRecord) bool {
	seq, ok := cp.seqs[n.name]
	if !ok {
		return false
	}
	cfg := t.fconfigAt(seq)
	key, ok := findKey(t.effectiveKeys(n, cfg), rec.kid)
	if !ok {
		return false
	}
	in := grantcheck.ScopeInput{ReadScopeResource: key.ReadScopeResource, KeyRules: key.Rules, BlockRules: rec.blockRules,
		Roles: map[string][]any{}, Principal: rec.principal}
	for _, r := range rec.roles {
		def, ok := cfg.Roles[r]
		if !ok {
			return false
		}
		in.Roles[r] = def.Rules
	}
	d, ok := grantcheck.ScopeDigest(in)
	return ok && d == rec.digest
}

// FilteredRedirect is a partial reader's request at an unfiltered URL,
// answered 302 to its filtered form (§B.11.9 URLs): /ns/{NS}/g/{GS}/at/{At}/…
// for ranges, or /ns/{NS}/g/{GS}/… with At "" for long-poll and events,
// which the caller clears. CP is the checkpoint At names: the caller
// records it (Engine.recordFilteredAt) before answering.
type FilteredRedirect struct {
	NS, GS, At string
	CP         *fcp
}

func (r *FilteredRedirect) Error() string {
	return "redirect to /ns/" + r.NS + "/g/" + r.GS + "/at/" + r.At
}

// partialRedirect is the redirect of partial reader a's request at an
// unfiltered URL of n (covered by fs): its gs at the current checkpoint.
// It returns *FilteredRedirect, or the *Error of a grant that can't read
// this way.
func (t *tx) partialRedirect(n *nsRow, fs *fscope, a *actor) error {
	cp := t.filteredCurrent(fs)
	fv, err := t.grantView(fs, cp, a)
	if err != nil {
		return err
	}
	return &FilteredRedirect{NS: n.name, GS: fv.gs, At: cp.at, CP: cp}
}
