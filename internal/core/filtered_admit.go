package core

import (
	"slices"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// grantView is the view of a partial reader's grant at cp (§B.11.9 gs):
// its subjects are gsSubjects, and its gs their
// grantcheck.SubjectSetID, never "all". Its scope digest and filter are
// over the rules a read is judged by, roles whose rules refer to /now
// left out, as they don't count for read (§C.2 item 5, readScopeInput,
// readFilterOf); a grant that carries roles and keeps none doesn't read
// (403), nor does one whose blocks or key scope refer to /now, which the
// read check refuses before (readerCheckURL).
func (t *tx) grantView(fs *fscope, cp *fcp, a *actor) (*fview, *Error) {
	in := readScopeInput(a.verified)
	digest, ok := grantcheck.ScopeDigest(in)
	if !ok || a.verified.HasRoles() && len(in.Roles) == 0 {
		return nil, forbidden("the grant's rules don't allow reading " + fs.n.name + " (§C.2 item 5, §B.11.9 Partial reader)")
	}
	cats := make([]*catvis.Catalog, len(cp.cats))
	for i := range cp.cats {
		cats[i] = t.catalogAt(&cp.cats[i], cp)
	}
	kid, pub := a.verified.Key.Kid, keyPub(*a.verified.Key)
	subjects := gsSubjects(cats, a.principal, catvis.ScopeKeyDigest(digest, kid, pub), catvis.KeySubject(kid, pub))
	return t.newFview(fs, cp, grantcheck.SubjectSetID(subjects), subjects, readFilterOf(a.verified), a), nil
}

// gsSubjects are §B.11.9's subjects of a gs: every group: entry of the
// caller's (deduped), its user: subject where §B.11.5 would add it for one
// of cats (a direct entry for it, or a sub-scoped catalog key:
// catvis.Profile's Users and SubScoped), scope:{scopeKeyDigest}, §A.4's
// marker digest, and keySubject, sorted. No gs leaves a group out, so it
// never holds "partial" (§B.11.5, v0.78). catvis.FilteredSubjects is
// given every group as deciding, which yields the same whether it reads
// its deciding argument or not.
func gsSubjects(cats []*catvis.Catalog, pr grant.Principal, scopeKeyDigest, keySubject string) []string {
	var all []string
	for _, g := range pr.Groups {
		if s := grantcheck.GroupPrefix + g; !slices.Contains(all, s) {
			all = append(all, s)
		}
	}
	var users []string
	if u := catvis.UserSubject(pr.ID); u != "" {
		for _, c := range cats {
			if p := c.Profile(); p.Users[u] || p.SubScoped {
				users = append(users, u)
				break
			}
		}
	}
	subjects := catvis.FilteredSubjects([][]string{append(slices.Clone(all), users...)}, pr.Groups, scopeKeyDigest)
	for _, s := range append(users, keySubject) {
		if !slices.Contains(subjects, s) {
			subjects = append(subjects, s)
		}
	}
	slices.Sort(subjects)
	return subjects
}

// readScopeInput is grantcheck.ScopeInputOf(v) without the roles whose
// rules refer to /now (or the whole envelope), which don't count for read
// (§C.2 item 5, §A.4 gs markers): the inputs of a partial reader's scope
// digest, and of its filtered_gs row (gsRecordOf), from one list.
func readScopeInput(v *grant.Verified) grantcheck.ScopeInput {
	in := grantcheck.ScopeInputOf(v)
	for r, rs := range in.Roles {
		if rulesReferToNow(rs) {
			delete(in.Roles, r)
		}
	}
	return in
}

// readFilterOf is grantcheck.FilterOf(v) without the roles readScopeInput
// leaves out. A grant with roles keeps a non-nil Roles, empty if none
// remains, so that its filter allows nothing rather than every role.
func readFilterOf(v *grant.Verified) *grantcheck.ReadFilter {
	f := grantcheck.FilterOf(v)
	if f.Roles != nil {
		kept := [][]any{}
		for _, rs := range f.Roles {
			if !rulesReferToNow(rs) {
				kept = append(kept, rs)
			}
		}
		f.Roles = kept
	}
	return f
}

// gsRecordOf is the filtered_gs row of fv, a grant's view, for edge grants
// expiring at exp (Unix seconds).
func gsRecordOf(fv *fview, exp int64) *gsRecord {
	v := fv.a.verified
	in := readScopeInput(v)
	digest, _ := grantcheck.ScopeDigest(in)
	roles := make([]string, 0, len(in.Roles))
	for r := range in.Roles {
		roles = append(roles, r)
	}
	slices.Sort(roles)
	return &gsRecord{gs: fv.gs, ns: fv.fs.n.name, subjects: fv.subjects, partial: slices.Contains(fv.subjects, catvis.Partial),
		kid: v.Key.Kid, pub: keyPub(*v.Key), roles: roles, blockRules: v.BlockRules, readScope: v.Key.ReadScopeResource, principal: in.Principal,
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
//     gone, or no longer listing read, or the kid's key with another pub
//     than the stored one, counts as differing); 403 where it holds
//     "partial", a set stored before v0.78 that leaves groups out, which
//     no gs does now (§B.11.5, §B.11.9 gs), whatever the catalogs decide;
//     otherwise item 1 from the stored subjects and item 2 from the
//     stored filter;
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
	if rec.partial || slices.Contains(rec.subjects, catvis.Partial) {
		return nil, forbidden("this subject set was stored leaving out some of the caller's groups, which no gs does now: exchange the grant again (§B.11.5, §B.11.9 gs)")
	}
	filter, err := grantcheck.DecodeReadFilter(rec.filter)
	if err != nil {
		return nil, apiErr(401, "unauthenticated", "message", "unknown subject set: exchange the grant again (§B.11.9)")
	}
	a := &actor{principal: grant.Principal{ID: "edge:" + eg.Prefix}, bucketKey: "edge:" + eg.Prefix, gs: urlGS}
	return t.newFview(fs, cp, urlGS, rec.subjects, filter, a), nil
}

// keyPub is k's pub member as its entry has it ("" if it has none).
func keyPub(k grant.Key) string {
	s, _ := k.Raw["pub"].(string)
	return s
}

// gsDigestHolds reports whether rec's scope digest is the same with its
// kid's scope rules and its roles' definitions as of n's document at cp
// (§B.11.9 gs: "a gs cookie is 403 at an at where those rules differ"),
// its kid and each of its roles still listing read there, so that a
// cookie never reads where its grant couldn't. Keys follow the base
// (§C.4), and the key with rec's kid must still have rec's pub: a kid
// whose pub was replaced is no longer the key the cookie came from
// (§B.11.9 gs, "no longer accepted"; §C.4, a shared kid "accepted only
// while the base has it with the same pub"). An empty stored pub, from a
// row recorded before pubs were kept, never holds, nor does a row whose
// subjects don't bind its kid and pub (catvis.KeySubject), so that no row is
// shared by readers through different keys.
func (t *tx) gsDigestHolds(n *nsRow, cp *fcp, rec *gsRecord) bool {
	seq, ok := cp.seqs[n.name]
	if !ok {
		return false
	}
	cfg := t.fconfigAt(seq)
	key, ok := findKey(t.effectiveKeys(n, cfg), rec.kid)
	if !ok || !key.Lists("read") || rec.pub == "" || keyPub(key) != rec.pub ||
		!slices.Contains(rec.subjects, catvis.KeySubject(rec.kid, rec.pub)) {
		return false
	}
	in := grantcheck.ScopeInput{ReadScopeResource: key.ReadScopeResource, KeyRules: key.Rules, BlockRules: rec.blockRules,
		Roles: map[string][]any{}, Principal: rec.principal}
	for _, r := range rec.roles {
		// A role that no longer lists read counts as gone: the grant
		// doesn't read through it there (§2.1, §A.4's marker digest).
		def, ok := cfg.Roles[r]
		if !ok || !def.Lists("read") {
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
