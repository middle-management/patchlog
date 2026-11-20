package core

import (
	"crypto/sha256"
	"database/sql"
	"slices"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// grantView is the view of a partial reader's grant at cp (§7.9 view):
// its subjects are grantcheck.ViewSubjects, scope:{digest} and key:{…},
// and its view their grantcheck.ViewID. Its scope digest and judge are
// over the rules a read is judged by, roles whose rules refer to /now
// left out, as they don't count for read (§C.2 item 5, readScopeInput,
// readFilterOf); a grant that carries roles and keeps none doesn't read
// (403), nor does one whose blocks or key scope refer to /now, which the
// read check refuses before (readerCheckURL).
func (t *tx) grantView(fs *fscope, cp *fcp, a *actor) (*fview, *Error) {
	j := t.grantJudge(a)
	if j == nil {
		return nil, forbidden("the grant's rules don't allow reading " + fs.n.name + " (§C.2 item 5, §7.9 Partial reader)")
	}
	subjects := grantcheck.ViewSubjects(j.key, a.verified.Key.Kid, keyPub(*a.verified.Key), true)
	return t.newFview(fs, cp, grantcheck.ViewID(subjects), subjects, j, a), nil
}

// readScopeInput is grantcheck.ScopeInputOf(v) without the roles whose
// rules refer to /now (or the whole envelope), which don't count for read
// (§C.2 item 5, §A.4 view markers): the inputs of a partial reader's scope
// digest, and of its filtered_views row (viewRecordOf), from one list.
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

// viewRecordOf is the filtered_views row of fv, a grant's view, for edge grants
// expiring at exp (Unix seconds).
func viewRecordOf(fv *fview, exp int64) *viewRecord {
	v := fv.a.verified
	in := readScopeInput(v)
	digest, _ := grantcheck.ScopeDigest(in)
	roles := make([]string, 0, len(in.Roles))
	for r := range in.Roles {
		roles = append(roles, r)
	}
	slices.Sort(roles)
	return &viewRecord{view: fv.view, ns: fv.fs.n.name, subjects: fv.subjects,
		kid: v.Key.Kid, pub: keyPub(*v.Key), roles: roles, blockRules: v.BlockRules, readScope: v.Key.ReadScopeResource, principal: in.Principal,
		digest: digest, filter: fv.j.filter.Encode(), exp: exp}
}

// filteredAdmit admits a request at a filtered URL of n, /ns/{ns}/view/{urlView}
// with checkpoint cp (§7.9 URLs, design H), and returns the view it
// reads with:
//
//   - a grant in Authorization: an unrestricted reader's is 403 there,
//     where its unfiltered URLs serve it; a partial reader's reads at its
//     own view as of cp, and any other view is 403;
//   - a cookie for /ns/{ns}/view/{view}: its view must be urlView (403), and is
//     judged from its filtered_views row alone (a miss is 401), at the
//     current checkpoint whatever cp is (an at before a change that ended
//     it is 403 too): 403 where the
//     scope digest of its stored kid's scope rules and stored roles'
//     definitions, read from {ns}'s current document, with its stored block
//     rules and principal, differs from the stored one (a kid or role
//     gone, or no longer listing read, or the kid's key with another pub
//     than the stored one, counts as differing), or where that key's
//     entry or one of those roles' definitions differs there in any
//     member from the one recorded at the exchange (viewEntryDigest,
//     v0.82), or did under any document of {ns} between the exchange's
//     and the current one, whatever a later one undoes (viewHeldSince, v0.86), the
//     entry and the exchange's document being those of the cookie's own
//     exp (filtered_view_exps), so that another exchange revives none;
//     otherwise visibility from the stored filter;
//   - a cookie for /ns/{ns}, which covers these URLs too, is judged as a
//     cookie for urlView would be;
//   - no credentials, or an expired cookie, are 401.
func (t *tx) filteredAdmit(n *nsRow, fs *fscope, urlView string, cp *fcp, cred Credentials) (*fview, *Error) {
	if cred.Bearer != "" {
		a, kind, _, err := t.nsAccess(n, cred)
		switch {
		case err != nil:
			return nil, err
		case kind == accessUnrestricted:
			return nil, forbidden("this grant reads " + n.name + " unrestricted, at its unfiltered URLs (§7.9 Partial reader)")
		case kind != accessPartial:
			return nil, forbidden("the grant does not allow this read in " + n.name)
		}
		fv, err := t.grantView(fs, cp, a)
		if err != nil {
			return nil, err
		}
		if fv.view != urlView {
			return nil, forbidden("the grant reads " + n.name + " at its own view, /ns/" + n.name + "/view/" + fv.view + " (§7.9, §B.11.5)")
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
	if eg.View == "" {
		// An unrestricted reader's /ns/{ns} cookie, which covers these
		// URLs too, counts as the view's cookie and reads there as at its
		// own URLs, unrestricted: the answer is no cache's (§7.9 Partial
		// reader, FilteredInfo.Private).
		a := &actor{principal: grant.Principal{ID: "edge:" + eg.Prefix}, bucketKey: "edge:" + eg.Prefix, view: urlView}
		fv := t.newFview(fs, cp, urlView, nil, t.newJudge("", &grantcheck.ReadFilter{}), a)
		fv.unrestricted = true
		return fv, nil
	}
	if eg.View != urlView {
		return nil, forbidden("the edge grant is for another view (§7.9)")
	}
	rec := t.loadView(n.name, urlView)
	if rec == nil {
		return nil, apiErr(401, "unauthenticated", "message", "unknown view: exchange the grant again (§7.9)")
	}
	// The cookie is judged from the row of its own exp, the entry digest
	// and document its exchanges recorded (recordFilteredView): one whose
	// row a change ended stays ended whoever exchanged since. A cookie
	// with no row, one from before rows were kept or without an expiry,
	// which the server never mints, is refused.
	slot, ok := viewSlot{}, false
	if !eg.Exp.IsZero() {
		slot, ok = t.loadViewSlot(n.name, urlView, eg.Exp.Unix())
	}
	rec.entry, rec.conf = slot.entry, slot.conf
	// Judged at the current checkpoint, whatever the URL's: a cookie is
	// 403 at every URL once an entry after its exchange changes its
	// rules, at an at from before that entry too (§7.9 view). cp decides
	// only what it sees.
	cur := t.filteredCurrent(fs)
	if !ok || !t.viewDigestHolds(n, cur, rec) || !t.viewHeldSince(n, cur, rec) {
		return nil, forbidden("the rules this view was issued under have changed: exchange the grant again (§7.9)")
	}
	filter, err := grantcheck.DecodeReadFilter(rec.filter)
	if err != nil {
		return nil, apiErr(401, "unauthenticated", "message", "unknown view: exchange the grant again (§7.9)")
	}
	a := &actor{principal: grant.Principal{ID: "edge:" + eg.Prefix}, bucketKey: "edge:" + eg.Prefix, view: urlView}
	return t.newFview(fs, cp, urlView, rec.subjects, t.newJudge(rec.digest, filter), a), nil
}

// keyPub is k's pub member as its entry has it ("" if it has none).
func keyPub(k grant.Key) string {
	s, _ := k.Raw["pub"].(string)
	return s
}

// viewDigestHolds reports whether rec's scope digest is the same with its
// kid's scope rules and its roles' definitions as of n's document at cp,
// which filteredAdmit passes as the current checkpoint whatever the URL's
// (§7.9 view, v0.87: a cookie is 403 "at every URL" once its rules
// change), its kid and each of its roles still listing read there, so that a
// cookie never reads where its grant couldn't. Keys follow the base
// (§C.4), and the key with rec's kid must still have rec's pub: a kid
// whose pub was replaced is no longer the key the cookie came from
// (§7.9 view, "no longer accepted"; §C.4, a shared kid "accepted only
// while the base has it with the same pub"). An empty stored pub, from a
// row recorded before pubs were kept, never holds, nor does a row whose
// subjects don't bind its kid and pub (grantcheck.KeySubject), so that no row is
// shared by readers through different keys.
//
// Nor does it hold where the key's entry or a role's definition differs
// in any member from the one the exchange recorded (rec.entry,
// viewEntryDigest), whether or not the scope digest reads that member: a
// changed sub, groups, attrs, maxTtl or can of the key, or a
// role's can or rules (§7.9 view, v0.82: "or the key its key: string
// names, or a key or role they came from, is gone or changes in any
// member, until the reader exchanges again"). An empty stored entry,
// from a row recorded before it was kept, never holds.
func (t *tx) viewDigestHolds(n *nsRow, cp *fcp, rec *viewRecord) bool {
	return t.viewHoldsUnder(n, t.fconfigAt(cp.seq), rec)
}

// viewHoldsUnder is viewDigestHolds for n's document cfg.
func (t *tx) viewHoldsUnder(n *nsRow, cfg *Config, rec *viewRecord) bool {
	key, ok := findKey(t.effectiveKeys(n, cfg), rec.kid)
	if !ok || !key.Lists("read") || rec.pub == "" || keyPub(key) != rec.pub ||
		!slices.Contains(rec.subjects, grantcheck.KeySubject(rec.kid, rec.pub)) {
		return false
	}
	if entry := t.viewEntryDigest(n, cfg, rec.kid); rec.entry == "" || entry != rec.entry {
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

// viewWalk is how many namespace documents back a view cookie's record is
// judged (viewHeldSince, viewShares): a cookie lives 15 minutes at the
// longest (§C.5.2), and a namespace that wrote more documents than this
// since an exchange ends its cookies, whose readers exchange again.
const viewWalk = 64

// viewHeldSince reports whether rec has held under every document of n
// after the one its exchange recorded it under (rec.conf), up to the one
// at cp, the current checkpoint (filteredAdmit; §7.9 view, v0.87: "Every
// cookie of a view is 403, at every URL, once an entry after its
// exchange changes those rules ..., even where a later entry undoes the
// change"; CONFORMANCE Access 145). viewDigestHolds judges
// the document at cp alone, which a change made and undone gives back.
// Each config entry is judged as a whole, so two changes in one batch,
// which leave the key's entry as it was, end nothing. A checkpoint at or
// before the exchange's document has none to judge. It fails closed for
// a row from before conf was kept, and where more than viewWalk documents
// lie between.
//
// A read at the exchange's own document, the usual one, costs the lookup
// of the checkpoint's ns_config seq and no more.
func (t *tx) viewHeldSince(n *nsRow, cp *fcp, rec *viewRecord) bool {
	if rec.conf == 0 {
		return false
	}
	c := t.fconfigSeqAt(cp.seq)
	if c <= rec.conf {
		return true
	}
	// Past the exchange's document the walk judges up to viewWalk
	// documents, the same ones at every read under the cookie there. Its
	// verdict depends on the record and on documents that never change
	// (ns_config rows, by seq), so it is kept for the engine's life.
	key := viewHeldKey(rec, c)
	t.e.viewHeldMu.Lock()
	held, ok := t.e.viewHeld.Get(key)
	t.e.viewHeldMu.Unlock()
	if ok {
		return held
	}
	held = true
	for i, d := 0, c; d > rec.conf; i++ {
		if i == viewWalk || !t.viewHoldsUnder(n, t.config(d), rec) {
			held = false
			break
		}
		d = t.configParent(d)
	}
	t.e.viewHeldMu.Lock()
	t.e.viewHeld.Put(key, held, 0)
	t.e.viewHeldMu.Unlock()
	return held
}

// viewHeldKey is the key of viewHeldSince's verdict for rec at the document
// with ns_config seq c: a digest of everything of rec that viewHoldsUnder
// reads, the record of the cookie's own second (entry, conf) and what
// the filtered_views row holds, which a later exchange may write again.
func viewHeldKey(rec *viewRecord, c int64) [32]byte {
	strs := func(xs []string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	return sha256.Sum256(jsonv.Canonical([]any{rec.ns, rec.view, rec.kid, rec.pub, rec.digest, rec.entry, float64(rec.conf), float64(c),
		strs(rec.subjects), strs(rec.roles), nonNilRules(rec.blockRules), rec.principal, rec.readScope}))
}

// viewShares returns the test of whether r's exchange may share the row s
// of the cookies expiring at one second (recordFilteredView): the same
// entry digest, and r holding under every document of n after the
// earlier of the two documents up to the later, so that neither cookie's
// verdict at any checkpoint depends on which of the two the row keeps.
// It fails closed where more than viewWalk documents lie between, for a
// row or record without a document, and for a namespace that is gone.
func (t *tx) viewShares(n *nsRow, r *viewRecord) func(s viewSlot) bool {
	holds := map[int64]bool{}
	held := func(from, to int64) bool {
		c := to
		for i := 0; c > from; i++ {
			if i == viewWalk {
				return false
			}
			h, ok := holds[c]
			if !ok {
				h = t.viewHoldsUnder(n, t.config(c), r)
				holds[c] = h
			}
			if !h {
				return false
			}
			c = t.configParent(c)
		}
		return true
	}
	return func(s viewSlot) bool {
		if n == nil || s.entry != r.entry || s.entry == "" || s.conf == 0 || r.conf == 0 {
			return false
		}
		return held(min(s.conf, r.conf), max(s.conf, r.conf))
	}
}

// configParent is the ns_config seq of the document before the one at
// seq in its namespace's chain, 0 for the first.
func (t *tx) configParent(seq int64) int64 {
	var p sql.NullInt64
	t.must(t.QueryRow(`SELECT parent_seq FROM ns_config WHERE seq = ?`, seq).Scan(&p))
	return p.Int64
}

// viewEntryDigest is the digest a view cookie's record keeps of what
// ends it once changed (§7.9: "an entry after its exchange changes those
// rules, the key its key: string names, a key they came from or any role
// that lists read"): the key named kid and every role that lists read in
// n with document cfg,
//
//	text(trunc160(sha256(canonical({ "key": K, "roles": R }))))
//
// in the id text form of §3.2, where K is the key's whole entry as the
// document gives it (the effective key's, §C.4) and R maps each role that
// lists read to its whole definition there, so that one gaining or losing
// read changes it too. It is "" where the key is gone, which never equals
// a stored digest and is never stored as one that holds. The exchange
// records it (filteredEdgeGrant) and every read under the cookie computes
// it again from the document at its checkpoint (viewDigestHolds), both
// through this function.
func (t *tx) viewEntryDigest(n *nsRow, cfg *Config, kid string) string {
	key, ok := findKey(t.effectiveKeys(n, cfg), kid)
	if !ok || key.Raw == nil {
		return ""
	}
	defs, _ := cfg.Doc["roles"].(map[string]any)
	rs := map[string]any{}
	for r, def := range cfg.Roles {
		if def.Lists("read") {
			rs[r] = defs[r]
		}
	}
	return entryDigest(key.Raw, rs)
}

// entryDigest is EntryDigest, text(trunc160(sha256(canonical({ "key": key, "roles":
// roles })))), the digest a view cookie's record keeps of the key entry and
// role definitions it came from (§7.9 view). Nil roles are {}.
func entryDigest(key map[string]any, roles map[string]any) string {
	if roles == nil {
		roles = map[string]any{}
	}
	return ids.Of(jsonv.Canonical(map[string]any{"key": key, "roles": roles})).String()
}

// FilteredRedirect is a partial reader's request at an unfiltered URL,
// answered 302 to its filtered form (§7.9 URLs): /ns/{NS}/view/{View}/at/{At}/…
// for ranges, /ns/{NS}/view/{View}/… with At "" for long-poll and events,
// which the caller clears, and, with Content set, /ns/{NS}/view/{View}
// followed by Content, a resource's immutable URL (§7.9 Content).
type FilteredRedirect struct {
	NS, View, At string
	Content      string
}

func (r *FilteredRedirect) Error() string {
	return "redirect to /ns/" + r.NS + "/view/" + r.View + "/at/" + r.At
}

// partialRedirect is the redirect of partial reader a's request at an
// unfiltered URL of n (covered by fs): its view at the current checkpoint.
// It returns *FilteredRedirect, or the *Error of a grant that can't read
// this way.
func (t *tx) partialRedirect(n *nsRow, fs *fscope, a *actor) error {
	cp := t.filteredCurrent(fs)
	fv, err := t.grantView(fs, cp, a)
	if err != nil {
		return err
	}
	return &FilteredRedirect{NS: n.name, View: fv.view, At: cp.at}
}
