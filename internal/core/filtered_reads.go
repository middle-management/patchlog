package core

import (
	"context"
	"errors"

	"github.com/middle-management/patchlog/internal/ids"
)

// The read paths of filtered namespace reads (§B.11.9 Answers, URLs): a
// partial reader's request at an unfiltered URL is redirected to its
// filtered form (nsReaderOrRedirect), and the filtered URLs under
// /ns/{ns}/g/{gs} are admitted (filteredAdmit) and answered at a combined
// checkpoint: /heads here, log ranges in filtered_log.go, long-poll and
// events in filtered_live.go.

// FilteredInfo is the checkpoint a filtered answer is at (§B.11.9 URLs):
// its subject set and at, NSID the ns_id of {ns} in at, which the answer
// carries as X-Namespace-Revision, and Others the other members of at,
// whose ns:{x} Cache-Tags it carries beside its unfiltered form's.
type FilteredInfo struct {
	GS, At, NSID string
	Others       []string
}

func filteredInfo(n *nsRow, fv *fview) *FilteredInfo {
	cp := fv.CP()
	return &FilteredInfo{GS: fv.GS(), At: cp.at, NSID: cp.nsID(n.name), Others: cp.others(n.name)}
}

// filteredRead is read for a request that may answer a *FilteredRedirect:
// the checkpoint its at names is recorded, in a write transaction of its
// own after the read, before the redirect is returned (§B.11.9 at).
func (e *Engine) filteredRead(ctx context.Context, f func(t *tx) error) error {
	err := e.read(ctx, f)
	var fr *FilteredRedirect
	if errors.As(err, &fr) && fr.At != "" && fr.CP != nil {
		if rerr := e.recordFilteredAt(ctx, fr.CP); rerr != nil {
			return rerr
		}
	}
	return err
}

// nsReaderOrRedirect is nsReader for an unfiltered URL of n that §B.11.9
// redirects: a partial reader of a covered namespace, by the grant in
// Authorization, gets a *FilteredRedirect to its gs at the current
// checkpoint (§B.11.9 URLs) instead of 403; every other reader is judged
// as by nsReader, a cookie included, which never reads in part.
func (t *tx) nsReaderOrRedirect(n *nsRow, cred Credentials) (*actor, error) {
	a, kind, fs, err := t.nsAccess(n, cred)
	if err != nil {
		return nil, err
	}
	if kind == accessPartial {
		return nil, t.partialRedirect(n, fs, a)
	}
	return a, nil
}

// fform is the form of a filtered URL, which decides what a purged
// namespace this section doesn't cover answers there (§B.11.9 Purged
// namespaces, §8.5): /heads, at an at or without; a log range; or
// long-poll and events (live), from since.
type fform struct {
	heads, live bool
	since       string
}

// filteredOpen is the covered namespace a filtered URL of form f names, or
// the answer for one that isn't covered (§B.11.9 Where): its credentials
// are judged as at its unfiltered URLs (401 without, 403 for a
// /ns/{ns}/g/{gs} cookie); then a purged namespace answers 410 where §8.5
// answers the unfiltered form so (purgedFiltered); then 401 for a request
// that carries neither a grant that verifies in {ns} nor a cookie the
// origin verifies, as in a public namespace, whose unfiltered URLs ignore
// an unusable grant; then 403, as no filtered URL serves it (§B.11.9
// Purged namespaces: "answer these URLs as §8.5 answers their unfiltered
// forms; other namespaces ... 403, or 401 as §B.11.5 says").
func (t *tx) filteredOpen(ns string, f fform, cred Credentials) (*nsRow, *fscope, error) {
	n := t.nsByName(ns)
	if n == nil {
		return nil, nil, t.absentNS(ns, cred)
	}
	fs := t.filteredScope(n)
	if fs == nil {
		if _, _, _, err := t.nsAccess(n, cred); err != nil {
			return nil, nil, err
		}
		if t.purgedFiltered(n, f) {
			return nil, nil, t.purgedRead(n)
		}
		if !t.e.opt.AuthDisabled && cred.Edge == nil && !t.grantVerifiesIn(n, cred) {
			return nil, nil, apiErr(401, "unauthenticated", "message",
				"no grant that verifies in "+ns+" and no cookie: "+ns+" isn't read filtered here (§B.11.9 Where, §B.11.5)")
		}
		return nil, nil, forbidden(ns + " isn't read filtered here (§B.11.9 Where)")
	}
	return n, fs, nil
}

// purgedFiltered reports whether §8.5 answers the unfiltered form of f in
// n 410: n is purged, and f is /heads (at any revision), or long-poll or
// events from the purge-ns entry, or n is sealed, where log ranges, events
// and long-poll are 410 too. A purged namespace's other forms are "served
// as before" (§8.5), which for a namespace this section doesn't cover is
// its 403 or 401 (§B.11.9 Purged namespaces).
func (t *tx) purgedFiltered(n *nsRow, f fform) bool {
	switch {
	case !n.purged:
		return false
	case f.heads || t.sealedPurged(n):
		return true
	case f.live:
		return t.fromPurgeEntry(n, f.since)
	}
	return false
}

// fromPurgeEntry reports whether since names purged n's purge-ns entry,
// the log's last: events and long-poll from it are 410 (§8.5).
func (t *tx) fromPurgeEntry(n *nsRow, since string) bool {
	if !n.purged || since == "" {
		return false
	}
	id, err := ids.Parse(since)
	if err != nil {
		return false
	}
	s, ok := t.nsLogSeq(n.id, id)
	return ok && s == n.headSeq.Int64
}

// grantVerifiesIn reports whether the grant in Authorization verifies in
// n (§C.2 item 1, its key's scope included), whatever n's read mode: a
// public namespace's reads ignore a grant that doesn't (readerCheckURL).
func (t *tx) grantVerifiesIn(n *nsRow, cred Credentials) bool {
	if cred.Bearer == "" {
		return false
	}
	g, err := t.decodeGrant(n.name, cred)
	if err != nil {
		return false
	}
	_, err = t.verifyGrant(g, n.name, n, t.config(n.configSeq), nil)
	return err == nil
}

// filteredAtView admits a request at /ns/{ns}/g/{gs}/at/{at}/… and returns
// its view at that checkpoint; an at filteredAt can't answer is a
// *FilteredRedirect to the current one, after admission there (§B.11.9
// URLs, at).
func (t *tx) filteredAtView(ns, gs, at string, cred Credentials) (*nsRow, *fview, error) {
	n, fs, err := t.filteredOpen(ns, fform{}, cred)
	if err != nil {
		return nil, nil, err
	}
	cp, ok := t.filteredAt(fs, at)
	if !ok {
		return nil, nil, t.filteredCurrentRedirect(n, fs, gs, cred)
	}
	fv, aerr := t.filteredAdmit(n, fs, gs, cp, cred)
	if aerr != nil {
		return nil, nil, aerr
	}
	return n, fv, nil
}

// filteredCurrentRedirect is the redirect of a request at a filtered URL
// of n for subject set gs to the current checkpoint, once admitted there
// (§B.11.9 URLs): a grant in Authorization reads only at its own gs, as
// filteredAdmit judges.
func (t *tx) filteredCurrentRedirect(n *nsRow, fs *fscope, gs string, cred Credentials) error {
	cp := t.filteredCurrent(fs)
	fv, err := t.filteredAdmit(n, fs, gs, cp, cred)
	if err != nil {
		return err
	}
	return &FilteredRedirect{NS: n.name, GS: fv.GS(), At: cp.at, CP: cp}
}

// FilteredCurrent answers a URL under /ns/{ns}/g/{gs} without at, suffix
// "/heads" or "/log" (without live): a *FilteredRedirect to its form at
// the current at, recorded first, once the request is admitted there
// (§B.11.9 URLs). It never returns nil.
func (e *Engine) FilteredCurrent(ctx context.Context, ns, gs, suffix string, cred Credentials) error {
	return e.filteredRead(ctx, func(t *tx) error {
		n, fs, err := t.filteredOpen(ns, fform{heads: suffix == "/heads"}, cred)
		if err != nil {
			return err
		}
		return t.filteredCurrentRedirect(n, fs, gs, cred)
	})
}

// FilteredHeads serves GET /ns/{ns}/g/{gs}/at/{at}/heads?after&prefix
// (§B.11.9 /heads): the rows of §7.4 as of {ns}'s ns_id in at, only those
// visible to the subject set, in ascending byte order after after and
// under prefix ("" for all), in pages filled to the log page size, with
// next, the last row, on every full page and no other. The candidates are
// the deciding catalogs' placement names (fview.candidates), so a sparse
// reader never scans the namespace. A purged namespace is 410, after
// admission (§8.5). info is set wherever the checkpoint is known, errors
// included, for the answer's tags.
func (e *Engine) FilteredHeads(ctx context.Context, ns, gs, at, after, prefix string, cred Credentials) (page *HeadsPage, info *FilteredInfo, err error) {
	err = e.filteredRead(ctx, func(t *tx) error {
		n, fv, err := t.filteredHeadsView(ns, gs, at, cred)
		if err != nil {
			return err
		}
		info = filteredInfo(n, fv)
		if n.purged {
			return t.purgedRead(n)
		}
		asOf := fv.CP().seqs[n.name]
		limit := e.opt.Maximums.LogPageSize
		var rows []headItem
		fv.candidates(t, after, prefix, func(name string) bool {
			seq := asOf
			v := t.resolve(n, name, &seq)
			if v.state == NotFound || !t.fvVisible(fv, name) {
				return true
			}
			rows = append(rows, headItem{name: name, state: v.state, row: v.head})
			return len(rows) < limit
		})
		page = &HeadsPage{Items: t.headRows(n, rows), Public: t.cachePublic(n)}
		if len(rows) == limit {
			page.Next = rows[len(rows)-1].name
		}
		return nil
	})
	return page, info, err
}

// filteredHeadsView is filteredAtView for /heads, except that a purged
// namespace's request at an at filteredAt can't answer is admitted at the
// current checkpoint instead of redirected there, so that it answers 410
// as soon as the read check passes, as the unfiltered /heads of a purged
// namespace does at any revision (§8.5, §B.11.9 Purged namespaces). Log
// ranges keep the redirect: a purged namespace's range stays readable.
func (t *tx) filteredHeadsView(ns, gs, at string, cred Credentials) (*nsRow, *fview, error) {
	n, fs, err := t.filteredOpen(ns, fform{heads: true}, cred)
	if err != nil {
		return nil, nil, err
	}
	cp, ok := t.filteredAt(fs, at)
	if !ok {
		if !n.purged {
			return nil, nil, t.filteredCurrentRedirect(n, fs, gs, cred)
		}
		cp = t.filteredCurrent(fs)
	}
	fv, aerr := t.filteredAdmit(n, fs, gs, cp, cred)
	if aerr != nil {
		return nil, nil, aerr
	}
	return n, fv, nil
}

// testFilteredJudge, if set, is called with each name a filtered read
// judges that its view hasn't judged yet (tests: §B.11.9 Cost).
var testFilteredJudge func(gs, name string)

// fvVisible is fv.visible, reporting first judgements to testFilteredJudge.
func (t *tx) fvVisible(fv *fview, name string) bool {
	if testFilteredJudge != nil {
		fv.mu.Lock()
		_, known := fv.memo[name]
		fv.mu.Unlock()
		if !known {
			testFilteredJudge(fv.gs, name)
		}
	}
	return fv.visible(t, name)
}
