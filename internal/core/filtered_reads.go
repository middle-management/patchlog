package core

import (
	"context"
)

// The read paths of filtered namespace reads (§7.9 Answers, URLs): a
// partial reader's request at an unfiltered URL is redirected to its
// filtered form (nsReaderOrRedirect), and the filtered URLs under
// /ns/{ns}/view/{view} are admitted (filteredAdmit) and answered at a combined
// checkpoint: /heads here, log ranges in filtered_log.go, long-poll and
// events in filtered_live.go.

// FilteredInfo is the checkpoint a filtered answer is at (§7.9 URLs):
// its view and at, the ns_id of {ns} the answer carries as
// X-Namespace-Revision.
type FilteredInfo struct {
	View, At string
	// Private: read under an unrestricted reader's /ns/{ns} cookie,
	// unfiltered, so no cache may keep the answer for the view's
	// readers (§7.9 Partial reader).
	Private bool
}

func filteredInfo(fv *fview) *FilteredInfo {
	return &FilteredInfo{View: fv.View(), At: fv.CP().at, Private: fv.unrestricted}
}

// nsReaderOrRedirect is nsReader for an unfiltered URL of n that §7.9
// redirects: a partial reader of a covered namespace, by the grant in
// Authorization, gets a *FilteredRedirect to its view at the current
// checkpoint (§7.9 URLs) instead of 403; every other reader is judged
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

// filteredOpen is the covered namespace a filtered URL names, or the
// answer for one that isn't covered (§7.9 Where): its credentials are
// judged as at its unfiltered URLs (401 without, 403 for a
// /ns/{ns}/view/{view} cookie); then 401 for a request that carries neither a
// grant that verifies in {ns} nor a cookie the origin verifies, as in a
// public namespace, whose unfiltered URLs ignore an unusable grant; then
// 403, as no filtered URL serves it. A purged namespace this section
// doesn't cover answers so too, never the 410 of its unfiltered forms
// (§7.9 Purged covered namespaces, v0.85: "Purged covered namespaces
// answer these URLs as §8.5 answers their unfiltered forms ... Other
// namespaces this section doesn't cover, branches among them, answer
// them 403, or 401, in §7's order"); before v0.85 its /heads, and its
// live reads from the purge-ns entry, were 410.
func (t *tx) filteredOpen(ns string, cred Credentials) (*nsRow, *fscope, error) {
	n := t.nsByName(ns)
	if n == nil {
		return nil, nil, t.absentNS(ns, cred)
	}
	if n.purged {
		// Covered or not, whatever the grant or cookie (§7.9 Purged
		// namespaces, §8.5, v0.91).
		return nil, nil, t.purgedRead(n)
	}
	fs := t.filteredScope(n)
	if fs == nil {
		if _, _, _, err := t.nsAccess(n, cred); err != nil {
			return nil, nil, err
		}
		if !t.e.opt.AuthDisabled && cred.Edge == nil && !t.grantVerifiesIn(n, cred) {
			return nil, nil, apiErr(401, "unauthenticated", "message",
				"no grant that verifies in "+ns+" and no cookie: "+ns+" isn't read filtered here (§7.9 Where, §B.11.5)")
		}
		return nil, nil, forbidden(ns + " isn't read filtered here (§7.9 Where)")
	}
	return n, fs, nil
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

// filteredAtView admits a request at /ns/{ns}/view/{view}/at/{at}/… and returns
// its view at that checkpoint; an at filteredAt can't answer is a
// *FilteredRedirect to the current one, after admission there (§7.9
// URLs, at).
func (t *tx) filteredAtView(ns, view, at string, cred Credentials) (*nsRow, *fview, error) {
	n, fs, err := t.filteredOpen(ns, cred)
	if err != nil {
		return nil, nil, err
	}
	cp, ok := t.filteredAt(fs, at)
	if !ok {
		return nil, nil, t.filteredCurrentRedirect(n, fs, view, cred)
	}
	fv, aerr := t.filteredAdmit(n, fs, view, cp, cred)
	if aerr != nil {
		return nil, nil, aerr
	}
	return n, fv, nil
}

// filteredCurrentRedirect is the redirect of a request at a filtered URL
// of n for view view to the current checkpoint, once admitted there
// (§7.9 URLs): a grant in Authorization reads only at its own view, as
// filteredAdmit judges.
func (t *tx) filteredCurrentRedirect(n *nsRow, fs *fscope, view string, cred Credentials) error {
	cp := t.filteredCurrent(fs)
	fv, err := t.filteredAdmit(n, fs, view, cp, cred)
	if err != nil {
		return err
	}
	return &FilteredRedirect{NS: n.name, View: fv.View(), At: cp.at}
}

// FilteredCurrent answers a URL under /ns/{ns}/view/{view} without at, suffix
// "/heads" or "/log" (without live): a *FilteredRedirect to its form at
// the current at, recorded first, once the request is admitted there
// (§7.9 URLs). A covered purged namespace's /heads, once admitted at
// the current checkpoint, is 410 purged with head, as §8.5 answers its
// unfiltered /heads, never a redirect (§7.9 Purged namespaces: "/heads
// without at as /heads"); its /log keeps the redirect, a purged range
// staying readable. It never returns nil.
func (e *Engine) FilteredCurrent(ctx context.Context, ns, view, suffix string, cred Credentials) error {
	return e.read(ctx, func(t *tx) error {
		n, fs, err := t.filteredOpen(ns, cred)
		if err != nil {
			return err
		}
		return t.filteredCurrentRedirect(n, fs, view, cred)
	})
}

// FilteredHeads serves GET /ns/{ns}/view/{view}/at/{at}/heads?after&prefix
// (§7.9 /heads): the rows of §7.4 as of {ns}'s ns_id in at, only those
// visible to the view, in ascending byte order after after and
// under prefix ("" for all), in pages filled to the log page size, with
// next, the last row, on every full page and no other. The candidates are
// the namespace's names (fview.candidates). A purged namespace is 410, after
// admission (§8.5). info is set wherever the checkpoint is known, errors
// included, for the answer's tags.
func (e *Engine) FilteredHeads(ctx context.Context, ns, view, at, after, prefix string, cred Credentials) (page *HeadsPage, info *FilteredInfo, err error) {
	var fsl *fsealing
	defer func() {
		// In a sealed namespace, one JWE under the view's K_view (§E.2.2).
		if err == nil && fsl != nil {
			page.JWE, err = e.sealFiltered(ctx, fsl)
		}
	}()
	err = e.read(ctx, func(t *tx) error {
		n, fv, err := t.filteredAtView(ns, view, at, cred)
		if err != nil {
			return err
		}
		info = filteredInfo(fv)
		asOf := fv.CP().seq
		limit := e.opt.Maximums.LogPageSize
		var rows []headItem
		fv.candidates(t, after, prefix, func(name string) bool {
			seq := asOf
			v := t.resolve(n, name, &seq)
			if v.state == NotFound || !t.headShown(fv, name, v) {
				return true
			}
			rows = append(rows, headItem{name: name, state: v.state, row: v.head})
			return len(rows) < limit
		})
		// Cached as a private namespace's, a public one's too (§7.9
		// Where, §9, v0.90).
		page = &HeadsPage{Items: t.headRows(n, rows)}
		if len(rows) == limit {
			page.Next = rows[len(rows)-1].name
		}
		fsl = t.filteredHeadsSealing(n, fv, after, page, rows)
		return nil
	})
	return page, info, err
}

// headShown reports whether /heads lists name, as v resolves it, to fv
// (§7.9 /heads): a live head where its revision is visible, a tombstone
// where the document it deleted is, a purge where its entry is shown.
func (t *tx) headShown(fv *fview, name string, v *view) bool {
	if v.state == Purged {
		return fv.purgeShown(name)
	}
	return fv.visible(t, name, v.head)
}
