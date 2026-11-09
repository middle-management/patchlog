package core

import (
	"context"
	"errors"
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

// filteredOpen is the covered namespace a filtered URL names, or the
// answer for one that isn't covered (§B.11.9 Where): its credentials are
// judged as at its unfiltered URLs (401 without, 403 for a /ns/{ns}/g/{gs}
// cookie), then 403, as no filtered URL serves it.
func (t *tx) filteredOpen(ns string, cred Credentials) (*nsRow, *fscope, error) {
	n := t.nsByName(ns)
	if n == nil {
		return nil, nil, t.absentNS(ns, cred)
	}
	fs := t.filteredScope(n)
	if fs == nil {
		if _, _, _, err := t.nsAccess(n, cred); err != nil {
			return nil, nil, err
		}
		return nil, nil, forbidden(ns + " isn't read filtered here (§B.11.9 Where)")
	}
	return n, fs, nil
}

// filteredAtView admits a request at /ns/{ns}/g/{gs}/at/{at}/… and returns
// its view at that checkpoint; an at filteredAt can't answer is a
// *FilteredRedirect to the current one, after admission there (§B.11.9
// URLs, at).
func (t *tx) filteredAtView(ns, gs, at string, cred Credentials) (*nsRow, *fview, error) {
	n, fs, err := t.filteredOpen(ns, cred)
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

// FilteredCurrent answers a URL under /ns/{ns}/g/{gs} without at, such as
// …/g/{gs}/heads or …/g/{gs}/log without live: a *FilteredRedirect to its
// form at the current at, recorded first, once the request is admitted
// there (§B.11.9 URLs). It never returns nil.
func (e *Engine) FilteredCurrent(ctx context.Context, ns, gs string, cred Credentials) error {
	return e.filteredRead(ctx, func(t *tx) error {
		n, fs, err := t.filteredOpen(ns, cred)
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
		n, fv, err := t.filteredAtView(ns, gs, at, cred)
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
