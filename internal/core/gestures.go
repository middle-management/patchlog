package core

import (
	"context"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
)

// Gestures (§7.2, §7.4).
//
// A write may carry Gesture and Undoes ids, stored with its revision or
// tombstone (revisions.gesture, revisions.undoes) as metadata, like its
// author: outside its id, unseen by rules, kept by pruning (§8.6). The
// namespace entry of a single write serves them as gesture and undoes, a
// batch's entry as gestures (batchGestures); neither is hashed
// (ns_log.gestures). GET /ns/{ns}/gestures/{gesture} lists them:
//
//   - One entry per revision or tombstone of the namespace written with the
//     gesture or undoing it, in the order they were written (revision
//     seq). Within one resource that is chain order; across resources it
//     is the order the rows were inserted, which is the order of a client's
//     own successive saves, the case a gesture is made of.
//   - Only the namespace's own rows: a branch doesn't list what it reads
//     through from its base (§7.6), whose gestures belong to the base's
//     history and are listed there. Purged resources are left out, since
//     nothing of their content is left to undo (§8.3).
//   - Paged as in §7.1, a page of at most the log page size. The cursor is
//     "{resource}/{id}" of a page's last entry, sent as X-Log-Next and as
//     the next page's since: ids repeat across resources (§3.3), resource
//     names never contain "/" (§3.6). The list grows, so the last page is
//     the one without X-Log-Next, and nothing is cached (no-store).
//   - It needs unrestricted read on the namespace, as branching does
//     (§7.6), and isn't offered in sealed or e2e namespaces: 404 with code
//     "not_offered", after authorisation, as a deployment without the
//     endpoint answers 404. Their logs are the place to look (§11.2).

// GesturePage is a page of GET /ns/{ns}/gestures/{gesture} (§7.4).
type GesturePage struct {
	Entries []map[string]any
	// Next is the cursor of the following page (X-Log-Next), "" on the
	// last one.
	Next string
}

// Gestures lists the revisions and tombstones of ns written with gesture
// or undoing it, after since ("" for the first page; else the Next of the
// previous page), oldest first (§7.4).
func (e *Engine) Gestures(ctx context.Context, ns, gesture, since string, cred Credentials) (*GesturePage, error) {
	if !ValidGesture(gesture) {
		return nil, badInput("a gesture id is 26 base32 characters")
	}
	var out *GesturePage
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		a, err := t.reader(n, cred, "")
		if err != nil {
			return err
		}
		// An anonymous reader of a public namespace reads all of it.
		if a != nil && !a.unrestrictedRead() {
			return forbidden("listing a gesture needs unrestricted read on the namespace")
		}
		if t.nsLevel(n) >= levelSealed {
			return apiErr(404, "not_offered", "message", "gestures aren't listed in sealed or end-to-end namespaces: their logs carry them (§7.4)")
		}
		if n.purged {
			return gone()
		}
		var after int64
		if since != "" {
			name, idText, ok := strings.Cut(since, "/")
			id, perr := ids.Parse(idText)
			r := t.resource(n.id, name)
			if !ok || perr != nil || r == nil {
				return notFound()
			}
			if err := t.QueryRow(`SELECT seq FROM revisions WHERE res = ? AND id = ?`, r.id, id[:]).Scan(&after); err != nil {
				return notFound()
			}
		}
		limit := e.opt.Maximums.LogPageSize
		rows, qerr := t.Query(`SELECT r.seq, r.res, s.name, r.id, r.kind, r.gesture, r.undoes, r.author FROM revisions r JOIN resources s ON s.res = r.res
			WHERE s.ns = ? AND s.state <> ? AND (r.gesture = ? OR r.undoes = ?) AND r.seq > ? ORDER BY r.seq LIMIT ?`,
			n.id, statePurged, gesture, gesture, after, limit+1)
		t.must(qerr)
		type row struct {
			seq, res        int64
			name            string
			id              []byte
			kind            int
			gesture, undoes *string
			author          int64
		}
		var rs []row
		for rows.Next() {
			var r row
			t.must(rows.Scan(&r.seq, &r.res, &r.name, &r.id, &r.kind, &r.gesture, &r.undoes, &r.author))
			rs = append(rs, r)
		}
		t.must(rows.Err())
		// Closed before querying again: a Postgres connection runs one
		// query at a time.
		rows.Close()
		out = &GesturePage{Entries: []map[string]any{}}
		if len(rs) > limit {
			rs = rs[:limit]
			last := rs[limit-1]
			out.Next = last.name + "/" + ids.FromBytes(last.id).String()
		}
		for _, r := range rs {
			kind := "rev"
			if r.kind == kindTombstone {
				kind = "tombstone"
			}
			m := map[string]any{"resource": r.name, "id": ids.FromBytes(r.id).String(), "kind": kind, "author": t.authorName(r.author)}
			if r.gesture != nil {
				m["gesture"] = *r.gesture
			}
			if r.undoes != nil {
				m["undoes"] = *r.undoes
			}
			// The namespace entry that wrote it: the first that moved the
			// resource's head to it or past it (a batch records only an
			// item's last step, §3.5).
			var nsSeq int64
			t.must(t.QueryRow(`SELECT COALESCE(MIN(ns_seq), 0) FROM head_history WHERE res = ? AND target_seq >= ?`, r.res, r.seq).Scan(&nsSeq))
			if nsSeq != 0 {
				m["ns_id"] = t.nsLogID(nsSeq).String()
			}
			out.Entries = append(out.Entries, m)
		}
		return nil
	})
	return out, err
}
