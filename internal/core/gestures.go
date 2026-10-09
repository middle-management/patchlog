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
//     the next page's ?after= (§7.4): ids repeat across resources (§3.3), resource
//     names never contain "/" (§3.6). The list grows, so the last page is
//     the one without X-Log-Next, and nothing is cached (no-store).
//   - It answers any reader, listing only the entries of resources its
//     grant may read, so a reader limited to some documents finds its own
//     gestures and learns nothing of others. It isn't offered in sealed
//     or e2e namespaces: 404 with code
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
// or undoing it, after since (?after=; "" for the first page, else the Next of the
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
		a, err := t.anyReader(n, cred)
		if err != nil {
			return err
		}
		// A reader limited to some resources gets only theirs (§7.4).
		cfg := t.config(n.configSeq)
		var visible func(name string) bool
		if !t.readsNS(n, cfg, a, false) {
			seen := map[string]bool{}
			visible = func(name string) bool {
				v, ok := seen[name]
				if !ok {
					v = t.canRead(n, cfg, a, name)
					seen[name] = v
				}
				return v
			}
		}
		if n.purged {
			return t.purgedNS(n)
		}
		if t.nsLevel(n) >= levelSealed {
			return apiErr(404, "not_offered", "message", "gestures aren't listed in sealed or end-to-end namespaces: their logs carry them (§7.4)")
		}
		var after int64
		if since != "" {
			name, idText, ok := strings.Cut(since, "/")
			id, perr := ids.Parse(idText)
			r := t.resource(n.id, name)
			if !ok || perr != nil || r == nil || (visible != nil && !visible(name)) {
				return notFound()
			}
			if err := t.QueryRow(`SELECT seq FROM revisions WHERE res = ? AND id = ?`, r.id, id[:]).Scan(&after); err != nil {
				return notFound()
			}
		}
		limit := e.opt.Maximums.LogPageSize
		type row struct {
			seq, res        int64
			name            string
			id              []byte
			kind            int
			gesture, undoes *string
			author          int64
		}
		// Rows the reader may not read are skipped, so a page is filled
		// from as many batches as it takes.
		var rs []row
		for len(rs) <= limit {
			rows, qerr := t.Query(`SELECT r.seq, r.res, s.name, r.id, r.kind, r.gesture, r.undoes, r.author FROM revisions r JOIN resources s ON s.res = r.res
				WHERE s.ns = ? AND s.state <> ? AND (r.gesture = ? OR r.undoes = ?) AND r.seq > ? ORDER BY r.seq LIMIT ?`,
				n.id, statePurged, gesture, gesture, after, limit+1)
			t.must(qerr)
			var batch []row
			for rows.Next() {
				var r row
				t.must(rows.Scan(&r.seq, &r.res, &r.name, &r.id, &r.kind, &r.gesture, &r.undoes, &r.author))
				batch = append(batch, r)
			}
			t.must(rows.Err())
			// Closed before querying again: a Postgres connection runs one
			// query at a time.
			rows.Close()
			for _, r := range batch {
				if visible == nil || visible(r.name) {
					rs = append(rs, r)
				}
			}
			if len(batch) <= limit {
				break
			}
			after = batch[len(batch)-1].seq
		}
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
