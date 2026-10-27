package core

import (
	"context"
	"database/sql"
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
//     endpoint answers 404. Their logs are the place to look (§11.2). A
//     purged namespace answers 410 before it (§8.5).

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
	err := e.gateRead(ctx, func(t *gate) error {
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
		var after *gestureRow
		if since != "" {
			name, idText, ok := strings.Cut(since, "/")
			id, perr := ids.Parse(idText)
			if !ok || perr != nil || (visible != nil && !visible(name)) {
				return notFound()
			}
			row := t.revByID(n, name, id)
			if row == nil {
				return notFound()
			}
			after = &gestureRow{name: name, res: row.res, seq: row.seq, id: row.id, created: row.created}
		}
		limit := e.opt.Maximums.LogPageSize
		// Rows the reader may not read are skipped, so a page is filled
		// from as many batches as it takes.
		var rs []gestureRow
		for len(rs) <= limit {
			batch := t.gestureRows(n, gesture, after, limit+1)
			for _, r := range batch {
				if visible == nil || visible(r.name) {
					rs = append(rs, r)
				}
			}
			if len(batch) <= limit {
				break
			}
			after = &batch[len(batch)-1]
		}
		out = &GesturePage{Entries: []map[string]any{}}
		if len(rs) > limit {
			rs = rs[:limit]
			last := rs[limit-1]
			out.Next = last.name + "/" + last.id.String()
		}
		for _, r := range rs {
			kind := "rev"
			if r.kind == kindTombstone {
				kind = "tombstone"
			}
			m := map[string]any{"resource": r.name, "id": r.id.String(), "kind": kind, "author": t.authorName(r.author)}
			if r.gesture.Valid {
				m["gesture"] = r.gesture.String
			}
			if r.undoes.Valid {
				m["undoes"] = r.undoes.String
			}
			if seq, ok := t.writingEntry(r.res, r.seq); ok {
				m["ns_id"] = t.nsLogID(seq).String()
			}
			out.Entries = append(out.Entries, m)
		}
		return nil
	})
	return out, err
}

// gestureRow is a revision or tombstone a gesture lists.
type gestureRow struct {
	name            string
	res, seq        int64
	id              ids.ID
	kind            int
	gesture, undoes sql.NullString
	author          int64
	created         int64
}

// gestureRows lists up to limit of n's own rows written with gesture or
// undoing it, after after (nil: from the first), in the order they were
// written (revision seq), leaving purged resources out.
func (t *tx) gestureRows(n *nsRow, gesture string, after *gestureRow, limit int) []gestureRow {
	var from int64
	if after != nil {
		from = after.seq
	}
	rows, err := t.Query(`SELECT r.seq, r.res, s.name, r.id, r.kind, r.gesture, r.undoes, r.author, r.created FROM revisions r JOIN resources s ON s.res = r.res
		WHERE s.ns = ? AND s.state <> ? AND (r.gesture = ? OR r.undoes = ?) AND r.seq > ? ORDER BY r.seq LIMIT ?`,
		n.id, statePurged, gesture, gesture, from, limit)
	t.must(err)
	defer rows.Close()
	var out []gestureRow
	for rows.Next() {
		var r gestureRow
		var id []byte
		t.must(rows.Scan(&r.seq, &r.res, &r.name, &id, &r.kind, &r.gesture, &r.undoes, &r.author, &r.created))
		r.id = ids.FromBytes(id)
		out = append(out, r)
	}
	t.must(rows.Err())
	return out
}

// writingEntry is the namespace entry that wrote res's revision seq: the
// first that moved the resource's head to it or past it (a batch records
// only an item's last step, §3.5).
func (t *tx) writingEntry(res, seq int64) (int64, bool) {
	var nsSeq int64
	t.must(t.QueryRow(`SELECT COALESCE(MIN(ns_seq), 0) FROM head_history WHERE res = ? AND target_seq >= ?`, res, seq).Scan(&nsSeq))
	return nsSeq, nsSeq != 0
}
