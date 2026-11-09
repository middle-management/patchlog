package core

import (
	"context"
	"database/sql"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// nsLogCols are the ns_log columns a namespace log page reads (scanNSLogRow).
const nsLogCols = `seq, id, prev_seq, body, author, created, grant_id, no_auth, gestures, via`

// nsLogRow is an ns_log row as a log page reads it.
type nsLogRow struct {
	seq     int64
	id      []byte
	prev    *int64
	body    string
	author  int64
	created int64
	grantID []byte
	noAuth  sql.NullInt64
	meta    sql.NullString
	via     sql.NullString
	m       map[string]any // body, parsed
}

// scanNSLogRow scans the row nsLogCols selects, its body parsed.
func (t *tx) scanNSLogRow(rows *sql.Rows) nsLogRow {
	var r nsLogRow
	t.must(rows.Scan(&r.seq, &r.id, &r.prev, &r.body, &r.author, &r.created, &r.grantID, &r.noAuth, &r.meta, &r.via))
	r.m = jsonv.MustParse([]byte(r.body)).(map[string]any)
	return r
}

// decorateNSEntry is r's entry as a log answer serves it (§7.4): its body
// with id, prev (the id of the entry before it, given), author, created,
// via, grant and the gesture members, none of them hashed but id and prev.
func (t *tx) decorateNSEntry(r *nsLogRow, prev string) map[string]any {
	m := r.m
	m["id"] = ids.FromBytes(r.id).String()
	if r.prev != nil {
		m["prev"] = prev
	}
	m["author"] = t.authorName(r.author)
	m["created"] = formatTime(r.created)
	if via := parseVia(r.via); via != nil {
		// The grant's delegatees, unhashed like author (§7.4); sealed with
		// the entry in a sealed namespace.
		m["via"] = anyStrings(via)
	}
	switch {
	case r.grantID != nil:
		// Not part of the hashed entry, like author and created (§7.4,
		// grantref.go).
		if g := t.grantRef(r.grantID); g != nil {
			m["grant"] = g
		}
	case r.noAuth.Valid && r.noAuth.Int64 != 0:
		// Written while authentication was disabled (§1): null, unlike
		// the server's own entries, which have none.
		m["grant"] = nil
	}
	if r.meta.Valid {
		// gesture and undoes of a single write, gestures of a batch: not
		// part of the hashed entry either (§7.4). In a sealed namespace
		// they are sealed with it (§E.4).
		for k, v := range jsonv.MustParse([]byte(r.meta.String)).(map[string]any) {
			m[k] = v
		}
	}
	return m
}

// filteredLogChunk is how many ns_log rows a filtered page reads at a time:
// the rows are read and closed before their entries are judged, since a
// Postgres connection runs one query at a time.
const filteredLogChunk = 256

// filteredRange is a page of n's log after since up to toSeq as fv sees it
// (§B.11.9 Log entries, Log ranges): Status 404 for a since not in the
// chain up to toSeq, as unfiltered (§7.1); otherwise 200 with the page's
// visible entries, possibly none. A page counts a batch as its visible
// items, a config-only batch and every other entry, hidden or dropped
// included, as one, ending before an entry that would take it past limit
// (0: no bound) but scanning at least one; Last is the last entry scanned,
// visible or not, and More whether the range goes on past it, so the next
// page's since is Last. An entry's prev is the entry before it in the
// chain, hidden or not. Covered namespaces are neither sealed nor e2e, so
// nothing is sealed.
func (t *tx) filteredRange(n *nsRow, fv *fview, since string, toSeq int64, limit int) *Log {
	out := &Log{Public: t.cachePublic(n), Purged: n.purged}
	var fromSeq int64
	if since != "" {
		id, err := ids.Parse(since)
		s, ok := t.nsLogSeq(n.id, id)
		if err != nil || !ok || s > toSeq {
			out.Status = 404
			return out
		}
		fromSeq = s
	}
	out.Status, out.Last = 200, since
	scanned, units := 0, 0
	at := fromSeq
	q := `SELECT ` + nsLogCols + ` FROM ns_log WHERE ns = ? AND seq > ? AND seq <= ? ORDER BY seq LIMIT ?`
	for at < toSeq {
		rows, err := t.Query(q, n.id, at, toSeq, filteredLogChunk)
		t.must(err)
		var rs []nsLogRow
		for rows.Next() {
			rs = append(rs, t.scanNSLogRow(rows))
		}
		t.must(rows.Err())
		rows.Close()
		if len(rs) == 0 {
			break
		}
		for i := range rs {
			r := &rs[i]
			shown, u, names := t.filterEntry(fv, r.m)
			if limit > 0 && scanned > 0 && units+u > limit {
				out.More = true
				return out
			}
			scanned, units, at = scanned+1, units+u, r.seq
			id := ids.FromBytes(r.id).String()
			if shown {
				prev := ""
				if r.prev != nil {
					if i > 0 && rs[i-1].seq == *r.prev {
						prev = ids.FromBytes(rs[i-1].id).String()
					} else {
						prev = t.nsLogID(*r.prev).String()
					}
				}
				m := t.decorateNSEntry(r, prev)
				if g, ok := m["gestures"].(map[string]any); ok && names != nil {
					// A batch's, from its row's metadata (§7.4).
					narrowNames(m, "gestures", g, names)
				}
				out.Entries = append(out.Entries, m)
			}
			out.Last = id
		}
	}
	out.More = at < toSeq
	return out
}

// filterEntry judges a log entry's body m for fv (§B.11.9 Log entries),
// narrowing a batch in place, and returns whether it is shown, the units it
// counts for on a page (Log ranges) and, for a batch, its visible names,
// which its gestures, metadata outside the body, are narrowed to:
//
//   - head, tombstone, purge and prune when their resource is visible;
//   - config and purge-ns always;
//   - a batch with only its visible entries, and its config entry, its
//     gestures and source.ids without hidden names; one with neither is
//     dropped, and one with only its config entry kept as config-only;
//   - branch never, as one answer serves its whole gs, nor any other
//     kind, remote ones included.
func (t *tx) filterEntry(fv *fview, m map[string]any) (bool, int, map[string]bool) {
	switch m["kind"] {
	case "config", "purge-ns":
		return true, 1, nil
	case "head", "tombstone", "purge", "prune":
		name, ok := m["resource"].(string)
		return ok && t.fvVisible(fv, name), 1, nil
	case "batch":
	default:
		return false, 1, nil
	}
	es, _ := m["entries"].([]any)
	kept := []any{}
	visible := map[string]bool{}
	config := false
	for _, x := range es {
		em, _ := x.(map[string]any)
		name, isRes := em["resource"].(string)
		switch {
		case em == nil:
		case !isRes && em["kind"] == "config":
			config = true
			kept = append(kept, em)
		case isRes && t.fvVisible(fv, name):
			visible[name] = true
			kept = append(kept, em)
		}
	}
	if len(visible) == 0 && !config {
		return false, 1, nil
	}
	m["entries"] = kept
	if src, ok := m["source"].(map[string]any); ok {
		if ids, ok := src["ids"].(map[string]any); ok {
			narrowNames(src, "ids", ids, visible)
		}
	}
	return true, max(len(visible), 1), visible
}

// narrowNames leaves in parent[key], a map by resource name, only the
// names in visible, and drops it if none is left.
func narrowNames(parent map[string]any, key string, byName map[string]any, visible map[string]bool) {
	out := map[string]any{}
	for name, v := range byName {
		if visible[name] {
			out[name] = v
		}
	}
	if len(out) == 0 {
		delete(parent, key)
		return
	}
	parent[key] = out
}

// FilteredLog serves GET /ns/{ns}/g/{gs}/at/{at}/log?since= (§B.11.9 Log
// ranges): a page of the range after since up to {ns}'s ns_id in at, the
// range's end, which answers carry as X-Namespace-Revision (info), filtered
// as filteredRange says, limit units a page. A purged namespace's range
// stays readable and ends with its purge-ns entry (§8.5). An at it can't
// answer is a *FilteredRedirect to the current one.
func (e *Engine) FilteredLog(ctx context.Context, ns, gs, at, since string, limit int, cred Credentials) (lg *Log, info *FilteredInfo, err error) {
	err = e.filteredRead(ctx, func(t *tx) error {
		n, fv, err := t.filteredAtView(ns, gs, at, cred)
		if err != nil {
			return err
		}
		info = filteredInfo(n, fv)
		lg = t.filteredRange(n, fv, since, fv.CP().seqs[n.name], limit)
		lg.Until = t.admittedUntil(n, cred, fv.a)
		return nil
	})
	return lg, info, err
}
