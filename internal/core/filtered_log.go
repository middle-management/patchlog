package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// nsLogCols are the ns_log columns a namespace log page reads (scanNSLogRow).
const nsLogCols = `seq, id, prev_seq, body, author, created, grant_id, no_auth, gestures, via, target_seq`

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
	target  sql.NullInt64  // the revision a single entry moves to, a prune's horizon
	m       map[string]any // body, parsed
}

// scanNSLogRow scans the row nsLogCols selects, its body parsed.
func (t *tx) scanNSLogRow(rows *sql.Rows) nsLogRow {
	var r nsLogRow
	t.must(rows.Scan(&r.seq, &r.id, &r.prev, &r.body, &r.author, &r.created, &r.grantID, &r.noAuth, &r.meta, &r.via, &r.target))
	r.m = jsonv.MustParse([]byte(r.body)).(map[string]any)
	return r
}

// decorateNSEntry is r's entry as a log answer serves it (§7.4): its body
// with id, prev (the id of the entry before it, given; "" on the chain's
// first, which always carries it, §7.4 v0.81), author, created, via, grant
// and the gesture members, none of them hashed but id and prev.
func (t *tx) decorateNSEntry(r *nsLogRow, prev string) map[string]any {
	m := r.m
	m["id"] = ids.FromBytes(r.id).String()
	if r.prev == nil {
		prev = ""
	}
	m["prev"] = prev
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
		// gesture and undoes of a single write, gestures of a batch, and
		// a head entry's schema: not part of the hashed entry either
		// (§7.4). In a sealed namespace they are sealed with it (§E.4).
		for k, v := range jsonv.MustParse([]byte(r.meta.String)).(map[string]any) {
			if k == "schemas" {
				// A batch's, by resource: each on its head entry, those
				// a filtered answer keeps included; never on a hidden
				// stand-in (§7.9 Log entries).
				byName, _ := v.(map[string]any)
				es, _ := m["entries"].([]any)
				for _, x := range es {
					if em, ok := x.(map[string]any); ok && em["kind"] == "head" {
						if sc, ok := byName[fmt.Sprint(em["resource"])]; ok {
							em["schema"] = sc
						}
					}
				}
				continue
			}
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
// (§7.9 Log entries, Log ranges): Status 404 for a since not in the
// chain up to toSeq, as unfiltered (§7.1); otherwise 200 with the page's
// shown entries, possibly none. A page counts a batch as its shown items
// (at least one), and every other entry, dropped ones included, as one,
// ending before an entry that would take it past limit (0: no bound) but
// scanning at least one; Last is the last entry scanned, shown or not,
// and More whether the range goes on past it, so the next page's since is
// Last. An entry's prev is the entry before it in the chain, shown or
// not. Purged is whether the range ends with n's purge-ns entry, not
// whether n is purged now: a live read's toSeq is its admission's
// checkpoint, and a purge committed since is past it, so its page doesn't
// end the stream (§7.3, §8.5). In a sealed namespace the page is sealed
// as a whole once read (filteredRangeSealing).
//
// What an entry shows is a function of the log alone (filterEntry), never
// of the pages before it, so a range reads the same in any pages.
func (t *tx) filteredRange(n *nsRow, fv *fview, since string, toSeq int64, limit int) *Log {
	// Cached as a private namespace's, a public one's too (§7.9 Where,
	// §9, v0.90).
	out := &Log{Purged: n.purged && n.headSeq.Valid && toSeq == n.headSeq.Int64}
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
			f := t.filterEntry(n, fv, r)
			if limit > 0 && scanned > 0 && units+f.units > limit {
				out.More = true
				return out
			}
			scanned, units, at = scanned+1, units+f.units, r.seq
			id := ids.FromBytes(r.id).String()
			if f.shown {
				prev := ""
				if r.prev != nil {
					if i > 0 && rs[i-1].seq == *r.prev {
						prev = ids.FromBytes(rs[i-1].id).String()
					} else {
						prev = t.nsLogID(*r.prev).String()
					}
				}
				var m map[string]any
				if f.hidden {
					// A stand-in carries nothing of the entry but its
					// place (§7.9 Log entries).
					m = map[string]any{"id": id, "prev": prev, "kind": "hidden", "resource": r.m["resource"]}
				} else {
					m = t.decorateNSEntry(r, prev)
					if g, ok := m["gestures"].(map[string]any); ok && f.names != nil {
						// A batch's, from its row's metadata (§7.4).
						narrowNames(m, "gestures", g, f.names)
					}
				}
				out.Entries = append(out.Entries, m)
				if f.hidden {
					f.revs = nil
				}
				out.named = append(out.named, f.revs)
			}
			out.Last = id
		}
	}
	out.More = at < toSeq
	return out
}

// entryFilter is what filterEntry decides for one entry.
type entryFilter struct {
	shown  bool
	hidden bool // shown as a hidden stand-in
	units  int
	// names, for a batch, are the resources of its items shown as head
	// or tombstone, which its gestures and source.ids are narrowed to.
	names map[string]bool
	// revs are the visible revisions and tombstones it names, as shown,
	// whose keys a sealed answer carries (filtered_seal.go).
	revs []namedRev
}

// filterEntry judges a log entry r for fv (§7.9 Log entries), narrowing a
// batch's body in place:
//
//   - a head when its revision is visible, a tombstone when the document
//     it deleted is (visible judges a tombstone so); one not shown whose
//     resource's previous head or tombstone entry was shown as itself
//     (shownAsItself) as a hidden stand-in, any other dropped;
//   - a prune when its target's document is visible, a purge when the
//     rules that don't refer to /doc allow reading its resource
//     (fview.purgeShown);
//   - config and purge-ns always, branch never, as one answer serves
//     every reader of the view, nor any other kind;
//   - a batch with only its shown entries, a hidden one as {kind:
//     "hidden", resource}, and its gestures and source.ids for the items
//     shown as head or tombstone only, each left out if empty; one with
//     nothing shown dropped, so kept config-only where it has a config
//     entry.
func (t *tx) filterEntry(n *nsRow, fv *fview, r *nsLogRow) entryFilter {
	m := r.m
	name, _ := m["resource"].(string)
	switch m["kind"] {
	case "config", "purge-ns":
		return entryFilter{shown: true, units: 1}
	case "head", "tombstone":
		res, target := t.movedBy(n, r.seq, name)
		if fv.visible(t, name, target) {
			return entryFilter{shown: true, units: 1, revs: []namedRev{{name, target}}}
		}
		if t.shownAsItself(n, fv, name, res, r.seq) {
			return entryFilter{shown: true, hidden: true, units: 1}
		}
		return entryFilter{units: 1}
	case "prune":
		var target *revRow
		if r.target.Valid {
			target = t.rev(r.target.Int64)
		}
		if fv.visible(t, name, target) {
			return entryFilter{shown: true, units: 1, revs: []namedRev{{name, target}}}
		}
		return entryFilter{units: 1}
	case "purge":
		return entryFilter{shown: fv.purgeShown(name), units: 1}
	case "batch":
	default:
		return entryFilter{units: 1}
	}
	es, _ := m["entries"].([]any)
	kept := []any{}
	names := map[string]bool{}
	var revs []namedRev
	for _, x := range es {
		em, _ := x.(map[string]any)
		ename, isRes := em["resource"].(string)
		switch {
		case em == nil:
		case !isRes && em["kind"] == "config":
			kept = append(kept, em)
		case isRes && (em["kind"] == "head" || em["kind"] == "tombstone"):
			res, target := t.movedBy(n, r.seq, ename)
			switch {
			case fv.visible(t, ename, target):
				names[ename] = true
				kept = append(kept, em)
				revs = append(revs, namedRev{ename, target})
			case t.shownAsItself(n, fv, ename, res, r.seq):
				kept = append(kept, map[string]any{"kind": "hidden", "resource": ename})
			}
		}
	}
	if len(kept) == 0 {
		return entryFilter{units: 1}
	}
	m["entries"] = kept
	if src, ok := m["source"].(map[string]any); ok {
		if ids, ok := src["ids"].(map[string]any); ok {
			narrowNames(src, "ids", ids, names)
		}
	}
	return entryFilter{shown: true, units: len(kept), names: names, revs: revs}
}

// movedBy is the resources row of name in n and the revision or tombstone
// the entry at ns_log seq moved its head to (head_history), nil for none.
func (t *tx) movedBy(n *nsRow, seq int64, name string) (int64, *revRow) {
	r := t.resource(n.id, name)
	if r == nil {
		return 0, nil
	}
	var target int64
	err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq = ?`, r.id, seq).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return r.id, nil
	}
	t.must(err)
	return r.id, t.rev(target)
}

// shownAsItself reports whether the previous head or tombstone entry of
// resource row res before ns_log seq was shown to fv as itself: whether
// the revision or tombstone it moved the head to is visible (§7.9 Log
// entries; a hidden stand-in doesn't count).
func (t *tx) shownAsItself(n *nsRow, fv *fview, name string, res, seq int64) bool {
	if res == 0 {
		return false
	}
	var target int64
	err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq < ? ORDER BY ns_seq DESC LIMIT 1`, res, seq).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	t.must(err)
	return fv.visible(t, name, t.rev(target))
}

// narrowNames leaves in parent[key], a map by resource name, only the
// names in shown, and drops it if none is left.
func narrowNames(parent map[string]any, key string, byName map[string]any, shown map[string]bool) {
	out := map[string]any{}
	for name, v := range byName {
		if shown[name] {
			out[name] = v
		}
	}
	if len(out) == 0 {
		delete(parent, key)
		return
	}
	parent[key] = out
}

// FilteredLog serves GET /ns/{ns}/view/{view}/at/{at}/log?since= (§7.9 Log
// ranges): a page of the range after since up to {ns}'s ns_id in at, the
// range's end, which answers carry as X-Namespace-Revision (info), filtered
// as filteredRange says, limit units a page. A purged namespace's range
// stays readable and ends with its purge-ns entry (§8.5). An at it can't
// answer is a *FilteredRedirect to the current one.
func (e *Engine) FilteredLog(ctx context.Context, ns, view, at, since string, limit int, cred Credentials) (lg *Log, info *FilteredInfo, err error) {
	err = e.read(ctx, func(t *tx) error {
		n, fv, err := t.filteredAtView(ns, view, at, cred)
		if err != nil {
			return err
		}
		info = filteredInfo(fv)
		if t.sealedPurged(n) {
			// Its keys are gone with it: 410, as its unfiltered range
			// answers (§8.5).
			return t.purgedRead(n)
		}
		lg = t.filteredRange(n, fv, since, fv.CP().seq, limit)
		lg.Until = t.credUntil(cred, fv.a)
		// In a sealed namespace, one JWE under the view's K_view (§E.2.2).
		t.filteredRangeSealing(n, fv, since, fv.CP().at, lg, false)
		return nil
	})
	if err == nil {
		err = e.sealFilteredLog(ctx, lg)
	}
	return lg, info, err
}

// judgeEntries judges a resource log's entries for a reader whose rules
// refer to /doc (§C.2 item 5, §7.9 Log entries). A partial reader of a
// namespace §7.9 covers sees its visible revisions, without patches where
// the parent is hidden, and as {id, parent, kind: "hidden"} each hidden
// one whose parent is visible; any other is dropped. Any other reader
// reads the range only where each entry passes and each entry's parent
// too, as patches show it: ok is false otherwise, a read-rule failure.
// shown[i] is the row of out[i] where it is shown as itself, nil for a
// hidden stand-in, and patches[i] whether it is shown with its patches.
func (t *tx) judgeEntries(n *nsRow, a *actor, name string, entries []LogEntry) (out []map[string]any, shown []*revRow, patches []bool, ok bool) {
	partial := t.readsPartially(n, a)
	parentOf := func(r *revRow) (*revRow, bool) {
		if !r.parentSeq.Valid {
			return nil, false
		}
		return t.rev(r.parentSeq.Int64), true
	}
	for _, e := range entries {
		vis := t.mayReadRow(a, n, name, e.row)
		p, hasParent := parentOf(e.row)
		pvis := hasParent && t.mayReadRow(a, n, name, p)
		if !partial {
			if !vis || hasParent && !pvis {
				return nil, nil, nil, false
			}
			out = append(out, e.value())
			shown, patches = append(shown, e.row), append(patches, true)
			continue
		}
		switch {
		case vis:
			m := e.value()
			if hasParent && !pvis {
				delete(m, "patches")
			}
			out = append(out, m)
			shown, patches = append(shown, e.row), append(patches, !hasParent || pvis)
		case pvis:
			out = append(out, map[string]any{"id": e.ID, "parent": e.Parent, "kind": "hidden"})
			shown, patches = append(shown, nil), append(patches, false)
		}
	}
	return out, shown, patches, true
}

// seesKeptRange judges, for a whose reads of n are judged per revision,
// the kept part of a pruned range of name ending at to (ResourceLog): the
// revisions from to down to the first revision pruning left without its
// patch set, the horizon, as judgeEntries judges a range. seen reports
// whether a may read any of them, all whether it may read every one.
func (t *tx) seesKeptRange(n *nsRow, a *actor, name string, to *revRow) (seen, all bool) {
	all = true
	for r := to; r != nil; {
		if t.mayReadRow(a, n, name, r) {
			seen = true
		} else {
			all = false
		}
		if r.kind == kindRev && !r.patches.Valid || !r.parentSeq.Valid {
			break
		}
		r = t.rev(r.parentSeq.Int64)
	}
	return seen, all
}

// seesAnyEntry reports whether a, whose reads of n are judged per
// revision, may read any of entries, revisions or tombstones of name.
func (t *tx) seesAnyEntry(n *nsRow, a *actor, name string, entries []LogEntry) bool {
	for _, e := range entries {
		if t.mayReadRow(a, n, name, e.row) {
			return true
		}
	}
	return false
}

// readsPartially reports whether a reads n as a partial reader at a
// resource's URLs (judgeEntries): hidden entries are left out of a range,
// rather than refusing it. Never in a public namespace.
func (t *tx) readsPartially(n *nsRow, a *actor) bool {
	// A public namespace's resource URLs ignore the grant (§7 step 1):
	// only its view prefix filters (v0.90).
	return a != nil && a.view == "" && a.verified != nil && t.config(n.configSeq).Read != "public" &&
		t.filteredScope(n) != nil && t.partialReader(a)
}

// judgePruneEvents leaves out of a resource stream's events (resourceEvents)
// the prune events whose target a reads by its rules on /doc can't read
// (§7.9 Log entries: "its purge and prune events as the namespace log
// shows them").
func (t *tx) judgePruneEvents(n *nsRow, a *actor, name string, es []map[string]any) []map[string]any {
	var head *revRow
	out := es[:0]
	for _, m := range es {
		if m["kind"] == "prune" {
			if head == nil {
				head = t.resolve(n, name, nil).head
			}
			var row *revRow
			if id, err := ids.Parse(fmt.Sprint(m["target"])); err == nil && head != nil {
				row = t.findInAncestry(head, id)
			}
			if !t.mayReadRow(a, n, name, row) {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}
