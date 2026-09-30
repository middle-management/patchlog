package core

import (
	"database/sql"
	"errors"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// State of a resource as seen from a namespace.
type State int

const (
	NotFound State = iota
	Live
	Tombstoned
	Purged
)

// resRow is a resources row.
type resRow struct {
	id         int64
	ns         int64
	name       string
	headSeq    sql.NullInt64
	state      int
	horizonSeq sql.NullInt64
	keep       sql.NullString
}

func (t *tx) resource(ns int64, name string) *resRow {
	r := &resRow{}
	err := t.QueryRow(`SELECT res, ns, name, head_seq, state, horizon_seq, keep FROM resources WHERE ns = ? AND name = ?`, ns, name).
		Scan(&r.id, &r.ns, &r.name, &r.headSeq, &r.state, &r.horizonSeq, &r.keep)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	return r
}

// revRow is a revisions row.
type revRow struct {
	seq       int64
	res       int64
	id        ids.ID
	parentSeq sql.NullInt64
	first     bool
	kind      int
	patches   sql.NullString
	author    int64
	via       sql.NullString
	grantID   []byte
	signature sql.NullString
	created   int64
}

const revCols = `seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, created`

func scanRev(row interface{ Scan(...any) error }) (*revRow, error) {
	r := &revRow{}
	var id []byte
	err := row.Scan(&r.seq, &r.res, &id, &r.parentSeq, &r.first, &r.kind, &r.patches, &r.author, &r.via, &r.grantID, &r.signature, &r.created)
	r.id = ids.FromBytes(id)
	return r, err
}

func (t *tx) rev(seq int64) *revRow {
	r, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE seq = ?`, seq))
	t.must(err)
	return r
}

// view is a resource as a namespace sees it, possibly read through from a
// base (§7.6).
type view struct {
	ns    *nsRow
	name  string
	own   *resRow // the namespace's own row, if any
	state State
	// head is the head entry (revision or tombstone), which may belong to a
	// base's resource. Nil when NotFound or Purged without entries.
	head *revRow
	// src is the resource row the answer came from (own or a base's).
	src *resRow
}

func (v *view) readThrough() bool { return v.own == nil || v.own.headSeq.Valid == false }

// resolve returns a resource as seen from ns, now (asOf nil) or as of an
// ns_log seq of ns.
func (t *tx) resolve(n *nsRow, name string, asOf *int64) *view {
	v := &view{ns: n, name: name}
	r := t.resource(n.id, name)
	v.own = r
	if r != nil {
		if r.state == statePurged {
			v.state, v.src = Purged, r
			if r.headSeq.Valid {
				v.head = t.rev(r.headSeq.Int64)
			}
			return v
		}
		var headSeq int64
		found := false
		if asOf == nil {
			if r.headSeq.Valid {
				headSeq, found = r.headSeq.Int64, true
			}
		} else {
			err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq <= ? ORDER BY ns_seq DESC LIMIT 1`, r.id, *asOf).Scan(&headSeq)
			if err == nil {
				found = true
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.must(err)
			}
		}
		if found {
			v.src = r
			v.head = t.rev(headSeq)
			if v.head.kind == kindTombstone {
				v.state = Tombstoned
			} else {
				v.state = Live
			}
			return v
		}
	}
	if n.isBranch() {
		base := t.nsByID(n.base.Int64)
		at := n.baseAt.Int64
		bv := t.resolve(base, name, &at)
		v.state, v.head, v.src = bv.state, bv.head, bv.src
		return v
	}
	v.state = NotFound
	return v
}

// segment is a stretch of one resource's chain: rows of res with seq ≤ max.
type segment struct{ res, max int64 }

// ancestry lists the chain segments from a head back to its first entry,
// crossing foreign parents (§7.6).
func (t *tx) ancestry(head *revRow) []segment {
	var segs []segment
	res, max := head.res, head.seq
	for {
		segs = append(segs, segment{res, max})
		var parent sql.NullInt64
		err := t.QueryRow(`SELECT parent_seq FROM revisions WHERE res = ? AND first = 1`, res).Scan(&parent)
		if errors.Is(err, sql.ErrNoRows) || !parent.Valid {
			return segs
		}
		t.must(err)
		var pres int64
		t.must(t.QueryRow(`SELECT res FROM revisions WHERE seq = ?`, parent.Int64).Scan(&pres))
		res, max = pres, parent.Int64
	}
}

// findInAncestry returns the row with id in the ancestry of head, or nil.
func (t *tx) findInAncestry(head *revRow, id ids.ID) *revRow {
	if head.id == id {
		return head
	}
	for _, s := range t.ancestry(head) {
		r, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ? AND seq <= ?`, s.res, id[:], s.max))
		if err == nil {
			return r
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
	}
	return nil
}

// prunedError reports a revision below a horizon (§8.6).
type prunedError struct{ res, seq int64 }

func (e *prunedError) Error() string { return "pruned" }

type purgedError struct{}

func (purgedError) Error() string { return "purged" }

// docAt returns the document at a revision row (for a tombstone: the last
// live document). exists is false when the chain has no document (a
// tombstone right after nothing, which cannot happen, or a failed fold).
func (t *tx) docAt(r *revRow) (any, error) {
	b, err := t.docBytesAt(r)
	if err != nil {
		return nil, err
	}
	return jsonv.MustParse(b), nil
}

func (t *tx) docBytesAt(r *revRow) ([]byte, error) {
	// Cached documents are used only for rows that still have their patch
	// set: an id shared with another resource must not revive a pruned or
	// purged revision (§8.3, §8.6).
	if b, ok := t.e.docs.get(r.id); ok && r.kind == kindRev && r.patches.Valid {
		return b, nil
	}
	var stack []*revRow
	var base []byte
	cur := r
	for {
		if cur.kind == kindRev {
			if b, ok := t.e.docs.get(cur.id); ok && cur.patches.Valid {
				base = b
				break
			}
			var doc string
			err := t.QueryRow(`SELECT doc FROM heads WHERE seq = ?`, cur.seq).Scan(&doc)
			if err == nil {
				base = []byte(doc)
				break
			}
			err = t.QueryRow(`SELECT doc FROM snapshots WHERE seq = ?`, cur.seq).Scan(&doc)
			if err == nil {
				base = []byte(doc)
				break
			}
			if !cur.patches.Valid {
				var state int
				t.must(t.QueryRow(`SELECT state FROM resources WHERE res = ?`, cur.res).Scan(&state))
				if state == statePurged {
					return nil, purgedError{}
				}
				return nil, &prunedError{res: cur.res, seq: cur.seq}
			}
			stack = append(stack, cur)
		}
		if !cur.parentSeq.Valid {
			break
		}
		cur = t.rev(cur.parentSeq.Int64)
	}
	var doc any
	exists := base != nil
	if exists {
		doc = jsonv.MustParse(base)
	}
	for i := len(stack) - 1; i >= 0; i-- {
		row := stack[i]
		ops, err := patch.Parse(jsonv.MustParse([]byte(row.patches.String)))
		if err != nil {
			return nil, err
		}
		doc, _, err = patch.Apply(doc, exists, ops, patch.Options{})
		if err != nil {
			return nil, err
		}
		exists = true
		t.e.docs.put(row.id, jsonv.Canonical(doc))
	}
	if !exists {
		return nil, errors.New("no document")
	}
	if len(stack) == 0 {
		return base, nil
	}
	return jsonv.Canonical(doc), nil
}

// horizonID returns the text id of a resource's horizon.
func (t *tx) horizonID(res int64) string {
	var seq sql.NullInt64
	t.must(t.QueryRow(`SELECT horizon_seq FROM resources WHERE res = ?`, res).Scan(&seq))
	if !seq.Valid {
		return ""
	}
	return t.rev(seq.Int64).id.String()
}

// LogEntry is a resource log entry (§7.1).
type LogEntry struct {
	ID        string `json:"id"`
	Parent    string `json:"parent,omitempty"`
	Kind      string `json:"kind"`
	Patches   any    `json:"patches,omitempty"`
	Author    string `json:"author"`
	Created   string `json:"created"`
	Signature string `json:"signature,omitempty"`
}

func (e LogEntry) value() map[string]any {
	m := map[string]any{"id": e.ID, "kind": e.Kind, "author": e.Author, "created": e.Created}
	if e.Parent != "" {
		m["parent"] = e.Parent
	}
	if e.Kind == "rev" && e.Patches != nil {
		m["patches"] = e.Patches
	}
	if e.Signature != "" {
		m["signature"] = e.Signature
	}
	return m
}

func (t *tx) logEntry(r *revRow) LogEntry {
	e := LogEntry{ID: r.id.String(), Author: t.authorName(r.author), Created: formatTime(r.created)}
	if r.parentSeq.Valid {
		e.Parent = t.rev(r.parentSeq.Int64).id.String()
	}
	if r.kind == kindTombstone {
		e.Kind = "tombstone"
	} else {
		e.Kind = "rev"
		if r.patches.Valid { // NULL below a horizon (§8.6)
			e.Patches = jsonv.MustParse([]byte(r.patches.String))
		}
	}
	if r.signature.Valid {
		e.Signature = r.signature.String
	}
	return e
}

// logBetween returns the entries after since (exclusive; nil = from the
// first entry) up to to (inclusive), oldest first. ok is false if since is
// not an ancestor of to. A pruned entry in the range is a prunedError.
func (t *tx) logBetween(to *revRow, since *ids.ID) ([]LogEntry, error) {
	// Ids and parent links survive pruning, so ancestry is decided first: a
	// since that isn't an ancestor is 404 even across a horizon (§7.1).
	if since != nil && t.findInAncestry(to, *since) == nil {
		return nil, errNotAncestor
	}
	var rows []*revRow
	cur := to
	for {
		if since != nil && cur.id == *since {
			break
		}
		if cur.kind == kindRev && !cur.patches.Valid {
			var state int
			t.must(t.QueryRow(`SELECT state FROM resources WHERE res = ?`, cur.res).Scan(&state))
			if state == statePurged {
				return nil, purgedError{}
			}
			return nil, &prunedError{res: cur.res, seq: cur.seq}
		}
		rows = append(rows, cur)
		if !cur.parentSeq.Valid {
			if since != nil {
				return nil, errNotAncestor
			}
			break
		}
		cur = t.rev(cur.parentSeq.Int64)
	}
	out := make([]LogEntry, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		out = append(out, t.logEntry(rows[i]))
	}
	return out, nil
}

var errNotAncestor = errors.New("not an ancestor")

// lastLive returns the last live revision at or before r (r itself if it is
// a revision, else the tombstone's parent).
func (t *tx) lastLive(r *revRow) *revRow {
	for r.kind == kindTombstone && r.parentSeq.Valid {
		r = t.rev(r.parentSeq.Int64)
	}
	return r
}
