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
	// snapRevs and snapBytes count the revisions, and the bytes of their
	// stored patch sets, since the resource's last intermediate snapshot
	// (D.4, insertItems); NULL when unknown (snapCounts).
	snapRevs, snapBytes sql.NullInt64
}

const resCols = `res, ns, name, head_seq, state, horizon_seq, keep, snap_revs, snap_bytes`

func scanRes(row interface{ Scan(...any) error }) (*resRow, error) {
	r := &resRow{}
	err := row.Scan(&r.id, &r.ns, &r.name, &r.headSeq, &r.state, &r.horizonSeq, &r.keep, &r.snapRevs, &r.snapBytes)
	return r, err
}

// resource returns a namespace's own resource row, or nil. The transaction
// remembers the answer, absence included (memo.go).
func (t *tx) resource(ns int64, name string) *resRow {
	k := resKey{ns, name}
	if r, ok := t.memo.res[k]; ok {
		if r == nil {
			return nil
		}
		c := *r
		return &c
	}
	r, err := scanRes(t.QueryRow(`SELECT `+resCols+` FROM resources WHERE ns = ? AND name = ?`, ns, name))
	if errors.Is(err, sql.ErrNoRows) {
		r = nil
	} else {
		t.must(err)
	}
	t.memoRes(k, r)
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

func (t *tx) memoRes(k resKey, r *resRow) {
	if t.memo.res == nil {
		t.memo.res = map[resKey]*resRow{}
	}
	t.memo.res[k] = r
}

// prefetchResources reads the rows of several resources of a namespace in
// one statement, for resource to answer from memory: a batch's items.
func (t *tx) prefetchResources(ns int64, names []string) {
	if !t.e.pg || len(names) < 2 {
		return // a SQLite query costs no round trip
	}
	var want []string
	for _, name := range names {
		if _, ok := t.memo.res[resKey{ns, name}]; !ok {
			want = append(want, name)
		}
	}
	if len(want) == 0 {
		return
	}
	rows, err := t.Query(`SELECT `+resCols+` FROM resources WHERE ns = ? AND name = ANY(?::text[])`, ns, want)
	t.must(err)
	found := map[string]*resRow{}
	for rows.Next() {
		r, err := scanRes(rows)
		t.must(err)
		found[r.name] = r
	}
	t.must(rows.Err())
	rows.Close()
	for _, name := range want {
		t.memoRes(resKey{ns, name}, found[name])
	}
}

// revRow is a revisions row.
type revRow struct {
	seq       int64
	res       int64
	id        ids.ID
	parentSeq sql.NullInt64
	first     bool
	kind      int
	patches   sql.NullString // as stored: encrypted at rest or not (patchesOf)
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
	if r, ok := t.memo.rev[seq]; ok {
		return &r
	}
	if r, ok := t.ownRevs[seq]; ok {
		return &r
	}
	r, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE seq = ?`, seq))
	t.must(err)
	if t.memo.rev == nil {
		t.memo.rev = map[int64]revRow{}
	}
	t.memo.rev[seq] = *r
	t.knowRevID(seq, r.id)
	return r
}

// revID returns a revision's id, which never changes once inserted.
func (t *tx) revID(seq int64) ids.ID {
	if id, ok := t.revIDs[seq]; ok {
		return id
	}
	return t.rev(seq).id
}

func (t *tx) knowRevID(seq int64, id ids.ID) {
	if t.revIDs == nil {
		t.revIDs = map[int64]ids.ID{}
	}
	t.revIDs[seq] = id
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
	_, r := t.locate(t.ancestry(head), id)
	return r
}

// locate returns the row with id in segs (an ancestry, newest first) and
// the index of its segment, or nil and -1.
func (t *tx) locate(segs []segment, id ids.ID) (int, *revRow) {
	for i, s := range segs {
		r, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ? AND seq <= ?`, s.res, id[:], s.max))
		if err == nil {
			return i, r
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
	}
	return -1, nil
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
			// A heads row may belong to another resource than cur (a
			// branch's head whose last live document is the base's): its
			// own res decides the key.
			var doc string
			var dres int64
			err := t.QueryRow(`SELECT res, doc FROM heads WHERE seq = ?`, cur.seq).Scan(&dres, &doc)
			if err == nil {
				base = t.docOf("heads", dres, cur.seq, doc)
				break
			}
			err = t.QueryRow(`SELECT res, doc FROM snapshots WHERE seq = ?`, cur.seq).Scan(&dres, &doc)
			if err == nil {
				base = t.docOf("snapshots", dres, cur.seq, doc)
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
		ops, err := patch.Parse(jsonv.MustParse(t.patchesOf(row)))
		if err != nil {
			return nil, err
		}
		// The fold owns doc (parsed above), so the ops change it in place,
		// and only the revision asked for is serialised and cached: copying
		// and canonicalising the whole document at every step made a fold
		// cost O(steps × size).
		doc, _, err = patch.Apply(doc, exists, ops, patch.Options{InPlace: true})
		if err != nil {
			return nil, err
		}
		exists = true
	}
	if !exists {
		return nil, errors.New("no document")
	}
	if len(stack) == 0 {
		return base, nil
	}
	b := jsonv.Canonical(doc)
	t.cacheDoc(r.id, b)
	return b, nil
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

	row *revRow // the entry's row (sealing, sealed.go)
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
	e := LogEntry{ID: r.id.String(), Author: t.authorName(r.author), Created: formatTime(r.created), row: r}
	if r.parentSeq.Valid {
		e.Parent = t.revID(r.parentSeq.Int64).String()
	}
	if r.kind == kindTombstone {
		e.Kind = "tombstone"
	} else {
		e.Kind = "rev"
		if r.patches.Valid { // NULL below a horizon (§8.6)
			e.Patches = jsonv.MustParse(t.patchesOf(r))
		}
	}
	if r.signature.Valid {
		e.Signature = r.signature.String
	}
	return e
}

// logBetween returns the entries after since (exclusive; nil = from the
// first entry) up to to (inclusive), oldest first: with limit > 0 only the
// oldest limit of them, more reporting that the range goes on (a page,
// §7.1). A since that isn't an ancestor of to is errNotAncestor. A pruned
// entry anywhere in the range is a prunedError, so every page of a range
// answers alike.
//
// A page costs its own rows, whatever the range's length (§7.1 Paging): a
// resource's chain is its rows in seq order (one first row, one child per
// parent), so the range is a seq interval of each ancestry segment, read
// oldest first and only as far as the page goes, and the pruning check
// looks only below horizons (prunedIn). Walking the parent links from to
// instead read the whole rest of the range for every page.
func (t *tx) logBetween(to *revRow, since *ids.ID, limit int) (entries []LogEntry, more bool, err error) {
	segs := t.ancestry(to)
	// The range is (lo, max] of the oldest segment it reaches, segs[k],
	// and the whole of the newer ones. Ids and parent links survive
	// pruning, so ancestry is decided first: a since that isn't an
	// ancestor is 404 even across a horizon (§7.1).
	k, lo := len(segs)-1, int64(0)
	if since != nil {
		var srow *revRow
		if to.id == *since {
			k, srow = 0, to
		} else {
			k, srow = t.locate(segs, *since)
		}
		if srow == nil {
			return nil, false, errNotAncestor
		}
		lo = srow.seq
		t.knowRevID(srow.seq, srow.id) // the first entry's parent
	}
	segs = segs[:k+1]
	if err := t.prunedIn(segs, lo); err != nil {
		return nil, false, err
	}
	var rows []*revRow
	for i := k; i >= 0 && (limit <= 0 || len(rows) < limit); i-- {
		from := int64(0)
		if i == k {
			from = lo
		}
		q := `SELECT ` + revCols + ` FROM revisions WHERE res = ? AND seq > ? AND seq <= ? ORDER BY seq`
		args := []any{segs[i].res, from, segs[i].max}
		if limit > 0 {
			q += ` LIMIT ?`
			args = append(args, limit-len(rows))
		}
		rs, err := t.Query(q, args...)
		t.must(err)
		for rs.Next() {
			r, err := scanRev(rs)
			t.must(err)
			rows = append(rows, r)
		}
		t.must(rs.Err())
		rs.Close()
	}
	// Each entry's parent is the row before it (a segment's first row's,
	// the last of the older segment), so its id is known.
	for _, r := range rows {
		t.knowRevID(r.seq, r.id)
	}
	more = len(rows) > 0 && rows[len(rows)-1].seq != to.seq
	out := make([]LogEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, t.logEntry(r))
	}
	return out, more, nil
}

// prunedIn reports a range's newest pruned entry (§8.6) as a prunedError,
// or purgedError if its resource is purged; segs are the range's segments,
// newest first, the oldest one from lo (exclusive). Pruning drops the patch
// sets of a resource's revisions below its horizon (a remote branch's
// mirrored horizon has none itself, §G.3; a partial restore fills some
// back in), and purging all of them, so a resource that is neither is
// looked at only at or below its horizon: a range above every horizon
// costs a query per segment, not a row per entry.
func (t *tx) prunedIn(segs []segment, lo int64) error {
	for i, s := range segs {
		from := int64(0)
		if i == len(segs)-1 {
			from = lo
		}
		var state int
		var horizon sql.NullInt64
		var nsPurged bool
		t.must(t.QueryRow(`SELECT r.state, r.horizon_seq, n.purged FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE r.res = ?`, s.res).Scan(&state, &horizon, &nsPurged))
		to := s.max
		if state != statePurged && !nsPurged {
			if !horizon.Valid {
				continue
			}
			to = min(to, horizon.Int64)
		}
		if to <= from {
			continue
		}
		var seq int64
		err := t.QueryRow(`SELECT seq FROM revisions WHERE res = ? AND seq > ? AND seq <= ? AND kind = 0 AND patches IS NULL ORDER BY seq DESC LIMIT 1`, s.res, from, to).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		t.must(err)
		if state == statePurged {
			return purgedError{}
		}
		return &prunedError{res: s.res, seq: seq}
	}
	return nil
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
