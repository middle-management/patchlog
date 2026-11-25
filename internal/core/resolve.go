package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	delete(t.memo.views, k)
}

// memoRev remembers a revision row (rev).
func (t *tx) memoRev(r *revRow) {
	if t.memo.rev == nil {
		t.memo.rev = map[int64]revRow{}
	}
	t.memo.rev[r.seq] = *r
	t.knowRevID(r.seq, r.id)
}

// revByID returns the revision of resource res with id, or nil: the
// idempotent-retry lookup's (§7.2) and the first segment of a revision
// read's (findInAncestry). The transaction remembers the answer, absence
// included (memo.byID), which lookupResource may already have read.
func (t *tx) revByID(res int64, id ids.ID) *revRow {
	k := revIDKey{res, id}
	if r, ok := t.memo.byID[k]; ok {
		if r == nil {
			return nil
		}
		c := *r
		return &c
	}
	var r *revRow
	if seq, ok := t.memo.idSeq[k]; ok {
		// Found by lookupResource, which read only its seq.
		r = t.rev(seq)
	} else {
		var err error
		r, err = scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ?`, res, id[:]))
		if errors.Is(err, sql.ErrNoRows) {
			r = nil
		} else {
			t.must(err)
		}
	}
	t.memoByID(k, r)
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

func (t *tx) memoByID(k revIDKey, r *revRow) {
	if t.memo.byID == nil {
		t.memo.byID = map[revIDKey]*revRow{}
	}
	t.memo.byID[k] = r
}

// lookupResource reads namespace name with, in the same statement, its
// own row of resource res (or its absence), that row's head revision, and
// if want isn't nil the revision of that row's resource with id want (or
// its absence): what a write's check of one item reads (the target, the
// item's resource as resolve sees it, the idempotent-retry lookup of
// §7.2) and a revision read. It fills the transaction's memo, so resolve,
// replay and findInAncestry answer from it, and returns the namespace row,
// or nil. On Postgres each statement is a round trip: separately they were
// four.
//
// Of the revision with id want it reads the whole row if full (a revision
// read, which serves it), else only its seq (a check, whose retry lookup
// rarely finds one; revByID reads the row then). Fewer columns cost less
// to decode: pgx allocates afresh for each result of more than 16.
//
// A namespace read through a base isn't helped below its own row (resolve
// reads the base's rows as before), but costs no more.
func (t *tx) lookupResource(name, res string, want *ids.ID, full bool) *nsRow {
	var idArg any
	if want != nil {
		idArg = want[:]
	}
	var nr nullRes
	var hr, xr nullRev
	var xseq sql.NullInt64
	n := &nsRow{}
	var cfg sql.NullInt64
	dest := make([]any, 0, 9+9+2*16)
	dest = append(dest, &n.id, &n.name, &n.base, &n.baseAt, &n.baseConfigSeq, &n.frozen, &n.purged, &n.headSeq, &cfg)
	dest = nr.dest(dest)
	dest = hr.dest(dest)
	if full {
		dest = xr.dest(dest)
	} else {
		dest = append(dest, &xseq)
	}
	// Spanner has no LATERAL: SQLite's forms, which tx rebinds; a check's
	// its own (lookupCheckSpanner).
	q := lookupSQL[b2i(full)][b2i(t.e.pg && !t.e.spanner)]
	if t.e.spanner && !full {
		q = lookupCheckSpanner
	}
	var row *sql.Row
	if full {
		row = t.QueryRow(q, res, idArg, name)
	} else {
		// The seq's subquery comes first, in the columns.
		row = t.QueryRow(q, idArg, res, name)
	}
	err := row.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	n.configSeq = cfg.Int64
	r := nr.row()
	t.memoRes(resKey{n.id, res}, r)
	if h := hr.row(); h != nil {
		t.memoRev(h)
	}
	if r != nil && want != nil {
		k := revIDKey{r.id, *want}
		switch {
		case full:
			t.memoByID(k, xr.row())
		case xseq.Valid:
			if t.memo.idSeq == nil {
				t.memo.idSeq = map[revIDKey]int64{}
			}
			t.memo.idSeq[k] = xseq.Int64
		default:
			t.memoByID(k, nil)
		}
	}
	return n
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// lookupSQL are lookupResource's statements, by full and Postgres (their
// placeholders in a different order: lookupResource): a
// namespace, a resource and its head (n, r, h), and the revision with an
// id (x, its seq or its row), the last three possibly NULL. That revision
// is at most one row, as revByID's QueryRow: LATERAL on Postgres, a scalar
// subquery in SQLite (which has no LATERAL).
var lookupSQL = func() (q [2][2]string) {
	cols := func(alias, list string) string {
		var out []string
		for _, c := range strings.Split(list, ",") {
			out = append(out, alias+"."+strings.TrimSpace(c))
		}
		return strings.Join(out, ", ")
	}
	common := cols("n", nsCols) + ", " + cols("r", resCols) + ", " + cols("h", revCols)
	from := ` FROM namespaces n
		LEFT JOIN resources r ON r.ns = n.ns AND r.name = ?
		LEFT JOIN revisions h ON h.seq = r.head_seq`
	byID := `SELECT seq FROM revisions WHERE res = r.res AND id = ? LIMIT 1`
	for pg := 0; pg < 2; pg++ {
		q[0][pg] = `SELECT ` + common + `, (` + byID + `)` + from + ` WHERE n.name = ?`
	}
	q[1][1] = `SELECT ` + common + `, ` + cols("x", revCols) + from + `
		LEFT JOIN LATERAL (SELECT ` + revCols + ` FROM revisions WHERE res = r.res AND id = ? LIMIT 1) x ON true
		WHERE n.name = ?`
	q[1][0] = `SELECT ` + common + `, ` + cols("x", revCols) + from + `
		LEFT JOIN revisions x ON x.seq = (` + byID + `)
		WHERE n.name = ?`
	return q
}()

// lookupCheckSpanner is lookupSQL's check form on Spanner: the seq of the
// revision with the id asked for is the head's when that is the one asked
// for, as a write's If-Match mostly is, without its own lookup of
// revisions_res_id_key; only otherwise the subquery. A write's check is
// half of Spanner's CPU at load (docs/SPANNER.md, the fifth bench run).
// Its placeholders are numbered: $1, the id, is used twice.
var lookupCheckSpanner = func() string {
	q := lookupSQL[0][0]
	sub := `(SELECT seq FROM revisions WHERE res = r.res AND id = ? LIMIT 1)`
	if !strings.Contains(q, sub) {
		panic("lookupCheckSpanner: lookupSQL changed")
	}
	q = strings.Replace(q, sub, `CASE WHEN h.id = $1 THEN h.seq ELSE (SELECT seq FROM revisions WHERE res = r.res AND id = $1 LIMIT 1) END`, 1)
	q = strings.Replace(q, `r.name = ?`, `r.name = $2`, 1)
	q = strings.Replace(q, `n.name = ?`, `n.name = $3`, 1)
	if strings.Contains(q, "?") {
		panic("lookupCheckSpanner: placeholders left")
	}
	return q
}()

// nullRes scans a resources row that may be all NULL (an outer join).
type nullRes struct {
	id, ns, headSeq, state, horizonSeq, snapRevs, snapBytes sql.NullInt64
	name, keep                                              sql.NullString
}

func (n *nullRes) dest(d []any) []any {
	return append(d, &n.id, &n.ns, &n.name, &n.headSeq, &n.state, &n.horizonSeq, &n.keep, &n.snapRevs, &n.snapBytes)
}

func (n *nullRes) row() *resRow {
	if !n.id.Valid {
		return nil
	}
	return &resRow{id: n.id.Int64, ns: n.ns.Int64, name: n.name.String, headSeq: n.headSeq, state: int(n.state.Int64),
		horizonSeq: n.horizonSeq, keep: n.keep, snapRevs: n.snapRevs, snapBytes: n.snapBytes}
}

// nullRev scans a revisions row that may be all NULL (an outer join).
type nullRev struct {
	seq, res, parentSeq, kind, author, created, size sql.NullInt64
	first                                            sql.NullBool
	id, grantID, digest                              []byte
	patches, via, signature, gesture, undoes         sql.NullString
}

func (n *nullRev) dest(d []any) []any {
	return append(d, &n.seq, &n.res, &n.id, &n.parentSeq, &n.first, &n.kind, &n.patches, &n.author, &n.via, &n.grantID, &n.signature, &n.created, &n.gesture, &n.undoes, &n.size, &n.digest)
}

func (n *nullRev) row() *revRow {
	if !n.seq.Valid {
		return nil
	}
	return &revRow{seq: n.seq.Int64, res: n.res.Int64, id: ids.FromBytes(n.id), parentSeq: n.parentSeq, first: n.first.Bool,
		kind: int(n.kind.Int64), patches: n.patches, author: n.author.Int64, via: n.via, grantID: n.grantID,
		signature: n.signature, created: n.created.Int64, gesture: n.gesture, undoes: n.undoes, size: n.size, digest: n.digest}
}

// prefetchResources reads the rows of several resources of a namespace in
// one statement, for resource to answer from memory: a batch's items.
// Postgres only: a SQLite query costs no round trip.
func (t *tx) prefetchResources(ns int64, names []string) {
	if t.e.pg {
		t.readResources(ns, names)
	}
}

// readResources is prefetchResources in either dialect.
func (t *tx) readResources(ns int64, names []string) {
	if len(names) < 2 {
		return
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
	rows, err := t.Query(`SELECT `+resCols+` FROM resources WHERE ns = ? AND `+t.e.inArray("name", "text"), ns, t.e.arrayArg(want))
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

// prefetchHeads reads what resolve needs for several resources of n as of
// asOf (nil = now) in a few statements per namespace level, for resolve to
// answer from memory: their resource rows, their heads at asOf from
// head_history, and those head revisions. Names with no head of n's own
// there are looked up in its base, as resolve reads them through. A page of
// a heads listing (pageHeads) costs a handful of statements this way
// instead of three per resource: on Postgres each is a round trip, and in
// SQLite, though none is, three per resource were most of a 1000-item
// page's time.
func (t *tx) prefetchHeads(n *nsRow, names []string, asOf *int64) {
	for len(names) > 1 {
		t.readResources(n.id, names)
		var rest []string
		var heads []int64
		var resIDs []int64
		for _, name := range names {
			r := t.memo.res[resKey{n.id, name}]
			switch {
			case r == nil:
				rest = append(rest, name)
			case asOf == nil:
				if r.headSeq.Valid {
					heads = append(heads, r.headSeq.Int64)
				} else if r.state != statePurged {
					rest = append(rest, name)
				}
			default:
				// A purged row too: as of asOf it is purged only if it
				// had an entry then, its own or, with none of its own
				// there, one read through from the base (resolve, §8.3).
				resIDs = append(resIDs, r.id)
			}
		}
		if len(resIDs) > 0 {
			q := `SELECT r.res, h.target_seq FROM unnest(?::bigint[]) AS r(res)
				LEFT JOIN LATERAL (SELECT target_seq FROM head_history
					WHERE res = r.res AND ns_seq <= ? ORDER BY ns_seq DESC LIMIT 1) h ON true`
			if !t.e.pg { // no LATERAL: a correlated subquery
				q = `WITH r(res) AS (SELECT value FROM json_each(?))
				SELECT r.res, (SELECT h.target_seq FROM head_history h
					WHERE h.res = r.res AND h.ns_seq <= ? ORDER BY h.ns_seq DESC LIMIT 1) FROM r`
			} else if t.e.spanner { // nor on Spanner
				q = `SELECT r.res, (SELECT h.target_seq FROM head_history h
					WHERE h.res = r.res AND h.ns_seq <= $2 ORDER BY h.ns_seq DESC LIMIT 1) FROM unnest($1::bigint[]) AS r(res)`
			}
			rows, err := t.Query(q, t.e.arrayArg(resIDs), *asOf)
			t.must(err)
			if t.memo.headAt == nil {
				t.memo.headAt = map[headAtKey]int64{}
			}
			at := map[int64]int64{}
			for rows.Next() {
				var res int64
				var target sql.NullInt64
				t.must(rows.Scan(&res, &target))
				at[res] = target.Int64
				t.memo.headAt[headAtKey{res, *asOf}] = target.Int64
				if target.Valid {
					heads = append(heads, target.Int64)
				}
			}
			t.must(rows.Err())
			rows.Close()
			for _, name := range names {
				if r := t.memo.res[resKey{n.id, name}]; r != nil && at[r.id] == 0 {
					rest = append(rest, name)
				}
			}
		}
		t.prefetchRevs(heads)
		if !n.isBranch() {
			return
		}
		at := n.baseAt.Int64
		n, names, asOf = t.base(n), rest, &at
	}
}

// prefetchRevs reads several revision rows in one statement into the
// transaction's memo, for rev to answer from memory.
func (t *tx) prefetchRevs(seqs []int64) {
	var want []int64
	for _, seq := range seqs {
		if _, ok := t.memo.rev[seq]; !ok {
			want = append(want, seq)
		}
	}
	if len(want) == 0 {
		return
	}
	rows, err := t.Query(`SELECT `+revCols+` FROM revisions WHERE `+t.e.inArray("seq", "bigint"), t.e.arrayArg(want))
	t.must(err)
	if t.memo.rev == nil {
		t.memo.rev = map[int64]revRow{}
	}
	for rows.Next() {
		r, err := scanRev(rows)
		t.must(err)
		t.memo.rev[r.seq] = *r
		t.knowRevID(r.seq, r.id)
	}
	t.must(rows.Err())
	rows.Close()
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
	// gesture and undoes are the gesture ids it was written with (§7.2),
	// metadata outside its id that pruning keeps (§8.6).
	gesture, undoes sql.NullString
	// size and digest are the length and sha-256 of the canonical document
	// of a revision a write left as a head (headMeta), which /heads lists;
	// NULL for any other row, and for rows from before them.
	size   sql.NullInt64
	digest []byte
}

const revCols = `seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, created, gesture, undoes, size, digest`

func scanRev(row interface{ Scan(...any) error }) (*revRow, error) {
	r := &revRow{}
	var id []byte
	err := row.Scan(&r.seq, &r.res, &id, &r.parentSeq, &r.first, &r.kind, &r.patches, &r.author, &r.via, &r.grantID, &r.signature, &r.created, &r.gesture, &r.undoes, &r.size, &r.digest)
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
	t.memoRev(r)
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
// ns_log seq of ns. A resource purged since asOf is purged as of asOf too,
// with its head then, but only if it had an entry then, its own or read
// through: one that didn't is not found, as it was then. So a branch
// created later at an at before a purge sees the name as purged only
// where it would read an entry for it through, and lists it with its head
// as of at (§8.3, invariant 7); head_history rows outlive the purge.
func (t *tx) resolve(n *nsRow, name string, asOf *int64) *view {
	if asOf == nil {
		// A write's check resolves each item's resource at each sub-step
		// of step 2 (purgedItems, settle, readsWrittenHead, precondition).
		if v, ok := t.memo.views[resKey{n.id, name}]; ok && v.ns == n {
			return v
		}
	}
	v := &view{ns: n, name: name}
	r := t.resource(n.id, name)
	v.own = r
	if r != nil {
		// Purged at the head.
		if r.state == statePurged && asOf == nil {
			v.state, v.src = Purged, r
			if r.headSeq.Valid {
				v.head = t.rev(r.headSeq.Int64)
			}
			t.memoView(v)
			return v
		}
		var headSeq int64
		found := false
		if asOf == nil {
			if r.headSeq.Valid {
				headSeq, found = r.headSeq.Int64, true
			}
		} else if seq, ok := t.memo.headAt[headAtKey{r.id, *asOf}]; ok {
			headSeq, found = seq, seq != 0
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
			switch {
			case r.state == statePurged:
				v.state = Purged
			case v.head.kind == kindTombstone:
				v.state = Tombstoned
			default:
				v.state = Live
			}
			if asOf == nil {
				t.memoView(v)
			}
			return v
		}
	}
	if n.isBranch() {
		base := t.base(n)
		// name's rows in all the bases it may be read through, at once.
		t.seedResources(base, name)
		at := n.baseAt.Int64
		bv := t.resolve(base, name, &at)
		v.state, v.head, v.src = bv.state, bv.head, bv.src
		if r != nil && r.state == statePurged && bv.state != NotFound {
			// Purged in n since asOf, when n read an entry for it
			// through: purged as of asOf too, with the head it read
			// through then. A purge of a name n reads through records
			// no head_history (purgeResource), and the base keeps it
			// live, since purges never propagate upwards (§8.3).
			v.state, v.src = Purged, r
		}
		return v
	}
	v.state = NotFound
	return v
}

// memoView remembers the view resolve returned for a resource of the
// namespace's own, now: it depends only on the resource's row, which the
// transaction remembers as long (memoRes forgets the view with it), and
// on immutable revision rows. Views read through a base aren't kept.
// Callers don't change a view they are given.
func (t *tx) memoView(v *view) {
	if t.memo.views == nil {
		t.memo.views = map[resKey]*view{}
	}
	t.memo.views[resKey{v.ns.id, v.name}] = v
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
// The head's own resource first: locate would find it there before any
// foreign parent, and a read of a recent revision then costs no walk of
// the chain (or, after lookupResource, no statement at all).
func (t *tx) findInAncestry(head *revRow, id ids.ID) *revRow {
	if head.id == id {
		return head
	}
	if r := t.revByID(head.res, id); r != nil && r.seq <= head.seq {
		return r
	} else if r == nil {
		// Not in the head's resource at all: in a foreign parent's, if
		// anywhere.
		segs := t.ancestry(head)
		_, r := t.locate(segs[1:], id)
		return r
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

// wholeDocument is the document a stored patch set adds as a whole, a
// lone add at "" (a create's, §3.3), cut from its canonical form; nil for
// any other patch set.
func wholeDocument(canon []byte) []byte {
	if !bytes.HasPrefix(canon, genesisPrefix) || !bytes.HasSuffix(canon, []byte("}]")) {
		return nil
	}
	// The op has no member after value: what follows the prefix is one
	// value.
	if v := canon[len(genesisPrefix) : len(canon)-2]; valueEnd(v) == len(v) {
		return v
	}
	return nil
}

// valueEnd is the offset just past the JSON value b starts with, or -1.
// b is canonical JSON the server stored, so it needs only to find where
// the value ends, by nesting and strings, not to validate it; a scalar is
// checked whole.
func valueEnd(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	if c := b[0]; c != '{' && c != '[' && c != '"' {
		if json.Valid(b) {
			return len(b)
		}
		return -1
	}
	depth := 0
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '"':
			for i++; i < len(b) && b[i] != '"'; i++ {
				if b[i] == '\\' {
					i++
				}
			}
			if i >= len(b) {
				return -1
			}
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		}
		if depth == 0 {
			return i + 1
		}
	}
	return -1
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
			// A genesis that adds the whole document is its snapshot (D.4),
			// and has no heads row of its own (insertItemsBy).
			if !cur.parentSeq.Valid && cur.patches.Valid {
				if b := wholeDocument(t.patchesOf(cur)); b != nil {
					base = b
					break
				}
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
	if base == nil && len(stack) == 0 {
		return nil, errors.New("no document")
	}
	var doc any
	if base != nil && len(stack) > 0 {
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
		// cost O(steps × size). Without a base the fold starts at the
		// genesis, whose patches apply to the document null, as the
		// create's did (§6.2 step 3).
		doc, _, err = patch.Apply(doc, true, ops, patch.Options{InPlace: true})
		if err != nil {
			return nil, err
		}
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
	ID string `json:"id"`
	// Parent is "" for a genesis, always served (§7.1, v0.81).
	Parent  string `json:"parent"`
	Kind    string `json:"kind"`
	Patches any    `json:"patches,omitempty"`
	Author  string `json:"author"`
	// Via is the delegation chain of the grant the entry was written under
	// (§7.1, §C.1): its delegatees in order, nil when there are none.
	Via     []string `json:"via,omitempty"`
	Created string   `json:"created"`
	// Grant is the grant reference { id, sub, kid } of the grant the entry
	// was written under (§7.1, §C.3), as namespace entries serve it
	// (grantref.go); nil if it wasn't written under one.
	Grant     map[string]any `json:"grant,omitempty"`
	Signature string         `json:"signature,omitempty"`
	// Gesture and Undoes are the gesture ids the entry was written with
	// (§7.1, §7.2), not hashed.
	Gesture string `json:"gesture,omitempty"`
	Undoes  string `json:"undoes,omitempty"`

	row  *revRow // the entry's row (sealing, sealed.go)
	size int     // its patch set's bytes as served (logPageBytes, logBetween)
}

func (e LogEntry) value() map[string]any {
	// A genesis's parent is "" (§7.1), in clear pages, events and the
	// sealed entry alike (§E.2.2). Stored sealings of genesis entries
	// from before v0.81, without it, are served as stored; readers take
	// an absent parent as "".
	m := map[string]any{"id": e.ID, "parent": e.Parent, "kind": e.Kind, "author": e.Author, "created": e.Created}
	if e.Kind == "rev" && e.Patches != nil {
		m["patches"] = e.Patches
	}
	if len(e.Via) > 0 {
		m["via"] = anyStrings(e.Via)
	}
	if e.Grant != nil {
		m["grant"] = e.Grant
	}
	if e.Signature != "" {
		m["signature"] = e.Signature
	}
	if e.Gesture != "" {
		m["gesture"] = e.Gesture
	}
	if e.Undoes != "" {
		m["undoes"] = e.Undoes
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
			b := t.patchesOf(r)
			e.Patches, e.size = jsonv.MustParse(b), len(b)
		}
	}
	e.Via = parseVia(r.via)
	if r.grantID != nil {
		e.Grant = t.grantRef(r.grantID)
	}
	if r.signature.Valid {
		e.Signature = r.signature.String
	}
	e.Gesture, e.Undoes = r.gesture.String, r.undoes.String
	return e
}

// parseVia reads a stored via column (revisions.via, ns_log.via): the
// canonical JSON array of a grant's delegatees (writtenBy, grantVia), or
// nil for NULL, an empty array and rows from before the column (§7.1).
func parseVia(col sql.NullString) []string {
	if !col.Valid || col.String == "" {
		return nil
	}
	var via []string
	if err := json.Unmarshal([]byte(col.String), &via); err != nil || len(via) == 0 {
		return nil
	}
	return via
}

// logBetween returns the entries after since (exclusive; nil = from the
// first entry) up to to (inclusive), oldest first: with limit > 0 only the
// oldest limit of them, and with maxBytes > 0 only as many as their patch
// sets fit in, as served (decompressed, decrypted at rest; the sealed op
// at E3), though always one, more reporting that the range goes on (a
// page, §7.1 Paging, logPageBytes). served, if not nil, measures an entry
// instead: at E2 its JWE, so a page ends where the bytes served say and
// padding hides where exact sizes would end it (§E.2.2). It is called in
// order, for the entries returned and at most one more. A since that
// isn't an ancestor of to is errNotAncestor. A pruned entry anywhere in
// the range is a prunedError, so every page of a range answers alike.
//
// A page costs its own rows, whatever the range's length (§7.1 Paging): a
// resource's chain is its rows in seq order (one first row, one child per
// parent), so the range is a seq interval of each ancestry segment, read
// oldest first and only as far as the page goes, and the pruning check
// looks only below horizons (prunedIn). Walking the parent links from to
// instead read the whole rest of the range for every page.
func (t *tx) logBetween(to *revRow, since *ids.ID, limit, maxBytes int, served func(LogEntry) int) (entries []LogEntry, more bool, err error) {
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
	// The scan stops once the rows' patch sets are sure to exceed
	// maxBytes (servedAtLeast), so a page of large ones doesn't load the
	// rest of limit; the page is cut exactly below, once they are opened.
	// A JWE is no shorter than the patch set it holds unless compressed,
	// which a padded one never is (§E.2.2), so at E2 only an unpadded
	// page can end sooner than its JWEs would.
	scanned := 0
	full := func() bool {
		return limit > 0 && len(rows) >= limit || maxBytes > 0 && scanned > maxBytes
	}
	for i := k; i >= 0 && !full(); i-- {
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
		for !full() && rs.Next() {
			r, err := scanRev(rs)
			t.must(err)
			rows = append(rows, r)
			scanned += servedAtLeast(r)
		}
		t.must(rs.Err())
		rs.Close()
	}
	// Each entry's parent is the row before it (a segment's first row's,
	// the last of the older segment), so its id is known. The schema keeps
	// one first row and one child per parent in a resource (one_first,
	// UNIQUE (res, parent_seq)), but not that a later row's parent is a
	// row of the same resource before it, so that is checked here, where
	// the rows are at hand: a writer that broke the chain would otherwise
	// make the range answer rows that aren't ancestors of to.
	prev := lo
	for _, r := range rows {
		if r.parentSeq.Valid != (prev != 0) || r.parentSeq.Valid && r.parentSeq.Int64 != prev {
			t.must(fmt.Errorf("revision row %d: parent %v, not the row before it, %d: the chain forks", r.seq, r.parentSeq, prev))
		}
		prev = r.seq
		t.knowRevID(r.seq, r.id)
	}
	out := make([]LogEntry, 0, len(rows))
	size := 0
	for _, r := range rows {
		e := t.logEntry(r)
		n := e.size
		if served != nil {
			n = served(e)
		}
		if size += n; maxBytes > 0 && len(out) > 0 && size > maxBytes {
			break
		}
		out = append(out, e)
	}
	rows = rows[:len(out)]
	more = len(rows) > 0 && rows[len(rows)-1].seq != to.seq
	return out, more, nil
}

// servedAtLeast is a lower bound of the bytes of r's patch set as served,
// from what is stored, without opening it: plaintext is served as stored;
// a compressed row as its frame's content size, or, where a small frame
// doesn't say, its length less the most a zstd frame adds to what it holds
// (raw blocks: the marker, frame header and checksum, and 3 bytes a
// block); and an encrypted row's plaintext, canonical JSON (compress.go),
// as its length less the version byte, nonce and tag (sealRow).
func servedAtLeast(r *revRow) int {
	if !r.patches.Valid {
		return 0
	}
	raw := r.patches.String
	switch {
	case isSealed(raw):
		return max(0, len(raw)-rowOverhead)
	case isPacked([]byte(raw[:min(len(raw), 1)])):
		if n := packedLen([]byte(raw[:min(len(raw), 19)])); n >= 0 {
			return int(n)
		}
		return max(0, len(raw)-1-18-4-3*(len(raw)/(128<<10)+1))
	}
	return len(raw)
}

// prunedIn reports a range's newest pruned entry (§8.6) as a prunedError,
// or purgedError if its resource is purged; segs are the range's segments,
// newest first, the oldest one from lo (exclusive). Pruning drops the patch
// sets of a resource's revisions below its horizon (a partial restore fills some
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
