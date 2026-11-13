package core

import (
	"fmt"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
)

// EXPERIMENTAL, with combine.go (Postgres only): the rows a group of
// writes to one document inserts are held back and written together, one
// statement per table, in place of three or four statements per write.
//
// While a transaction defers (tx.def), step 7's inserts of revisions, the
// moves of heads, the heads documents and the namespace entries are kept
// in memory. Later writes of the group read none of them from the
// database: the revisions are ownRevs, the resource rows movedRes, the
// documents ownDocs, and the log's head is the entry deferred last.
// Revision seqs are drawn from the table's sequence beforehand, so the
// rows that name them (a child's parent_seq, a namespace entry's target)
// can be built before the insert.
//
// Nothing else may see the database without those rows: every other
// statement the transaction runs flushes them first (stmts.go, bulk.go),
// but for the few that touch none of the tables concerned
// (safeWhileDeferred). So a write that does something this file doesn't
// know (a snapshot, a blob, a sealed namespace's counts, a grant to
// store) costs a flush, never a wrong answer.
type deferred struct {
	want     int // revisions still expected: how many seqs to draw at once
	revSeqs  []int64
	revs     [][]any
	moves    map[int64][]any // by res: {h, st, sr, sb, res, old}
	moveRes  []int64
	heads    map[int64][]any // by res: {res, seq, doc}
	headRes  []int64
	ns       []nsAppend
	total    int
	done     []ids.ID
	nsRow    *nsRow
	nsConfig int64
	flushing bool
	// nsRows are namespace rows read under the shared lock the
	// transaction holds (nsByNameLocked), and open the blobs each
	// resource's head references after the transaction's own writes
	// (insertItemsBy): neither is read again.
	nsRows map[string]nsRow
	open   map[int64]map[ids.ID]bool
	// producers are the retry records of the group's writes
	// (producer.go), written together at the flush.
	producers      map[producerKey]*producerState
	producersDirty bool
}

var insRevisionsSeq = bulkInsert("revisions", "seq bigint, res bigint, id bytea, parent_seq bigint, first smallint, kind smallint, patches bytea, author bigint, "+
	"via text, grant_id bytea, signature text, schema_ref text, created bigint, gesture text, undoes text, size bigint, digest bytea, rules smallint", "")

// deferring reports whether step 7's rows are being held back.
func (t *tx) deferring() bool { return t.def != nil && !t.def.flushing }

func (d *deferred) pending() bool {
	return len(d.revs)+len(d.moves)+len(d.heads)+len(d.ns) > 0 || d.producersDirty
}

// safeWhileDeferred reports statements that read or write none of the
// tables deferred rows belong to, nor anything that depends on them.
func safeWhileDeferred(q string) bool {
	q = strings.TrimSpace(q)
	for _, p := range []string{
		"SELECT k, t, admitted FROM rate_draw",
		"SELECT res, bid FROM blob_refs",
		// The namespace's row by name: only its head changes with the
		// entries held back, and the write path reads the head under the
		// log lock, at the flush.
		"SELECT ns, name, base, base_at, base_config_seq, frozen, purged, head_seq, config_seq FROM namespaces WHERE na",
		"SELECT nextval(pg_get_serial_sequence('revisions', 'seq'))",
		"-- ping",
		// Rows that aren't the transaction's own (those are found in
		// memory first: ownRevs, ownDocs) and that the rows held back
		// don't change: a committed revision by its seq, the document
		// stored for one, an author.
		"SELECT res, doc FROM heads WHERE seq = ?",
		"SELECT res, doc FROM snapshots WHERE seq = ?",
		"SELECT author FROM authors",
		"SELECT name FROM authors",
	} {
		if strings.HasPrefix(q, p) {
			return true
		}
	}
	return strings.HasPrefix(q, "SELECT seq, res, id, parent_seq") && strings.HasSuffix(q, "FROM revisions WHERE seq = ?")
}

// beforeStatement flushes the deferred rows before a statement that might
// see the database without them.
func (t *tx) beforeStatement(q string) {
	if t.def == nil || t.def.flushing || !t.def.pending() || safeWhileDeferred(q) {
		return
	}
	t.flushDeferred()
}

// revSeq draws the seq of the next revision row.
func (t *tx) revSeq() int64 {
	d := t.def
	if len(d.revSeqs) == 0 {
		n := max(d.want, 4)
		rows, err := t.Query(`SELECT nextval(pg_get_serial_sequence('revisions', 'seq')) FROM generate_series(1, ?::int)`, n)
		t.must(err)
		for rows.Next() {
			var s int64
			t.must(rows.Scan(&s))
			d.revSeqs = append(d.revSeqs, s)
		}
		t.must(rows.Err())
		rows.Close()
		if len(d.revSeqs) == 0 {
			panic(fmt.Errorf("drew no revision seqs"))
		}
	}
	s := d.revSeqs[0]
	d.revSeqs = d.revSeqs[1:]
	if d.want > 0 {
		d.want--
	}
	return s
}

// deferMove holds back a head's move, joined with an earlier one of the
// same resource: from the head the first matched to the one the last
// leaves.
func (t *tx) deferMove(m []any) {
	d := t.def
	res := m[4].(int64)
	if d.moves == nil {
		d.moves = map[int64][]any{}
	}
	if old, ok := d.moves[res]; ok {
		old[0], old[1], old[2], old[3] = m[0], m[1], m[2], m[3]
		return
	}
	d.moves[res] = append([]any(nil), m...)
	d.moveRes = append(d.moveRes, res)
}

// deferHead holds back a heads document; a later one of the resource
// replaces it.
func (t *tx) deferHead(h []any) {
	d := t.def
	res := h[0].(int64)
	if d.heads == nil {
		d.heads = map[int64][]any{}
	}
	if _, ok := d.heads[res]; !ok {
		d.headRes = append(d.headRes, res)
	}
	d.heads[res] = h
}

// deferAppend holds back a namespace entry without a config change. Its
// id isn't known yet: it covers the entry before it, which is read under
// the log lock, and that lock is taken only once every row is inserted
// (pglock.go), at the flush. total counts the entries held back so far,
// and done collects their ids as they are appended, so a caller finds
// the id of entry number k in done[k] after the flush.
func (t *tx) deferAppend(n *nsRow, a nsAppend) {
	d := t.def
	if d.nsRow != nil && d.nsRow.id != n.id {
		t.flushDeferred()
	}
	d.ns = append(d.ns, a)
	d.total++
	d.nsRow, d.nsConfig = n, n.configSeq
	t.wrote()
	t.notify[n.name] = true
}

// flushDeferred writes the rows held back: the revisions, the heads'
// moves, the heads documents, then the namespace entries, each in one
// statement.
func (t *tx) flushDeferred() {
	d := t.def
	if d == nil || d.flushing || !d.pending() {
		return
	}
	d.flushing = true
	defer func() { d.flushing = false }()
	revs, ns, nsRow, nsConfig := d.revs, d.ns, d.nsRow, d.nsConfig
	var moves, heads [][]any
	for _, res := range d.moveRes {
		moves = append(moves, d.moves[res])
	}
	for _, res := range d.headRes {
		heads = append(heads, d.heads[res])
	}
	d.revs, d.moves, d.moveRes, d.heads, d.headRes, d.ns, d.nsRow = nil, nil, nil, nil, nil, nil, nil

	t.bulkExec(insRevisionsSeq, revs)
	if t.bulkExec(moveHeads, moves) != int64(len(moves)) {
		panic(errChainRace)
	}
	t.bulkExec(upsertHeads, heads)
	if d.producersDirty {
		var rows [][]any
		for k, st := range d.producers {
			if !st.dirty {
				continue
			}
			rows = append(rows, producerRow(k, st.epoch, st.seq, st.lastSeq, st.prev))
			// What the database holds from here on.
			st.prev, st.dirty = producerPrev{true, st.epoch, st.seq}, false
		}
		d.producersDirty = false
		t.producerWrite(rows)
	}
	if len(ns) > 0 {
		// The log lock is taken here, after the rows above.
		d.done = append(d.done, t.appendNSMany(nsRow, nsConfig, ns)...)
	}
}

// revByID is the revision of res with id, or sql.ErrNoRows. While rows
// are held back, one of them is found in memory, and the database is
// asked without a flush for any other: a row held back with that id would
// have been found, so the rows held back don't change its answer.
func (t *tx) revByID(res int64, id ids.ID) (*revRow, error) {
	if t.def != nil {
		for _, r := range t.ownRevs {
			if r.res == res && r.id == id {
				c := r
				return &c, nil
			}
		}
		was := t.def.flushing
		t.def.flushing = true // no flush for this statement
		defer func() { t.def.flushing = was }()
	}
	return scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ?`, res, id[:]))
}
