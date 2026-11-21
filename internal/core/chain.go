package core

import (
	"database/sql"
	"fmt"
	"strings"
)

// A branch's chain of bases, read once per transaction.
//
// A request in a branch of a branch of … asks for its bases again and
// again: the keys and revocations that follow each base (§C.4), the root
// its drafts serve, every name it
// reads through. One statement per base and use made a request cost in
// proportion to the branch's depth. A transaction now reads the chain in
// one recursive statement and keeps it until it ends, in two forms:
//
//   - links: a namespace's id, name and base, which never change once
//     inserted (and no namespace row is ever deleted). They are read
//     without a lock and kept until the transaction ends, for what walks
//     the chain's structure alone (draftRoot, draftsServe,
//     schemaReadsServe, copiesIn), as nsRowUnlocked read them.
//   - rows: the whole namespaces row of a base (base), with the columns a
//     decision rests on: config_seq, frozen, purged. What a write
//     transaction may keep of those is bounded by what made nsByID read
//     each row again (memo.go):
//
//     In SQLite a write transaction is the only writer, so a row changes
//     under it only by its own statements: every INSERT into and UPDATE of
//     namespaces it runs drops the rows (changedNS, from the statement
//     wrappers of stmts.go, which every such statement goes through).
//
//     On Postgres a write transaction sees each statement's own snapshot,
//     and a row is as of a lock only if read in a statement begun after
//     the lock was granted. So the chain is read in three steps, never
//     fewer: its ids (links); then the advisory locks of all of them,
//     shared, in one statement, in the order pglock.go requires (lockAll);
//     then the rows. A row is kept only while the transaction holds its
//     namespace's lock, and taking that lock again in another mode drops
//     it (held). Under the lock shared, config_seq, frozen and purged
//     can't change, since their writers hold it exclusively; head_seq can,
//     since the appends of other resources' writers move it under the lock
//     shared and the log lock. So a kept row's head is not to be relied on
//     there, and nothing that takes a row from base reads it: under
//     PATCHLOG_TEST_VALIDATE_BOTH such a row is handed out with a head
//     that is in no chain, which fails whatever reads it.
//
//     A read transaction sees one snapshot and takes no lock: its rows
//     stay as first read (as memo.ns).
//
// Nothing is kept beyond the transaction: a revocation or a removed key in
// a base's namespace document takes effect with the next transaction of
// any instance, as before.
//
// nsByID is unchanged: in a write transaction it reads the row again, for
// the callers that read a namespace after changing it or need its head.

// nsLink is what never changes of a namespace: its id, name and base.
type nsLink struct {
	id   int64
	name string
	base sql.NullInt64
}

func (l nsLink) isBranch() bool { return l.base.Valid }

func linkOf(n *nsRow) nsLink { return nsLink{n.id, n.name, n.base} }

// poisonedHead is the head of a row handed out under a shared lock while
// PATCHLOG_TEST_VALIDATE_BOTH is set: no entry's seq.
const poisonedHead = -1 << 60

// snapshotRows reports whether this transaction's namespace rows change
// only by its own statements: a read transaction, or SQLite's one writer.
// Otherwise (a write transaction on Postgres) a row is kept under its lock.
func (t *tx) snapshotRows() bool { return !t.e.pg || !t.write }

// link returns the id, name and base of a namespace, reading its chain of
// bases, all of it, in one statement if the transaction doesn't know it.
func (t *tx) link(id int64) nsLink {
	l, ok := t.links[id]
	if !ok {
		t.readChain(id)
		if l, ok = t.links[id]; !ok {
			panic(fmt.Errorf("namespace %d does not exist", id))
		}
	}
	if validateBoth {
		var cur nsLink
		t.must(t.uncounted(`SELECT ns, name, base FROM namespaces WHERE ns = ?`, id).Scan(&cur.id, &cur.name, &cur.base))
		if cur != l {
			panic(fmt.Errorf("kept link of namespace %d is %+v, the database has %+v", id, l, cur))
		}
	}
	return l
}

// readChain reads the chain of bases from id up: the links, and where rows change only by this transaction's own
// statements (snapshotRows) the rows as well, which costs nothing more.
func (t *tx) readChain(id int64) {
	cols, colsN := `ns, name, base`, `n.ns, n.name, n.base`
	if t.snapshotRows() {
		cols, colsN = nsCols, nsColsN
	}
	// The rows travel with the recursion, each base found by its key from
	// the row below it. Read afterwards from namespaces by the ids the
	// recursion returned (ns IN (SELECT ns FROM c)), Postgres hashed those
	// and scanned the whole table, so a read through a branch cost in
	// proportion to the deployment's namespaces.
	rows, err := t.Query(`WITH RECURSIVE c(`+cols+`) AS (
			SELECT `+cols+` FROM namespaces WHERE ns = ?
			UNION ALL
			SELECT `+colsN+` FROM c JOIN namespaces n ON n.ns = c.base)
		SELECT `+cols+` FROM c`, id)
	t.must(err)
	defer rows.Close()
	if t.links == nil {
		t.links = map[int64]nsLink{}
	}
	for rows.Next() {
		if !t.snapshotRows() {
			var l nsLink
			t.must(rows.Scan(&l.id, &l.name, &l.base))
			t.links[l.id] = l
			continue
		}
		n, err := scanNS(rows)
		t.must(err)
		t.links[n.id] = linkOf(n)
		t.keep(n)
	}
	t.must(rows.Err())
}

// readChains reads the links of the chains of bases from each of ids up,
// in one statement however many they are: those of the namespaces a purge
// reaches (nspurge.go).
func (t *tx) readChains(ids []int64) {
	rows, err := t.Query(`WITH RECURSIVE c(ns, name, base) AS (
			SELECT ns, name, base FROM namespaces WHERE `+t.e.inArray("ns", "bigint")+`
			UNION
			SELECT n.ns, n.name, n.base FROM c JOIN namespaces n ON n.ns = c.base)
		SELECT ns, name, base FROM c`, t.e.arrayArg(ids))
	t.must(err)
	defer rows.Close()
	if t.links == nil {
		t.links = map[int64]nsLink{}
	}
	for rows.Next() {
		var l nsLink
		t.must(rows.Scan(&l.id, &l.name, &l.base))
		t.links[l.id] = l
	}
	t.must(rows.Err())
}

func (t *tx) keep(n *nsRow) {
	if t.kept == nil {
		t.kept = map[int64]nsRow{}
	}
	t.kept[n.id] = *n
}

// keepLocked keeps a row a write transaction read after it took the
// namespace's lock, or that changes only by its own statements.
func (t *tx) keepLocked(n *nsRow) {
	if t.snapshotRows() || t.locks[lockKey(n.id)] >= lockShared {
		t.keep(n)
	}
}

// changedNS drops the rows kept: the transaction is about to insert or
// update a namespaces row (stmts.go).
func (t *tx) changedNS() { t.kept = nil }

// writesNS reports whether a statement inserts or updates namespaces rows.
func writesNS(q string) bool {
	return strings.Contains(q, "UPDATE namespaces") || strings.Contains(q, "INSERT INTO namespaces")
}

// keptRow returns a copy of the row kept for id, if it may be used: on
// Postgres, in a write transaction, only while id's lock is held.
func (t *tx) keptRow(id int64) (*nsRow, bool) {
	n, ok := t.kept[id]
	if !ok {
		return nil, false
	}
	shared := false
	if !t.snapshotRows() {
		switch t.locks[lockKey(id)] {
		case 0:
			return nil, false
		case lockShared:
			shared = true
		}
	}
	if validateBoth {
		// The oracle: the row as the database has it now, in all that the
		// lock held covers.
		cur, err := scanNS(t.uncounted(`SELECT `+nsCols+` FROM namespaces WHERE ns = ?`, id))
		t.must(err)
		if !sameNS(&n, cur) || !shared && n.headSeq != cur.headSeq {
			panic(fmt.Errorf("kept row of namespace %d is %+v, the database has %+v", id, n, *cur))
		}
		if shared {
			n.headSeq = sql.NullInt64{Int64: poisonedHead, Valid: true}
		}
	}
	return &n, true
}

// uncounted runs a query of the PATCHLOG_TEST_VALIDATE_BOTH oracle, which
// tests that count statements don't see (onStatement).
func (t *tx) uncounted(q string, args ...any) *sql.Row {
	if t.e.pg {
		q = rebind(q)
	}
	return t.Tx.QueryRow(q, args...)
}

// asOracle runs f, a check of the PATCHLOG_TEST_VALIDATE_BOTH oracle that
// reads through the transaction's own helpers: tests that count statements
// don't see its statements, it takes no lock, and what it read, unlocked,
// stays neither in the transaction's memo nor among a write's dependencies.
func (t *tx) asOracle(f func()) {
	m, deps := t.memo, t.deps
	t.memo, t.deps = memo{}, nil
	t.oracle++
	t.noLock++
	defer func() {
		t.oracle--
		t.noLock--
		t.memo, t.deps = m, deps
	}()
	f()
}

// base returns the base of branch n as nsByID does, its lock taken shared
// on Postgres, from the rows the transaction keeps of n's chain. All but
// its head is as nsByID would read it now (see above).
func (t *tx) base(n *nsRow) *nsRow {
	id := n.base.Int64
	b, ok := t.keptRow(id)
	if !ok && (t.snapshotRows() || t.locking()) {
		t.keepChain(id)
		b, ok = t.keptRow(id)
	}
	if !ok {
		// Namespaces read without their locks (noLock): nothing to keep.
		return t.nsByID(id)
	}
	t.deps.addNS(b)
	return b
}

// keepChain reads and keeps the rows of the chain from id up to its root.
func (t *tx) keepChain(id int64) {
	if t.snapshotRows() {
		t.readChain(id)
		return
	}
	// Postgres: the ids, then their locks, then the rows as of the locks.
	var ids []int64
	want := map[int32]lockMode{}
	for l := t.link(id); ; l = t.link(l.base.Int64) {
		ids = append(ids, l.id)
		want[lockKey(l.id)] = lockShared
		if !l.isBranch() {
			break
		}
	}
	t.lockAll(want)
	rows, err := t.Query(`SELECT `+nsCols+` FROM namespaces WHERE ns = ANY(?::bigint[])`, ids)
	t.must(err)
	defer rows.Close()
	for rows.Next() {
		n, err := scanNS(rows)
		t.must(err)
		t.keepLocked(n)
	}
	t.must(rows.Err())
}

// seedResources reads, in one statement, the rows of resource name in base
// and the bases above it whose rows the transaction keeps, for resolve to
// answer from memory as it reads name through them (memo.res): rows found
// missing too.
func (t *tx) seedResources(base *nsRow, name string) {
	if _, ok := t.memo.res[resKey{base.id, name}]; ok || !base.isBranch() {
		return
	}
	ids := []int64{base.id}
	for l := linkOf(base); l.isBranch(); {
		n, ok := t.keptRow(l.base.Int64)
		if !ok {
			break
		}
		l = linkOf(n)
		if _, ok := t.memo.res[resKey{l.id, name}]; !ok {
			ids = append(ids, l.id)
		}
	}
	if len(ids) < 2 {
		return
	}
	rows, err := t.Query(`SELECT `+resCols+` FROM resources WHERE name = ? AND `+t.e.inArray("ns", "bigint"), name, t.e.arrayArg(ids))
	t.must(err)
	found := map[int64]*resRow{}
	for rows.Next() {
		r, err := scanRes(rows)
		t.must(err)
		found[r.ns] = r
	}
	t.must(rows.Err())
	rows.Close()
	for _, id := range ids {
		t.memoRes(resKey{id, name}, found[id])
	}
}
