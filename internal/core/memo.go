package core

import (
	"database/sql"
	"sync"
)

// Fewer round trips per write (Postgres, where each statement is one).
//
// Two kinds of rows are looked up again and again by a write:
//
//   - rows that never change once committed: an author's id and name, a
//     namespace's id by name. The engine keeps them (idCache), learnt from
//     transactions that hadn't written yet, so never a row of their own
//     that a rollback could take back. (Neither is ever deleted.)
//   - resource and revision rows, which the check and the insert each read
//     several times, and resources found missing (and namespace rows: in
//     a read transaction, as a branch page resolves through its bases
//     name by name; in any, the namespaces of the schema paths a batch's
//     documents name, schemaNS). A transaction keeps them (tx.memo) until
//     it writes or takes another lock: on Postgres a write transaction
//     sees each statement's own snapshot, and what it reads after a lock
//     must be as of that lock (pglock.go).

// idCache maps immutable names to ids and back.
type idCache struct {
	authors     sync.Map // string -> int64
	authorNames sync.Map // int64 -> string
	nss         sync.Map // string -> int64
}

// memo is a transaction's resource and revision rows, and namespace rows
// (in a read transaction, or for schema resolution). A resource found
// missing is remembered too (nil): a create looks its resource up again
// and again.
type memo struct {
	res map[resKey]*resRow
	rev map[int64]revRow
	// headAt is a resource's head as of a namespace log position, from
	// head_history (resolve); 0 when it had none there. Prefetched for a
	// page of a heads listing (prefetchHeads).
	headAt map[headAtKey]int64
	// ns is namespace rows by id (nsByID), in a read transaction only: it
	// sees one snapshot, takes no lock and writes nothing, so a row stays
	// as first read until it ends. A branch's heads page looks its base up
	// for every name it reads through. A write transaction's rows change
	// under it: its own config writes, freezes, purges and appends, and on
	// Postgres other writers' appends between its statements.
	ns map[int64]nsRow
	// schemaNS is namespace rows by name for schema resolution (schemaNS),
	// in a write transaction too: on Postgres, of a row read once its
	// namespace's lock is held, other writers change only the head, which
	// their appends move under the lock shared (pglock.go) and schema
	// resolution never reads; in SQLite a write transaction is the only
	// writer. What the transaction writes itself, or a lock it takes,
	// forgets the row like any other.
	schemaNS map[string]nsRow
}

type headAtKey struct{ res, asOf int64 }

// inserted remembers a revision row the transaction inserted: its own, so
// valid until the transaction ends (nothing changes a row it just
// inserted), whatever it writes or locks next.
func (t *tx) inserted(r revRow) {
	if t.ownRevs == nil {
		t.ownRevs = map[int64]revRow{}
	}
	t.ownRevs[r.seq] = r
	t.knowRevID(r.seq, r.id)
}

func anyInt(v any) sql.NullInt64 {
	if i, ok := v.(int64); ok {
		return sql.NullInt64{Int64: i, Valid: true}
	}
	return sql.NullInt64{}
}

func anyStr(v any) sql.NullString {
	switch v := v.(type) {
	case string:
		return sql.NullString{String: v, Valid: true}
	case []byte:
		return sql.NullString{String: string(v), Valid: true}
	}
	return sql.NullString{}
}

// nullStr is s as a column value: NULL if empty.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type resKey struct {
	ns   int64
	name string
}

// forget drops what the transaction remembers, before it writes or takes
// a lock.
func (t *tx) forget() {
	t.memo = memo{}
}

// wrote marks a transaction that has written: from then on, what it reads
// may be its own uncommitted rows.
func (t *tx) wrote() {
	t.dirty = true
	t.forget()
}

func (t *tx) learnAuthor(name string, id int64) {
	if t.dirty {
		return
	}
	t.e.ids.authors.Store(name, id)
	t.e.ids.authorNames.Store(id, name)
}
