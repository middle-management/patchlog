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
//     several times. A transaction keeps them (tx.memo) until it writes or
//     takes another lock: on Postgres a write transaction sees each
//     statement's own snapshot, and what it reads after a lock must be as
//     of that lock (pglock.go).

// idCache maps immutable names to ids and back.
type idCache struct {
	authors     sync.Map // string -> int64
	authorNames sync.Map // int64 -> string
	nss         sync.Map // string -> int64
}

// memo is a transaction's resource and revision rows.
type memo struct {
	res map[resKey]resRow
	rev map[int64]revRow
}

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
