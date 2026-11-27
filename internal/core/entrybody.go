package core

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Derived namespace entries (docs/capacity/storage). A head or tombstone
// entry of a single write is { kind, resource, target } of the revision the
// write inserted, in the same transaction: everything in it, and its
// created time, is in rows the entry points at (ns_log.res, target_seq). So
// such an entry is stored without them, its body empty (NULL on Postgres,
// '' in SQLite, whose column stays NOT NULL) and its created NULL (0 in
// SQLite), and a read rebuilds the body from l.kind, the name of l.res and
// the id of l.target_seq, and takes the revision's created.
//
// The rebuilt body must be the bytes that were hashed into the entry's id
// (§3.5). appendNS stores an entry so only when the rebuild from the rows it
// points at gives exactly its canonical bytes, and the revision was written
// at the entry's time; any other entry keeps its body. Names and ids never
// change once stored (a purge keeps both, and a purged name can't be
// written again), so the rebuild holds for good. Under
// PATCHLOG_TEST_VALIDATE_BOTH every rebuilt body read is checked against
// the entry's id.

// derivedCond holds for an ns_log row l whose body is derived.
const derivedCond = `(l.body IS NULL OR l.body = '')`

// nsLogCreated is the created of ns_log row l: its own, or a derived
// entry's revision's.
const nsLogCreated = `CASE WHEN ` + derivedCond + ` THEN (SELECT dv.created FROM revisions dv WHERE dv.seq = l.target_seq) ELSE l.created END`

// grantIDOf is the grant id an ns_log or revisions row (alias a) records:
// grant_id in rows from before grant references by number, else the
// stored grant's numbered by grant_ref.
func (t *tx) grantIDOf(a string) string { return grantIDOf(t.e.refs, a) }

func grantIDOf(refs bool, a string) string {
	if !refs {
		return a + `.grant_id`
	}
	return `COALESCE(` + a + `.grant_id, (SELECT gr.id FROM grants gr WHERE gr.ref = ` + a + `.grant_ref))`
}

// entryBody is the canonical body of a derived entry (§3.5).
func entryBody(kind int, name string, target ids.ID) []byte {
	return jsonv.Canonical(map[string]any{"kind": nsKindNames[kind], "resource": name, "target": target.String()})
}

// derivable reports whether entry, whose canonical bytes are body, may be
// stored derived: a head or tombstone entry of nothing but kind, resource
// and target, whose target revision this transaction inserted in res at
// its time, the rebuild from them giving body exactly.
func (t *tx) derivable(entry map[string]any, body []byte, res, target *int64) bool {
	if !t.e.refs || res == nil || target == nil || len(entry) != 3 {
		return false
	}
	kind, _ := entry["kind"].(string)
	if kind != "head" && kind != "tombstone" {
		return false
	}
	name, ok := entry["resource"].(string)
	r, own := t.ownRevs[*target]
	if !ok || !own || r.res != *res || r.created != t.now.UnixMilli() || (r.kind == kindTombstone) != (kind == "tombstone") {
		return false
	}
	if !bytes.Equal(entryBody(nsKindCode(kind), name, r.id), body) {
		return false
	}
	if validateBoth {
		// The oracle: the row the read takes the name from.
		var stored string
		t.must(t.uncounted(`SELECT name FROM resources WHERE res = ?`, *res).Scan(&stored))
		if stored != name {
			panic(fmt.Errorf("entry of %q points at resource %d, named %q", name, *res, stored))
		}
	}
	return true
}

// storedEntry is what appendNS stores as an entry's body and created.
func (t *tx) storedEntry(entry map[string]any, body []byte, res, target *int64) (storedBody, storedCreated any) {
	if !t.derivable(entry, body, res, target) {
		return string(body), t.now.UnixMilli()
	}
	if t.e.pg {
		return nil, nil
	}
	return "", int64(0)
}

// derivedCols are the columns a log read adds to rebuild a derived entry
// (scanNSLogRow): its kind, its resource's name and its target's id and
// created, NULL for any other entry; derivedJoins are their joins.
const (
	derivedCols  = `l.kind, dr.name, dv.id, dv.created`
	derivedJoins = ` LEFT JOIN resources dr ON dr.res = l.res AND ` + derivedCond +
		` LEFT JOIN revisions dv ON dv.seq = l.target_seq AND ` + derivedCond
)

// derived holds derivedCols as scanned.
type derived struct {
	kind    int
	name    sql.NullString
	id      []byte
	created sql.NullInt64
}

// rebuild fills a derived entry's body and created from d. Under
// PATCHLOG_TEST_VALIDATE_BOTH the body is checked against the entry's id,
// that of the entry before it (prevSeq) read again.
func (t *tx) rebuild(d *derived, body *string, created *int64, id []byte, prevSeq *int64) {
	if *body != "" {
		return
	}
	if !d.name.Valid || d.id == nil || !d.created.Valid {
		panic(fmt.Errorf("namespace entry %s has no body and nothing to rebuild it from", ids.FromBytes(id)))
	}
	*body = string(entryBody(d.kind, d.name.String, ids.FromBytes(d.id)))
	*created = d.created.Int64
	if validateBoth {
		var prev *ids.ID
		if prevSeq != nil {
			var b []byte
			t.must(t.uncounted(`SELECT id FROM ns_log WHERE seq = ?`, *prevSeq).Scan(&b))
			p := ids.FromBytes(b)
			prev = &p
		}
		if ids.Hash(prev, []byte(*body)) != ids.FromBytes(id) {
			panic(fmt.Errorf("namespace entry %s: the rebuilt body %s doesn't hash to its id", ids.FromBytes(id), *body))
		}
	}
}

// firstGrantEntry is SQL for the seq of the first entry of ns that records
// grant id, of seq at most bound if valid, NULL for none, and its
// arguments: rows record a grant by id (grant_id, before grant references
// by number) or by number (grant_ref).
func (t *tx) firstGrantEntry(id []byte, ns int64, bound sql.NullInt64) (string, []any) {
	upto, args := "", []any{id, ns}
	if bound.Valid {
		upto = ` AND seq <= ?`
		args = append(args, bound.Int64)
	}
	if !t.e.refs {
		return `(SELECT MIN(seq) FROM ns_log WHERE grant_id = ? AND ns = ?` + upto + `)`, args
	}
	args = append(args, args...)
	return `(SELECT MIN(s) FROM (SELECT MIN(seq) AS s FROM ns_log WHERE grant_id = ? AND ns = ?` + upto + `
		UNION ALL SELECT MIN(seq) FROM ns_log WHERE grant_ref = (SELECT ref FROM grants WHERE id = ?) AND ns = ?` + upto + `) fg)`, args
}

// checkDerived checks every derived entry stored: its body rebuilt hashes,
// after the id of the entry before it, to its id (§3.5). Close runs it
// under PATCHLOG_TEST_VALIDATE_BOTH, so every test's entries are checked.
// A database it can't read is no failure of the check's.
func (e *Engine) checkDerived(ctx context.Context) error {
	rows, err := e.db.QueryContext(ctx, `SELECT l.id, p.id, `+derivedCols+` FROM ns_log l LEFT JOIN ns_log p ON p.seq = l.prev_seq`+derivedJoins+`
		WHERE `+derivedCond)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var id, prev []byte
		var d derived
		if err := rows.Scan(&id, &prev, &d.kind, &d.name, &d.id, &d.created); err != nil {
			return nil
		}
		if !d.name.Valid || d.id == nil || !d.created.Valid {
			return fmt.Errorf("derived namespace entry %s has nothing to rebuild it from", ids.FromBytes(id))
		}
		var p *ids.ID
		if prev != nil {
			x := ids.FromBytes(prev)
			p = &x
		}
		if body := entryBody(d.kind, d.name.String, ids.FromBytes(d.id)); ids.Hash(p, body) != ids.FromBytes(id) {
			return fmt.Errorf("derived namespace entry %s: the rebuilt body %s doesn't hash to its id", ids.FromBytes(id), body)
		}
	}
	return nil
}
