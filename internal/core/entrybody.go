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

// rebuild fills a derived entry's body and created from d, and reports
// whether it was derived (checkRebuilt).
func (t *tx) rebuild(d *derived, body *string, created *int64, id []byte) bool {
	if *body != "" {
		return false
	}
	if !d.name.Valid || d.id == nil || !d.created.Valid {
		panic(fmt.Errorf("namespace entry %s has no body and nothing to rebuild it from", ids.FromBytes(id)))
	}
	*body = string(entryBody(d.kind, d.name.String, ids.FromBytes(d.id)))
	*created = d.created.Int64
	return true
}

// checkRebuilt checks, under PATCHLOG_TEST_VALIDATE_BOTH, that each derived
// entry of rs, a log page read in order with its rows closed, hashes to its
// id after the entry before it, read again unless it is in rs.
func (t *tx) checkRebuilt(rs []nsLogRow) {
	if !validateBoth {
		return
	}
	known := map[int64][]byte{}
	for _, r := range rs {
		known[r.seq] = r.id
	}
	for _, r := range rs {
		if !r.derived {
			continue
		}
		var prev *ids.ID
		if r.prev != nil {
			b, ok := known[*r.prev]
			if !ok {
				t.must(t.uncounted(`SELECT id FROM ns_log WHERE seq = ?`, *r.prev).Scan(&b))
			}
			p := ids.FromBytes(b)
			prev = &p
		}
		if ids.Hash(prev, []byte(r.body)) != ids.FromBytes(r.id) {
			panic(fmt.Errorf("namespace entry %s: the rebuilt body %s doesn't hash to its id", ids.FromBytes(r.id), r.body))
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
	if t.e.firsts {
		if bound.Valid {
			upto = ` AND f.first_seq <= ?`
		}
		return `(SELECT f.first_seq FROM ns_grants f WHERE f.grant_ref = (SELECT ref FROM grants WHERE id = ?) AND f.ns = ?` + upto + `)`, args
	}
	args = append(args, args...)
	return `(SELECT MIN(s) FROM (SELECT MIN(seq) AS s FROM ns_log WHERE grant_id = ? AND ns = ?` + upto + `
		UNION ALL SELECT MIN(seq) FROM ns_log WHERE grant_ref = (SELECT ref FROM grants WHERE id = ?) AND ns = ?` + upto + `) fg)`, args
}

// checkDerived checks every derived entry stored: its body rebuilt hashes,
// after the id of the entry before it, to its id (§3.5); and that
// ns_config.first_seq and ns_grants hold what the entries give. Close runs it
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
		// created doesn't enter the hash (a test may spoil it).
		if !d.name.Valid || d.id == nil {
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
	rows.Close()
	if !e.firsts {
		return nil
	}
	// The rows written once in place of indexes, against the entries.
	for _, q := range []string{
		`SELECT COUNT(*) FROM ns_config c WHERE c.first_seq IS DISTINCT FROM (SELECT MIN(l.seq) FROM ns_log l WHERE l.ns = c.ns AND l.config_seq = c.seq)`,
		`SELECT COUNT(*) FROM (SELECT COALESCE(l.grant_ref, g.ref) AS ref, l.ns, MIN(l.seq) AS s FROM ns_log l LEFT JOIN grants g ON g.id = l.grant_id
			WHERE l.grant_id IS NOT NULL OR l.grant_ref IS NOT NULL GROUP BY COALESCE(l.grant_ref, g.ref), l.ns) w
			FULL JOIN ns_grants f ON f.grant_ref = w.ref AND f.ns = w.ns WHERE f.first_seq IS DISTINCT FROM w.s`,
	} {
		var bad int
		if err := e.db.QueryRowContext(ctx, q).Scan(&bad); err != nil {
			return nil
		}
		if bad != 0 {
			return fmt.Errorf("%d rows differ from the entries: %s", bad, q)
		}
	}
	return nil
}

// firstUnder is the first entry of namespace ns under configuration row
// cseq, the entry that wrote it (§7.4), NULL for none: ns_config.first_seq
// (migration 032 in SQLite, 034 in Postgres), which a trigger sets as the
// entry is inserted. Under PATCHLOG_TEST_VALIDATE_BOTH it is checked
// against the entries themselves.
func (t *tx) firstUnder(ns, cseq int64) sql.NullInt64 {
	var seq sql.NullInt64
	if !t.e.firsts {
		t.QueryRow(`SELECT MIN(seq) FROM ns_log WHERE ns = ? AND config_seq = ?`, ns, cseq).Scan(&seq)
		return seq
	}
	if err := t.QueryRow(`SELECT first_seq FROM ns_config WHERE seq = ? AND ns = ?`, cseq, ns).Scan(&seq); err != nil {
		return sql.NullInt64{}
	}
	if validateBoth {
		var want sql.NullInt64
		t.must(t.uncounted(`SELECT MIN(seq) FROM ns_log WHERE ns = ? AND config_seq = ?`, ns, cseq).Scan(&want))
		if want != seq {
			panic(fmt.Errorf("namespace %d, configuration %d: first_seq %v, its first entry %v", ns, cseq, seq, want))
		}
	}
	return seq
}
