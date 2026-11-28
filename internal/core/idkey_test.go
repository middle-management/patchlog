package core

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pgtest"
)

var errIDKeyDone = errors.New("done")

// decoy is id with its first 8 bytes kept and the rest changed: a
// different id with the same key (idKeySQL).
func decoy(id ids.ID) []byte {
	b := append([]byte(nil), id[:]...)
	for i := 8; i < len(b); i++ {
		b[i] ^= 0xa5
	}
	return b
}

// TestIDKeyCollision: ids are found by their first 8 bytes and then
// compared whole (idKeySQL). A revision and a namespace entry whose ids
// share their first 8 bytes with rows already in the resource and the
// namespace are written, found and replayed as themselves; an id already
// in the resource or the namespace is still refused, as the unique
// constraints refused it, and the refusal is a lost race (isConflict).
func TestIDKeyCollision(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "a", map[string]any{"read": "public"})
	mkNS(t, e, "b", map[string]any{"read": "public"})
	ga, err := put(e, "a", "x", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	gb, err := put(e, "b", "x", "", 1)
	if err != nil || gb != ga {
		t.Fatalf("twin genesis %s %v, want %s", gb, err, ga)
	}
	// The revision a's append will make: b's twin made it first.
	want, err := put(e, "b", "x", gb, 2)
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := ids.Parse(want)
	info, err := e.NamespaceHead(ctx, "a", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	prev, _ := ids.Parse(info.Head)
	entry := ids.Hash(&prev, entryBody(nsKindCode("head"), "x", rev))

	// Decoys: a revision of a's x and an entry of a, each sharing the
	// first 8 bytes of the id a's append will make.
	var nsA, resX int64
	if err := e.update(ctx, func(t *tx) error {
		n := t.nsByName("a")
		nsA = n.id
		t.must(t.QueryRow(`SELECT res FROM resources WHERE ns = ? AND name = 'x'`, n.id).Scan(&resX))
		_, err := t.Exec(`INSERT INTO revisions (res, id, first, kind, author, created)
			SELECT res, ?, 0, kind, author, created FROM revisions WHERE res = ? AND first = 1`, decoy(rev), resX)
		t.must(err)
		_, err = t.Exec(`INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created)
			SELECT ns, ?, -1, kind, '{}', config_seq, author, 0 FROM ns_log WHERE ns = ? AND prev_seq IS NULL`, decoy(entry), n.id)
		t.must(err)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	r := who
	r.NS = "a"
	it := Item{Resource: "x", IfMatch: ga, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"n": float64(2)}}}}}}
	res, err := e.WriteResource(ctx, r, it)
	if err != nil {
		t.Fatalf("the write whose ids share their keys with the decoys: %v", err)
	}
	if res.Items[0].IDs[0] != want || res.NSID != entry.String() || res.Replayed {
		t.Fatalf("wrote %s, entry %s, replayed %v; want %s, %s", res.Items[0].IDs[0], res.NSID, res.Replayed, want, entry)
	}
	// The retry finds the write (§7.2), not the decoys.
	again, err := e.WriteResource(ctx, r, it)
	if err != nil || !again.Replayed || again.Items[0].IDs[0] != want || again.NSID != entry.String() {
		t.Fatalf("retry: %+v %v", again, err)
	}
	doc, err := e.ResourceRev(ctx, "a", "x", want, Credentials{})
	if err != nil || doc.Status != 200 || !strings.Contains(string(doc.Doc), `"n":2`) {
		t.Fatalf("read at %s: %+v %v", want, doc, err)
	}

	if err := e.read(ctx, func(t *tx) error {
		for _, c := range []struct {
			id   []byte
			want string
		}{{rev[:], want}, {decoy(rev), ids.FromBytes(decoy(rev)).String()}} {
			got := t.revByID(resX, ids.FromBytes(c.id))
			if got == nil || got.id.String() != c.want {
				return errors.New("revByID " + c.want + ": " + func() string {
					if got == nil {
						return "none"
					}
					return got.id.String()
				}())
			}
		}
		for _, id := range [][]byte{entry[:], decoy(entry)} {
			seq, ok := t.nsLogSeq(nsA, ids.FromBytes(id))
			if !ok || !t.nsLogIDIs(seq, id) {
				return errors.New("nsLogSeq " + ids.FromBytes(id).String())
			}
		}
		if _, ok := t.nsLogSeq(nsA, ids.FromBytes(decoy(prev))); ok {
			return errors.New("nsLogSeq found an id that isn't there by its key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The same id again, in the same resource or namespace: refused.
	for _, c := range []struct{ what, q string }{
		{"revision", `INSERT INTO revisions (res, id, first, kind, author, created)
			SELECT res, ?, 0, kind, author, created FROM revisions WHERE res = ? AND first = 1`},
		{"entry", `INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created)
			SELECT ns, ?, -2, kind, '{}', config_seq, author, 0 FROM ns_log WHERE ns = ? AND prev_seq IS NULL`},
	} {
		id, in := rev[:], resX
		if c.what == "entry" {
			id, in = entry[:], nsA
		}
		var dup error
		e.update(ctx, func(t *tx) error {
			q := c.q
			if t.e.pg {
				q = rebind(q)
			}
			_, dup = t.Tx.Exec(q, id, in)
			return errIDKeyDone
		})
		if dup == nil || !isConflict(dup) {
			t.Errorf("a second %s with one id: %v, want a unique violation (isConflict)", c.what, dup)
		}
	}
	// On Postgres, an entry inserted as appendNS inserts it, in a
	// data-modifying WITH, with an id the namespace holds: refused.
	if e.pg {
		var viaWith error
		e.update(ctx, func(t *tx) error {
			var seq int64
			viaWith = t.Tx.QueryRow(rebind(`WITH l AS (INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created)
				SELECT ns, ?, -3, kind, '{}', config_seq, author, 0 FROM ns_log WHERE ns = ? AND prev_seq IS NULL RETURNING seq) SELECT seq FROM l`), entry[:], nsA).Scan(&seq)
			return errIDKeyDone
		})
		if viaWith == nil || !isConflict(viaWith) {
			t.Errorf("an entry with an id the namespace holds, inserted in a WITH: %v, want a unique violation", viaWith)
		}
	}
	// One insert of two rows with one new id: refused too (on Postgres the
	// check runs once per statement, over the rows it inserted).
	fresh := append([]byte(nil), rev[:]...)
	fresh[0] ^= 0xff
	var twice error
	e.update(ctx, func(t *tx) error {
		q := `INSERT INTO revisions (res, id, first, kind, author, created)
			SELECT res, ?, 0, kind, author, created FROM revisions WHERE res = ? ORDER BY seq LIMIT 2`
		if t.e.pg {
			q = rebind(q)
		}
		_, twice = t.Tx.Exec(q, fresh, resX)
		return errIDKeyDone
	})
	if twice == nil || !isConflict(twice) {
		t.Errorf("two new revisions with one id in one statement: %v, want a unique violation", twice)
	}
	// Another resource or namespace may hold the same id (§3.3).
	if err := e.update(ctx, func(t *tx) error {
		var other int64
		t.must(t.QueryRow(`SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.name = 'b' AND r.name = 'x'`).Scan(&other))
		_, err := t.Exec(`INSERT INTO revisions (res, id, first, kind, author, created)
			SELECT res, ?, 0, kind, author, created FROM revisions WHERE res = ? AND first = 1`, decoy(rev), other)
		return err
	}); err != nil {
		t.Fatalf("a decoy id in another resource: %v", err)
	}
}

// nsLogIDIs reports whether ns_log row seq has id.
func (t *tx) nsLogIDIs(seq int64, id []byte) bool {
	return t.nsLogID(seq) == ids.FromBytes(id)
}

// TestIDKeyPlans: every lookup of a revision of a resource or an entry of
// a namespace by id, and the triggers' probes, use the key indexes
// (revisions_res_id8, ns_log_ns_id8) on a resource of many revisions and a
// namespace of many entries, with and without statistics.
func TestIDKeyPlans(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	head := ""
	for i := 0; i < 50; i++ {
		id, err := put(e, "n", "x", head, i)
		if err != nil {
			t.Fatal(err)
		}
		head = id
	}
	h, _ := ids.Parse(head)
	pg := e.pg
	key := func(col string) string { return idKeySQL(pg, col) }
	param, idCol := "?", "+id" // as the triggers write them (migrations)
	if pg {
		param, idCol = "?::bytea", "id"
	}
	if err := e.update(ctx, func(tx *tx) error {
		n := tx.nsByName("n")
		var res int64
		tx.must(tx.QueryRow(`SELECT res FROM resources WHERE ns = ? AND name = 'x'`, n.id).Scan(&res))
		// 20,000 more revisions of x and entries of n, their ids random
		// (hashes); the chains' columns are the API's.
		fill := []string{
			`INSERT INTO revisions (res, id, parent_seq, first, kind, author, created)
				SELECT r.res, substr(sha256(int8send(g)), 1, 20), 1000000 + g, 0, 0, r.author, r.created FROM revisions r, generate_series(1, 20000) g WHERE r.seq = (SELECT MAX(seq) FROM revisions)`,
			`INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created)
				SELECT l.ns, substr(sha256(int8send(g) || '\x01'::bytea), 1, 20), 1000000 + g, 0, '{}', l.config_seq, l.author, 0 FROM ns_log l, generate_series(1, 20000) g WHERE l.seq = (SELECT MAX(seq) FROM ns_log)`,
		}
		if !pg {
			fill = []string{
				`WITH RECURSIVE g(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM g WHERE i < 20000)
				INSERT INTO revisions (res, id, parent_seq, first, kind, author, created)
				SELECT r.res, randomblob(20), 1000000 + i, 0, 0, r.author, r.created FROM revisions r, g WHERE r.seq = (SELECT MAX(seq) FROM revisions)`,
				`WITH RECURSIVE g(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM g WHERE i < 20000)
				INSERT INTO ns_log (ns, id, prev_seq, kind, body, config_seq, author, created)
				SELECT l.ns, randomblob(20), 1000000 + i, 0, '{}', l.config_seq, l.author, 0 FROM ns_log l, g WHERE l.seq = (SELECT MAX(seq) FROM ns_log)`,
			}
		}
		for _, q := range fill {
			if _, err := tx.Tx.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		kr, ir := idKeyArg(pg, h[:]), h[:]
		// A revision of one resource by id: on Postgres the planner may
		// also take revisions_by_id (id), as selective, depending on the
		// statistics; the write inserts into both, so either page is one
		// it reads anyway. SQLite compares +id (idIsSQL) and takes the key.
		resRev := "revisions_res_id8"
		if pg {
			resRev = "revisions_res_id8|revisions_by_id"
		}
		type plan struct {
			what, q, want string
			args          []any
		}
		plans := []plan{
			{"nsLogSeq", `SELECT seq FROM ns_log WHERE ns = ? AND ` + idIsSQL(pg, "id"), "ns_log_ns_id8", []any{n.id, kr, ir}},
			{"revByID", `SELECT ` + tx.revCols() + ` FROM revisions WHERE res = ? AND ` + idIsSQL(pg, "id"), resRev, []any{res, kr, ir}},
			{"locate", `SELECT ` + tx.revCols() + ` FROM revisions WHERE res = ? AND ` + idIsSQL(pg, "id") + ` AND seq <= ?`, resRev, []any{res, kr, ir, int64(1 << 40)}},
			// Or by the gesture's own indexes, as selective.
			{"gestures", `SELECT seq FROM revisions WHERE res = ? AND ` + idIsSQL(pg, "id") + ` AND (gesture = ? OR undoes = ?)`, "revisions_res_id8|revisions_by_gesture", []any{res, kr, ir, "g", "g"}},
			{"lookupResource (seq)", lookupSQL[b2i(e.refs)][0][b2i(pg)], resRev, []any{kr, ir, "x", "n"}},
			{"lookupResource (row)", lookupSQL[b2i(e.refs)][1][b2i(pg)], resRev, []any{"x", kr, ir, "n"}},
			// Across resources, by the whole id (drafts.go copyRows,
			// schemaload.go docRules): revisions_by_id, which stays.
			{"copyRows", `SELECT r.seq, s.ns, s.res, s.state FROM revisions r JOIN resources s ON s.res = r.res
				WHERE r.id = ? AND s.name = ? AND r.kind = 0 ORDER BY s.ns, r.seq`, "revisions_by_id", []any{ir, "x"}},
			{"docRules", `SELECT COUNT(*), MIN(COALESCE(r.rules, 0)) FROM revisions r JOIN resources s ON s.res = r.res
				WHERE r.id = ? AND r.kind = 0 AND ` + tx.e.inArray("s.ns", "bigint"), "revisions_by_id", []any{ir, tx.e.arrayArg([]int64{n.id})}},
			// The SQLite triggers' probes, and the Postgres update triggers'
			// (the Postgres insert triggers join the inserted rows to the
			// table by the same condition, with nothing but the index left
			// to the planner).
			{"ns_log_id_unique", `SELECT 1 FROM ns_log WHERE ns = ? AND ` + key("id") + ` = ` + key(param) + ` AND ` + idCol + ` = ?`, "ns_log_ns_id8", []any{n.id, ir, ir}},
			{"revisions_id_unique", `SELECT 1 FROM revisions WHERE res = ? AND ` + key("id") + ` = ` + key(param) + ` AND ` + idCol + ` = ?`, "revisions_res_id8", []any{res, ir, ir}},
		}
		for _, analyzed := range []bool{false, true} {
			if analyzed {
				if _, err := tx.Tx.Exec(`ANALYZE`); err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range plans {
				q, explain := p.q, `EXPLAIN QUERY PLAN `
				args := p.args
				if pg {
					q, explain, args = rebind(q), `EXPLAIN (COSTS OFF) `, pgArgs(args)
				}
				rows, err := tx.Tx.Query(explain+q, args...)
				if err != nil {
					t.Fatalf("%s: %v", p.what, err)
				}
				var lines []string
				cols, _ := rows.Columns()
				for rows.Next() {
					v := make([]any, len(cols))
					ptr := make([]any, len(cols))
					for i := range v {
						ptr[i] = &v[i]
					}
					tx.must(rows.Scan(ptr...))
					lines = append(lines, strings.TrimSpace(func() string {
						var b strings.Builder
						for _, x := range v {
							switch s := x.(type) {
							case string:
								b.WriteString(s + " ")
							case []byte:
								b.WriteString(string(s) + " ")
							}
						}
						return b.String()
					}()))
				}
				rows.Close()
				got := strings.Join(lines, "\n")
				found := false
				for _, w := range strings.Split(p.want, "|") {
					found = found || strings.Contains(got, w)
				}
				if !found || strings.Contains(got, "Seq Scan on revisions") || strings.Contains(got, "Seq Scan on ns_log") || strings.Contains(got, "SCAN revisions") || strings.Contains(got, "SCAN ns_log") {
					t.Errorf("%s (analyzed %v):\n%s\nwant %s, no scan", p.what, analyzed, got, p.want)
				}
			}
		}
		return errIDKeyDone
	}); err != nil && !errors.Is(err, errIDKeyDone) {
		t.Fatal(err)
	}
}

// TestIDKeyUpgrade: a database written before the key indexes (migration
// 033 in SQLite, 035 on Postgres), migrated: its rows are all there, its
// foreign keys hold, its schema of ns_log and revisions is a fresh
// database's, and it is written and read as before: an old write replays,
// old revisions and entries are found by id, and new writes chain on.
func TestIDKeyUpgrade(t *testing.T) {
	path, fresh := pgtest.FreshDB(t), pgtest.FreshDB(t)
	before := 35 // Postgres: 035_purged_namespaces_keep_name_and_purge_id
	if !pgtest.Enabled() {
		path, fresh = filepath.Join(t.TempDir(), "old.db"), filepath.Join(t.TempDir(), "fresh.db")
		before = 33 // SQLite: 033_purged_namespaces_keep_name_and_purge_id
	}
	ctx := context.Background()
	opts := func(p string) Options {
		lim := DefaultLimits()
		fast := Rate{1e9, 1e9}
		lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
		return Options{Path: p, BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1, Limits: lim, Purger: discardPurger{}}
	}
	o := opts(path)
	o.migrations = migrationsUpTo(t, before)
	old, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	mkNS(t, old, "a", map[string]any{"read": "public"})
	var revs []string
	head := ""
	for i := 0; i < 5; i++ {
		head, err = put(old, "a", "x", head, i)
		if err != nil {
			t.Fatal(err)
		}
		revs = append(revs, head)
	}
	r := who
	r.NS = "a"
	y, err := old.WriteResource(ctx, r, Item{Resource: "y", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	last := Item{Resource: "y", IfMatch: y.Items[0].IDs[0], Steps: []Step{{Delete: true}}}
	del, err := old.WriteResource(ctx, r, last)
	if err != nil {
		t.Fatal(err)
	}
	count := func(e *Engine) (n [3]int64) {
		t.Helper()
		if err := e.read(ctx, func(t *tx) error {
			t.must(t.QueryRow(`SELECT (SELECT COUNT(*) FROM revisions), (SELECT COUNT(*) FROM ns_log), (SELECT COUNT(*) FROM head_history)`).Scan(&n[0], &n[1], &n[2]))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	was := count(old)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := Open(opts(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if now := count(e); now != was {
		t.Fatalf("rows after the migration %v, want %v", now, was)
	}
	f, err := Open(opts(fresh))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if a, b := idKeySchema(t, e), idKeySchema(t, f); a != b {
		t.Errorf("migrated schema\n%s\nwant a fresh database's\n%s", a, b)
	}
	if !e.pg {
		for _, q := range []string{`PRAGMA foreign_key_check`, `PRAGMA integrity_check`} {
			rows, err := e.db.Query(q)
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			cols, _ := rows.Columns()
			for rows.Next() {
				v := make([]any, len(cols))
				p := make([]any, len(cols))
				for i := range v {
					p[i] = &v[i]
				}
				if err := rows.Scan(p...); err != nil {
					t.Fatal(err)
				}
				out = append(out, fmt.Sprint(v...))
			}
			rows.Close()
			if got := strings.Join(out, "; "); got != "" && got != "ok" {
				t.Errorf("%s: %s", q, got)
			}
		}
	}
	// An old write again: replayed, with the entry it wrote.
	again, err := e.WriteResource(ctx, r, last)
	if err != nil || !again.Replayed || again.NSID != del.NSID {
		t.Fatalf("retry of the delete: %+v %v, want a replay of %s", again, err, del.NSID)
	}
	for _, id := range revs {
		if rv, err := e.ResourceRev(ctx, "a", "x", id, Credentials{}); err != nil || rv.Status != 200 {
			t.Errorf("old revision %s: %+v %v", id, rv, err)
		}
	}
	lg, err := e.NamespaceLog(ctx, "a", "", y.NSID, 0, Credentials{})
	if err != nil || lg.Status != 200 || len(lg.Entries) != 1 {
		t.Errorf("the log after an old entry: %v %+v", err, lg)
	}
	if _, err := put(e, "a", "x", head, 9); err != nil {
		t.Fatalf("a new write on the old head: %v", err)
	}
	if _, err := put(e, "a", "x", head, 10); status(err) != 412 {
		t.Fatalf("a second write on the old head: %v, want 412", err)
	}
}

// idKeySchema is ns_log's and revisions' indexes, constraints and
// triggers.
func idKeySchema(t *testing.T, e *Engine) string {
	t.Helper()
	q := `SELECT type || ' ' || name || ': ' || COALESCE(sql, '') FROM sqlite_master WHERE tbl_name IN ('ns_log', 'revisions') ORDER BY type, name`
	if e.pg {
		q = `SELECT 'index ' || indexname || ': ' || indexdef FROM pg_indexes WHERE tablename IN ('ns_log', 'revisions')
			UNION ALL SELECT 'constraint ' || conname || ': ' || pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid IN ('ns_log'::regclass, 'revisions'::regclass)
			UNION ALL SELECT 'trigger ' || tgname || ': ' || pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid IN ('ns_log'::regclass, 'revisions'::regclass) AND NOT tgisinternal
			UNION ALL SELECT 'column ' || table_name || '.' || column_name || ': ' || data_type || ' ' || is_nullable FROM information_schema.columns WHERE table_name IN ('ns_log', 'revisions') AND table_schema = current_schema()
			ORDER BY 1`
	}
	rows, err := e.db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}
