package core

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// TestDerivedEntries writes entries of every kind, in a namespace and a
// branch of it, and checks that only single writes' head and tombstone
// entries are stored derived (entrybody.go), that every entry's body as a
// read rebuilds it hashes to its id after the one before it (§3.5), and
// that the log serves a derived entry's hashed members as rebuilt.
func TestDerivedEntries(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	req := func(ns string) Request { r := who; r.NS = ns; return r }
	must := func(id string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	x := must(put(e, "n", "x", "", 1))
	x = must(put(e, "n", "x", x, 2))
	y := must(put(e, "n", "y", "", 1))
	// A tombstone, and a write with gesture members (unhashed, §7.4).
	if _, err := e.WriteResource(ctx, req("n"), Item{Resource: "y", IfMatch: y, Steps: []Step{{Delete: true}}}); err != nil {
		t.Fatal(err)
	}
	g := "abcdefghijklmnopqrstuvwxyz"
	if _, err := e.WriteResource(ctx, req("n"), Item{Resource: "x", IfMatch: x,
		Steps: []Step{{Gesture: g, Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": float64(3)}}}}}); err != nil {
		t.Fatal(err)
	}
	// A batch, kept whole.
	if _, err := e.Batch(ctx, req("n"), []Item{
		{Resource: "b1", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
		{Resource: "b2", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
	}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	// A branch (a branch entry in n), written to: its own rows of x.
	if _, err := e.CreateBranch(ctx, req("n"), BranchRequest{Name: "b", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	head := func(ns, name string) string {
		t.Helper()
		l, err := e.ResourceLog(ctx, ns, name, "", "", 0, Credentials{})
		if err != nil || len(l.Entries) == 0 {
			t.Fatalf("log of %s/%s: %v", ns, name, err)
		}
		return l.Entries[len(l.Entries)-1]["id"].(string)
	}
	must(put(e, "b", "x", head("b", "x"), 4))
	must(put(e, "b", "z", "", 1))
	// A purge in n, propagated to the branch (purge entries in both).
	if _, err := e.Purge(ctx, req("n"), "b1", head("n", "b1"), false); err != nil {
		t.Fatal(err)
	}
	must(put(e, "n", "x", head("n", "x"), 5))

	if err := e.checkDerived(ctx); err != nil {
		t.Fatal(err)
	}
	// Every entry: derived only for single writes' heads and tombstones,
	// and its body, rebuilt where derived, chains (§3.5).
	byKind := map[string][2]int{}
	if err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT l.seq, l.id, p.id, COALESCE(l.body, ''), l.kind, ` + derivedCols + ` FROM ns_log l LEFT JOIN ns_log p ON p.seq = l.prev_seq` + derivedJoins + ` ORDER BY l.seq`)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var seq int64
			var id, prev []byte
			var body string
			var kind int
			var d derived
			t.must(rows.Scan(&seq, &id, &prev, &body, &kind, &d.kind, &d.name, &d.id, &d.created))
			c := byKind[nsKindNames[kind]]
			if body == "" {
				c[0]++
				body = string(entryBody(d.kind, d.name.String, ids.FromBytes(d.id)))
			} else {
				c[1]++
			}
			byKind[nsKindNames[kind]] = c
			var p *ids.ID
			if prev != nil {
				x := ids.FromBytes(prev)
				p = &x
			}
			if ids.Hash(p, []byte(body)) != ids.FromBytes(id) {
				panic("entry " + ids.FromBytes(id).String() + " doesn't chain: " + body)
			}
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for k, c := range byKind {
		switch {
		case (k == "head" || k == "tombstone") && (c[0] == 0 || c[1] != 0):
			t.Errorf("%s entries: %d derived, %d stored; want all derived", k, c[0], c[1])
		case k != "head" && k != "tombstone" && c[0] != 0:
			t.Errorf("%s entries: %d derived", k, c[0])
		}
	}
	for _, k := range []string{"head", "tombstone", "config", "batch", "branch", "purge"} {
		if _, ok := byKind[k]; !ok {
			t.Errorf("no %s entry written", k)
		}
	}
	// The log serves a derived entry's members as rebuilt, its created
	// that of its revision, and its gesture members.
	for _, ns := range []string{"n", "b"} {
		lg, err := e.NamespaceLog(ctx, ns, "", "", 0, Credentials{})
		if err != nil || lg.Status != 200 {
			t.Fatalf("log of %s: %v %+v", ns, err, lg)
		}
		var prev *ids.ID
		sawGesture := false
		for _, en := range lg.Entries {
			hashed := map[string]any{}
			for _, k := range []string{"kind", "resource", "target", "entries", "name", "at", "forced", "source"} {
				if v, ok := en[k]; ok {
					hashed[k] = v
				}
			}
			id, _ := ids.Parse(en["id"].(string))
			if ids.Hash(prev, jsonv.Canonical(jsonv.FromGo(hashed))) != id {
				t.Errorf("%s: served entry %v doesn't hash to its id", ns, en)
			}
			prev = &id
			if en["kind"] == "head" || en["kind"] == "tombstone" {
				rl, err := e.ResourceLog(ctx, ns, en["resource"].(string), en["target"].(string), "", 0, Credentials{})
				if err == nil && rl.Status == 200 && len(rl.Entries) > 0 {
					if rc := rl.Entries[len(rl.Entries)-1]["created"]; rc != en["created"] {
						t.Errorf("%s: entry %v created %v, its revision %v", ns, en["id"], en["created"], rc)
					}
				}
			}
			if en["gesture"] == g {
				sawGesture = true
			}
		}
		if ns == "n" && !sawGesture {
			t.Errorf("%s: the gesture members aren't served", ns)
		}
	}
}

// TestPGFirstsPlans: on Postgres the lookups that replaced ns_log's
// indexes of rare queries (ns_config.first_seq for config retries,
// ns_grants for a namespace's first entry recording a grant) read their
// rows by key, never ns_log.
var errPlansDone = errors.New("rolled back: plans only")

func TestPGFirstsPlans(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("PATCHLOG_TEST_PG is not set")
	}
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	head := ""
	for i := 0; i < 200; i++ {
		id, err := put(e, "n", "x", head, i)
		if err != nil {
			t.Fatal(err)
		}
		head = id
	}
	if err := e.update(ctx, func(tx *tx) error {
		for _, q := range []string{
			`INSERT INTO grants (id, blocks) SELECT decode(lpad(to_hex(g), 40, '0'), 'hex'), '\x00' FROM generate_series(1, 5000) g`,
			`INSERT INTO ns_grants (grant_ref, ns, first_seq) SELECT ref, 1, ref FROM grants`,
			`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created)
				SELECT c.ns, decode(lpad(to_hex(g), 40, '0'), 'hex'), 1000000 + g, '[]', '{}', c.author, 0 FROM ns_config c, generate_series(1, 5000) g`,
			`ANALYZE grants`, `ANALYZE ns_grants`, `ANALYZE ns_config`, `ANALYZE ns_log`,
		} {
			if _, err := tx.Tx.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		n := tx.nsByName("n")
		for _, c := range []struct {
			q    string
			args []any
			want string
		}{
			{`SELECT first_seq FROM ns_config WHERE seq = ? AND ns = ?`, []any{n.configSeq, n.id}, "ns_config_pkey"},
			{`SELECT f.first_seq FROM ns_grants f WHERE f.grant_ref = (SELECT ref FROM grants WHERE id = ?) AND f.ns = ? AND f.first_seq <= ?`,
				[]any{make([]byte, 20), n.id, int64(1000)}, "ns_grants_pkey"},
		} {
			rows, err := tx.Tx.Query(`EXPLAIN (COSTS OFF) `+rebind(c.q), pgArgs(c.args)...)
			tx.must(err)
			var plan []string
			for rows.Next() {
				var l string
				tx.must(rows.Scan(&l))
				plan = append(plan, l)
			}
			rows.Close()
			p := strings.Join(plan, "\n")
			if !strings.Contains(p, c.want) || strings.Contains(p, "ns_log") || strings.Contains(p, "Seq Scan") {
				t.Errorf("%s:\n%s\nwant %s, no scan", c.q, p, c.want)
			}
		}
		return errPlansDone
	}); err != nil && !errors.Is(err, errPlansDone) {
		t.Fatal(err)
	}
}

// TestStorageUpgrade: a database written before derived entries, grant
// numbers and the rows that replaced ns_log's rare-lookup indexes
// (migrations 031-032 in SQLite, 033-034 on Postgres), migrated and written
// to again, serves its old entries as before, chains, finds the first
// entry recording a grant whichever rows record it, replays a config
// write, and serves old revisions' grants.
func TestStorageUpgrade(t *testing.T) {
	path := pgtest.FreshDB(t)
	before := 32 // Postgres: 032_filtered_served
	if !pgtest.Enabled() {
		path = filepath.Join(t.TempDir(), "old.db")
		before = 30 // SQLite: 030_filtered_served
	}
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	blobs := t.TempDir()
	opts := func() Options {
		lim := DefaultLimits()
		fast := Rate{1e9, 1e9}
		lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
		return Options{Path: path, BlobDir: blobs, OperatorKeys: ops, RetentionInterval: -1, BlobSweepInterval: -1, Limits: lim, Purger: discardPurger{}}
	}
	exp := time.Now().Add(time.Hour).Format(time.RFC3339)
	mint := func(priv ed25519.PrivateKey, root map[string]any) (string, string) {
		g, err := grant.Mint(root, priv)
		if err != nil {
			t.Fatal(err)
		}
		return g.Encode(), g.ID().String()
	}
	pub, priv := grant.GenerateKey()
	can := []any{"read", "create", "append", "delete", "config"}
	opG, _ := mint(opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}, "exp": exp})
	g1, g1id := mint(priv, map[string]any{"kid": "k", "sub": "svc:one", "ns": []any{"n"}, "can": can, "exp": exp})
	g2, g2id := mint(priv, map[string]any{"kid": "k", "sub": "svc:two", "ns": []any{"n"}, "can": can, "exp": exp})
	ctx := context.Background()
	as := func(b string) Request { return Request{NS: "n", Cred: Credentials{Bearer: b}} }
	type writes struct{ x, y string }
	write := func(e *Engine, b string, w *writes, n int) {
		t.Helper()
		it := Item{Resource: "x", IfMatch: w.x, IfNoneMatch: w.x == ""}
		op := "replace"
		if w.x == "" {
			op = "add"
		}
		it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(n)}}}}}
		r, err := e.WriteResource(ctx, as(b), it)
		if err != nil {
			t.Fatal(err)
		}
		w.x = r.Entry.ID
	}
	cfg := ConfigChange{Patches: []any{map[string]any{"op": "add", "path": "/x-title", "value": "t"}}}

	o := opts()
	o.migrations = migrationsUpTo(t, before)
	old, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"read": "public", "keys": []any{map[string]any{"kid": "k", "alg": "ed25519", "pub": pub, "can": can}}}
	c0, err := old.WriteConfig(ctx, as(opG), ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}})
	if err != nil {
		t.Fatal(err)
	}
	var w writes
	write(old, g1, &w, 1)
	write(old, g1, &w, 2)
	y, err := old.WriteResource(ctx, as(g1), Item{Resource: "y", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.WriteResource(ctx, as(g1), Item{Resource: "y", IfMatch: y.Entry.ID, Steps: []Step{{Delete: true}}}); err != nil {
		t.Fatal(err)
	}
	cfg.IfMatch = c0.ConfigID
	c1, err := old.WriteConfig(ctx, as(g1), cfg)
	if err != nil {
		t.Fatal(err)
	}
	served := func(e *Engine) []string {
		t.Helper()
		lg, err := e.NamespaceLog(ctx, "n", "", "", 0, Credentials{})
		if err != nil || lg.Status != 200 {
			t.Fatalf("log: %v %+v", err, lg)
		}
		var out []string
		for _, en := range lg.Entries {
			out = append(out, string(jsonv.Canonical(jsonv.FromGo(en))))
		}
		return out
	}
	was := served(old)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := Open(opts())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if !e.refs || !e.firsts {
		t.Fatalf("migrated schema: refs %v, firsts %v", e.refs, e.firsts)
	}
	if now := served(e); strings.Join(now, "\n") != strings.Join(was, "\n") {
		t.Fatalf("the old entries serve\n%s\nwant\n%s", strings.Join(now, "\n"), strings.Join(was, "\n"))
	}
	// Written again: under the old grant and a new one.
	write(e, g1, &w, 3)
	write(e, g2, &w, 4)
	now := served(e)
	if strings.Join(now[:len(was)], "\n") != strings.Join(was, "\n") || len(now) != len(was)+2 {
		t.Fatalf("after writing: %d entries, the old ones changed", len(now))
	}
	if err := e.checkDerived(ctx); err != nil {
		t.Fatal(err)
	}
	var derived, byNumber int
	firsts := map[string]sql.NullInt64{}
	if err := e.read(ctx, func(t *tx) error {
		t.must(t.QueryRow(`SELECT COUNT(*), COUNT(grant_ref) FROM ns_log WHERE `+strings.ReplaceAll(derivedCond, "l.", "")).Scan(&derived, &byNumber))
		for _, g := range []string{g1id, g2id} {
			id, _ := ids.Parse(g)
			var seq sql.NullInt64
			first, args := t.firstGrantEntry(id[:], t.nsByName("n").id, sql.NullInt64{})
			t.must(t.QueryRow(`SELECT `+first, args...).Scan(&seq))
			firsts[g] = seq
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if derived != 2 || byNumber != 2 {
		t.Errorf("new entries: %d derived, %d naming their grant by number; want 2, 2", derived, byNumber)
	}
	// g1's first entry is the old one recording it (the namespace's second,
	// after the operator's config); g2's the last.
	var seqs []int64
	if err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT seq FROM ns_log ORDER BY seq`)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var s int64
			t.must(rows.Scan(&s))
			seqs = append(seqs, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if firsts[g1id].Int64 != seqs[1] || firsts[g2id].Int64 != seqs[len(seqs)-1] {
		t.Errorf("first entries %v, want %d and %d", firsts, seqs[1], seqs[len(seqs)-1])
	}
	for _, g := range []string{g1id, g2id} {
		if _, err := e.Grant(ctx, "n", g, Credentials{}); err != nil {
			t.Errorf("grant %s: %v", g, err)
		}
	}
	// The config write again: replayed, with the entry that wrote it.
	r, err := e.WriteConfig(ctx, as(g1), cfg)
	if err != nil || !r.Replayed || r.ConfigID != c1.ConfigID || r.NSID != c1.NSID {
		t.Errorf("config retry: %v %+v, want a replay of %+v", err, r, c1)
	}
	// Old and new revisions serve their grants.
	lg, err := e.ResourceLog(ctx, "n", "x", "", "", 0, Credentials{})
	if err != nil || len(lg.Entries) != 4 {
		t.Fatalf("x's log: %v %+v", err, lg)
	}
	for i, en := range lg.Entries {
		g, _ := en["grant"].(map[string]any)
		if want := []string{g1id, g1id, g1id, g2id}[i]; g == nil || g["id"] != want {
			t.Errorf("x's revision %d serves grant %v, want %s", i, en["grant"], want)
		}
	}
}
