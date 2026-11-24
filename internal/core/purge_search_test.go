package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A purge finds the namespaces it has something to do in from the name
// (purgeHolders), or, for a name too many namespaces hold, level by level
// below its namespace (purgeLevels): both reach the same ones (§8.3). The
// tree has what the search must tell apart: a holder deep below branches
// that see nothing, a branch made exactly at the name's first entry and
// one made just before, holders of sealed copies or blob sealings alone,
// frozen branches, and a namespace below a purged one, which a purge never
// reaches.
func TestPurgeSearch(t *testing.T) {
	t.Parallel()
	for _, mode := range []struct {
		name string
		max  int
	}{{"by name", 0}, {"by level", -1}, {"by level, any negative bound", -5}, {"over the bound", 3}} {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			e := openInstance(t, pgtest.DB(t), t.TempDir())
			e.purgeHoldersMax = mode.max
			ctx := context.Background()
			mkNS(t, e, "n", map[string]any{"read": "public"})
			branch := func(base, name string) string {
				t.Helper()
				r := who
				r.NS = base
				br, err := e.CreateBranch(ctx, r, BranchRequest{Name: name, IfNoneMatch: true})
				if err != nil {
					t.Fatalf("branch %s: %v", name, err)
				}
				return br.ConfigID
			}
			create := func(ns string) string {
				t.Helper()
				id, err := put(e, ns, "x", "", 1)
				if err != nil {
					t.Fatalf("create %s/x: %v", ns, err)
				}
				return id
			}
			freeze := func(ns, cfg string) {
				t.Helper()
				r := who
				r.NS = ns
				if _, err := e.WriteConfig(ctx, r, ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}}); err != nil {
					t.Fatalf("freeze %s: %v", ns, err)
				}
			}
			// Made before n's x: none of these sees it.
			branch("n", "old")
			branch("old", "oldkid")
			branch("oldkid", "deep")
			branch("deep", "deepown")
			create("deepown") // a holder three skipped branches down
			branch("deepown", "deepownkid")
			branch("n", "so") // will hold sealed copies alone
			branch("n", "bo") // will hold blob sealings alone
			fzold := branch("n", "fzold")
			branch("n", "gone")
			branch("gone", "goneown")
			create("goneown") // a holder below a purged namespace
			if _, err := put(e, "n", "other", "", 1); err != nil {
				t.Fatal(err)
			}
			branch("n", "pre") // at the entry just before x's first
			head := create("n")
			branch("n", "at") // at x's first entry exactly
			fz := branch("n", "fz")
			branch("fz", "fzkid")
			branch("n", "gone2")
			branch("gone2", "gone2kid") // reads through a purged namespace
			freeze("fz", fz)
			freeze("fzold", fzold)
			if err := e.update(ctx, func(t *tx) error {
				id := func(name string) int64 { return t.nsByName(name).id }
				// As a namespace purge leaves them, but with their branches
				// still there, which only a hand can do: a purge stops at a
				// purged namespace.
				_, err := t.Exec(`UPDATE namespaces SET purged = 1 WHERE name IN ('gone', 'gone2')`)
				t.must(err)
				_, err = t.Exec(`INSERT INTO sealed (ns, kind, key, name, jwe, created, kver) VALUES (?, 'doc', 'k', 'x', 'j', 0, 1)`, id("so"))
				t.must(err)
				_, err = t.Exec(`INSERT INTO sealed (ns, kind, key, name, jwe, created, kver) VALUES (?, 'doc', 'k2', 'other', 'j', 0, 1)`, id("so"))
				t.must(err)
				_, err = t.Exec(`INSERT INTO blob_epochs (ns, name, bid, epoch, created) VALUES (?, 'x', ?, 1, 0)`, id("bo"), make([]byte, 20))
				t.must(err)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			r := who
			r.NS = "n"
			if _, err := e.Purge(ctx, r, "x", head, false); err != nil {
				t.Fatal(err)
			}
			var got []string
			var stored int
			if err := e.read(ctx, func(t *tx) error {
				rows, err := t.Query(`SELECT n.name FROM ns_log l JOIN namespaces n ON n.ns = l.ns WHERE l.kind = ?`, nsKindCode("purge"))
				t.must(err)
				defer rows.Close()
				for rows.Next() {
					var s string
					t.must(rows.Scan(&s))
					got = append(got, s)
				}
				t.must(rows.Err())
				t.must(t.QueryRow(`SELECT (SELECT COUNT(*) FROM sealed WHERE name = 'x') + (SELECT COUNT(*) FROM blob_epochs WHERE name = 'x')`).Scan(&stored))
				var kept int
				t.must(t.QueryRow(`SELECT COUNT(*) FROM sealed WHERE name = 'other'`).Scan(&kept))
				if kept != 1 {
					panic(fmt.Sprintf("%d sealed rows of another name left, want 1", kept))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			sort.Strings(got)
			if want := "at deepown deepownkid fz fzkid n"; strings.Join(got, " ") != want {
				t.Errorf("purge entries in %v, want in %s", got, want)
			}
			if stored != 0 {
				t.Errorf("%d sealed copies and blob sealings of x left", stored)
			}
		})
	}
}

// On Postgres the statements of a purge's search and the count of a
// base's live branches read by the indexes made for them, and no row of a
// branch they have nothing to say about: with 40 branches made before the
// document, 2 after and 30 frozen, the search's statement returns the 2
// and filters nothing out, and the count reads the live branches' index.
// The namespaces with sealed copies or blob sealings of a name are read
// one index seek each, however many rows each has, and the holders' chains
// of bases by key.
func TestPGPurgeSearchPlans(t *testing.T) {
	if pgtest.Spanner() {
		t.Skip("Postgres's plans")
	}
	if !pgtest.Enabled() {
		t.Skip("PATCHLOG_TEST_PG is not set")
	}
	t.Parallel()
	lim := DefaultLimits()
	lim.BranchesPerNamespace = 1000
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, Limits: lim, Purger: discardPurger{},
		RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	r := who
	r.NS = "n"
	branch := func(name string, frozen bool) {
		t.Helper()
		br := BranchRequest{Name: name, IfNoneMatch: true}
		if frozen {
			br.Patches = []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}
		}
		if _, err := e.CreateBranch(ctx, r, br); err != nil {
			t.Fatalf("branch %s: %v", name, err)
		}
	}
	for i := 0; i < 40; i++ {
		branch(fmt.Sprintf("pre%d", i), i < 30)
	}
	if _, err := put(e, "n", "x", "", 1); err != nil {
		t.Fatal(err)
	}
	branch("post0", false)
	branch("post1", false)
	explain := func(t *tx, q string, args ...any) string {
		rows, err := t.Tx.Query(`EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) `+rebind(q), pgArgs(args, false)...)
		t.must(err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var l string
			t.must(rows.Scan(&l))
			out = append(out, l)
		}
		t.must(rows.Err())
		return strings.Join(out, "\n")
	}
	if err := e.update(ctx, func(tx *tx) error {
		n := tx.nsByName("n")
		var lo int64
		tx.must(tx.QueryRow(`SELECT MIN(h.ns_seq) FROM resources r JOIN head_history h ON h.res = r.res WHERE r.ns = ? AND r.name = 'x'`, n.id).Scan(&lo))
		// Many rows per namespace and name, as sealed copies and blob
		// sealings come: 500 each in three namespaces.
		post0 := tx.nsByName("post0").id
		for _, q := range []string{
			`INSERT INTO sealed (ns, kind, key, name, jwe, created, kver) SELECT b.ns, 'doc', 'k' || g, 'x', 'j', 0, 1
				FROM namespaces b, generate_series(1, 500) g WHERE b.name IN ('pre0', 'pre1', 'post0')`,
			`INSERT INTO blob_epochs (ns, name, bid, epoch, created) SELECT b.ns, 'x', decode(lpad(to_hex(g), 40, '0'), 'hex'), 1, 0
				FROM namespaces b, generate_series(1, 500) g WHERE b.name IN ('pre0', 'pre1', 'post0')`,
		} {
			_, err := tx.Tx.Exec(q)
			tx.must(err)
		}
		restore := tx.planByIndex()
		defer restore()
		for _, c := range []struct {
			what, plan, index, rows string
		}{
			{"the branches made at or after the document", explain(tx, purgeBranchesFrom, []int64{n.id}, []int64{lo}), "namespaces_base_at", "rows=2 "},
			{"the namespaces with a row for the name", explain(tx, purgeHoldersByRow, "x", 1001), "resources_name", "rows=1 "},
			{"the live branches", explain(tx, liveBranchesCount, n.id, 0), "namespaces_live", "rows=12 "},
			// One index seek per namespace, not the 1,500 rows.
			{"the namespaces with sealed copies of the name", explain(tx, purgeHoldersSealed, "x", "x", 1001), "sealed_by_name", "rows=3 "},
			{"the namespaces with blob sealings of the name", explain(tx, purgeHoldersEpochs, "x", "x", 1001), "blob_epochs_name", "rows=3 "},
			{"the holders' chains of bases", explain(tx, tx.e.purgeChains(), []int64{post0}, n.id), "namespaces_pkey", "rows=2 "},
		} {
			// The recursive statements filter their own working rows (the
			// row that ends the recursion), never a table's.
			plan := strings.NewReplacer("Rows Removed by Filter: 0", "", "Rows Removed by Filter: 1\n", "\n").Replace(c.plan + "\n")
			if !strings.Contains(plan, c.index) || !strings.Contains(plan, c.rows) || strings.Contains(plan, "Seq Scan") ||
				strings.Contains(plan, "Rows Removed by Filter") || strings.Contains(plan, "rows=500 ") || strings.Contains(plan, "rows=1500 ") {
				t.Errorf("%s: want an index scan of %s with %s and nothing filtered out, got\n%s", c.what, c.index, c.rows, c.plan)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
