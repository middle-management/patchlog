package index

// More of facetplan_test.go's differential comparison: rows the write path
// never leaves (orphans, empty namespaces), extreme pagination, and the
// driver's thresholds.

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
)

func envInt(name string, def int) int {
	if s := os.Getenv(name); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return def
}

// corrupt adds rows the write path never leaves: facet, sort and refs rows
// with no docs row (in a and in an otherwise empty namespace o), docs rows
// whose rows were deleted, docs rows deleted under their rows, and rows of
// a's resource names in b.
func corrupt(t *testing.T, ix *Index, r *rand.Rand) {
	t.Helper()
	tx, err := ix.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(q, args...); err != nil {
			t.Fatalf("%v: %s", err, q)
		}
	}
	for range r.IntN(40) {
		ns := []string{"a", "o", "o", "b"}[r.IntN(4)]
		res := fmt.Sprintf("r%03d", r.IntN(330)) // some have docs rows in a, some not
		if r.IntN(2) == 0 {
			res = fmt.Sprintf("z%03d", r.IntN(30))
		}
		path := []string{"/a", "/b", "/c", "/orph"}[r.IntN(4)]
		fv, raw := facetValue(facetPool[r.IntN(len(facetPool))])
		exec(`INSERT OR IGNORE INTO facet (ns, resource, schema, path, value, raw) VALUES (?, ?, 's', ?, ?, ?)`, ns, res, path, fv, raw)
		if r.IntN(2) == 0 {
			f := float64(r.IntN(10)) / 2
			exec(`INSERT OR IGNORE INTO "sort" (ns, resource, schema, path, value, raw) VALUES (?, ?, 's', '/s', ?, ?)`, ns, res, f, strconv.FormatFloat(f, 'g', -1, 64))
		}
		if r.IntN(2) == 0 {
			tg := refTargets[r.IntN(len(refTargets))]
			exec(`INSERT OR IGNORE INTO refs (ns, resource, schema, path, ref, target_ns, target, rev, entry) VALUES (?, ?, 's', '/refs/9', ?, ?, ?, NULL, NULL)`, ns, res, "/r/"+tg[0]+"/"+tg[1], tg[0], tg[1])
		}
	}
	// docs rows gone, their rows kept
	for range r.IntN(10) {
		exec(`DELETE FROM docs WHERE ns = 'a' AND resource = ?`, fmt.Sprintf("r%03d", r.IntN(300)))
	}
	// rows gone, docs rows kept
	for range r.IntN(10) {
		res := fmt.Sprintf("r%03d", r.IntN(300))
		exec(`DELETE FROM facet WHERE ns = 'a' AND resource = ?`, res)
		if r.IntN(2) == 0 {
			exec(`DELETE FROM "sort" WHERE ns = 'a' AND resource = ?`, res)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func randomQueryExt(r *rand.Rand) url.Values {
	v := randomQuery(r)
	if r.IntN(6) == 0 {
		v.Add("facet[/orph]", []string{"x", "y", "1"}[r.IntN(3)])
	}
	if r.IntN(8) == 0 {
		// the same value twice, and values of another path's type
		v.Add("facet[/b]", "x")
		v.Add("facet[/b]", "x")
	}
	if r.IntN(8) == 0 {
		v.Add("sort", "/s")
		v.Add("sort", "-/s")
	}
	if r.IntN(8) == 0 {
		v.Set("ref", []string{"/r/a/r001/rev/" + revA, "/r/a/r001%23e1", "/r/t/one/rev/" + revA + "%23e1"}[r.IntN(3)])
		if u, err := url.QueryUnescape(v.Get("ref")); err == nil {
			v.Set("ref", u)
		}
	}
	if r.IntN(6) == 0 {
		v.Set("after", fmt.Sprint([]int{999, 1000, 1001, 16383, 16384, 20000}[r.IntN(6)]))
	}
	if r.IntN(10) == 0 {
		v.Add("ge[/s]", "-1")
		v.Add("le[/s]", "100")
	}
	if r.IntN(10) == 0 {
		v.Set("schema", "/r/schemas/")
	}
	return v
}

func TestPlansMatchScanOrphans(t *testing.T) {
	t.Parallel()
	skipRace(t)
	seeds := envInt("FACETPLAN_SEEDS", 24)
	base := uint64(envInt("FACETPLAN_BASE", 1000))
	perSeed := envInt("FACETPLAN_QUERIES", 120)
	var driven, hits atomic.Int64
	t.Run("seeds", func(t *testing.T) {
		for i := range seeds {
			seed := base + uint64(i)
			t.Run(fmt.Sprint(seed), func(t *testing.T) {
				t.Parallel()
				r := rand.New(rand.NewPCG(seed, 11))
				ix := randomIndex(t, r, seed%4 == 3)
				corrupt(t, ix, r)
				ctx := context.Background()
				for range perSeed {
					v := randomQueryExt(r)
					q, err := ParseQuery(v)
					if err != nil {
						t.Fatalf("%s: %v", v.Encode(), err)
					}
					desc := v.Encode()
					switch r.IntN(12) {
					case 0: // an empty value list (not reachable by ParseQuery)
						q.Facets["/b"] = []string{}
						desc += " +facet[/b]=()"
					case 1:
						q.After = math.MaxInt
						desc += " +after=MaxInt"
					case 2:
						q.Facets["/zz"] = []string{"x"} // a path no doc has
						desc += " +facet[/zz]=x"
					}
					var allow func(string) bool
					if r.IntN(4) == 0 {
						allow = func(res string) bool { h := fnv.New32a(); h.Write([]byte(res)); return h.Sum32()%3 != 0 }
					}
					ns := []string{"a", "a", "b", "c", "e", "o"}[r.IntN(6)]
					tx, err := ix.db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					stmt, args := oldCandidateSQL(ix.fts, ns, q)
					want := candidates(t, tx, stmt, args)
					fs := q.filters()
					for drive := -1; drive < len(fs); drive++ {
						stmt, args := ix.candidateSQL(ns, q, fs, drive)
						if got := candidates(t, tx, stmt, args); !reflect.DeepEqual(got, want) {
							t.Errorf("%s in %s, driven by %d:\n got %v\nwant %v\n%s", desc, ns, drive, got, want, stmt)
						}
					}
					if d, err := ix.driver(ctx, tx, ns, q, fs); err != nil {
						t.Fatalf("%s: driver: %v", desc, err)
					} else if d >= 0 {
						driven.Add(1)
					}
					wantRes, wantErr := ix.oldRun(ctx, tx, ns, q, allow)
					gotRes, gotErr := ix.run(ctx, tx, ns, q, allow)
					if gotRes != nil {
						hits.Add(int64(len(gotRes.Hits)))
					}
					if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(gotRes, wantRes) {
						g, _ := json.Marshal(gotRes)
						w, _ := json.Marshal(wantRes)
						t.Errorf("%s in %s (allow %v):\n got %s %v\nwant %s %v", desc, ns, allow != nil, g, gotErr, w, wantErr)
					}
					tx.Rollback()
				}
			})
		}
	})
	t.Logf("driven %d, hits %d", driven.Load(), hits.Load())
}

// TestDriverThresholds compares run with the scan at the driver's
// thresholds: 4*m documents, maxDrive matches, After+Limit around maxDrive,
// maxDriveAll matches with sort and counts (len(resources) around it).
func TestDriverThresholds(t *testing.T) {
	t.Parallel()
	skipRace(t)
	ix := openTestIndex(t, false)
	ctx := context.Background()
	// namespaces: n1000 (1000 docs, /k=hit on 250), n1001 (1001 docs, 250),
	// big (70000 docs; /k=hit on the first K of each tier).
	fill := func(ns string, n int, tiers map[string]int) {
		tx, err := ix.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for i := range n {
			res := fmt.Sprintf("d%06d", (i*7919)%n) // resource order differs from tier order
			if _, err := tx.Exec(`INSERT INTO docs (ns, resource, head, schema) VALUES (?, ?, 'h', 's')`, ns, res); err != nil {
				t.Fatal(err)
			}
			for v, k := range tiers {
				if i < k {
					if _, err := tx.Exec(`INSERT INTO facet (ns, resource, schema, path, value, raw) VALUES (?, ?, 's', '/k', ?, ?)`, ns, res, v, `"`+v+`"`); err != nil {
						t.Fatal(err)
					}
				}
			}
			st := fmt.Sprintf("s%d", i%37)
			if _, err := tx.Exec(`INSERT INTO facet (ns, resource, schema, path, value, raw) VALUES (?, ?, 's', '/st', ?, ?)`, ns, res, st, `"`+st+`"`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`INSERT INTO "sort" (ns, resource, schema, path, value, raw) VALUES (?, ?, 's', '/n', ?, ?)`, ns, res, float64(i%101), strconv.Itoa(i%101)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	fill("n1000", 1000, map[string]int{"hit": 250})
	fill("n1001", 1001, map[string]int{"hit": 250})
	// maxDrive's edges; with FACETPLAN_BIG set, maxDriveAll's too (70k
	// documents, about 20 s).
	big, n := map[string]int{"m999": 999, "m1000": 1000, "m1001": 1001}, 5000
	if os.Getenv("FACETPLAN_BIG") != "" {
		big["m16383"], big["m16384"], big["m16385"], n = 16383, 16384, 16385, 70000
	}
	fill("big", n, big)
	type c struct{ ns, q string }
	var cases []c
	for _, ns := range []string{"n1000", "n1001"} {
		cases = append(cases, c{ns, "facet[/k]=hit"}, c{ns, "facet[/k]=hit&sort=-/n&counts=/st"}, c{ns, "facet[/k]=hit&after=240&limit=20"})
	}
	for v := range big {
		for _, extra := range []string{"", "&sort=/n", "&counts=/st&counts=/k", "&after=980&limit=20", "&after=981&limit=20", "&after=16380&limit=4", "&after=16400&limit=1", "&facet[/st]=s3", "&ge[/n]=50"} {
			cases = append(cases, c{"big", "facet[/k]=" + v + extra})
		}
	}
	cases = append(cases, c{"big", "counts=/st&limit=1"}, c{"big", "ge[/n]=100&counts=/k"}, c{"big", "ge[/n]=100&sort=-/n&counts=/k"})
	for _, cs := range cases {
		v, err := url.ParseQuery(cs.q)
		if err != nil {
			t.Fatal(err)
		}
		q, err := ParseQuery(v)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := ix.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ix.driver(ctx, tx, cs.ns, q, q.filters())
		if err != nil {
			t.Fatal(err)
		}
		want, wantErr := ix.oldRun(ctx, tx, cs.ns, q, nil)
		got, gotErr := ix.run(ctx, tx, cs.ns, q, nil)
		tx.Rollback()
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
			t.Errorf("%s in %s (driver %d): differs (%v / %v)", cs.q, cs.ns, d, gotErr, wantErr)
		} else {
			t.Logf("%s in %s: driver %d, %d hits, more %v", cs.q, cs.ns, d, len(got.Hits), got.More)
		}
	}
}
