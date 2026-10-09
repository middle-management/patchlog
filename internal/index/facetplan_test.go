package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Issue B6: facet, range and ref queries read their candidates from the
// filter's index instead of scanning the namespace. These tests check that
// every query shape answers exactly as the scan did (oldRun, below, is the
// query path of v0.15.2), and that the plans are the intended ones with
// and without ANALYZE statistics.

// TestPlansMatchScan runs random queries over random datasets, with every
// filter driving in turn and with the one driver picks, against the scan.
func TestPlansMatchScan(t *testing.T) {
	t.Parallel()
	skipRace(t)
	var driven, scanned, hits atomic.Int64
	t.Run("seeds", func(t *testing.T) {
		testPlansMatchScan(t, &driven, &scanned, &hits)
	})
	// The datasets are large enough for both plans, and for results.
	if driven.Load() < 500 || scanned.Load() < 100 || hits.Load() < 1000 {
		t.Errorf("%d queries driven by a filter, %d scanned, %d hits", driven.Load(), scanned.Load(), hits.Load())
	}
}

// skipRace skips a single-threaded comparison of query plans under the
// race detector, which has nothing to check there and slows building the
// datasets (SQLite in Go) about tenfold; go test without -race runs it.
func skipRace(t *testing.T) {
	t.Helper()
	if raceBuild {
		t.Skip("query plans, single-threaded: without -race")
	}
}

func testPlansMatchScan(t *testing.T, driven, scanned, hits *atomic.Int64) {
	for seed := range uint64(24) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			r := rand.New(rand.NewPCG(seed, 7))
			ix := randomIndex(t, r, seed%4 == 3)
			ctx := context.Background()
			for range 80 {
				v := randomQuery(r)
				q, err := ParseQuery(v)
				if err != nil {
					t.Fatalf("%s: %v", v.Encode(), err)
				}
				var allow func(string) bool
				if r.IntN(4) == 0 {
					allow = func(res string) bool { h := fnv.New32a(); h.Write([]byte(res)); return h.Sum32()%3 != 0 }
				}
				ns := []string{"a", "a", "a", "b", "c"}[r.IntN(5)]
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
						t.Errorf("%s in %s, driven by %d:\n got %v\nwant %v\n%s", v.Encode(), ns, drive, got, want, stmt)
					}
				}
				if len(q.words) == 0 && len(fs) > 0 {
					if drive, err := ix.driver(ctx, tx, ns, q, fs); err != nil {
						t.Fatal(err)
					} else if drive >= 0 {
						driven.Add(1)
					} else {
						scanned.Add(1)
					}
				}
				wantRes, wantErr := ix.oldRun(ctx, tx, ns, q, allow)
				gotRes, gotErr := ix.run(ctx, tx, ns, q, allow)
				if gotRes != nil {
					hits.Add(int64(len(gotRes.Hits)))
				}
				if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(gotRes, wantRes) {
					g, _ := json.Marshal(gotRes)
					w, _ := json.Marshal(wantRes)
					t.Errorf("%s in %s (allow %v):\n got %s %v\nwant %s %v", v.Encode(), ns, allow != nil, g, gotErr, w, wantErr)
				}
				tx.Rollback()
			}
		})
	}
}

// TestCountsLookup checks the two ways counts reads a path against each
// other, over random subsets of the namespace.
func TestCountsLookup(t *testing.T) {
	t.Parallel()
	skipRace(t)
	r := rand.New(rand.NewPCG(1, 1))
	ix := randomIndex(t, r, false)
	ctx := context.Background()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	all := candidates(t, tx, `SELECT resource FROM docs WHERE ns = 'a'`, nil)
	paths := []string{"/a", "/b", "/c", "/zz"}
	lookups := 0
	for range 200 {
		var res []string
		for _, c := range all {
			if r.IntN(8) == 0 {
				res = append(res, c[0].(string))
			}
		}
		got, err := ix.counts(ctx, tx, "a", paths, res)
		if err != nil {
			t.Fatal(err)
		}
		want, err := oldCounts(ctx, tx, "a", paths, res)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("counts of %v:\n got %v\nwant %v", res, got, want)
		}
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM facet WHERE ns = 'a' AND path = '/a'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 2*len(res) {
			lookups++
		}
	}
	if lookups == 0 {
		t.Fatal("no subset was looked up")
	}
}

// TestPlans pins the plans: a selective facet, range or ref reads its
// matches on its query index and looks each document up (never a scan of
// the namespace's documents), q= is driven by the text matches, and
// unselective queries scan the namespace. The first two don't change with
// ANALYZE statistics, even ones that make the namespace look small.
func TestPlans(t *testing.T) {
	t.Parallel()
	skipRace(t)
	ix := openTestIndex(t, false)
	fillBench(t, ix, 5000)
	ctx := context.Background()
	driven := []string{
		"facet[/accountId]=acct-12",
		"facet[/accountId]=acct-12&facet[/accountId]=acct-13&sort=/accountId",
		"facet[/accountId]=acct-12&facet[/status]=open&facet[/kind]=item",
		"facet[/accountId]=acct-12&schema=/r/schemas/item&counts=/status",
		"facet[/kind]=item&facet[/region]=region-07&sort=-/createdAt",
		"ge[/createdAt]=2026-12-29T00:00:00Z",
		"ge[/score]=995&lt[/score]=999",
		"ref=/r/accounts/acct-12",
		"facet[/kind]=item&ref=/r/accounts/acct-12",
		"facet[/id]=id-1&facet[/id]=id-2&after=1&limit=1",
	}
	scanned := []string{"", "facet[/kind]=item", "facet[/kind]=item&sort=/score", "facet[/kind]=item&counts=/status", "facet[/status]=open", "facet[/status]=open&sort=/score"}
	docScan := regexp.MustCompile(`^(SCAN d\b|SEARCH d USING .*\(ns=\?\)$)`)
	plans := func() map[string]string {
		out := map[string]string{}
		for _, s := range append(append([]string{"q=alpha&facet[/accountId]=acct-12"}, driven...), scanned...) {
			v, _ := url.ParseQuery(s)
			q, err := ParseQuery(v)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := ix.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			fs := q.filters()
			drive, err := ix.driver(ctx, tx, benchNS, q, fs)
			tx.Rollback()
			if err != nil {
				t.Fatal(err)
			}
			stmt, args := ix.candidateSQL(benchNS, q, fs, drive)
			plan := explainPlan(t, ix.db, stmt, args...)
			out[s] = strings.Join(plan, "\n")
			top := topLevel(plan)
			switch {
			case len(q.words) > 0:
				if len(top) < 2 || top[0] != "SCAN t" || top[1] != "SEARCH d USING INTEGER PRIMARY KEY (rowid=?)" {
					t.Errorf("%s: not driven by the text matches:\n%s", s, out[s])
				}
			case containsString(driven, s):
				if drive < 0 || len(top) < 2 || top[0] != "SCAN m" || top[1] != "SEARCH d USING INDEX sqlite_autoindex_docs_1 (ns=? AND resource=?)" {
					t.Errorf("%s: not driven by a filter (%d):\n%s", s, drive, out[s])
				}
				if !strings.Contains(out[s], "USING INDEX "+fs[max(drive, 0)].idx+" (") {
					t.Errorf("%s: the driver does not read %s:\n%s", s, fs[max(drive, 0)].idx, out[s])
				}
			default:
				if drive >= 0 || len(top) == 0 || !docScan.MatchString(top[0]) {
					t.Errorf("%s: not a scan (%d):\n%s", s, drive, out[s])
				}
			}
			for _, l := range plan {
				if docScan.MatchString(strings.TrimPrefix(l, "top: ")) && drive >= 0 {
					t.Errorf("%s: scans docs:\n%s", s, out[s])
				}
			}
		}
		// counts looks a few resources up by primary key.
		out["counts"] = strings.Join(explainPlan(t, ix.db, `SELECT f.resource, f.raw FROM json_each(?) j CROSS JOIN facet f INDEXED BY sqlite_autoindex_facet_1 WHERE f.ns = ? AND f.resource = j.value AND f.path = ?`, `["x"]`, benchNS, "/status"), "\n")
		if !strings.Contains(out["counts"], "SEARCH f USING INDEX sqlite_autoindex_facet_1 (ns=? AND resource=? AND path=?)") {
			t.Errorf("counts lookup:\n%s", out["counts"])
		}
		return out
	}
	before := plans()
	// Statistics where the average namespace has a document or two.
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3000 {
		ns := fmt.Sprintf("tiny%d", i)
		if _, err := tx.Exec(`INSERT INTO docs (ns, resource, head, schema) VALUES (?, 'r', 'h', 's')`, ns); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO facet (ns, resource, schema, path, value, raw) VALUES (?, 'r', 's', '/accountId', 'acct-12', '"acct-12"')`, ns); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := ix.db.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	after := plans()
	for s, p := range before {
		// (The scans are v0.15.2's plans, and SQLite may then read the
		// whole table instead of the namespace's index range.)
		if !containsString(scanned, s) && after[s] != p {
			t.Errorf("%s: the plan changed with ANALYZE:\n%s\n---\n%s", s, p, after[s])
		}
	}
}

// --- helpers -------------------------------------------------------------------

// openTestIndex opens an index database in a temporary directory, without a
// core, keeping untyped documents.
func openTestIndex(t *testing.T, noFTS bool) *Index {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "i.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ix := &Index{opt: Options{Logf: t.Logf, NoFTS: noFTS, UntypedListing: true}, db: db, cps: follow.SQLCheckpoints{DB: db}, sealed: derived.NewCache(0, db)}
	if err := ix.initSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ix.fts == noFTS {
		t.Fatalf("fts = %v", ix.fts)
	}
	return ix
}

var (
	revA, revB  = "1" + strings.Repeat("a", 32), "1" + strings.Repeat("b", 32)
	facetPool   = []any{"x", "y", "z", "1", 1.0, 2.5, true, nil, "Ärlig"}
	textPool    = []string{"alpha", "beta", "gamma", "alphabet", "Ärlig", "delta"}
	schemaPool  = []string{"/r/schemas/m/rev/" + revA, "/r/schemas/m/rev/" + revB, "/r/schemas/mm/rev/" + revA, "/r/schemas/n/rev/" + revA}
	refTargets  = [][2]string{{"t", "one"}, {"t", "two"}, {"a", "r001"}}
	sortStrings = []string{"apple", "banana", "Banana", "2026-10-04T18:00:00Z", "2026-10-04T20:00:00+02:00", ""}
)

// randomIndex writes random documents to namespaces a, b and c through
// the index's write path, with updates and removals: facets (multi-valued,
// a string and a number with one facet value), sort values of mixed types
// (some missing), text, references, schemas sharing prefixes, untyped
// documents.
func randomIndex(t *testing.T, r *rand.Rand, noFTS bool) *Index {
	t.Helper()
	ix := openTestIndex(t, noFTS)
	ctx := context.Background()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	n := r.IntN(400)
	for i := range n {
		ns := []string{"a", "a", "a", "b", "c"}[r.IntN(5)]
		p := prepared{resource: fmt.Sprintf("r%03d", r.IntN(300)), head: fmt.Sprintf("h%d", i)}
		switch x := r.IntN(20); {
		case x == 0:
			p.remove = true
		case x == 1:
		default:
			p.typed, p.schema, p.rows = true, schemaPool[r.IntN(len(schemaPool))], &docRows{}
			// /a: few values, often present; /b: few; /c: many.
			for k, path := range []string{"/a", "/b", "/c"} {
				k = []int{3, 6, len(facetPool)}[k]
				if r.IntN(10) < 7 {
					for range 1 + r.IntN(3) {
						fv, raw := facetValue(facetPool[r.IntN(k)])
						if path == "/c" && r.IntN(2) == 0 {
							fv, raw = facetValue(fmt.Sprintf("c%d", r.IntN(40)))
						}
						p.rows.facet = append(p.rows.facet, facetRow{path, fv, raw})
					}
				}
			}
			if r.IntN(10) < 8 {
				f := float64(r.IntN(10)) / 2
				p.rows.sort = append(p.rows.sort, sortRow{"/s", f, string(jsonv.Canonical(f))})
			}
			for _, path := range []string{"/t", "/u"} {
				if r.IntN(10) < 6 {
					var v any = sortStrings[r.IntN(len(sortStrings))]
					if path == "/u" && r.IntN(2) == 0 {
						v = float64(r.IntN(5))
					}
					sv, _ := sortValue(v)
					p.rows.sort = append(p.rows.sort, sortRow{path, sv, string(jsonv.Canonical(v))})
				}
			}
			for k := range r.IntN(3) {
				var words []string
				for range 1 + r.IntN(3) {
					words = append(words, textPool[r.IntN(len(textPool))])
				}
				p.rows.text = append(p.rows.text, textRow{[]string{"/title", "/body"}[k%2], strings.Join(words, " ")})
			}
			for k := range r.IntN(3) {
				tg := refTargets[r.IntN(len(refTargets))]
				ref := refRow{path: fmt.Sprintf("/refs/%d", k), targetNS: tg[0], target: tg[1]}
				switch r.IntN(4) {
				case 0:
					ref.rev = revA
				case 1:
					ref.entry = "e1"
				}
				ref.ref = "/r/" + tg[0] + "/" + tg[1]
				p.rows.refs = append(p.rows.refs, ref)
			}
		}
		if err := ix.write(ctx, tx, ns, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ix
}

// randomQuery combines random filters, sorts, text, counts, fields and
// paging.
func randomQuery(r *rand.Rand) url.Values {
	v := url.Values{}
	values := []string{"x", "y", "z", "1", "2.5", "true", "null", "Ärlig", "c3", "c7", "nope"}
	for _, p := range []string{"/a", "/b", "/c", "/zz"} {
		if r.IntN(10) < 3 {
			for range 1 + r.IntN(3) {
				if p == "/a" && r.IntN(4) > 0 {
					v.Add("facet["+p+"]", values[r.IntN(3)]) // one of /a's values: unselective
				} else {
					v.Add("facet["+p+"]", values[r.IntN(len(values))])
				}
			}
		}
	}
	ranges := [][2]string{{"ge[/s]", "3"}, {"lt[/s]", "2.5"}, {"gt[/t]", "b"}, {"le[/t]", "2026-10-04T18:00:00Z"}, {"ge[/u]", "2"}, {"lt[/u]", "c"}, {"gt[/zz]", "1"}}
	for range r.IntN(3) {
		x := ranges[r.IntN(len(ranges))]
		v.Add(x[0], x[1])
	}
	for range r.IntN(3) {
		s := []string{"/s", "/t", "/u", "/a"}[r.IntN(4)]
		if r.IntN(2) == 0 {
			s = "-" + s
		}
		v.Add("sort", s)
	}
	if r.IntN(5) == 0 {
		v.Set("q", []string{"alpha", "alph*", "beta gamma", "ärlig", "nothing"}[r.IntN(5)])
	}
	if r.IntN(5) == 0 {
		v.Set("schema", []string{"/r/schemas/m", "/r/schemas/m/", "/r/schemas/mm", schemaPool[0]}[r.IntN(4)])
	}
	if r.IntN(4) == 0 {
		v.Set("ref", []string{"/r/t/one", "/r/t/two", "/r/t/one/rev/" + revA, "/r/t/two#e1", "/r/a/r001", "/r/t/none"}[r.IntN(6)])
	}
	for range r.IntN(3) {
		v.Add("counts", []string{"/a", "/b", "/c", "/zz"}[r.IntN(4)])
	}
	if r.IntN(10) == 0 {
		v.Set("fields", "/title")
	}
	v.Set("limit", fmt.Sprint([]int{1, 2, 5, 20, 100}[r.IntN(5)]))
	if r.IntN(3) == 0 {
		v.Set("after", fmt.Sprint(r.IntN(60)))
	}
	return v
}

// candidates runs a candidate query and returns its rows.
func candidates(t *testing.T, tx *sql.Tx, stmt string, args []any) [][]any {
	t.Helper()
	rows, err := tx.Query(stmt, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stmt)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out [][]any
	for rows.Next() {
		row := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range row {
			ptrs[i] = &row[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// explainPlan returns the lines of a statement's query plan.
func explainPlan(t *testing.T, db *sql.DB, stmt string, args ...any) []string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+stmt, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stmt)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if parent == 0 {
			detail = "top: " + detail
		}
		out = append(out, detail)
	}
	return out
}

// topLevel returns the plan's top-level loops, outermost first.
func topLevel(plan []string) []string {
	var out []string
	for _, l := range plan {
		if s, ok := strings.CutPrefix(l, "top: "); ok && (strings.HasPrefix(s, "SCAN ") || strings.HasPrefix(s, "SEARCH ")) {
			out = append(out, s)
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- the query path of v0.15.2 ------------------------------------------------

// oldCandidateSQL is candidateSQL of v0.15.2: every query scans the
// namespace's documents and tests each filter on them.
func oldCandidateSQL(fts bool, ns string, q *Query) (string, []any) {
	var sb strings.Builder
	var args []any
	sb.WriteString(`SELECT d.docid, d.resource, d.head, COALESCE(d.schema, ''), `)
	if len(q.words) > 0 {
		sb.WriteString(`t.score`)
	} else {
		sb.WriteString(`0.0`)
	}
	sb.WriteString(` FROM docs d`)
	if len(q.words) > 0 {
		sb.WriteString(` JOIN (SELECT docid, sum(s) AS score FROM (`)
		for i, w := range q.words {
			if i > 0 {
				sb.WriteString(` UNION ALL `)
			}
			if fts {
				fmt.Fprintf(&sb, `SELECT rowid >> %d AS docid, %d AS k, -rank AS s FROM "text" WHERE "text" MATCH ?`, textShift, i)
				args = append(args, ftsPhrase(w))
			} else {
				fmt.Fprintf(&sb, `SELECT docid, %d AS k, 1.0 AS s FROM "text" WHERE body LIKE ? ESCAPE '\'`, i)
				args = append(args, likePattern(w))
			}
		}
		fmt.Fprintf(&sb, `) GROUP BY docid HAVING count(DISTINCT k) = %d) t ON t.docid = d.docid`, len(q.words))
	}
	for i, s := range q.Sorts {
		fmt.Fprintf(&sb, ` LEFT JOIN "sort" s%d ON s%d.ns = d.ns AND s%d.resource = d.resource AND s%d.path = ?`, i, i, i, i)
		args = append(args, s.path)
	}
	sb.WriteString(` WHERE d.ns = ?`)
	args = append(args, ns)
	if q.Schema != "" {
		pre := strings.TrimRight(q.Schema, "/") + "/"
		sb.WriteString(` AND (d.schema = ? OR substr(d.schema, 1, ?) = ?)`)
		args = append(args, q.Schema, len(pre), pre)
	}
	if rf := q.Ref; rf != nil {
		cond, a := refCond(rf)
		sb.WriteString(` AND EXISTS (SELECT 1 FROM refs x WHERE x.ns = d.ns AND x.resource = d.resource AND ` + cond + `)`)
		args = append(args, a...)
	}
	paths := make([]string, 0, len(q.Facets))
	for p := range q.Facets {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		vals := q.Facets[p]
		sb.WriteString(` AND EXISTS (SELECT 1 FROM facet f WHERE f.ns = d.ns AND f.resource = d.resource AND f.path = ? AND f.value IN (`)
		args = append(args, p)
		for i, v := range vals {
			if i > 0 {
				sb.WriteString(`, `)
			}
			sb.WriteString(`?`)
			args = append(args, v)
		}
		sb.WriteString(`))`)
	}
	for _, r := range q.Ranges {
		sb.WriteString(` AND EXISTS (SELECT 1 FROM "sort" r WHERE r.ns = d.ns AND r.resource = d.resource AND r.path = ? AND `)
		args = append(args, r.path)
		if r.num {
			fmt.Fprintf(&sb, `typeof(r.value) IN ('integer', 'real') AND r.value %s ?)`, r.op)
			args = append(args, r.f)
		} else {
			fmt.Fprintf(&sb, `typeof(r.value) = 'text' AND r.value %s ?)`, r.op)
			args = append(args, r.s)
		}
	}
	sb.WriteString(` ORDER BY `)
	for i, s := range q.Sorts {
		dir := "ASC"
		if s.desc {
			dir = "DESC"
		}
		fmt.Fprintf(&sb, `s%d.value IS NULL, s%d.value %s, `, i, i, dir)
	}
	if len(q.words) > 0 {
		sb.WriteString(`t.score DESC, `)
	}
	sb.WriteString(`d.resource`)
	return sb.String(), args
}

// oldRun is run of v0.15.2, less its check of fields, which reads the
// schemas now (checkFields, in query).
func (ix *Index) oldRun(ctx context.Context, tx *sql.Tx, ns string, q *Query, allow func(resource string) bool) (*Result, error) {
	stmt, args := oldCandidateSQL(ix.fts, ns, q)
	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	var all []string // allowed resources, when counting
	n := 0
	for rows.Next() {
		var h Hit
		if err := rows.Scan(&h.docid, &h.Resource, &h.ID, &h.Schema, &h.Score); err != nil {
			rows.Close()
			return nil, err
		}
		if allow != nil && !allow(h.Resource) {
			continue
		}
		if len(q.Counts) > 0 {
			all = append(all, h.Resource)
		}
		n++
		switch {
		case n <= q.After:
		case len(res.Hits) < q.Limit:
			res.Hits = append(res.Hits, h)
		default:
			res.More = true
		}
		if res.More && len(q.Counts) == 0 {
			break
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ix.attachFacets(ctx, tx, ns, res.Hits); err != nil {
		return nil, err
	}
	if err := ix.attachSorts(ctx, tx, ns, res.Hits); err != nil {
		return nil, err
	}
	if err := ix.attachText(ctx, tx, q.Fields, res.Hits); err != nil {
		return nil, err
	}
	if err := ix.attachRefs(ctx, tx, ns, q.Ref, res.Hits); err != nil {
		return nil, err
	}
	if len(q.Counts) > 0 {
		if res.Counts, err = oldCounts(ctx, tx, ns, q.Counts, all); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// oldCounts is counts of v0.15.2: it reads every row of each path.
func oldCounts(ctx context.Context, tx *sql.Tx, ns string, paths, resources []string) (map[string][]FacetCount, error) {
	in := make(map[string]bool, len(resources))
	for _, r := range resources {
		in[r] = true
	}
	out := map[string][]FacetCount{}
	for _, p := range paths {
		rows, err := tx.QueryContext(ctx, `SELECT resource, raw FROM facet WHERE ns = ? AND path = ?`, ns, p)
		if err != nil {
			return nil, err
		}
		c := map[string]int{}
		for rows.Next() {
			var r, raw string
			if err := rows.Scan(&r, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			if in[r] {
				c[raw]++
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		list := []FacetCount{}
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if c[keys[i]] != c[keys[j]] {
				return c[keys[i]] > c[keys[j]]
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			v, _ := jsonv.Parse([]byte(k))
			list = append(list, FacetCount{Value: v, Count: c[k]})
		}
		out[p] = list
	}
	return out, nil
}
