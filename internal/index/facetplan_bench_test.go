package index

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// The benchmark dataset of issue B6: one namespace of 48.7k items shaped
// like the Demo Play seed. Each item has an /accountId (facet and sort,
// about 100 items per account), a few other facets of low and high
// cardinality (/status, /kind ≈ every item, /region ≈ 1/30, multi-valued
// /tags, unique /id), sort values (/createdAt, /score), a text /title and
// a reference to its account.
const (
	benchNS   = "items"
	benchDocs = 48700
)

var benchStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// benchShapes are the measured queries.
var benchShapes = []struct{ name, query string }{
	{"facet", "facet[/accountId]=acct-123&limit=100"},
	{"facet+sort", "facet[/accountId]=acct-123&sort=/accountId&limit=100"},
	{"facet+facet", "facet[/accountId]=acct-123&facet[/status]=open&limit=100"},
	{"facet+schema", "facet[/accountId]=acct-123&schema=/r/schemas/item&limit=100"},
	{"facet+text", "facet[/accountId]=acct-123&q=alpha&limit=100"},
	{"range", "ge[/createdAt]=2026-12-29T00:00:00Z&limit=100"},
	{"facet+counts", "facet[/accountId]=acct-123&counts=/status&counts=/tags&limit=100"},
	{"ref", "ref=/r/accounts/acct-123&limit=100"},
	{"listing", "limit=100"},
	{"all", "facet[/kind]=item&limit=100"},
	{"all+sort", "facet[/kind]=item&sort=-/createdAt&limit=100"},
	{"all+counts", "facet[/kind]=item&counts=/status&limit=100"},
	{"listing+counts", "counts=/status&limit=100"},
	{"region", "facet[/region]=region-07&limit=100"},
	{"region+sort", "facet[/region]=region-07&sort=-/createdAt&limit=100"},
}

// benchDB returns the path of the dataset's database: $PATCHLOG_BENCH_DB,
// built there if missing and kept, or a fresh one in a temporary directory.
func benchDB(tb testing.TB) string {
	path := os.Getenv("PATCHLOG_BENCH_DB")
	if path == "" {
		path = filepath.Join(tb.TempDir(), "bench.db")
	} else if _, err := os.Stat(path); err == nil {
		return path
	}
	ix := openBare(tb, path)
	fillBench(tb, ix, benchDocs)
	return path
}

// openBare opens an index database as Open does, without a core.
func openBare(tb testing.TB, path string) *Index {
	tb.Helper()
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { db.Close() })
	ix := &Index{opt: Options{Logf: tb.Logf}, db: db, cps: follow.SQLCheckpoints{DB: db}, sealed: derived.NewCache(0, db)}
	if err := ix.initSchema(context.Background()); err != nil {
		tb.Fatal(err)
	}
	return ix
}

// fillBench writes n items through the index's own write path, in one
// transaction.
func fillBench(tb testing.TB, ix *Index, n int) {
	tb.Helper()
	ctx := context.Background()
	r := rand.New(rand.NewPCG(1, 2))
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatal(err)
	}
	defer tx.Rollback()
	str := func(s string) string { return string(jsonv.Canonical(s)) }
	for i := range n {
		p := prepared{resource: fmt.Sprintf("%016x", r.Uint64()), head: fmt.Sprintf("h%d", i), typed: true, rows: &docRows{}}
		switch x := r.IntN(100); {
		case x < 95:
			p.schema = "/r/schemas/item/rev/A"
		case x < 99:
			p.schema = "/r/schemas/item/rev/B"
		default:
			p.schema = "/r/schemas/note/rev/C"
		}
		acct := fmt.Sprintf("acct-%03d", r.IntN(n/100+1))
		status := "open"
		switch x := r.IntN(100); {
		case x < 30:
			status = "closed"
		case x < 38:
			status = "draft"
		case x < 40:
			status = "archived"
		}
		kind := "item"
		if r.IntN(100) == 0 {
			kind = "special"
		}
		facets := map[string][]any{
			"/accountId": {acct}, "/status": {status}, "/kind": {kind},
			"/region": {fmt.Sprintf("region-%02d", r.IntN(30))}, "/id": {fmt.Sprintf("id-%d", i)},
		}
		seen := map[int]bool{}
		for range r.IntN(4) {
			if t := r.IntN(20); !seen[t] {
				seen[t] = true
				facets["/tags"] = append(facets["/tags"], fmt.Sprintf("tag-%02d", t))
			}
		}
		for path, vs := range facets {
			for _, v := range vs {
				fv, raw := facetValue(v)
				p.rows.facet = append(p.rows.facet, facetRow{path, fv, raw})
			}
		}
		created := benchStart.Add(time.Duration(r.Int64N(int64(365 * 24 * time.Hour)))).Format(time.RFC3339)
		ct, _ := normTime(created)
		score := float64(r.IntN(100000)) / 100
		p.rows.sort = append(p.rows.sort,
			sortRow{"/accountId", acct, str(acct)},
			sortRow{"/createdAt", ct, str(created)},
			sortRow{"/score", score, string(jsonv.Canonical(score))})
		title := ""
		for k := range 4 {
			if k > 0 {
				title += " "
			}
			title += fmt.Sprintf("w%04d", r.IntN(2000))
		}
		if r.IntN(10) < 3 {
			title += " alpha"
		}
		p.rows.text = append(p.rows.text, textRow{"/title", title})
		p.rows.refs = append(p.rows.refs, refRow{path: "/account", ref: "/r/accounts/" + acct, targetNS: "accounts", target: acct})
		if err := ix.write(ctx, tx, benchNS, p); err != nil {
			tb.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
}

// benchRun runs one query as the HTTP handler does: parsed, in its own
// read transaction.
func benchRun(tb testing.TB, ix *Index, query string) *Result {
	v, err := url.ParseQuery(query)
	if err != nil {
		tb.Fatal(err)
	}
	q, err := ParseQuery(v)
	if err != nil {
		tb.Fatal(err)
	}
	ctx := context.Background()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatal(err)
	}
	defer tx.Rollback()
	res, err := ix.run(ctx, tx, benchNS, q, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return res
}

// at50 runs fn 50 times at once and waits for all of them.
func at50(fn func()) {
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(fn)
	}
	wg.Wait()
}

// BenchmarkFacetPlan measures each shape alone and 50 at once (ns/op is the
// time for all 50).
func BenchmarkFacetPlan(b *testing.B) {
	ix := openBare(b, benchDB(b))
	for _, s := range benchShapes {
		b.Run(s.name+"/single", func(b *testing.B) {
			b.ReportMetric(float64(len(benchRun(b, ix, s.query).Hits)), "hits")
			for b.Loop() {
				benchRun(b, ix, s.query)
			}
		})
		b.Run(s.name+"/x50", func(b *testing.B) {
			for b.Loop() {
				at50(func() { benchRun(b, ix, s.query) })
			}
		})
	}
}

// BenchmarkFacetPlanHTTP measures the shapes end to end, through the
// query handler of an index on the dataset.
func BenchmarkFacetPlanHTTP(b *testing.B) {
	path := benchDB(b)
	ctx := context.Background()
	core := clienttest.New(b, clienttest.Options{})
	c := core.Client(b, client.WithAuthor("admin"))
	if _, err := c.CreateNamespace(ctx, benchNS, map[string]any{"read": "public"}); err != nil {
		b.Fatal(err)
	}
	head, err := c.NSHead(ctx, benchNS)
	if err != nil {
		b.Fatal(err)
	}
	ix, err := Open(ctx, Options{Client: c, DB: path, Namespaces: []string{benchNS}, Logf: b.Logf})
	if err != nil {
		b.Fatal(err)
	}
	defer ix.Close()
	if err := ix.cps.Save(ctx, ix.db, ix.Origin(), benchNS, head.ID); err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(ix.Handler())
	defer srv.Close()
	hc := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	get := func(b *testing.B, query string) {
		v, _ := url.ParseQuery(query)
		r, err := hc.Get(srv.URL + "/" + benchNS + "/at/" + head.ID + "?" + v.Encode())
		if err != nil {
			b.Error(err)
			return
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			b.Errorf("%s: %d", query, r.StatusCode)
		}
	}
	for _, s := range benchShapes {
		b.Run(s.name+"/single", func(b *testing.B) {
			for b.Loop() {
				get(b, s.query)
			}
		})
		b.Run(s.name+"/x50", func(b *testing.B) {
			for b.Loop() {
				at50(func() { get(b, s.query) })
			}
		})
	}
}
