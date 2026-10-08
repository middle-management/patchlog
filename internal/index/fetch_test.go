package index_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
)

// revFetches counts GET /r/{ns}/…/rev/… requests of one namespace, per
// path and at most in flight; each takes at least delay.
type revFetches struct {
	prefix string
	delay  time.Duration
	rt     http.RoundTripper

	mu       sync.Mutex
	inFlight int
	max      int
	paths    map[string]int
}

func (f *revFetches) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.Path, f.prefix) || !strings.Contains(r.URL.Path, "/rev/") {
		return f.rt.RoundTrip(r)
	}
	f.mu.Lock()
	f.inFlight++
	f.max = max(f.max, f.inFlight)
	f.paths[r.URL.Path]++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	time.Sleep(f.delay)
	return f.rt.RoundTrip(r)
}

// dumpIndex returns every row the index holds, in a stable order.
func dumpIndex(t *testing.T, path string) string {
	t.Helper()
	db := must(sql.Open("sqlite", "file:"+path))
	defer db.Close()
	var b strings.Builder
	for _, q := range []string{
		`SELECT * FROM docs ORDER BY docid`,
		`SELECT rowid, ns, resource, schema, path, body FROM "text" ORDER BY rowid`,
		`SELECT * FROM facet ORDER BY ns, resource, path, value`,
		`SELECT * FROM "sort" ORDER BY ns, resource, path`,
		`SELECT * FROM refs ORDER BY ns, resource, path`,
		`SELECT * FROM seen ORDER BY ns, ns_id`,
		`SELECT ns, ns_id FROM checkpoints ORDER BY ns`,
	} {
		rows := must(db.Query(q))
		cols := must(rows.Columns())
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&b, vals...)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		b.WriteString("--\n")
	}
	return b.String()
}

// TestConcurrentFetch: a page's documents are fetched FetchConcurrency at
// a time, each latest head once (superseded revisions and removed
// resources not at all), and the index ends up exactly as when they are
// fetched one by one. A failing fetch fails the whole batch.
func TestConcurrentFetch(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	const n = 24
	for i := range n {
		w.doc(t, fmt.Sprintf("m%02d", i), w.match, map[string]any{
			"title": fmt.Sprintf("Match %d", i), "tags": []any{fmt.Sprint("t", i%3)}, "attendance": 1000 + i,
			"players": []any{map[string]any{"name": fmt.Sprint("Player ", i), "id": fmt.Sprint("p", i)}},
		})
	}
	// Superseded twice, and gone: neither revision of m01 is fetched, and
	// of m00 only the last.
	h := must(w.c.Head(ctx, "matches", "m00"))
	h2 := must(w.c.Append(ctx, "matches", "m00", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Match zero"}}))
	last := must(w.c.Append(ctx, "matches", "m00", h2.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Match nil"}}))
	must(w.c.Delete(ctx, "matches", "m01", must(w.c.Head(ctx, "matches", "m01")).ID))
	must(w.c.Batch(ctx, "matches", client.BatchRequest{Items: []client.BatchItem{
		{Resource: "a", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"$schema": w.match, "title": "alpha"}))}},
		{Resource: "b", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"$schema": w.match, "title": "beta"}))}},
	}}, false))

	origin := must(w.c.Origin(ctx))
	head := must(w.c.NSHead(ctx, "matches")).ID
	var units []follow.Unit
	for _, e := range must(w.c.NSLog(ctx, "matches", head, "")) {
		units = append(units, follow.Unit{Entry: e})
	}
	batch := &follow.Batch{Origin: origin, NS: "matches", Units: units, NewCheckpoint: head}

	run := func(conc int, fail *failing) (*revFetches, string) {
		t.Helper()
		rf := &revFetches{prefix: "/r/matches/", delay: 5 * time.Millisecond, rt: http.DefaultTransport, paths: map[string]int{}}
		var rt http.RoundTripper = rf
		if fail != nil {
			fail.rt, rt = rf, fail
		}
		db := filepath.Join(t.TempDir(), "i.db")
		s := startSvcWith(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true, noRun: true, hc: &http.Client{Transport: rt}},
			func(o *index.Options) { o.FetchConcurrency = conc })
		if fail != nil {
			fail.armed.Store(true)
			if err := s.ix.Apply(ctx, batch); err == nil {
				t.Fatalf("FetchConcurrency %d: Apply succeeded with a failing fetch", conc)
			}
			if s.ix.Checkpoint("matches") != "" {
				t.Fatalf("FetchConcurrency %d: checkpoint moved", conc)
			}
			if d := dumpIndex(t, db); d != strings.Repeat("--\n", 7) {
				t.Fatalf("FetchConcurrency %d: a failed Apply wrote:\n%s", conc, d)
			}
			fail.armed.Store(false)
		}
		start := time.Now()
		if err := s.ix.Apply(ctx, batch); err != nil {
			t.Fatal(err)
		}
		t.Logf("FetchConcurrency %d: %d fetches in %s", conc, len(rf.paths), time.Since(start))
		s.expect("/matches?q=nil", "m00")
		s.stop()
		return rf, dumpIndex(t, db)
	}

	seq, want := run(1, nil)
	if seq.max != 1 {
		t.Errorf("FetchConcurrency 1: %d fetches in flight", seq.max)
	}
	par, got := run(4, nil)
	if par.max < 2 || par.max > 4 {
		t.Errorf("FetchConcurrency 4: at most %d fetches in flight", par.max)
	}
	if got != want {
		t.Errorf("index differs from one fetched one by one:\n%s\nwant:\n%s", got, want)
	}
	// One fetch per live resource: n-1 seeded (m01 is gone) and a, b.
	for _, rf := range []*revFetches{seq, par} {
		if len(rf.paths) != n+1 {
			t.Errorf("fetched %d paths, want %d: %v", len(rf.paths), n+1, rf.paths)
		}
		for p, k := range rf.paths {
			if k != 1 || strings.HasPrefix(p, "/r/matches/m01/") || strings.HasPrefix(p, "/r/matches/m00/") && p != "/r/matches/m00/rev/"+last.ID {
				t.Errorf("fetched %s %d times", p, k)
			}
		}
	}

	_, failed := run(4, &failing{path: "/r/matches/m07/"})
	if failed != want {
		t.Errorf("index after a failed Apply differs:\n%s\nwant:\n%s", failed, want)
	}
}

// TestFetchConcurrencyShared: FetchConcurrency bounds the fetches of every
// followed namespace together: two namespaces applying pages at once have
// at most FetchConcurrency documents in flight between them.
func TestFetchConcurrencyShared(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	must(w.c.CreateNamespace(ctx, "cups", map[string]any{"read": "public"}))
	const n, limit = 12, 4
	origin := must(w.c.Origin(ctx))
	batches := map[string]*follow.Batch{}
	for _, ns := range []string{"matches", "cups"} {
		for i := range n {
			must(w.c.CreateDoc(ctx, ns, fmt.Sprintf("m%02d", i), map[string]any{"$schema": w.match, "title": fmt.Sprintf("Match %d", i)}))
		}
		head := must(w.c.NSHead(ctx, ns)).ID
		var units []follow.Unit
		for _, e := range must(w.c.NSLog(ctx, ns, head, "")) {
			units = append(units, follow.Unit{Entry: e})
		}
		batches[ns] = &follow.Batch{Origin: origin, NS: ns, Units: units, NewCheckpoint: head}
	}

	rf := &revFetches{prefix: "/r/", delay: 20 * time.Millisecond, rt: http.DefaultTransport, paths: map[string]int{}}
	s := startSvcWith(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "cups"}, noRun: true, hc: &http.Client{Transport: rf}},
		func(o *index.Options) { o.FetchConcurrency = limit })
	// Both at once, as their followers would.
	var wg sync.WaitGroup
	for _, b := range batches {
		wg.Go(func() {
			if err := s.ix.Apply(ctx, b); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if rf.max != limit {
		t.Errorf("at most %d fetches in flight across both namespaces, want %d", rf.max, limit)
	}
	for ns, b := range batches {
		if cp := s.ix.Checkpoint(ns); cp != b.NewCheckpoint {
			t.Errorf("%s: checkpoint %q, want %q", ns, cp, b.NewCheckpoint)
		}
	}
	s.expect("/cups?q=11", "m11")
}
