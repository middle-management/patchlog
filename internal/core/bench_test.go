package core

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Small writes and reads, for comparing the storage dialects:
//
//	go test ./internal/core -run '^$' -bench .
//	PATCHLOG_TEST_PG=postgres://… go test ./internal/core -run '^$' -bench .

func benchEngine(b *testing.B, read string) *Engine {
	b.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(b), BlobDir: b.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Limits: lim})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { e.Close() })
	genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": read}}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
		b.Fatal(err)
	}
	return e
}

func benchWrite(e *Engine, name, ifMatch string, i int) (string, error) {
	it := Item{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == ""}
	op := "replace"
	if ifMatch == "" {
		op = "add"
	}
	it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(i)}}}}}
	r, err := e.WriteResource(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, it)
	if err != nil {
		return "", err
	}
	return r.Items[0].IDs[0], nil
}

// BenchmarkWrite appends to one resource, one write at a time.
func BenchmarkWrite(b *testing.B) {
	e := benchEngine(b, "public")
	head, err := benchWrite(e, "r", "", 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if head, err = benchWrite(e, "r", head, i+1); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteParallel appends from several goroutines, each to a
// resource of its own namespace: serialised in SQLite, in parallel on
// Postgres (one lock per namespace).
func BenchmarkWriteParallel(b *testing.B) {
	e := benchEngine(b, "public")
	var next atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ns := fmt.Sprint("p", next.Add(1))
		genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}
		if _, err := e.WriteConfig(context.Background(), Request{NS: ns, Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
			b.Error(err)
			return
		}
		head, i := "", 0
		for pb.Next() {
			it := Item{Resource: "r", IfMatch: head, IfNoneMatch: head == ""}
			op := "replace"
			if head == "" {
				op = "add"
			}
			it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(i)}}}}}
			r, err := e.WriteResource(context.Background(), Request{NS: ns, Cred: Credentials{Author: "a"}}, it)
			if err != nil {
				b.Error(err)
				return
			}
			head = r.Items[0].IDs[0]
			i++
		}
	})
}

// BenchmarkReadHead resolves a head pointer in a namespace that isn't
// public, so every read opens a transaction (no transaction-free cache).
func BenchmarkReadHead(b *testing.B) {
	e := benchEngine(b, "grant")
	for i := 0; i < 10; i++ {
		if _, err := benchWrite(e, fmt.Sprint("r", i), "", i); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := e.ResourceHead(context.Background(), "b", fmt.Sprint("r", i%10), Credentials{Author: "a"}); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
}

// BenchmarkNamespaceLogPage reads a 600-entry page of a namespace log from
// a since, so every entry has a prev.
func BenchmarkNamespaceLogPage(b *testing.B) {
	e := benchEngine(b, "public")
	head := ""
	for i := 0; i < 601; i++ {
		var err error
		if head, err = benchWrite(e, "r", head, i); err != nil {
			b.Fatal(err)
		}
	}
	ctx := context.Background()
	first, err := e.NamespaceLog(ctx, "b", "", "", 1, Credentials{})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lg, err := e.NamespaceLog(ctx, "b", "", first.Last, 600, Credentials{})
		if err != nil || len(lg.Entries) != 600 {
			b.Fatal(err)
		}
	}
}

// Concurrent creates into one namespace, shaped like a content import:
// documents of 20–70 KiB (about 25 bytes a leaf), each to a resource of
// its own. Every sub-benchmark writes b.N documents with that many
// writers and reports writes/s and the 99th percentile latency:
//
//	go test ./internal/core -run '^$' -bench CreatesOneNamespace -benchtime 2000x
//
// SQLite runs on a file (one writer at a time, WAL); Postgres on a fresh
// database (PATCHLOG_TEST_PG).
func BenchmarkCreatesOneNamespace(b *testing.B) {
	e := benchFileEngine(b)
	var names atomic.Int64
	docs := make([]any, 16)
	for i := range docs {
		docs[i] = benchDoc(i, 20<<10+(i*7919)%(50<<10))
	}
	for _, writers := range []int{1, 8, 32, 64} {
		b.Run(fmt.Sprintf("writers=%d", writers), func(b *testing.B) {
			lat := make([]time.Duration, b.N)
			var next atomic.Int64
			var wg sync.WaitGroup
			b.ResetTimer()
			start := time.Now()
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						i := int(next.Add(1)) - 1
						if i >= b.N {
							return
						}
						it := Item{Resource: fmt.Sprint("c", names.Add(1)), IfNoneMatch: true,
							Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": docs[i%len(docs)]}}}}}
						t0 := time.Now()
						if _, err := e.WriteResource(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, it); err != nil {
							b.Error(err)
							return
						}
						lat[i] = time.Since(t0)
					}
				}()
			}
			wg.Wait()
			el := time.Since(start)
			b.StopTimer()
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			b.ReportMetric(float64(b.N)/el.Seconds(), "writes/s")
			b.ReportMetric(float64(lat[len(lat)*99/100].Microseconds())/1000, "p99-ms")
		})
	}
}

// Small appends from concurrent writers into one namespace, each writer to
// a resource of its own, so they contend only on the namespace's log (D.8
// "Contention"). Every sub-benchmark writes b.N revisions with that many
// writers and reports writes/s and the 99th percentile latency:
//
//	PATCHLOG_TEST_PG=postgres://… go test ./internal/core -run '^$' -bench AppendsOneNamespace -benchtime 3000x
func BenchmarkAppendsOneNamespace(b *testing.B) {
	e := benchFileEngine(b)
	var runs atomic.Int64
	for _, writers := range []int{1, 2, 4, 8, 16, 32} {
		b.Run(fmt.Sprintf("writers=%d", writers), func(b *testing.B) {
			// Resources of their own for every run (b.Run runs more than once).
			run := runs.Add(1)
			heads := make([]string, writers)
			for w := range heads {
				h, err := benchWrite(e, fmt.Sprintf("w%d_%d", run, w), "", 0)
				if err != nil {
					b.Fatal(err)
				}
				heads[w] = h
			}
			lat := make([]time.Duration, b.N)
			var next atomic.Int64
			var wg sync.WaitGroup
			groups, grouped := e.groups.committed.Load(), e.groups.appended.Load()
			b.ResetTimer()
			start := time.Now()
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						i := int(next.Add(1)) - 1
						if i >= b.N {
							return
						}
						t0 := time.Now()
						h, err := benchWrite(e, fmt.Sprintf("w%d_%d", run, w), heads[w], i+1)
						if err != nil {
							b.Error(err)
							return
						}
						heads[w] = h
						lat[i] = time.Since(t0)
					}
				}()
			}
			wg.Wait()
			el := time.Since(start)
			b.StopTimer()
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			b.ReportMetric(float64(b.N)/el.Seconds(), "writes/s")
			b.ReportMetric(float64(lat[len(lat)*99/100].Microseconds())/1000, "p99-ms")
			// Group commit (Postgres): the share of writes appended in
			// groups, and their average size.
			if n := e.groups.committed.Load() - groups; n > 0 {
				g := e.groups.appended.Load() - grouped
				b.ReportMetric(float64(g)/float64(b.N), "grouped/op")
				b.ReportMetric(float64(g)/float64(n), "writes/group")
			}
		})
	}
}

// BenchmarkBatch1000 creates 1,000 resources of about 2 KiB in one batch.
func BenchmarkBatch1000(b *testing.B) {
	e := benchFileEngine(b)
	items := make([]Item, 1000)
	for i := 0; i < b.N; i++ {
		for j := range items {
			items[j] = Item{Resource: fmt.Sprintf("b%d_%d", i, j), IfNoneMatch: true,
				Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": benchDoc(j, 2<<10)}}}}}
		}
		if _, err := e.Batch(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, items, nil, nil, false); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Milliseconds())/float64(b.N), "ms/batch")
}

// benchFileEngine is benchEngine on a SQLite file rather than :memory:,
// which has a single connection.
func benchFileEngine(b *testing.B) *Engine {
	b.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	path := filepath.Join(b.TempDir(), "bench.db")
	if pgtest.Enabled() {
		path = pgtest.NewDB(b)
	}
	e, err := Open(Options{Path: path, BlobDir: b.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Limits: lim, Purger: discardPurger{}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { e.Close() })
	genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
		b.Fatal(err)
	}
	return e
}

// benchDoc is a document of about size bytes as JSON: sections of a dozen
// short leaves each, varied by seed.
func benchDoc(seed, size int) map[string]any {
	var secs []any
	n := 40
	for k := 0; n < size; k++ {
		secs = append(secs, map[string]any{
			"id":      fmt.Sprintf("s%d-%d", seed, k),
			"heading": fmt.Sprintf("Section %d of document %d", k, seed),
			"order":   float64(k),
			"visible": k%3 != 0,
			"tags":    []any{"alpha", fmt.Sprint("t", k%7), fmt.Sprint("u", seed%5)},
			"meta":    map[string]any{"author": fmt.Sprint("w", k%11), "words": float64(100 + k*seed%900), "lang": "en"},
			"body":    fmt.Sprintf("Paragraph %d: lorem ipsum dolor sit amet %d", k, seed*k),
		})
		n += 300
	}
	return map[string]any{"title": fmt.Sprint("Document ", seed), "sections": secs}
}

// BenchmarkNamespaceHeads reads a 1000-item page of GET
// /ns/{ns}/rev/{ns_id}/heads: of a namespace of 1,000 resources, and of a
// branch of it with 100 resources of its own, which reads the rest
// through.
func BenchmarkNamespaceHeads(b *testing.B) {
	e := benchFileEngine(b)
	ctx := context.Background()
	create := func(ns string, n, step, from int) string {
		items := make([]Item, n)
		for i := range items {
			items[i] = Item{Resource: fmt.Sprintf("r%05d", from+i*step), IfNoneMatch: true,
				Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": float64(i)}}}}}}
		}
		res, err := e.Batch(ctx, Request{NS: ns, Cred: Credentials{Author: "a"}}, items, nil, nil, false)
		if err != nil {
			b.Fatal(err)
		}
		return res.NSID
	}
	base := create("b", 1000, 2, 0)
	if _, err := e.CreateBranch(ctx, Request{NS: "b", Cred: Credentials{Author: "a"}}, BranchRequest{Name: "c", IfNoneMatch: true}); err != nil {
		b.Fatal(err)
	}
	branch := create("c", 100, 20, 1)
	for _, c := range []struct{ ns, id string }{{"b", base}, {"c", branch}} {
		b.Run("ns="+c.ns, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p, err := e.NamespaceHeads(ctx, c.ns, c.id, "", Credentials{Author: "a"})
				if err != nil {
					b.Fatal(err)
				}
				if len(p.Items) != 1000 {
					b.Fatalf("%d items, want 1000", len(p.Items))
				}
			}
			b.ReportMetric(float64(b.Elapsed().Microseconds())/1000/float64(b.N), "ms/page")
		})
	}
}
