package core

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A write's check outside the lock (checkOutside, D.3) and a revision read
// (resourceRev) not served from the read cache, which are most of a busy
// core's CPU besides the group commits (docs/CAPACITY.md):
//
//	PATCHLOG_TEST_PG=postgres://… go test ./internal/core -run '^$' -bench 'Check|RevUncached' -benchmem

func checkBenchEngine(b *testing.B) (*Engine, string, string) {
	b.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	// No read cache: every revision read reads the database.
	e, err := Open(Options{Path: pgtest.DB(b), BlobDir: b.TempDir(), AuthDisabled: true, RetentionInterval: -1, Limits: lim,
		LocalRateBuckets: true, ReadCacheBytes: 1})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { e.Close() })
	genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
		b.Fatal(err)
	}
	head, err := benchWrite(e, "r", "", 0)
	if err != nil {
		b.Fatal(err)
	}
	var older string
	for i := 1; i < 10; i++ {
		if i == 5 {
			older = head
		}
		if head, err = benchWrite(e, "r", head, i); err != nil {
			b.Fatal(err)
		}
	}
	return e, older, head
}

// BenchmarkCheckAppend checks an append to a resource's head, as every
// write of a busy namespace's group is checked, without writing it.
func BenchmarkCheckAppend(b *testing.B) {
	e, _, head := checkBenchEngine(b)
	ctx := context.Background()
	req := Request{NS: "b", Cred: Credentials{Author: "a"}}
	it := Item{Resource: "r", IfMatch: head, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 100.0}}}}}
	for i := 0; i < 100; i++ { // past the first reads of a namespace
		e.checkOutside(ctx, req, []Item{it}, nil, false, false)
	}
	b.ReportAllocs()
	b.ResetTimer()
	cpu := processCPU()
	for i := 0; i < b.N; i++ {
		plan, _, _, err := e.checkOutside(ctx, req, []Item{it}, nil, false, false)
		if err != nil || plan == nil {
			b.Fatal(err)
		}
	}
	reportCPU(b, cpu)
}

// reportCPU reports the CPU time this process used per operation since
// cpu (processCPU): the core's own, without the database's, which
// ns/op includes in its waiting.
func reportCPU(b *testing.B, cpu time.Duration) {
	if used := processCPU() - cpu; cpu > 0 {
		b.ReportMetric(float64(used.Nanoseconds())/float64(b.N), "cpu-ns/op")
	}
}

// BenchmarkRevUncached reads a resource's head revision and one written
// a little before it, as followers read each change's.
func BenchmarkRevUncached(b *testing.B) {
	e, older, head := checkBenchEngine(b)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		e.ResourceRev(ctx, "b", "r", head, Credentials{})
	}
	b.ReportAllocs()
	b.ResetTimer()
	cpu := processCPU()
	defer reportCPU(b, cpu)
	for i := 0; i < b.N; i++ {
		id := head
		if i%2 == 1 {
			id = older
		}
		r, err := e.ResourceRev(ctx, "b", "r", id, Credentials{})
		if err != nil || r.Status != 200 {
			b.Fatal(r, err)
		}
	}
}
