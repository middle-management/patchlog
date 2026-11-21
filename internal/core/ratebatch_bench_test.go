package core

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// BenchmarkDrawContended draws as writes do, from many goroutines at once,
// on a bucket pool of 16 connections (pool_max_conns=64, as on the EC2
// bench: docs/CAPACITY.md, "Several namespaces on one database"): each
// draw is a write's, on its principal's, its namespace's and a resource's
// bucket. With one principal every draw shares the principal's row; with
// a principal per namespace, draws in different namespaces share none.
//
// It reports draws a second, the draw statements run per draw (rate_draw
// and rate_draws together) and the draws per statement.
//
//	PATCHLOG_TEST_PG=... go test ./internal/core -run '^$' -bench DrawContended -benchtime 5s
func BenchmarkDrawContended(b *testing.B) {
	for _, principals := range []string{"one", "namespace"} {
		b.Run("principals="+principals, func(b *testing.B) {
			benchDraws(b, principals == "one")
		})
	}
}

func benchDraws(b *testing.B, onePrincipal bool) {
	if !pgtest.Enabled() {
		b.Skip("Postgres only")
	}
	const namespaces = 16
	url := strings.Replace(pgtest.NewDB(b), "pool_max_conns=8", "pool_max_conns=64", 1)
	e, err := Open(Options{Path: url, BlobDir: b.TempDir(), AuthDisabled: true, RetentionInterval: -1,
		Limits: p17Fast(), TailInterval: tailEvery, Purger: discardPurger{}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { e.Close() })
	s := e.rate.store
	if v := os.Getenv("BENCH_SLOTS"); v != "" {
		s.slots, _ = strconv.Atoi(v)
	}
	fast := Rate{1e9, 1e9}
	var next atomic.Int64
	batches, batched := s.batches.Load(), s.batched.Load()
	b.SetParallelism(16) // 64 goroutines at GOMAXPROCS 4
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		g := next.Add(1)
		ns := fmt.Sprint("ns", g%namespaces)
		principal := "w"
		if !onePrincipal {
			principal = "w" + ns
		}
		i := 0
		for pb.Next() {
			i++
			ds := []draw{
				{"p\x00" + principal, fast, 1, "ratePerPrincipal"},
				{"n\x00" + ns, fast, 1, "ratePerNamespace"},
				{fmt.Sprintf("r\x00%s\x00c%d-%d\x00%s", ns, g, i%32, principal), fast, 1, "ratePerResource"},
			}
			if _, _, ok, err := s.admit(b.Context(), time.Now(), ds); err != nil || !ok {
				b.Errorf("draw: %v %v", ok, err)
				return
			}
		}
	})
	elapsed := time.Since(start)
	b.StopTimer()
	nb, nd := s.batches.Load()-batches, s.batched.Load()-batched
	stmts := float64(nb) + float64(int64(b.N)-nd)
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "draws/s")
	b.ReportMetric(stmts/float64(b.N), "stmts/draw")
	b.ReportMetric(float64(b.N)/stmts, "draws/stmt")
	b.ReportMetric(float64(int64(b.N)-nd)/float64(b.N), "alone/draw")
}
