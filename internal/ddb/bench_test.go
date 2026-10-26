package ddb

// Storage-path benchmarks against DynamoDB Local (DDB_ENDPOINT). They
// isolate the backend: no HTTP, grants, rules or validation (all core CPU,
// unchanged by the backend). Local has no network RTT or partitioning, so
// treat absolute numbers as the design's round-trip structure made
// visible, not as AWS projections — see docs/DYNAMODB.md §12.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// bench runs workers goroutines for d, each looping op, and reports ops/s
// and p50 latency.
func bench(b *testing.B, workers int, d time.Duration, op func(i int) error) {
	b.Helper()
	var count atomic.Int64
	var fail atomic.Int64
	var firstErr atomic.Value
	lat := make([][]time.Duration, workers)
	start := make(chan struct{})
	deadline := time.Now().Add(d)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; time.Now().Before(deadline); i++ {
				t0 := time.Now()
				if err := op(w*1_000_000 + i); err != nil {
					fail.Add(1)
					firstErr.CompareAndSwap(nil, err)
				} else {
					lat[w] = append(lat[w], time.Since(t0))
				}
				count.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if e := firstErr.Load(); e != nil {
		b.Logf("first error: %v", e)
	}
	n := count.Load()
	b.ReportMetric(float64(n)/d.Seconds(), "ops/s")
	var all []time.Duration
	for _, l := range lat {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	if len(all) > 0 {
		b.ReportMetric(float64(all[len(all)/2].Microseconds())/1000, "p50-ms")
		b.ReportMetric(float64(all[(len(all)*99)/100].Microseconds())/1000, "p99-ms")
	}
	if f := fail.Load(); f > 0 {
		b.ReportMetric(float64(f), "errors")
	}
}

func benchStores(b *testing.B, n int) []*Store {
	b.Helper()
	s := newLocalStore(b)
	var stores []*Store
	for i := range n {
		ns := fmt.Sprintf("ns%d", i)
		if _, _, err := s.CreateNamespace(context.Background(), ns, "bench", patches(`[{"op":"add","path":"","value":{}}]`)); err != nil {
			b.Fatal(err)
		}
		stores = append(stores, s)
	}
	return stores
}

const benchPatch = `[{"op":"add","path":"/n","value":1}]`

// benchCreate is a create's root replace (§6.2); appends use benchPatch.
func benchCreate(i int) any {
	return patches(fmt.Sprintf(`[{"op":"add","path":"","value":{"n":%d}}]`, i))
}

func BenchmarkDDB(b *testing.B) {
	ctx := context.Background()

	b.Run("write-1w-1ns", func(b *testing.B) {
		s := benchStores(b, 1)[0]
		bench(b, 1, 3*time.Second, func(i int) error {
			_, err := s.WriteResource(ctx, "ns0", fmt.Sprintf("doc%d", i), "", benchCreate(i), "bench")
			return err
		})
	})

	b.Run("write-8w-1ns", func(b *testing.B) {
		s := benchStores(b, 1)[0]
		bench(b, 8, 3*time.Second, func(i int) error {
			_, err := s.WriteResource(ctx, "ns0", fmt.Sprintf("doc%d", i), "", benchCreate(i), "bench")
			return err
		})
	})

	b.Run("write-32w-1ns", func(b *testing.B) {
		s := benchStores(b, 1)[0]
		bench(b, 32, 3*time.Second, func(i int) error {
			_, err := s.WriteResource(ctx, "ns0", fmt.Sprintf("doc%d", i), "", benchCreate(i), "bench")
			return err
		})
	})

	b.Run("write-32w-64ns", func(b *testing.B) {
		s := benchStores(b, 64)[0]
		bench(b, 32, 3*time.Second, func(i int) error {
			ns := fmt.Sprintf("ns%d", i%64)
			_, err := s.WriteResource(ctx, ns, fmt.Sprintf("doc%d", i), "", benchCreate(i), "bench")
			return err
		})
	})

	b.Run("append-1w-1doc", func(b *testing.B) {
		s := benchStores(b, 1)[0]
		if _, err := s.WriteResource(ctx, "ns0", "doc", "", patches(`[{"op":"add","path":"","value":{"n":0}}]`), "bench"); err != nil {
			b.Fatal(err)
		}
		var head string
		bench(b, 1, 3*time.Second, func(i int) error {
			res, err := s.WriteResource(ctx, "ns0", "doc", head, patches(benchPatch), "bench")
			if err != nil {
				return err
			}
			head = res.ID
			return nil
		})
	})

	b.Run("read-head-8w", func(b *testing.B) {
		s := benchStores(b, 1)[0]
		if _, err := s.WriteResource(ctx, "ns0", "doc", "", patches(`[{"op":"add","path":"","value":{"n":0}}]`), "bench"); err != nil {
			b.Fatal(err)
		}
		bench(b, 8, 3*time.Second, func(i int) error {
			_, _, err := s.ReadHead(ctx, "ns0", "doc")
			return err
		})
	})

	b.Run("log-page-1w", func(b *testing.B) {
		s := benchStores(b, 1)[0]
		for i := range 200 {
			if _, err := s.WriteResource(ctx, "ns0", fmt.Sprintf("doc%d", i), "", benchCreate(i), "bench"); err != nil {
				b.Fatal(err)
			}
		}
		bench(b, 1, 3*time.Second, func(i int) error {
			_, _, err := s.ReadLog(ctx, "ns0", "", 100)
			return err
		})
	})
}
