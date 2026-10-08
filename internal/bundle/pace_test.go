package bundle_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/core"
)

// allowanceTarget has the bulk namespace with small limits and two
// allowances: svc:importer's, with smaller batches than the namespace
// would give it and a bucket of 1000/s, and svc:old's, which ended.
func allowanceTarget(t *testing.T) *deployment {
	dst := newDeployment(t, cmsOrigin)
	dst.ns("bulk", map[string]any{
		"read":   "public",
		"limits": map[string]any{"itemsPerBatch": 3, "batchSize": 1 << 10},
		"allowances": []any{
			map[string]any{"sub": "svc:importer", "kid": "ops-2026", "bucket": map[string]any{"rate": 1000, "burst": 1000},
				"itemsPerBatch": 5, "batchSize": 1 << 20},
			map[string]any{"sub": "svc:old", "kid": "ops-2025", "bucket": map[string]any{"rate": 1000, "burst": 1000},
				"itemsPerBatch": 5, "batchSize": 1 << 20, "until": "2026-01-01T00:00:00Z"},
		},
	})
	return dst
}

// testClock is a clock that moves only when told to.
type testClock struct {
	t0 time.Time
	d  atomic.Int64
}

func newTestClock() *testClock { return &testClock{t0: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)} }

func (c *testClock) Now() time.Time      { return c.t0.Add(time.Duration(c.d.Load())) }
func (c *testClock) add(d time.Duration) { c.d.Add(int64(d)) }

// clockedTarget is a deployment on a test clock.
func clockedTarget(t *testing.T) (*deployment, *testClock) {
	clk := newTestClock()
	return newDeployment(t, cmsOrigin, func(o *core.Options) { o.Now = clk.Now }), clk
}

// slowBatches moves a clock on by took during every batch request, dry
// runs included, and counts the requests and 429s.
type slowBatches struct {
	countingTransport
	clock *testClock
	took  time.Duration
}

func (s *slowBatches) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") {
		s.clock.add(s.took)
	}
	return s.countingTransport.RoundTrip(r)
}

// backfill runs a backfill by who into dst on clk, which moves on by took
// during every batch request and by every wait the import asks for, and
// returns its report, the waits and its requests.
func backfill(t *testing.T, dst *deployment, clk *testClock, who string, b []byte, took time.Duration) (*bundle.Report, []time.Duration, *slowBatches) {
	t.Helper()
	rt := &slowBatches{countingTransport: countingTransport{rt: http.DefaultTransport}, clock: clk, took: took}
	c := must(client.New(dst.url, client.WithAuthor(who), client.WithHTTPClient(&http.Client{Transport: rt})))
	var sleeps []time.Duration
	rep, err := bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 0.5,
		Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); clk.add(d); return nil },
		Now:   clk.Now})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return rep, sleeps, rt
}

func batchSizes(rep *bundle.Report) []int {
	var out []int
	for _, br := range rep.Batches {
		out = append(out, len(br.Resources))
	}
	return out
}

// A backfill by an importer with an allowance in the target namespace
// (§6.6) splits by the allowance's itemsPerBatch and batchSize and paces
// at the full rate of its bucket, counting every dry run as a submit; any
// other importer, or one whose allowance ended, splits and paces as the
// namespace's limits say. Pacing takes off the time a batch took.
func TestBackfillAllowance(t *testing.T) {
	t.Parallel()
	b := bulkSource(t)

	t.Run("allowance", func(t *testing.T) {
		t.Parallel()
		dst := allowanceTarget(t)
		rep, sleeps, _ := backfill(t, dst, newTestClock(), "svc:importer", b, 0)
		// doc-0…doc-4, then doc-5 and the whole long chain, in 1 MiB.
		if got := batchSizes(rep); !slices.Equal(got, []int{5, 2}) || rep.Batches[1].Steps != 8 {
			t.Fatalf("batches %v, %d steps", got, rep.Batches[1].Steps)
		}
		// Each batch is dry-run, the first before anything is written, and
		// submitted: 5 items twice, then 2 twice.
		if want := []time.Duration{10 * time.Millisecond, 4 * time.Millisecond}; !slices.Equal(sleeps, want) {
			t.Fatalf("sleeps %v, want %v", sleeps, want)
		}
		for _, br := range rep.Batches {
			if br.PacedBy != "allowance" || br.Rate != 1000 || br.NSID == "" {
				t.Fatalf("batch %+v", br)
			}
		}
		if h := dst.head("bulk", "long"); h.State != client.Live {
			t.Fatal("not imported")
		}
	})

	t.Run("elapsed", func(t *testing.T) {
		t.Parallel()
		// Each batch request takes 1ms by the clock, a dry run and a
		// submit a batch: the bucket refills as they run, and each wait is
		// 2ms shorter.
		_, sleeps, _ := backfill(t, allowanceTarget(t), newTestClock(), "svc:importer", b, time.Millisecond)
		if want := []time.Duration{8 * time.Millisecond, 2 * time.Millisecond}; !slices.Equal(sleeps, want) {
			t.Fatalf("sleeps %v, want %v", sleeps, want)
		}
		// Batches that take longer than their wait don't wait.
		_, sleeps, _ = backfill(t, allowanceTarget(t), newTestClock(), "svc:importer", b, 10*time.Millisecond)
		if len(sleeps) != 0 {
			t.Fatalf("sleeps %v", sleeps)
		}
		// Without an allowance, a batch's items at 25/s, less its time:
		// the first batch's submit, every later one's dry run too.
		rep, sleeps, _ := backfill(t, allowanceTarget(t), newTestClock(), "bob", b, 10*time.Millisecond)
		for i, br := range rep.Batches {
			want := time.Duration(len(br.Resources))*40*time.Millisecond - 20*time.Millisecond
			if i == 0 {
				want += 10 * time.Millisecond
			}
			if sleeps[i] != want {
				t.Fatalf("batch %d of %d items slept %v, want %v", i+1, len(br.Resources), sleeps[i], want)
			}
		}
	})

	for _, who := range []string{"bob", "svc:old"} {
		t.Run(who, func(t *testing.T) {
			t.Parallel()
			rep, sleeps, _ := backfill(t, allowanceTarget(t), newTestClock(), who, b, 0)
			if len(rep.Batches) < 4 || len(sleeps) != len(rep.Batches) {
				t.Fatalf("batches %v, sleeps %v", batchSizes(rep), sleeps)
			}
			for i, br := range rep.Batches {
				// Items at 0.5 × min(500/s namespace, 50/s principal).
				want := time.Duration(float64(len(br.Resources)) / 25 * float64(time.Second))
				if len(br.Resources) > 3 || br.PacedBy != "ratePerPrincipal" || br.Rate != 25 || sleeps[i] != want {
					t.Fatalf("batch %+v slept %v, want %v", br, sleeps[i], want)
				}
			}
		})
	}
}

// Under grants, an allowance is the importer's when both its sub and the
// kid that signed its grant's root block match (§6.6).
func TestBackfillAllowanceGrant(t *testing.T) {
	t.Parallel()
	b := bulkSource(t)
	s := clienttest.New(t, clienttest.Options{Auth: true})
	admin, ops := clienttest.NewKey("admin"), clienttest.NewKey("ops-2026")
	oper := s.Client(t, client.WithBearer(s.OperatorGrant(t, "bulk")))
	must(oper.CreateNamespace(ctx, "bulk", map[string]any{
		"read":   "public",
		"keys":   []any{admin.Entry("*"), ops.Entry("read", "create", "append")},
		"limits": map[string]any{"itemsPerBatch": 3, "batchSize": 1 << 10},
		"allowances": []any{map[string]any{"sub": "svc:importer", "kid": "ops-2026", "bucket": map[string]any{"rate": 1000, "burst": 1000},
			"itemsPerBatch": 5, "batchSize": 1 << 20}},
	}))
	can := []string{"read", "create", "append"}

	// The same sub under another key has no allowance.
	other := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:importer", []string{"bulk"}, can)))
	rep := must(bundle.Import(ctx, other, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, DryRun: true}))
	if br := rep.Batches[0]; len(rep.Batches) < 4 || br.PacedBy != "ratePerPrincipal" {
		t.Fatalf("batches %v, paced by %s", batchSizes(rep), br.PacedBy)
	}

	imp := s.Client(t, client.WithBearer(ops.Grant(t, s.Now(), "svc:importer", []string{"bulk"}, can)))
	var sleeps []time.Duration
	rep = must(bundle.Import(ctx, imp, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Now: s.Now,
		Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }}))
	if got := batchSizes(rep); !slices.Equal(got, []int{5, 2}) || rep.Batches[0].PacedBy != "allowance" || rep.Batches[1].NSID == "" {
		t.Fatalf("batches %v %+v", got, rep.Batches[0])
	}
	if want := []time.Duration{10 * time.Millisecond, 4 * time.Millisecond}; !slices.Equal(sleeps, want) {
		t.Fatalf("sleeps %v, want %v", sleeps, want)
	}
}

// An allowance's bucket is paced at its full rate, so a backfill counts
// every draw on it as the server does (§6.6, §7.8): a token per blob
// upload, per item dry-run and per item submitted, refilling between them
// up to its burst. A burst just large enough for a batch then answers no
// request 429. The first batches of both namespaces are dry-run before
// anything is written: b's was refilled by the time b's batches start,
// its submit not.
func TestBackfillAllowanceDraws(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin, fastLimits)
	dst, clk := clockedTarget(t)
	for _, ns := range []string{"a", "b"} {
		src.ns(ns, nil)
		for i := 0; i < 20; i++ {
			name := fmt.Sprintf("d%02d", i)
			src.create(ns, name, map[string]any{"b": src.upload(ns, name, "text/plain", "", []byte(ns+name))})
		}
		// A batch of 10 makes 10 uploads, a dry run and a submit, each
		// admitted with a token left: 30 tokens from a burst of 21.
		dst.ns(ns, map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
			"bucket": map[string]any{"rate": 100, "burst": 21}, "itemsPerBatch": 10}}})
	}
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"a", "b"}})
	rep, sleeps, rt := backfill(t, dst, clk, "alice", b, 0)
	if got := batchSizes(rep); !slices.Equal(got, []int{10, 10, 10, 10}) || rt.rejected.Load() != 0 {
		t.Fatalf("batches %v, %d 429s", got, rt.rejected.Load())
	}
	ms := time.Millisecond
	if want := []time.Duration{300 * ms, 300 * ms, 100 * ms, 300 * ms}; !slices.Equal(sleeps, want) {
		t.Fatalf("sleeps %v, want %v", sleeps, want)
	}
	if dst.blobBytes("b", "d19", dst.doc("b", "d19")["b"].(map[string]any)) != "bd19" {
		t.Fatal("not imported")
	}
}

// An allowance that ends during a backfill (an import's should, §6.6) is
// the importer's no more from a minute before its until: the namespace's
// batches from then on are split again to fit its own limits, a chain cut
// between two of them whole again first, and paced by its own buckets. The
// target's clock moves on as the import waits, so it ends there too.
func TestBackfillAllowanceEnds(t *testing.T) {
	t.Parallel()
	allowance := func(clk *testClock, ends time.Duration, limits, al map[string]any) map[string]any {
		al["sub"], al["kid"], al["until"] = "alice", "any", clk.Now().Add(time.Minute+ends).Format(time.RFC3339)
		al["bucket"] = map[string]any{"rate": 1, "burst": 100}
		return map[string]any{"read": "public", "limits": limits, "allowances": []any{al}}
	}

	t.Run("batches", func(t *testing.T) {
		t.Parallel()
		src := newDeployment(t, stagingOrigin, fastLimits)
		src.ns("data", nil)
		for i := 0; i < 60; i++ {
			src.create("data", fmt.Sprintf("d%02d", i), map[string]any{"i": i})
		}
		b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"data"}})
		dst, clk := clockedTarget(t)
		// A batch of 10 draws 20 tokens at 1/s: the third starts 40s in,
		// less than a minute before until, and the sixth would start
		// after it.
		dst.ns("data", allowance(clk, 25*time.Second, map[string]any{"itemsPerBatch": 3}, map[string]any{"itemsPerBatch": 10}))
		rep, sleeps, _ := backfill(t, dst, clk, "alice", b, 0)
		if got, want := batchSizes(rep), append([]int{10, 10}, append(slices.Repeat([]int{3}, 13), 1)...); !slices.Equal(got, want) {
			t.Fatalf("batches %v, want %v", got, want)
		}
		for i, br := range rep.Batches {
			by, rate, wait := "allowance", 1.0, 20*time.Second
			if i >= 2 {
				by, rate, wait = "ratePerPrincipal", 25.0, time.Duration(len(br.Resources))*40*time.Millisecond
			}
			if br.PacedBy != by || br.Rate != rate || br.Part != i+1 || br.Parts != 16 || br.NSID == "" || sleeps[i] != wait {
				t.Fatalf("batch %+v slept %v, want %s at %v, %v", br, sleeps[i], by, rate, wait)
			}
		}
		if len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "allowance in data ends") || !strings.Contains(rep.Notes[0], "batches 3 to 16") {
			t.Fatalf("notes %q", rep.Notes)
		}
		if dst.head("data", "d59").State != client.Live {
			t.Fatal("not imported")
		}
	})

	t.Run("chain", func(t *testing.T) {
		t.Parallel()
		src := newDeployment(t, stagingOrigin, fastLimits)
		src.ns("data", nil)
		src.create("data", "long", map[string]any{"v": 0})
		for _, n := range []int{600, 300, 600, 300, 200} {
			src.append("data", "long", op("replace", "/v", strings.Repeat("x", n-41))) // a step of n bytes
		}
		b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"data"}})
		dst, clk := clockedTarget(t)
		// The allowance's batchSize cuts the chain after 3 steps and 5, and
		// ends after the first part. The namespace's own takes the step of
		// 600 bytes alone, then the rest of the chain, both parts, in one
		// batch.
		dst.ns("data", allowance(clk, time.Second, map[string]any{"batchSize": 700}, map[string]any{"batchSize": 1000}))
		rep, _, _ := backfill(t, dst, clk, "alice", b, 0)
		var steps []int
		for _, br := range rep.Batches {
			steps = append(steps, br.Steps)
		}
		if !slices.Equal(steps, []int{3, 1, 2}) || rep.Batches[0].PacedBy != "allowance" || rep.Batches[1].PacedBy != "ratePerPrincipal" {
			t.Fatalf("steps %v, %+v", steps, rep.Batches)
		}
		if dst.head("data", "long").ID != src.head("data", "long").ID {
			t.Fatal("not imported with its ids")
		}
	})
}
