package bundle_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
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

// backfill runs a backfill whose clock moves step on every reading, and
// returns its report and the waits it asked for.
func backfill(t *testing.T, c *client.Client, b []byte, step time.Duration) (*bundle.Report, []time.Duration) {
	t.Helper()
	var sleeps []time.Duration
	now := time.Now()
	rep, err := bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 0.5,
		Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil },
		Now:   func() time.Time { now = now.Add(step); return now }})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return rep, sleeps
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
// at the full rate of its bucket, counting the dry run before a submit;
// any other importer, or one whose allowance ended, splits and paces as
// the namespace's limits say. Pacing takes off the time a batch took.
func TestBackfillAllowance(t *testing.T) {
	t.Parallel()
	b := bulkSource(t)

	t.Run("allowance", func(t *testing.T) {
		t.Parallel()
		dst := allowanceTarget(t)
		rep, sleeps := backfill(t, dst.c.With(client.WithAuthor("svc:importer")), b, 0)
		// doc-0…doc-4, then doc-5 and the whole long chain, in 1 MiB.
		if got := batchSizes(rep); !slices.Equal(got, []int{5, 2}) || rep.Batches[1].Steps != 8 {
			t.Fatalf("batches %v, %d steps", got, rep.Batches[1].Steps)
		}
		// The first batch was dry-run before anything was written; the
		// second just before its submit, which draws its 2 items again.
		if want := []time.Duration{5 * time.Millisecond, 4 * time.Millisecond}; !slices.Equal(sleeps, want) {
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
		// Each batch takes 1ms by the clock: its wait is that much shorter.
		_, sleeps := backfill(t, allowanceTarget(t).c.With(client.WithAuthor("svc:importer")), b, time.Millisecond)
		if want := []time.Duration{4 * time.Millisecond, 3 * time.Millisecond}; !slices.Equal(sleeps, want) {
			t.Fatalf("sleeps %v, want %v", sleeps, want)
		}
		// Batches that take longer than their wait don't wait.
		_, sleeps = backfill(t, allowanceTarget(t).c.With(client.WithAuthor("svc:importer")), b, 10*time.Millisecond)
		if len(sleeps) != 0 {
			t.Fatalf("sleeps %v", sleeps)
		}
	})

	for _, who := range []string{"bob", "svc:old"} {
		t.Run(who, func(t *testing.T) {
			t.Parallel()
			rep, sleeps := backfill(t, allowanceTarget(t).c.With(client.WithAuthor(who)), b, 0)
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
	if want := []time.Duration{5 * time.Millisecond, 4 * time.Millisecond}; !slices.Equal(sleeps, want) {
		t.Fatalf("sleeps %v, want %v", sleeps, want)
	}
}
