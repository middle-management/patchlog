package bundle_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
)

// laterIDs answers the batch requests after the first skip as a server
// that derives revision ids otherwise would (idTransport).
type laterIDs struct {
	idTransport
	skip atomic.Int64
}

func (l *laterIDs) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") && l.skip.Add(-1) >= 0 {
		return l.countingTransport.RoundTrip(r)
	}
	return l.idTransport.RoundTrip(r)
}

// requestLog records an importer's blob uploads ("blob"), dry runs ("dry")
// and submits ("submit"), in order.
type requestLog struct {
	mu  sync.Mutex
	seq []string
}

func (l *requestLog) RoundTrip(r *http.Request) (*http.Response, error) {
	kind := ""
	switch {
	case r.Method == "PUT" && strings.Contains(r.URL.Path, "/blob/"):
		kind = "blob"
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") && r.URL.Query().Get("dry-run") == "1":
		kind = "dry"
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch"):
		kind = "submit"
	}
	if kind != "" {
		l.mu.Lock()
		l.seq = append(l.seq, kind)
		l.mu.Unlock()
	}
	return http.DefaultTransport.RoundTrip(r)
}

// twoPerBatch is a deployment whose bulk namespace takes two items a batch.
func twoPerBatch(t *testing.T) *deployment {
	dst := newDeployment(t, cmsOrigin)
	dst.ns("bulk", map[string]any{"read": "public", "limits": map[string]any{"itemsPerBatch": 2}})
	return dst
}

// backfillVia imports b into dst through rt as a backfill, its waits only
// counted, or only dry-runs it.
func backfillVia(dst *deployment, b []byte, rt http.RoundTripper, dryRun bool) (*bundle.Report, error) {
	c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: rt})))
	clk := newTestClock()
	return bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, DryRun: dryRun, Now: clk.Now,
		Sleep: func(_ context.Context, d time.Duration) error { clk.add(d); return nil }})
}

// dryRuns lists the dry-run result of each batch of an import.
func dryRuns(rep *bundle.Report) string {
	var out []string
	for _, br := range rep.Batches {
		out = append(out, br.DryRun)
	}
	return strings.Join(out, ",")
}

// §G.4.4: an import dry-runs each existing namespace's first batch and a
// created namespace's first item, and relies on each later batch's own
// failure report, except for batches that write to resources the target
// had, which are dry-run before their submit. An import into an empty
// namespace makes one dry run however many batches it takes; one that
// fast-forwards documents dry-runs every batch that does, and a server
// that would give such a batch other ids stops the import before it moves
// their heads. A -dry-run import dry-runs the same batches, so a promotion
// can be checked end to end. A snapshot's next diffs upstream aren't
// dry-run but in the first batch, its merges into the target are.
// (BenchmarkImport's pace1 variants count the dry runs of imports into a
// fresh deployment.)
func TestImportUpdateDryRuns(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("bulk", nil)
	for i := range 6 {
		src.create("bulk", fmt.Sprintf("a%d", i), map[string]any{"i": i})
	}
	first, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"bulk"}})
	for _, i := range []int{0, 1, 4} {
		src.append("bulk", fmt.Sprintf("a%d", i), op("replace", "/i", -i))
	}
	for i := 6; i < 9; i++ {
		src.create("bulk", fmt.Sprintf("a%d", i), map[string]any{"i": i})
	}
	second, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"bulk"}})

	// Into an empty namespace: only its first batch.
	dst := twoPerBatch(t)
	rt := &countingTransport{rt: http.DefaultTransport}
	rep := must(backfillVia(dst, first, rt, false))
	if got := dryRuns(rep); got != "ok,," || rep.Timings.DryRuns != 1 || rt.dry.Load() != 1 || rt.submits.Load() != 3 {
		t.Fatalf("import: dry runs %q, %d dry, %d submits", got, rt.dry.Load(), rt.submits.Load())
	}

	// a0, a1 and a4 fast-forward, a6 to a8 are created: [a0 a1], dry-run
	// first as the namespace exists, [a4 a6], which moves a4, and [a7 a8].
	rt = &countingTransport{rt: http.DefaultTransport}
	rep = must(backfillVia(dst, second, rt, true))
	if got := dryRuns(rep); got != "ok,ok," || rt.dry.Load() != 2 || rt.submits.Load() != 0 {
		t.Fatalf("-dry-run: dry runs %q, %d dry, %d submits", got, rt.dry.Load(), rt.submits.Load())
	}
	rt = &countingTransport{rt: http.DefaultTransport}
	rep = must(backfillVia(dst, second, rt, false))
	if got := dryRuns(rep); got != "ok,ok," || rep.Timings.DryRuns != 2 || rt.dry.Load() != 2 || rt.submits.Load() != 3 {
		t.Fatalf("update: dry runs %q, %d dry, %d submits", got, rt.dry.Load(), rt.submits.Load())
	}
	sameHeads(t, src, "bulk", dst, "bulk", "a0", "a1", "a4", "a6", "a8")

	// Other ids from the second batch on: its dry run stops the import.
	dst = twoPerBatch(t)
	must(backfillVia(dst, first, http.DefaultTransport, false))
	before := dst.head("bulk", "a4").ID
	lt := &laterIDs{idTransport: idTransport{countingTransport: countingTransport{rt: http.DefaultTransport}, other: true}}
	lt.skip.Store(2)
	rep, err := backfillVia(dst, second, lt, false)
	if err == nil || !strings.Contains(err.Error(), "a4: would produce") || lt.submits.Load() != 1 {
		t.Fatalf("import: %v; %d submits", err, lt.submits.Load())
	}
	if got := dryRuns(rep); got != "ok,failed," {
		t.Fatalf("dry runs %q", got)
	}
	if dst.head("bulk", "a4").ID != before || dst.head("bulk", "a6").State != client.NotFound {
		t.Fatal("written with ids the bundle doesn't know")
	}

	// Snapshots of a0 to a8, then of a0, a1 and a4 changed again: [a0 a1]
	// and [a4] upstream, then into the target.
	snapshot := func() []byte {
		b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"bulk"}, Mode: bundle.Snapshot})
		return b
	}
	dst = twoPerBatch(t)
	dst.ns("bulk-upstream", map[string]any{"read": "public", "limits": map[string]any{"itemsPerBatch": 2}})
	must(backfillVia(dst, snapshot(), http.DefaultTransport, false))
	for _, i := range []int{0, 1, 4} {
		src.append("bulk", fmt.Sprintf("a%d", i), op("replace", "/i", 10+i))
	}
	rep = must(backfillVia(dst, snapshot(), http.DefaultTransport, false))
	var got []string
	for _, br := range rep.Batches {
		got = append(got, fmt.Sprintf("%s:%v", br.NS, br.DryRun))
	}
	if want := "bulk-upstream:ok bulk-upstream: bulk:ok bulk:ok"; strings.Join(got, " ") != want {
		t.Fatalf("snapshot: dry runs %s, want %s", strings.Join(got, " "), want)
	}
	if dst.doc("bulk", "a4")["i"] != float64(14) {
		t.Fatalf("a4 %v", dst.doc("bulk", "a4"))
	}
}

// §G.4.4 Blobs first: an import that will submit uploads a batch's blobs
// before that batch's dry run, a later batch's too; one that only dry-runs
// uploads none, and gets them reported as missing (§7.5).
func TestImportBlobsBeforeDryRun(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("bulk", nil)
	for i := range 3 {
		src.create("bulk", fmt.Sprintf("a%d", i), map[string]any{"i": i})
	}
	first, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"bulk"}})
	ry := src.upload("bulk", "a0", "text/plain", "", []byte("blob y"))
	src.append("bulk", "a0", op("add", "/blob", ry))
	src.append("bulk", "a1", op("replace", "/i", -1))
	rz := src.upload("bulk", "a2", "text/plain", "", []byte("blob z"))
	src.append("bulk", "a2", op("add", "/blob", rz))
	second, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"bulk"}})
	dst := twoPerBatch(t)
	must(backfillVia(dst, first, http.DefaultTransport, false))

	// [a0 a1] and [a2]: a dry-run import dry-runs both, uploading nothing,
	// and a0's and a2's blobs are missing.
	rl := &requestLog{}
	rep := must(backfillVia(dst, second, rl, true))
	if got := strings.Join(rl.seq, " "); got != "dry dry" {
		t.Fatalf("dry-run import sent %s", got)
	}
	for i, name := range []string{"a0", "a2"} {
		if br := rep.Batches[i]; br.DryRun != "deferred" || br.Uploaded != 0 || len(br.Failures) == 0 || !strings.HasPrefix(br.Failures[0], name+": 422 blob") {
			t.Fatalf("batch %+v", br)
		}
	}

	// An import sends each batch's blobs before its dry run.
	rl = &requestLog{}
	rep = must(backfillVia(dst, second, rl, false))
	if got := strings.Join(rl.seq, " "); got != "blob dry submit blob dry submit" {
		t.Fatalf("import sent %s", got)
	}
	if got := dryRuns(rep); got != "ok,ok" || rep.Batches[1].Uploaded != 1 {
		t.Fatalf("dry runs %q, %+v", got, rep.Batches[1])
	}
	if dst.blobBytes("bulk", "a0", ry) != "blob y" || dst.blobBytes("bulk", "a2", rz) != "blob z" {
		t.Fatal("blobs not imported")
	}
}
