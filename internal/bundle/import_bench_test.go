package bundle_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
)

// countingTransport counts the requests a client sends, and the 429s.
type countingTransport struct {
	n, rejected atomic.Int64
	rt          http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	res, err := c.rt.RoundTrip(r)
	if err == nil && res.StatusCode == http.StatusTooManyRequests {
		c.rejected.Add(1)
	}
	return res, err
}

// fastLimits keeps a deployment's own rate limits out of the way. An
// import into a namespace whose document doesn't set limits still paces
// at the defaults of §6.6, which the importer assumes.
func fastLimits(o *core.Options) {
	l := core.DefaultLimits()
	fast := core.Rate{Rate: 1e9, Burst: 1e9}
	l.RatePerResource, l.RatePerPrincipal, l.RatePerNamespace = fast, fast, fast
	o.Limits = l
}

// BenchmarkImport imports 2,000 documents into a fresh deployment as a
// backfill, in history and snapshot mode, with Sleep stubbed: it moves the
// deployment's clock on instead, so rate buckets refill as if the import
// had waited. It reports the documents imported per second of work
// (items/s), the HTTP requests the importer sent per document (req/item),
// how long the backfill would have slept (slept-s/op), and the 429s it
// got. The allowance variants give the importer an allowance in its
// target namespaces (§6.6); the again variants import the bundle a second
// time, into a target that has it all. Cheap enough for -benchtime 1x:
//
//	go test ./internal/bundle -run '^$' -bench Import -benchtime 1x
func BenchmarkImport(b *testing.B) {
	const docs = 2000
	src := newDeployment(b, stagingOrigin, fastLimits)
	src.ns("data", nil)
	for i := 0; i < docs; i += 1000 {
		var items []client.BatchItem
		for j := i; j < min(i+1000, docs); j++ {
			items = append(items, client.BatchItem{Resource: fmt.Sprintf("doc-%d", j), IfNoneMatch: true,
				Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": fmt.Sprint("t", j), "n": j, "tags": []any{"a", "b"}}))}})
		}
		must(src.c.Batch(ctx, "data", client.BatchRequest{Items: items}, false))
	}
	// A burst above two batches: a batch is dry-run, then submitted.
	allowance := map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
		"bucket": map[string]any{"rate": 1000, "burst": 5000}}}}
	for _, mode := range []string{bundle.Full, bundle.Snapshot} {
		var buf bytes.Buffer
		must2(bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"data"}, Mode: mode}))
		for _, variant := range []string{"", "/allowance", "/again"} {
			b.Run(mode+variant, func(b *testing.B) {
				var work, slept time.Duration
				var reqs, rejected int64
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					var skew atomic.Int64
					dst := newDeployment(b, cmsOrigin, fastLimits, func(o *core.Options) {
						o.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
					})
					var wait time.Duration
					imp := func(rt http.RoundTripper) error {
						c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: rt})))
						_, err := bundle.Import(ctx, c, bundle.BytesOpener(buf.Bytes()), bundle.ImportOptions{Mode: bundle.Backfill, CreateNamespaces: true,
							Sleep: func(_ context.Context, d time.Duration) error { wait += d; skew.Add(int64(d)); return nil }})
						return err
					}
					switch variant {
					case "/allowance":
						dst.ns("data", allowance)
						if mode == bundle.Snapshot {
							dst.ns("data-upstream", allowance)
						}
					case "/again":
						if err := imp(http.DefaultTransport); err != nil {
							b.Fatal(err)
						}
						wait = 0
					}
					rt := &countingTransport{rt: http.DefaultTransport}
					b.StartTimer()
					t0 := time.Now()
					err := imp(rt)
					work += time.Since(t0)
					if err != nil {
						b.Fatal(err)
					}
					slept, reqs, rejected = slept+wait, reqs+rt.n.Load(), rejected+rt.rejected.Load()
				}
				n := float64(docs * b.N)
				b.ReportMetric(n/work.Seconds(), "items/s")
				b.ReportMetric(float64(reqs)/n, "req/item")
				b.ReportMetric(slept.Seconds()/float64(b.N), "slept-s/op")
				b.ReportMetric(float64(rejected)/float64(b.N), "429s/op")
			})
		}
	}
}
