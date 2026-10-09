package bundle_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
)

// countingTransport counts the requests a client sends, and the 429s. It
// times the batch requests, and counts the dry runs and submits that
// succeed; limited is set by a 429 until the importer's next wait, which
// is then for it.
type countingTransport struct {
	n, rejected  atomic.Int64
	dry, submits atomic.Int64
	batchTime    atomic.Int64
	limited      atomic.Bool
	rt           http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	t0 := time.Now()
	res, err := c.rt.RoundTrip(r)
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") {
		c.batchTime.Add(int64(time.Since(t0)))
		if err == nil && res.StatusCode < 300 {
			if r.URL.Query().Get("dry-run") == "1" {
				c.dry.Add(1)
			} else {
				c.submits.Add(1)
			}
		}
	}
	if err == nil && res.StatusCode == http.StatusTooManyRequests {
		c.rejected.Add(1)
		c.limited.Store(true)
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

// BenchmarkImport imports 2,000 documents into a fresh deployment with the
// default limits of §6.6 as a backfill, in history and snapshot mode,
// small documents and ones of about 6 KB (/6KB), with Sleep stubbed: it
// moves the deployment's clock on instead, so rate buckets refill as if
// the import had waited. The pace1 variants pace as -pace 1 does; the
// allowance variants give the importer an allowance in its target
// namespaces (§6.6); the again variants import the bundle a second time,
// into a target that has it all. It reports the documents imported per
// second of work (items/s) and the HTTP requests the importer sent per
// document (req/item); the batches submitted and dry-run, and the 429s;
// and per batch submitted, where the time goes: its batch requests, dry
// runs included (batch-ms/batch, the server's time), the paced waits
// (paced-ms/batch) and the waits after a 429 (429-ms/batch). Cheap enough
// for -benchtime 1x:
//
//	go test ./internal/bundle -run '^$' -bench Import -benchtime 1x
func BenchmarkImport(b *testing.B) {
	const docs = 2000
	for _, size := range []string{"", "/6KB"} {
		src := newDeployment(b, stagingOrigin, fastLimits)
		src.ns("data", nil)
		for i := 0; i < docs; i += 1000 {
			var items []client.BatchItem
			for j := i; j < min(i+1000, docs); j++ {
				doc := map[string]any{"title": fmt.Sprint("t", j), "n": j, "tags": []any{"a", "b"}}
				if size != "" {
					// Six paragraphs of 1,000 bytes.
					var body []any
					for k := 0; k < 6; k++ {
						body = append(body, strings.Repeat(fmt.Sprintf("%d lorem ipsum %d ", j, k), 100)[:1000])
					}
					doc["body"] = body
				}
				items = append(items, client.BatchItem{Resource: fmt.Sprintf("doc-%d", j), IfNoneMatch: true,
					Steps: []client.Step{client.PatchStep(client.GenesisPatches(doc))}})
			}
			must(src.c.Batch(ctx, "data", client.BatchRequest{Items: items}, false))
		}
		// A burst above two batches: a batch may be dry-run, then submitted.
		allowance := map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
			"bucket": map[string]any{"rate": 1000, "burst": 5000}}}}
		for _, mode := range []string{bundle.Full, bundle.Snapshot} {
			var buf bytes.Buffer
			must2(bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"data"}, Mode: mode}))
			for _, variant := range []string{"/pace1", "/allowance", "/again"} {
				b.Run(mode+size+variant, func(b *testing.B) {
					var work, paced, limited, batchTime time.Duration
					var reqs, rejected, submits, dry int64
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						var skew atomic.Int64
						dst := newDeployment(b, cmsOrigin, func(o *core.Options) {
							o.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
						})
						var p, l time.Duration
						imp := func(rt *countingTransport) error {
							c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: rt})))
							_, err := bundle.Import(ctx, c, bundle.BytesOpener(buf.Bytes()), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true,
								Sleep: func(_ context.Context, d time.Duration) error {
									if rt.limited.Swap(false) {
										l += d
									} else {
										p += d
									}
									skew.Add(int64(d))
									return nil
								}})
							return err
						}
						switch variant {
						case "/allowance":
							dst.ns("data", allowance)
							if mode == bundle.Snapshot {
								dst.ns("data-upstream", allowance)
							}
						case "/again":
							if err := imp(&countingTransport{rt: http.DefaultTransport}); err != nil {
								b.Fatal(err)
							}
							p, l = 0, 0
						}
						rt := &countingTransport{rt: http.DefaultTransport}
						b.StartTimer()
						t0 := time.Now()
						err := imp(rt)
						work += time.Since(t0)
						if err != nil {
							b.Fatal(err)
						}
						paced, limited, batchTime = paced+p, limited+l, batchTime+time.Duration(rt.batchTime.Load())
						reqs, rejected = reqs+rt.n.Load(), rejected+rt.rejected.Load()
						submits, dry = submits+rt.submits.Load(), dry+rt.dry.Load()
					}
					n, ops := float64(docs*b.N), float64(b.N)
					b.ReportMetric(n/work.Seconds(), "items/s")
					b.ReportMetric(float64(reqs)/n, "req/item")
					b.ReportMetric(float64(submits)/ops, "batches/op")
					b.ReportMetric(float64(dry)/ops, "dry/op")
					b.ReportMetric(float64(rejected)/ops, "429s/op")
					if submits > 0 {
						per := func(d time.Duration) float64 { return float64(d.Milliseconds()) / float64(submits) }
						b.ReportMetric(per(batchTime), "batch-ms/batch")
						b.ReportMetric(per(paced), "paced-ms/batch")
						b.ReportMetric(per(limited), "429-ms/batch")
					}
				})
			}
		}
	}
}
