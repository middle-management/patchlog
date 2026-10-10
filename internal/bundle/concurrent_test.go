package bundle_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/schema"
)

// batchLog records the batch requests a client sends (not dry runs): their
// namespace, resources, and when each started and ended; and how many were
// in flight at most. fail, if set, answers a request 422 instead of
// sending it.
type batchLog struct {
	rt   http.RoundTripper
	fail func(ns string, resources []string) bool

	mu       sync.Mutex
	batches  []loggedBatch
	now      int
	max      int
	n429     int
	failedAt int // the tick of the request fail answered
}

type loggedBatch struct {
	ns         string
	resources  []string
	start, end int // ticks of the log: start < end; one batch before another if its end < the other's start
}

func (l *batchLog) RoundTrip(r *http.Request) (*http.Response, error) {
	ns, ok := strings.CutPrefix(r.URL.Path, "/ns/")
	if !ok || !strings.HasSuffix(ns, "/batch") || r.URL.Query().Get("dry-run") == "1" {
		res, err := l.rt.RoundTrip(r)
		l.count429(res)
		return res, err
	}
	ns = strings.TrimSuffix(ns, "/batch")
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	var req struct {
		Items []struct{ Resource string } `json:"items"`
	}
	json.Unmarshal(body, &req)
	b := loggedBatch{ns: ns}
	for _, it := range req.Items {
		b.resources = append(b.resources, it.Resource)
	}
	if l.fail != nil && l.fail(ns, b.resources) {
		l.mu.Lock()
		l.now++
		l.failedAt = l.now
		l.mu.Unlock()
		return &http.Response{StatusCode: 422, Header: http.Header{"Content-Type": {"application/json"}}, Request: r,
			Body: io.NopCloser(strings.NewReader(`{"code":"invalid","message":"refused by the test"}`))}, nil
	}
	l.mu.Lock()
	l.now++
	b.start = l.now
	inFlight := 1
	for _, o := range l.batches {
		if o.end == 0 {
			inFlight++
		}
	}
	l.max = max(l.max, inFlight)
	i := len(l.batches)
	l.batches = append(l.batches, b)
	l.mu.Unlock()
	res, err := l.rt.RoundTrip(r)
	if err == nil {
		// The batch has committed once its answer has been read.
		buf, _ := io.ReadAll(res.Body)
		res.Body.Close()
		res.Body = io.NopCloser(bytes.NewReader(buf))
	}
	l.count429(res)
	l.mu.Lock()
	l.now++
	l.batches[i].end = l.now
	l.mu.Unlock()
	return res, err
}

func (l *batchLog) count429(res *http.Response) {
	if res != nil && res.StatusCode == http.StatusTooManyRequests {
		l.mu.Lock()
		l.n429++
		l.mu.Unlock()
	}
}

// heads lists every resource's head in the namespaces, as "ns/name id".
func heads(t *testing.T, c *client.Client, nss ...string) []string {
	t.Helper()
	var out []string
	for _, ns := range nss {
		h := must(c.NSHead(ctx, ns))
		after := ""
		for {
			items, next, err := c.HeadsPage(ctx, ns, h.ID, after)
			if err != nil {
				t.Fatal(err)
			}
			for _, it := range items {
				out = append(out, ns+"/"+it.Resource+" "+it.Target)
			}
			if next == "" {
				break
			}
			after = next
		}
	}
	return out
}

// An import under an allowance submits several batches at once (§G.4.4):
// in dependency order all the same, a namespace's batches after those of
// the namespaces they depend on, upstream namespaces first, and a batch
// after those holding the documents it pins. It leaves the target as an
// import one batch at a time does.
func TestImportConcurrent(t *testing.T) {
	t.Parallel()
	shape := contentShape{layouts: 8, pages: 40, items: 30, comments: 20, verifications: 3}
	b := contentBundle(t, shape)
	allowance := map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
		"bucket": map[string]any{"rate": 1e6, "burst": 1e6}, "itemsPerBatch": 4}}}
	imp := func(concurrency int) (*deployment, *batchLog, *bundle.Report) {
		dst := newDeployment(t, cmsOrigin, fastLimits)
		log := &batchLog{rt: transport}
		c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: log})))
		var mu sync.Mutex
		rep, err := bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true,
			Concurrency: concurrency, NamespaceDoc: func(string, string) any { return allowance },
			Sleep: func(context.Context, time.Duration) error { mu.Lock(); defer mu.Unlock(); return nil }})
		if err != nil {
			t.Fatalf("import with concurrency %d: %v", concurrency, err)
		}
		return dst, log, rep
	}
	seq, seqLog, _ := imp(1)
	dst, log, rep := imp(4)
	if seqLog.max != 1 || log.max < 2 {
		t.Fatalf("at most %d batches in flight one at a time, %d at once", seqLog.max, log.max)
	}
	if log.n429 > 0 {
		t.Fatalf("%d 429s", log.n429)
	}
	nss := []string{"demo-schemas", "demo", "demo-upstream", "cat-demo", "cat-demo-upstream", "demo-comments", "demo-comments-upstream",
		"domain-verifications", "domain-verifications-upstream"}
	if got, want := heads(t, dst.c, nss...), heads(t, seq.c, nss...); !slices.Equal(got, want) {
		t.Fatalf("the target differs from a sequential import's:\n%v\n%v", got, want)
	}
	if !slices.Equal(rep.Order[:3], []string{"demo-schemas", "cat-demo-upstream", "cat-demo"}) ||
		slices.Index(rep.Order, "demo-upstream") > slices.Index(rep.Order, "demo") {
		t.Fatalf("order %v", rep.Order)
	}

	// before reports whether every batch matching a ended before every
	// batch matching b started.
	before := func(a, b func(loggedBatch) bool) bool {
		for _, x := range log.batches {
			for _, y := range log.batches {
				if a(x) && b(y) && x.end > y.start {
					return false
				}
			}
		}
		return true
	}
	in := func(ns string) func(loggedBatch) bool { return func(b loggedBatch) bool { return b.ns == ns } }
	other := func(ns string) func(loggedBatch) bool { return func(b loggedBatch) bool { return b.ns != ns } }
	// A target after its upstream; layouts pin items, which they name
	// upstream once rewritten; comments name pages live, which doesn't
	// order them.
	for _, dep := range [][2]string{
		{"demo-upstream", "demo"}, {"cat-demo-upstream", "cat-demo"}, {"cat-demo-upstream", "demo-upstream"}, {"cat-demo-upstream", "demo"},
		{"demo-comments-upstream", "demo-comments"},
	} {
		if !before(in(dep[0]), in(dep[1])) {
			t.Errorf("a batch into %s started before those into %s ended", dep[1], dep[0])
		}
	}
	if !before(in("demo-schemas"), other("demo-schemas")) {
		t.Error("a batch started before the schemas'")
	}
	// A page pins its layout, which upstream is in the same namespace.
	pins := map[string]string{}
	rd := must(bundle.NewReader(bytes.NewReader(b)))
	for {
		l, err := rd.Next()
		if err == io.EOF {
			break
		}
		noErr(t, err)
		if l.NS == "demo" && strings.HasPrefix(l.Resource, "page-") {
			ref := l.Doc.(map[string]any)["layout"].(string)
			pins[l.Resource] = strings.Split(ref, "/")[3]
		}
	}
	concurrentPages := false
	for _, x := range log.batches {
		if x.ns != "demo-upstream" {
			continue
		}
		for _, y := range log.batches {
			if y.ns != "demo-upstream" {
				continue
			}
			for _, page := range x.resources {
				if layout, ok := pins[page]; ok && slices.Contains(y.resources, layout) && y.end > x.start {
					t.Fatalf("%s started before the batch with %s, which it pins, ended", page, layout)
				}
			}
			if x.start < y.end && y.start < x.end && x.start != y.start {
				concurrentPages = true
			}
		}
	}
	if !concurrentPages {
		t.Error("no batches into demo-upstream overlapped")
	}
}

// A concurrent import paces every request at the allowance's rate: its
// blob uploads, dry runs and submits, each admitted once the bucket has
// refilled what those before it drew, so none is answered 429 (§6.6). A
// namespace has as many batches in flight as the allowance's burst holds
// the draws of; where it holds no more than one batch's, the import goes
// one batch at a time.
func TestImportConcurrentDraws(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin, fastLimits)
	for _, ns := range []string{"a", "b"} {
		src.ns(ns, nil)
		for i := 0; i < 40; i++ {
			name := fmt.Sprintf("d%02d", i)
			src.create(ns, name, map[string]any{"b": src.upload(ns, name, "text/plain", "", []byte(ns+name))})
		}
	}
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"a", "b"}})
	// A batch of 10 makes 10 uploads and a submit: 20 tokens, refilling
	// at 100/s.
	for _, tc := range []struct {
		burst    float64
		inFlight int // at most
	}{{45, 4}, {11, 1}} {
		t.Run(fmt.Sprint("burst", tc.burst), func(t *testing.T) {
			t.Parallel()
			dst, clk := clockedTarget(t)
			for _, ns := range []string{"a", "b"} {
				dst.ns(ns, map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
					"bucket": map[string]any{"rate": 100, "burst": tc.burst}, "itemsPerBatch": 10}}})
			}
			log := &batchLog{rt: transport}
			c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: log})))
			var mu sync.Mutex
			var slept time.Duration
			rep, err := bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, Concurrency: 4, Now: clk.Now,
				Sleep: func(_ context.Context, d time.Duration) error {
					mu.Lock()
					defer mu.Unlock()
					slept += d
					clk.add(d)
					return nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			if got := batchSizes(rep); !slices.Equal(got, []int{10, 10, 10, 10, 10, 10, 10, 10}) || log.n429 != 0 {
				t.Fatalf("batches %v, %d 429s", got, log.n429)
			}
			// Two of each namespace's batches at once, which the burst
			// holds the draws of, or one at a time.
			if log.max > tc.inFlight {
				t.Fatalf("%d batches in flight at most", log.max)
			}
			// Each namespace: its first batch's uploads and dry run, then 3
			// batches' uploads and 4 submits, 120 tokens at 100/s; the
			// namespaces' waits overlap.
			if slept < 1200*time.Millisecond {
				t.Fatalf("slept %v", slept)
			}
			for _, ns := range []string{"a", "b"} {
				if dst.blobBytes(ns, "d39", dst.doc(ns, "d39")["b"].(map[string]any)) != ns+"d39" {
					t.Fatalf("%s not imported", ns)
				}
			}
		})
	}
}

// fastClock runs a hundred times faster than time, for server and importer
// alike: concurrent batches' waits overlap as they would.
type fastClock struct{ t0, start time.Time }

func newFastClock() *fastClock {
	return &fastClock{t0: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC), start: time.Now()}
}

func (c *fastClock) Now() time.Time { return c.t0.Add(100 * time.Since(c.start)) }

func (c *fastClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d / 100)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// A batch that fails stops the import: the batches in flight finish, and
// no other request is sent after it, not by a batch waiting at its gate,
// nor into a namespace that depends on the failed one's.
func TestImportConcurrentFailure(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin, fastLimits)
	src.ns("a", nil)
	for i := 0; i < 80; i++ {
		src.create("a", fmt.Sprintf("d%03d", i), map[string]any{"i": i})
	}
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"a"}})
	clk := newFastClock()
	dst := newDeployment(t, cmsOrigin, func(o *core.Options) { o.Now = clk.Now })
	// A batch of 10 a second: batches wait at the gate.
	dst.ns("a", map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
		"bucket": map[string]any{"rate": 1, "burst": 100}, "itemsPerBatch": 10}}})
	log := &batchLog{rt: transport, fail: func(ns string, resources []string) bool { return slices.Contains(resources, "d030") }}
	c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: log})))
	_, err := bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, Concurrency: 4,
		Now: clk.Now, Sleep: clk.Sleep})
	if err == nil || !strings.Contains(err.Error(), "refused by the test") {
		t.Fatalf("import: %v", err)
	}
	if log.failedAt == 0 {
		t.Fatal("no batch failed")
	}
	for _, x := range log.batches {
		if x.start > log.failedAt {
			t.Fatalf("a batch with %v sent after the failure", x.resources)
		}
		if x.end == 0 {
			t.Fatalf("a batch with %v still in flight", x.resources)
		}
	}

	// A namespace that depends on the failed one's gets no batch.
	content := contentBundle(t, contentShape{layouts: 4, pages: 20, items: 30, comments: 10, verifications: 2})
	allowance := map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
		"bucket": map[string]any{"rate": 1e6, "burst": 1e6}, "itemsPerBatch": 4}}}
	dst = newDeployment(t, cmsOrigin, fastLimits)
	log = &batchLog{rt: transport, fail: func(ns string, resources []string) bool {
		return ns == "cat-demo-upstream" && slices.Contains(resources, "item-20")
	}}
	c = must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: log})))
	_, err = bundle.Import(ctx, c, bundle.BytesOpener(content), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true,
		Concurrency: 4, NamespaceDoc: func(string, string) any { return allowance }})
	if err == nil || !strings.Contains(err.Error(), "refused by the test") {
		t.Fatalf("import: %v", err)
	}
	for _, x := range log.batches {
		if x.ns != "demo-schemas" && x.ns != "cat-demo-upstream" {
			t.Fatalf("a batch into %s after the failure", x.ns)
		}
	}
}

// An allowance that ends during a concurrent backfill: batches wait at the
// gate no longer than half the margin before its until, so each one goes
// out while the allowance holds, none answered 413 for the namespace's own
// limits (§6.6). At 0.5/s that leaves no room for two batches of 10: they
// go one at a time, and those after the allowance ends are split to fit
// the namespace's limits. At 2/s six wait at once; each is sent in time.
func TestImportConcurrentAllowanceEnds(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin, fastLimits)
	src.ns("data", nil)
	for i := 0; i < 100; i++ {
		src.create("data", fmt.Sprintf("d%03d", i), map[string]any{"i": i})
	}
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"data"}})
	for _, tc := range []struct {
		rate float64
		ends time.Duration
	}{{0.5, 100 * time.Second}, {2, 90 * time.Second}} {
		t.Run(fmt.Sprint("rate", tc.rate), func(t *testing.T) {
			t.Parallel()
			clk := newFastClock()
			dst := newDeployment(t, cmsOrigin, func(o *core.Options) { o.Now = clk.Now })
			dst.ns("data", map[string]any{"read": "public", "limits": map[string]any{"itemsPerBatch": 3},
				"allowances": []any{map[string]any{"sub": "alice", "kid": "any", "until": clk.Now().Add(tc.ends).Format(time.RFC3339),
					"bucket": map[string]any{"rate": tc.rate, "burst": 1000}, "itemsPerBatch": 10}}})
			log := &batchLog{rt: transport}
			c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: log})))
			rep, err := bundle.Import(ctx, c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, Concurrency: 8,
				Now: clk.Now, Sleep: clk.Sleep})
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			sizes := batchSizes(rep)
			if sizes[0] != 10 || tc.rate < 1 && (sizes[len(sizes)-1] > 3 || log.max > 1) {
				t.Fatalf("batches %v, %d in flight at most", sizes, log.max)
			}
		})
	}
}

// A namespace holding a schema and snapshot documents typed by it: the
// schema goes first, before the upstream namespace whose documents name it
// (§G.4.4 Order), though the two form a cycle.
func TestImportSchemaWithSnapshots(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("forms", nil)
	s := src.create("forms", "s", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	src.create("forms", "d", map[string]any{"$schema": rev("forms", "s", s), "title": "D"})
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"forms/d"}, Mode: bundle.Snapshot})
	for _, mode := range []bundle.ImportMode{bundle.Atomic, bundle.Backfill} {
		dst := newDeployment(t, cmsOrigin)
		rep := importB(t, dst, b, bundle.ImportOptions{Mode: mode, Pace: 1})
		if !slices.Equal(rep.Order, []string{"forms", "forms-upstream"}) || dst.head("forms", "d").State != client.Live {
			t.Fatalf("%s: order %v", mode, rep.Order)
		}
	}
}
