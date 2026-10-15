// Command capacity seeds a patchlog deployment to a given size and measures
// what a deployment of that size answers: writes, reads, log and /heads
// pages, full scans (what a consumer's catch-up or bootstrap costs), and
// appends to large documents. It talks to a running core over HTTP, so
// the numbers include the HTTP stack and are taken on the hardware it runs
// on: run it there (docs/CAPACITY.md).
//
//	patchlog serve -dev -addr :8080 -db /data/cap.db -origin http://localhost:8080 &
//	go run ./cmd/capacity -url http://localhost:8080 -docs 1000000 -revs 5000000
//
// The core must run with -dev: the loader names itself with X-Author and
// gives itself an allowance (§6.6) in the namespaces it creates, so seeding
// isn't held to the default rates (50 items/s a principal, 500 a
// namespace). Seeding is skipped for a namespace that already exists, so a
// second run measures the same data again.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
)

const author = "capacity"

type config struct {
	url         string
	big         string
	docs, revs  int
	docSize     int
	small       int
	smallDocs   int
	workers     int
	samples     int
	fetch       int
	large       string
	out         string
	liveURL     string
	waiters     string
	pid         int
	only        string
	appendBatch int
	operator    string
	readers     int
}

func main() {
	var c config
	flag.StringVar(&c.url, "url", "http://localhost:8080", "the core (serve -dev)")
	flag.StringVar(&c.big, "ns", "cap-big", "the large namespace")
	flag.IntVar(&c.docs, "docs", 1_000_000, "documents in the large namespace")
	flag.IntVar(&c.revs, "revs", 5_000_000, "revisions in the large namespace (at least -docs)")
	flag.IntVar(&c.docSize, "doc-size", 512, "approximate bytes per seeded document")
	flag.IntVar(&c.small, "namespaces", 1000, "small namespaces (cap-0001, …) besides the large one")
	flag.IntVar(&c.smallDocs, "namespace-docs", 10, "documents per small namespace")
	flag.IntVar(&c.workers, "seed-workers", 16, "concurrent seeding requests")
	flag.IntVar(&c.appendBatch, "append-batch", 1, "appends per seeding request: 1 writes each on its own, as most clients do, so the namespace log holds an entry per append; more makes batch entries (§7.5) of that many")
	flag.IntVar(&c.samples, "samples", 2000, "requests per latency measurement")
	flag.IntVar(&c.fetch, "fetch", 20000, "documents fetched in the bootstrap measurement")
	flag.StringVar(&c.large, "large-sizes", "16384,262144,1048576,3670016", "document sizes for the large-document appends ('' to skip)")
	flag.StringVar(&c.out, "json", "", "also write the results to this file")
	flag.StringVar(&c.liveURL, "live-url", "", "where long-poll followers connect: a CDN in front of -url (default -url itself)")
	flag.StringVar(&c.waiters, "waiters", "100,1000,5000", "long-poll followers of one namespace to measure ('' to skip)")
	flag.IntVar(&c.pid, "pid", 0, "the core's process id, to report the CPU time it spends per measurement (Linux)")
	flag.StringVar(&c.operator, "operator-seed", "", "grants profile: the private seed of the core's -operator-key (patchlog keygen); namespaces are then read: grant, and every request carries a signed grant (§C)")
	flag.IntVar(&c.readers, "readers", 5000, "grants profile: distinct reader grants the reads draw from (past the core's 1,024 cached bearers, most reads verify their grant)")
	flag.StringVar(&c.only, "only", "", "run only these phases, comma-separated: seed, scans, reads, writes, bootstrap, large, live")
	flag.Parse()
	if c.revs < c.docs {
		fail(errors.New("-revs must be at least -docs"))
	}
	r := &runner{c: c, ctx: context.Background(), res: map[string]any{}, hc: sharedHTTP(512)}
	r.cl = r.newClient(c.url, "")
	if c.operator != "" {
		op, err := grant.ParsePrivateKey(c.operator)
		if err != nil {
			fail(fmt.Errorf("-operator-seed: %w", err))
		}
		r.op = op
		r.keyPub, r.key = grant.GenerateKey()
		r.writers = map[string]*client.Client{}
		r.readerPools = map[string][]*client.Client{}
		r.res["profile"] = "grants"
	} else {
		r.res["profile"] = "public"
	}
	r.run()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "capacity:", err)
	os.Exit(1)
}

type runner struct {
	c  config
	cl *client.Client
	hc *http.Client
	// the grants profile: the operator key, the namespaces' key, and
	// clients by namespace
	op          ed25519.PrivateKey
	key         ed25519.PrivateKey
	keyPub      string
	mu          sync.Mutex
	writers     map[string]*client.Client
	readerPools map[string][]*client.Client
	ctx         context.Context
	res         map[string]any
	// what the scans found in the large namespace
	heads   []client.HeadItem
	entries []string // namespace entry ids, in log order
}

func (r *runner) logf(format string, a ...any) {
	fmt.Printf("%s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}

func (r *runner) record(name string, v any) {
	r.res[name] = v
	b, _ := json.Marshal(v)
	r.logf("%-28s %s", name, b)
}

// sharedHTTP is the HTTP client every harness client shares, so clients
// of many grants share connections.
func sharedHTTP(conns int) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns, t.MaxIdleConnsPerHost = conns, conns
	return &http.Client{Transport: t}
}

// newClient is a client of url with the shared connections, carrying
// token if given.
func (r *runner) newClient(url, token string) *client.Client {
	opts := []client.Option{client.WithHTTPClient(r.hc), client.WithAuthor(author)}
	if token != "" {
		opts = append(opts, client.WithBearer(token))
	}
	return must(client.New(url, opts...))
}

// The loader's principal in the grants profile, and its key's kid.
const loaderSub, keyKid = "user:capacity", "cap"

// nsDoc is the document of the namespaces the harness creates: public, or
// in the grants profile read: grant with the harness's key. Either way an
// allowance frees the loader from the default rates.
func (r *runner) nsDoc() map[string]any {
	bucket := map[string]any{"rate": 1e9, "burst": 1e9}
	if r.op == nil {
		return map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": author, "kid": "capacity", "bucket": bucket}}}
	}
	return map[string]any{"read": "grant",
		"keys":       []any{map[string]any{"kid": keyKid, "alg": "ed25519", "pub": r.keyPub, "can": []any{"read", "create", "append"}}},
		"allowances": []any{map[string]any{"sub": loaderSub, "kid": keyKid, "bucket": bucket}}}
}

func (r *runner) mint(signer ed25519.PrivateKey, root map[string]any) string {
	root["exp"] = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	g, err := grant.Mint(root, signer)
	if err != nil {
		fail(err)
	}
	return g.Encode()
}

// createNS creates ns: in the grants profile with an operator grant.
func (r *runner) createNS(ns string) {
	c := r.cl
	if r.op != nil {
		c = r.newClient(r.c.url, r.mint(r.op, map[string]any{"kid": "operator", "sub": "op:capacity", "ns": []any{ns}, "can": []any{"config"}}))
	}
	must(c.CreateNamespace(r.ctx, ns, r.nsDoc()))
}

// w is the loader's client for ns: its grant may read, create and append
// there.
func (r *runner) w(ns string) *client.Client {
	if r.op == nil {
		return r.cl
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.writers[ns]
	if c == nil {
		c = r.newClient(r.c.url, r.mint(r.key, map[string]any{"kid": keyKid, "sub": loaderSub, "ns": []any{ns}, "can": []any{"read", "create", "append"}}))
		r.writers[ns] = c
	}
	return c
}

// rd is a reader's client for ns, one of -readers readers each with a
// grant of its own (read, unrestricted), as a fleet of devices has.
func (r *runner) rd(ns string) *client.Client {
	return r.readerOf(ns, r.c.readers)
}

func (r *runner) readerOf(ns string, n int) *client.Client {
	if r.op == nil {
		return r.cl
	}
	k := fmt.Sprintf("%s/%d", ns, n)
	r.mu.Lock()
	defer r.mu.Unlock()
	pool := r.readerPools[k]
	if len(pool) < n {
		c := r.newClient(r.c.url, r.mint(r.key, map[string]any{"kid": keyKid, "sub": fmt.Sprintf("user:reader-%d", len(pool)), "ns": []any{ns}, "can": []any{"read"}}))
		r.readerPools[k] = append(pool, c)
		return c
	}
	return pool[rand.IntN(n)]
}

func (r *runner) run() {
	start := time.Now()
	on := func(p string) bool { return r.c.only == "" || strings.Contains(","+r.c.only+",", ","+p+",") }
	if on("seed") {
		r.seedBig()
		r.seedSmall()
	}
	if on("scans") || on("reads") || on("writes") || on("bootstrap") {
		r.scans()
	}
	if on("reads") {
		r.reads()
	}
	if on("writes") {
		r.writes()
	}
	if on("bootstrap") {
		r.bootstrap()
	}
	if on("large") {
		r.largeDocs()
	}
	if on("live") {
		r.live()
	}
	if r.c.pid != 0 {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", r.c.pid)); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if f := strings.Fields(l); len(f) >= 2 && (f[0] == "VmHWM:" || f[0] == "VmRSS:") {
					var kb float64
					fmt.Sscan(f[1], &kb)
					r.record("origin_"+strings.ToLower(strings.TrimSuffix(f[0], ":"))+"_mb", kb/1024)
				}
			}
		}
	}
	r.record("total_seconds", time.Since(start).Seconds())
	if r.c.out != "" {
		b, _ := json.MarshalIndent(r.res, "", "  ")
		if err := os.WriteFile(r.c.out, b, 0o644); err != nil {
			fail(err)
		}
	}
}

// exists reports whether ns exists already.
func (r *runner) exists(ns string) bool {
	_, err := r.w(ns).NSHead(r.ctx, ns)
	return err == nil
}

func (r *runner) body(i, n int) map[string]any {
	pad := r.c.docSize - 60
	if pad < 0 {
		pad = 0
	}
	return map[string]any{"title": fmt.Sprintf("document %d", i), "n": n, "body": strings.Repeat("x", pad)}
}

func docName(i int) string { return fmt.Sprintf("d%07d", i) }

// seedBig creates the large namespace: -docs documents in batches of
// 1,000, then appends to them, a batch writing 1,000 distinct documents,
// until it holds -revs revisions.
func (r *runner) seedBig() {
	ns := r.c.big
	if r.exists(ns) {
		r.logf("%s exists; not seeding it", ns)
		return
	}
	r.createNS(ns)
	heads := make([]string, r.c.docs)
	t0 := time.Now()
	var done atomic.Int64
	batches := func(total, per int, item func(i int) client.BatchItem, after func(i int, res client.BatchItemResult)) {
		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < r.c.workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for from := range jobs {
					to := min(from+per, total)
					items := make([]client.BatchItem, 0, to-from)
					for i := from; i < to; i++ {
						items = append(items, item(i))
					}
					if len(items) == 1 && items[0].IfMatch != "" {
						// One append on its own: a single write, not a batch.
						it := items[0]
						w, err := retry(func() (*client.WriteResult, error) {
							return r.w(ns).Append(r.ctx, ns, it.Resource, it.IfMatch, it.Steps[0].Patches)
						})
						if err != nil {
							fail(fmt.Errorf("seeding %s: %w", ns, err))
						}
						after(from, client.BatchItemResult{Resource: it.Resource, IDs: []string{w.ID}})
					} else {
						res, err := retry(func() (*client.BatchResult, error) {
							return r.w(ns).Batch(r.ctx, ns, client.BatchRequest{Items: items}, false)
						})
						if err != nil {
							fail(fmt.Errorf("seeding %s: %w", ns, err))
						}
						for k, it := range res.Items {
							after(from+k, it)
						}
					}
					if n := done.Add(int64(to - from)); n/100_000 != (n-int64(to-from))/100_000 {
						r.logf("seeded %d revisions (%.0f/s)", n, float64(n)/time.Since(t0).Seconds())
					}
				}
			}()
		}
		for from := 0; from < total; from += per {
			jobs <- from
		}
		close(jobs)
		wg.Wait()
	}
	batches(r.c.docs, 1000, func(i int) client.BatchItem {
		return client.BatchItem{Resource: docName(i), IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(r.body(i, 0)))}}
	}, func(i int, res client.BatchItemResult) { heads[i] = last(res.IDs) })
	created := time.Since(t0)
	// Appends: in passes over the documents, each writing every document
	// at most once, so concurrent batches never write the same document;
	// a pass ends before the next starts.
	appends := r.c.revs - r.c.docs
	var mu sync.Mutex
	pass := func(from, n int) {
		batches(n, r.c.appendBatch, func(k int) client.BatchItem {
			i := (from + k) % r.c.docs
			mu.Lock()
			h := heads[i]
			mu.Unlock()
			return client.BatchItem{Resource: docName(i), IfMatch: h,
				Steps: []client.Step{client.PatchStep([]any{map[string]any{"op": "replace", "path": "/n", "value": from + k}})}}
		}, func(k int, res client.BatchItemResult) {
			mu.Lock()
			heads[(from+k)%r.c.docs] = last(res.IDs)
			mu.Unlock()
		})
	}
	for off := 0; off < appends; off += r.c.docs {
		pass(off, min(r.c.docs, appends-off))
	}
	total := time.Since(t0)
	r.record("seed_big", map[string]any{"docs": r.c.docs, "revisions": r.c.revs, "doc_bytes": r.c.docSize,
		"create_seconds": created.Seconds(), "total_seconds": total.Seconds(),
		"revisions_per_second": float64(r.c.revs) / total.Seconds()})
}

// seedSmall creates the small namespaces, each with a batch of documents.
func (r *runner) seedSmall() {
	t0 := time.Now()
	made := 0
	for i := 1; i <= r.c.small; i++ {
		ns := fmt.Sprintf("cap-%04d", i)
		if r.exists(ns) {
			continue
		}
		r.createNS(ns)
		var items []client.BatchItem
		for j := 0; j < r.c.smallDocs; j++ {
			items = append(items, client.BatchItem{Resource: docName(j), IfNoneMatch: true,
				Steps: []client.Step{client.PatchStep(client.GenesisPatches(r.body(j, 0)))}})
		}
		if len(items) > 0 {
			must(r.w(ns).Batch(r.ctx, ns, client.BatchRequest{Items: items}, false))
		}
		made++
	}
	if made > 0 {
		r.record("seed_small", map[string]any{"namespaces": made, "seconds": time.Since(t0).Seconds()})
	}
}

// scans reads the large namespace's whole /heads listing and its whole
// log, a page at a time: what a consumer's bootstrap and catch-up read
// before fetching any document.
func (r *runner) scans() {
	ns := r.c.big
	head := must(r.w(ns).NSHead(r.ctx, ns)).ID
	t0 := time.Now()
	pages, after := 0, ""
	r.heads = r.heads[:0]
	for {
		items, next, err := r.w(ns).HeadsPage(r.ctx, ns, head, after)
		if err != nil {
			fail(err)
		}
		r.heads = append(r.heads, items...)
		pages++
		if next == "" {
			break
		}
		after = next
	}
	d := time.Since(t0)
	r.record("scan_heads", map[string]any{"resources": len(r.heads), "pages": pages, "seconds": d.Seconds(),
		"resources_per_second": float64(len(r.heads)) / d.Seconds()})

	t0 = time.Now()
	pages, since := 0, ""
	r.entries = r.entries[:0]
	units := 0
	for {
		es, _, err := r.w(ns).NSLogPage(r.ctx, ns, head, since)
		if err != nil {
			fail(err)
		}
		for _, e := range es {
			r.entries = append(r.entries, e.ID)
			units += max(1, len(e.Entries))
		}
		pages++
		if len(es) == 0 || es[len(es)-1].ID == head {
			break
		}
		since = es[len(es)-1].ID
	}
	d = time.Since(t0)
	r.record("scan_log", map[string]any{"entries": len(r.entries), "resource_entries": units, "pages": pages,
		"seconds": d.Seconds(), "entries_per_second": float64(len(r.entries)) / d.Seconds()})
}

// reads measures single requests at random positions of the large
// namespace.
func (r *runner) reads() {
	ns := r.c.big
	head := must(r.w(ns).NSHead(r.ctx, ns)).ID
	pick := func() client.HeadItem { return r.heads[rand.IntN(len(r.heads))] }
	r.record("read_head_doc", r.measure(8, func() error {
		h := pick()
		_, err := r.rd(ns).Doc(r.ctx, ns, h.Resource, h.Target)
		return err
	}))
	if r.op != nil {
		// The same reads from 16 readers, whose grants stay in the core's
		// bearer cache.
		r.record("read_head_doc_cached_grants", r.measure(8, func() error {
			h := pick()
			_, err := r.readerOf(ns, 16).Doc(r.ctx, ns, h.Resource, h.Target)
			return err
		}))
	}
	r.record("read_head_pointer", r.measure(8, func() error {
		_, err := r.rd(ns).Head(r.ctx, ns, pick().Resource)
		return err
	}))
	r.record("read_old_revision", r.measure(8, func() error {
		h := pick()
		// The resource's log, then its first revision: a fold from the
		// genesis (or the nearest snapshot), uncached.
		lg, _, err := r.rd(ns).LogPage(r.ctx, ns, h.Resource, h.Target, "")
		if err != nil || len(lg) == 0 {
			return err
		}
		_, err = r.rd(ns).Doc(r.ctx, ns, h.Resource, lg[0].ID)
		return err
	}))
	r.record("ns_log_page_random", r.measure(8, func() error {
		_, _, err := r.w(ns).NSLogPage(r.ctx, ns, head, r.entries[rand.IntN(len(r.entries))])
		return err
	}))
	r.record("heads_page_random", r.measure(8, func() error {
		_, _, err := r.w(ns).HeadsPage(r.ctx, ns, head, pick().Resource)
		return err
	}))
	if r.c.small > 0 {
		r.record("read_small_ns_doc", r.measure(8, func() error {
			ns := fmt.Sprintf("cap-%04d", 1+rand.IntN(r.c.small))
			name := docName(rand.IntN(max(1, r.c.smallDocs)))
			h, err := r.rd(ns).Head(r.ctx, ns, name)
			if err != nil || h.ID == "" {
				return err
			}
			_, err = r.rd(ns).Doc(r.ctx, ns, name, h.ID)
			return err
		}))
	}
}

// writes measures single appends from concurrent writers to distinct
// documents, in the large namespace and spread over the small ones, and
// batches of 1,000 appends.
func (r *runner) writes() {
	ns := r.c.big
	var mu sync.Mutex
	next := 0
	// Each write takes a document no other write of the run takes (per
	// resource rate: 10/s).
	take := func() int {
		mu.Lock()
		defer mu.Unlock()
		next++
		return (next * 7919) % len(r.heads)
	}
	// moved records a write's new head, should a later one take the
	// document again (a namespace smaller than the samples).
	moved := func(i int, id string) {
		mu.Lock()
		r.heads[i].Target = id
		mu.Unlock()
	}
	headOf := func(i int) client.HeadItem {
		mu.Lock()
		defer mu.Unlock()
		return r.heads[i]
	}
	for _, c := range []int{1, 8, 32} {
		r.record(fmt.Sprintf("append_big_c%d", c), r.measure(c, func() error {
			i := take()
			h := headOf(i)
			w, err := r.w(ns).Append(r.ctx, ns, h.Resource, h.Target, []any{map[string]any{"op": "replace", "path": "/n", "value": -1}})
			if err == nil {
				moved(i, w.ID)
			}
			return err
		}))
	}
	if r.c.small > 0 && r.c.smallDocs > 0 {
		r.record("append_small_ns_c32", r.measure(32, func() error {
			ns := fmt.Sprintf("cap-%04d", 1+rand.IntN(r.c.small))
			name := docName(rand.IntN(r.c.smallDocs))
			h, err := r.w(ns).Head(r.ctx, ns, name)
			if err != nil {
				return err
			}
			_, err = r.w(ns).Append(r.ctx, ns, name, h.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": -1}})
			if ae, ok := client.AsAPIError(err); ok && (ae.Status == 412 || ae.Status == 429) {
				return nil // two writers met on one document, or its rate
			}
			return err
		}))
	}
	old := r.c.samples
	r.c.samples = 20
	r.record("batch_1000_appends", r.measure(1, func() error {
		items := make([]client.BatchItem, 0, 1000)
		var took []int
		for len(items) < 1000 {
			i := take()
			h := headOf(i)
			took = append(took, i)
			items = append(items, client.BatchItem{Resource: h.Resource, IfMatch: h.Target,
				Steps: []client.Step{client.PatchStep([]any{map[string]any{"op": "replace", "path": "/n", "value": -2}})}})
		}
		res, err := r.w(ns).Batch(r.ctx, ns, client.BatchRequest{Items: items}, false)
		if err == nil {
			for k, it := range res.Items {
				moved(took[k], last(it.IDs))
			}
		}
		return err
	}))
	r.c.samples = old
}

// bootstrap measures what an index-like consumer's bootstrap costs past
// the /heads scan: fetching documents, 8 at a time, as the index does.
func (r *runner) bootstrap() {
	n := min(r.c.fetch, len(r.heads))
	if n == 0 {
		return
	}
	idx := rand.Perm(len(r.heads))[:n]
	jobs := make(chan int)
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				h := r.heads[i]
				if _, err := r.rd(r.c.big).Doc(r.ctx, r.c.big, h.Resource, h.Target); err != nil {
					fail(err)
				}
			}
		}()
	}
	for _, i := range idx {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	d := time.Since(t0)
	rate := float64(n) / d.Seconds()
	r.record("bootstrap_doc_fetch_c8", map[string]any{"documents": n, "seconds": d.Seconds(), "documents_per_second": rate,
		"projected_seconds_for_namespace": float64(len(r.heads)) / rate})
}

// largeDocs measures appends of a small patch to documents of growing
// size: every append re-reads, re-serialises and checks the whole
// document.
func (r *runner) largeDocs() {
	if r.c.large == "" {
		return
	}
	ns := r.c.big + "-large"
	if !r.exists(ns) {
		r.createNS(ns)
	}
	out := map[string]any{}
	for _, s := range strings.Split(r.c.large, ",") {
		var size int
		if _, err := fmt.Sscan(s, &size); err != nil {
			fail(fmt.Errorf("-large-sizes: %w", err))
		}
		// Many small values, as a large structured document has, each
		// under valueSize.
		doc := map[string]any{"n": 0}
		items := []any{}
		for b := 0; b < size; b += 1024 {
			items = append(items, strings.Repeat("y", 1000))
		}
		doc["items"] = items
		name := fmt.Sprintf("large-%d-%d", size, time.Now().UnixNano())
		w, err := r.w(ns).CreateDoc(r.ctx, ns, name, doc)
		if err != nil {
			fail(fmt.Errorf("creating a %d-byte document: %w", size, err))
		}
		id := w.ID
		var lat []time.Duration
		for i := 1; i <= 60; i++ {
			t := time.Now()
			w, err := r.w(ns).Append(r.ctx, ns, name, id, []any{map[string]any{"op": "replace", "path": "/n", "value": i}})
			if ae, ok := client.AsAPIError(err); ok && ae.Status == 429 {
				time.Sleep(200 * time.Millisecond) // the resource's rate (10/s)
				i--
				continue
			}
			if err != nil {
				fail(err)
			}
			lat = append(lat, time.Since(t))
			id = w.ID
		}
		out[fmt.Sprint(size)] = summary(lat, 0)
	}
	r.record("append_large_doc", out)
}

// live measures long-poll followers (§7.7) of one namespace: w followers
// wait on the same URL (the namespace's head as since, no cursor), one
// write lands, and each follower's wait ends with it. Through a CDN that
// collapses identical misses (-live-url), the origin answers one request
// for all of them; directly, every follower is a request of its own that
// the write wakes and that reads the log again.
func (r *runner) live() {
	if r.c.waiters == "" {
		return
	}
	ns := r.c.big + "-live"
	if !r.exists(ns) {
		r.createNS(ns)
		must(r.w(ns).CreateDoc(r.ctx, ns, "doc", map[string]any{"n": 0}))
	}
	url := r.c.liveURL
	if url == "" {
		url = r.c.url
	}
	out := map[string]any{"via": url}
	for _, s := range strings.Split(r.c.waiters, ",") {
		var w int
		if _, err := fmt.Sscan(s, &w); err != nil {
			fail(fmt.Errorf("-waiters: %w", err))
		}
		hc := sharedHTTP(w + 16)
		lcs := make([]*client.Client, w)
		for i := range lcs {
			opts := []client.Option{client.WithHTTPClient(hc)}
			if r.op != nil {
				opts = append(opts, client.WithBearer(r.mint(r.key, map[string]any{"kid": keyKid, "sub": fmt.Sprintf("user:device-%d", i), "ns": []any{ns}, "can": []any{"read"}})))
			}
			lcs[i] = must(client.New(url, opts...))
		}
		head := must(r.w(ns).NSHead(r.ctx, ns)).ID
		ctx, cancel := context.WithTimeout(r.ctx, 2*time.Minute)
		var parked atomic.Int64
		got := make([]time.Time, w)
		var errs atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < w; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				since, cursor := head, ""
				parked.Add(1)
				for ctx.Err() == nil {
					res, err := lcs[i].LongPoll(ctx, ns, since, cursor)
					if err != nil {
						if errs.Add(1) == 1 {
							r.logf("long-poll: %v", err)
						}
						time.Sleep(100 * time.Millisecond)
						continue
					}
					if len(res.Entries) > 0 {
						got[i] = time.Now()
						return
					}
					since, cursor = res.Since, res.Cursor
				}
			}()
		}
		for parked.Load() < int64(w) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(2 * time.Second) // their requests reach the origin, or the CDN's waiting list
		cpu0 := r.cpu()
		t0 := time.Now()
		h := must(r.w(ns).Head(r.ctx, ns, "doc"))
		must(r.w(ns).Append(r.ctx, ns, "doc", h.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": t0.UnixMilli()}}))
		wg.Wait()
		cancel()
		cpu := r.cpu() - cpu0
		var lat []time.Duration
		for _, t := range got {
			if !t.IsZero() {
				lat = append(lat, t.Sub(t0))
			}
		}
		res := map[string]any{"delivered": len(lat), "errors": errs.Load()}
		if len(lat) > 0 {
			res["latency"] = summary(lat, 0)
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			res["all_delivered_ms"] = float64(lat[len(lat)-1].Microseconds()) / 1000
		}
		if r.c.pid != 0 {
			res["origin_cpu_seconds"] = cpu
		}
		out[fmt.Sprint(w)] = res
	}
	r.record("long_poll_fanout", out)
}

// cpu is the core's user and system CPU time so far, in seconds (0
// without -pid).
func (r *runner) cpu() float64 {
	if r.c.pid == 0 {
		return 0
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", r.c.pid))
	if err != nil {
		return 0
	}
	// The fields after the command name (which may hold spaces): utime
	// and stime are the 12th and 13th, in clock ticks (100 a second).
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	var u, s float64
	fmt.Sscan(f[11], &u)
	fmt.Sscan(f[12], &s)
	return (u + s) / 100
}

// measure runs fn -samples times from c concurrent callers.
func (r *runner) measure(c int, fn func() error) map[string]any {
	n := r.c.samples
	lat := make([]time.Duration, n)
	var i atomic.Int64
	var errs atomic.Int64
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				k := int(i.Add(1)) - 1
				if k >= n {
					return
				}
				t := time.Now()
				if err := fn(); err != nil {
					if errs.Add(1) == 1 {
						r.logf("error: %v", err)
					}
				}
				lat[k] = time.Since(t)
			}
		}()
	}
	wg.Wait()
	s := summary(lat, time.Since(t0))
	s["concurrency"] = c
	s["errors"] = errs.Load()
	return s
}

func summary(lat []time.Duration, wall time.Duration) map[string]any {
	s := append([]time.Duration(nil), lat...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) float64 { return float64(s[int(p*float64(len(s)-1))].Microseconds()) / 1000 }
	out := map[string]any{"n": len(s), "p50_ms": q(0.5), "p95_ms": q(0.95), "p99_ms": q(0.99), "max_ms": q(1)}
	if wall > 0 {
		out["per_second"] = float64(len(s)) / wall.Seconds()
	}
	return out
}

func retry[T any](f func() (T, error)) (T, error) {
	var v T
	var err error
	for i := 0; i < 5; i++ {
		if v, err = f(); err == nil || !client.Retryable(err) {
			return v, err
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return v, err
}

func must[T any](v T, err error) T {
	if err != nil {
		fail(err)
	}
	return v
}

func last(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[len(ids)-1]
}
