package bundle_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schema"
)

// contentShape sizes a synthetic CMS content bundle (contentBundle): its
// documents per namespace. Layouts are the large ones.
type contentShape struct {
	layouts, pages, items, comments, verifications, data int
}

// demoContent is shaped like a CMS deployment's content: about 6,950
// snapshot documents and 130 MB, 350 of them layouts of 100–450 KB,
// deeply nested, with many internal ids and pinned references.
var demoContent = contentShape{layouts: 350, pages: 2600, items: 2200, comments: 1700, verifications: 50}

// scaled is the shape with every count multiplied by f (at least one).
func (s contentShape) scaled(f float64) contentShape {
	n := func(c int) int {
		if c == 0 {
			return 0
		}
		return max(1, int(float64(c)*f))
	}
	return contentShape{n(s.layouts), n(s.pages), n(s.items), n(s.comments), n(s.verifications), n(s.data)}
}

// contentBundle writes a snapshot bundle of the shape: schemas in
// demo-schemas (full), layouts and pages in demo, catalogue items in
// cat-demo, comments in demo-comments, verifications in
// domain-verifications and, if any, small data items in demo-data. Layouts
// pin items (x-ref pinned, rewritten on import) and link pages (live);
// pages pin their layout. Documents are generated from their index, so the
// bundle is the same every time.
func contentBundle(tb testing.TB, s contentShape) []byte {
	tb.Helper()
	at := func(ns string) string { return fakeID("at " + ns) }
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{}, Docs: map[string]bundle.DocInfo{},
		Access: map[string]string{}}
	nss := []string{"demo-schemas", "demo", "cat-demo", "demo-comments", "domain-verifications"}
	if s.data > 0 {
		nss = append(nss, "demo-data")
	}
	for _, ns := range nss {
		h.At[ns], h.Access[ns] = at(ns), bundle.AccessPublic
	}
	schemas := contentSchemas()
	schemaIDs := map[string]string{}
	for _, name := range sortedNames(schemas) {
		id := must(client.ExpectedRevision("", client.GenesisPatches(schemas[name])))
		schemaIDs[name] = id
		h.Docs[bundle.Key("demo-schemas", name)] = bundle.DocInfo{History: bundle.Full, Head: id}
	}
	type gen struct {
		ns, prefix string
		n          int
		doc        func(i int, r *rand.Rand) map[string]any
	}
	snapID := func(ns, name string) string { return fakeID(ns + "/" + name) }
	pin := func(ns, name string) string { return rev(ns, name, snapID(ns, name)) }
	typed := func(schemaName string, doc map[string]any) map[string]any {
		doc["$schema"] = rev("demo-schemas", schemaName, schemaIDs[schemaName])
		return doc
	}
	gens := []gen{
		{"cat-demo", "item-", s.items, func(i int, r *rand.Rand) map[string]any {
			return typed("item", map[string]any{"title": words(r, 4), "price": float64(r.Intn(10000)) / 100,
				"image":       map[string]any{"url": fmt.Sprintf("https://img.example/%d.jpg", i), "alt": words(r, 6)},
				"description": words(r, 300+r.Intn(200)), "tags": []any{words(r, 1), words(r, 1), words(r, 1)}})
		}},
		{"demo", "layout-", s.layouts, func(i int, r *rand.Rand) map[string]any {
			size := 100<<10 + r.Intn(350<<10)
			nodes := 0
			root := layoutNode(r, 0, size/420, &nodes, func() string {
				return pin("cat-demo", fmt.Sprintf("item-%d", r.Intn(max(1, s.items))))
			}, func() string { return fmt.Sprintf("/r/demo/page-%d", r.Intn(max(1, s.pages))) })
			return typed("layout", map[string]any{"title": words(r, 5), "root": root})
		}},
		{"demo", "page-", s.pages, func(i int, r *rand.Rand) map[string]any {
			var blocks []any
			for k := 0; k < 12; k++ {
				blocks = append(blocks, map[string]any{"id": hexID(r), "kind": "text", "text": words(r, 100+r.Intn(60))})
			}
			return typed("page", map[string]any{"title": words(r, 5), "slug": fmt.Sprintf("page-%d", i),
				"layout": pin("demo", fmt.Sprintf("layout-%d", r.Intn(max(1, s.layouts)))), "blocks": blocks})
		}},
		{"demo-comments", "comment-", s.comments, func(i int, r *rand.Rand) map[string]any {
			return typed("comment", map[string]any{"on": fmt.Sprintf("/r/demo/page-%d", r.Intn(max(1, s.pages))),
				"author": words(r, 2), "text": words(r, 40+r.Intn(120)), "created": "2026-09-01T12:00:00Z"})
		}},
		{"domain-verifications", "domain-", s.verifications, func(i int, r *rand.Rand) map[string]any {
			return map[string]any{"domain": fmt.Sprintf("d%d.example", i), "token": hexID(r) + hexID(r)}
		}},
		{"demo-data", "row-", s.data, func(i int, r *rand.Rand) map[string]any {
			return map[string]any{"k": fmt.Sprint("row", i), "v": r.Intn(1e6), "label": words(r, 6)}
		}},
	}
	for _, g := range gens {
		for i := 0; i < g.n; i++ {
			name := g.prefix + strconv.Itoa(i)
			h.Docs[bundle.Key(g.ns, name)] = bundle.DocInfo{History: bundle.Snapshot, Head: snapID(g.ns, name)}
		}
	}
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	for _, name := range sortedNames(schemas) {
		noErr(tb, w.Line(bundle.Line{NS: "demo-schemas", Resource: name, ID: schemaIDs[name], Kind: "rev",
			Patches: client.GenesisPatches(schemas[name])}))
	}
	for _, g := range gens {
		for i := 0; i < g.n; i++ {
			name := g.prefix + strconv.Itoa(i)
			r := rand.New(rand.NewSource(int64(len(g.ns))<<32 + int64(i)))
			b := must(json.Marshal(g.doc(i, r)))
			noErr(tb, w.SnapshotDoc(g.ns, name, snapID(g.ns, name), json.RawMessage(b), false))
		}
	}
	must(w.Close())
	return buf.Bytes()
}

// contentSchemas are the schemas of contentBundle. A layout is a tree of
// nodes ($defs/node, recursive) that may pin an item and link a page.
func contentSchemas() map[string]any {
	str := map[string]any{"type": "string"}
	obj := func(props map[string]any) map[string]any {
		return map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": props}
	}
	node := map[string]any{"type": "object", "properties": map[string]any{
		"id": str, "type": str,
		"props":    map[string]any{"type": "object"},
		"image":    map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}},
		"link":     map[string]any{"type": "string", "x-ref": map[string]any{}},
		"children": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/node"}},
	}}
	layout := obj(map[string]any{"title": str, "root": map[string]any{"$ref": "#/$defs/node"}})
	layout["$defs"] = map[string]any{"node": node}
	return map[string]any{
		"layout": layout,
		"page": obj(map[string]any{"title": str, "slug": str, "blocks": map[string]any{"type": "array"},
			"layout": map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}}}),
		"item": obj(map[string]any{"title": str, "price": map[string]any{"type": "number"}, "image": map[string]any{"type": "object"},
			"description": str, "tags": map[string]any{"type": "array", "items": str}}),
		"comment": obj(map[string]any{"on": map[string]any{"type": "string", "x-ref": map[string]any{}}, "author": str, "text": str, "created": str}),
	}
}

// layoutNode generates a layout subtree of about budget nodes (counted in
// n), at most 12 deep.
func layoutNode(r *rand.Rand, depth, budget int, n *int, item, page func() string) map[string]any {
	*n++
	kinds := []string{"Section", "Row", "Column", "Text", "Image", "Button", "Card", "Grid"}
	nd := map[string]any{"id": "n-" + hexID(r), "type": kinds[r.Intn(len(kinds))], "props": map[string]any{
		"style": map[string]any{"margin": r.Intn(40), "padding": r.Intn(40), "color": "#" + hexID(r)[:6], "align": "start",
			"width": fmt.Sprint(r.Intn(100), "%"), "gap": r.Intn(24)},
		"text": words(r, 8+r.Intn(30)), "visible": true, "order": r.Intn(100), "anchor": "a-" + hexID(r)}}
	switch r.Intn(6) {
	case 0:
		nd["image"] = item()
	case 1:
		nd["link"] = page()
	}
	if budget > 1 && depth < 12 {
		kids := min(budget-1, 2+r.Intn(4))
		var children []any
		left := budget - 1
		for k := 0; k < kids && left > 0; k++ {
			share := left / (kids - k)
			children = append(children, layoutNode(r, depth+1, share, n, item, page))
			left -= share
		}
		nd["children"] = children
	}
	return nd
}

var lorem = strings.Fields("lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat")

func words(r *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(lorem[r.Intn(len(lorem))])
	}
	return b.String()
}

func hexID(r *rand.Rand) string { return fmt.Sprintf("%08x", r.Uint32()) }

// fakeID is a well-formed revision id derived from s.
func fakeID(s string) string {
	return must(client.ExpectedRevision("", client.GenesisPatches(s)))
}

func sortedNames(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	contentOnce sync.Once
	contentData []byte
)

// BenchmarkImportContent imports a synthetic CMS content bundle
// (contentBundle, demoContent; PATCHLOG_CONTENT_SCALE scales it) into a
// fresh deployment as a snapshot backfill under an allowance of 10,000/s
// (PATCHLOG_CONTENT_OUT, if set, names a file to write the bundle to),
// then again into the target that has it (/again). It reports the
// report's timings per import (planning-s, batches-s, total-s), the
// requests the importer sent, and the peak heap of the process, the
// in-process server's included (peak-heap-MiB):
//
//	go test ./internal/bundle -run '^$' -bench ImportContent -benchtime 1x -cpuprofile cpu.out
func BenchmarkImportContent(b *testing.B) {
	shape := demoContent
	if f, err := strconv.ParseFloat(os.Getenv("PATCHLOG_CONTENT_SCALE"), 64); err == nil {
		shape = shape.scaled(f)
	}
	contentOnce.Do(func() {
		t0 := time.Now()
		contentData = contentBundle(b, shape)
		if out := os.Getenv("PATCHLOG_CONTENT_OUT"); out != "" {
			// The bundle, for a run of patchlog import.
			noErr(b, os.WriteFile(out, contentData, 0o644))
		}
		b.Logf("bundle: %d documents, %.1f MB, generated in %s", shape.layouts+shape.pages+shape.items+shape.comments+shape.verifications+shape.data,
			float64(len(contentData))/1e6, time.Since(t0).Round(time.Millisecond))
	})
	// The importer's allowance in the namespaces it creates (§6.6).
	allowance := map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
		"bucket": map[string]any{"rate": 10000, "burst": 50000}}}}
	for _, variant := range []string{"", "/again"} {
		b.Run("snapshot"+variant, func(b *testing.B) {
			var planning, batches, total float64
			var reqs int64
			var peak uint64
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				dst := newDeployment(b, cmsOrigin, fastLimits)
				imp := func(rt *countingTransport) (*bundle.Report, error) {
					c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: rt})))
					return bundle.Import(ctx, c, bundle.BytesOpener(contentData), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true,
						NamespaceDoc: func(string, string) any { return allowance }})
				}
				if variant == "/again" {
					if _, err := imp(&countingTransport{rt: transport}); err != nil {
						b.Fatal(err)
					}
				}
				rt := &countingTransport{rt: transport}
				runtime.GC()
				stop := sampleHeap(&peak)
				b.StartTimer()
				rep, err := imp(rt)
				stop()
				if err != nil {
					b.Fatal(err)
				}
				planning, batches, total = planning+rep.Timings.Planning, batches+rep.Timings.Batches, total+rep.Timings.Total
				reqs += rt.n.Load()
			}
			n := float64(b.N)
			b.ReportMetric(planning/n, "planning-s")
			b.ReportMetric(batches/n, "batches-s")
			b.ReportMetric(total/n, "total-s")
			b.ReportMetric(float64(reqs)/n, "req/op")
			b.ReportMetric(float64(peak)/(1<<20), "peak-heap-MiB")
		})
	}
}

// sampleHeap records the peak live heap in *peak until stop is called.
func sampleHeap(peak *uint64) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	go func() {
		defer close(finished)
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			metrics.Read(sample)
			*peak = max(*peak, sample[0].Value.Uint64())
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	return func() { close(done); <-finished }
}
