package bundle_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
)

// A synthetic copy of a deployment whose import was measured (Demo Play,
// 2026-10-09): its namespaces, document kinds, and their sizes as bundle
// lines (median, 95th percentile and largest, in bytes). At full scale it
// has the deployment's 64,887 documents in about 294 MB (the deployment's
// bundle: 378 MB), of which its content (all but demo-data) 16,355
// documents in about 120 MB (141 MB).
//
//   - demo-schemas: 11 schemas (full; one has two revisions) and 3 other
//     documents.
//   - demo: 1,149 blueprints, schemas of demo-data's rows (full, one
//     revision each), and snapshot documents of the kinds below, typed by
//     demo-schemas, many naming a blueprint live; 18 of them reference a
//     blob, one of 4.6 MB.
//   - cat-demo: 8,241 small catalogue items; demo-comments: 14 comments;
//     domain-verifications: 1.
//   - demo-data: 48,532 rows, most typed by a blueprint.
type demoKind struct {
	ns, prefix, schema string // schema: a demo-schemas name, "" untyped
	n                  int
	median, p95, max   int
}

var demoKinds = []demoKind{
	{"demo", "layout", "layout", 747, 46187, 476318, 2491412},
	{"demo", "logic", "logic", 1631, 3213, 16666, 1549710},
	{"demo", "workflow", "workflow", 4279, 1657, 19064, 323315},
	{"demo", "route", "route", 104, 556, 12030, 78406},
	{"demo", "source", "source", 112, 696, 902, 1282},
	{"demo", "transport", "transport", 29, 1563, 24310, 27956},
	{"demo", "values", "values", 14, 7559, 66442, 66442},
	{"demo", "screen", "screen", 16, 410, 425, 425},
	{"demo", "domain", "domain", 3, 302, 302, 302},
	{"demo", "canvas", "canvas", 1, 119, 119, 119},
	{"cat-demo", "item", "", 8241, 225, 227, 648},
	{"demo-comments", "comment", "comment", 14, 804, 9995, 9995},
	{"domain-verifications", "domain", "", 1, 158, 158, 158},
	{"demo-schemas", "settings", "", 3, 38387, 50760, 50760},
}

// demoBlueprints and demoData are the blueprints' and rows' shapes.
var (
	demoBlueprints = demoKind{"demo", "blueprint", "", 1149, 611, 3181, 62165}
	demoData       = demoKind{"demo-data", "row", "", 48532, 1294, 12718, 387612}
)

// demoBlobs are the blobs: per kind, sizes of their bundle lines, which
// carry the bytes in base64.
var demoBlobs = map[string][]int{
	"layout":   {94059, 94059, 94059, 94059, 94059, 94059, 50000, 60000, 80000, 120000, 200000, 400000, 674501},
	"logic":    {128998, 128998, 60000, 291290},
	"workflow": {4579735},
}

// size picks the i-th document's size from a lognormal with the kind's
// median and 95th percentile, the first at the largest.
func (k demoKind) size(r *rand.Rand, i int) int {
	if i == 0 {
		return k.max
	}
	sigma := 0.0
	if k.p95 > k.median {
		sigma = math.Log(float64(k.p95)/float64(k.median)) / 1.645
	}
	s := int(float64(k.median) * math.Exp(r.NormFloat64()*sigma))
	return min(max(s, 60), k.max)
}

// padded fills a document out to about size bytes of JSON with strings of
// at most 1,000 bytes under member (an array).
func padded(r *rand.Rand, doc map[string]any, member string, size int) map[string]any {
	have := len(must(json.Marshal(doc)))
	var notes []any
	for have < size-20 {
		s := words(r, 1+min(1000, size-have)/7)
		if len(s) > 1000 {
			s = s[:1000]
		}
		notes = append(notes, s)
		have += len(s) + 3
	}
	if notes != nil {
		doc[member] = notes
	}
	return doc
}

// filler is n bytes of text.
func filler(r *rand.Rand, n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(words(r, 100))
	}
	return b.Bytes()[:n]
}

// demoTree is a tree-shaped document of about size bytes: nodes with ids,
// props, children, and now and then a blueprint named live.
func demoTree(r *rand.Rand, size int, blueprint func() string) map[string]any {
	n := 0
	var node func(depth, budget int) map[string]any
	node = func(depth, budget int) map[string]any {
		n++
		nd := map[string]any{"id": "n-" + hexID(r), "type": "Box", "props": map[string]any{
			"text": words(r, 4+r.Intn(20)), "order": float64(r.Intn(100)), "visible": true}}
		if r.Intn(5) == 0 {
			nd["uses"] = blueprint()
		}
		if budget > 1 && depth < 10 {
			kids := min(budget-1, 2+r.Intn(4))
			left := budget - 1
			var children []any
			for k := 0; k < kids && left > 0; k++ {
				share := left / (kids - k)
				children = append(children, node(depth+1, share))
				left -= share
			}
			nd["children"] = children
		}
		return nd
	}
	return map[string]any{"title": words(r, 4), "root": node(0, max(1, size/230))}
}

// demoSchemas are demo-schemas' schemas: the trees recursive, the rest flat.
func demoSchemas() map[string]any {
	str := map[string]any{"type": "string"}
	tree := func() map[string]any {
		s := map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": map[string]any{
			"title": str, "root": map[string]any{"$ref": "#/$defs/node"}}}
		s["$defs"] = map[string]any{"node": map[string]any{"type": "object", "required": []any{"id"}, "properties": map[string]any{
			"id": str, "type": str, "props": map[string]any{"type": "object"}, "uses": map[string]any{"type": "string", "x-ref": map[string]any{}},
			"children": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/node"}}}}}
		return s
	}
	flat := func() map[string]any {
		return map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": map[string]any{"title": str, "notes": map[string]any{"type": "array"}}}
	}
	out := map[string]any{"comment": flat()}
	for _, k := range demoKinds {
		if k.schema == "" || k.schema == "comment" {
			continue
		}
		switch k.schema {
		case "layout", "logic", "workflow", "transport", "values", "route":
			out[k.schema] = tree()
		default:
			out[k.schema] = flat()
		}
	}
	return out
}

// demoPlayBundle writes the synthetic Demo Play bundle at scale (document
// counts multiplied by it, sizes kept), as snapshots, schemas full; with
// data, demo-data too.
func demoPlayBundle(tb testing.TB, scale float64, data bool) []byte {
	tb.Helper()
	count := func(n int) int { return max(1, int(float64(n)*scale)) }
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{}, Docs: map[string]bundle.DocInfo{},
		Access: map[string]string{}}
	nss := []string{"demo-schemas", "demo", "cat-demo", "demo-comments", "domain-verifications"}
	if data {
		nss = append(nss, "demo-data")
	}
	for _, ns := range nss {
		h.At[ns], h.Access[ns] = fakeID("at "+ns), bundle.AccessPublic
	}
	snapID := func(ns, name string) string { return fakeID(ns + "/" + name) }

	// Full documents: demo-schemas' schemas (workflow with two revisions)
	// and the blueprints.
	type fullLine struct {
		ns, name string
		lines    []bundle.Line
	}
	var fulls []fullLine
	schemaRev := map[string]string{}
	schemas := demoSchemas()
	for _, name := range sortedNames(schemas) {
		doc := schemas[name]
		patches := client.GenesisPatches(doc)
		id := must(client.ExpectedRevision("", patches))
		fl := fullLine{"demo-schemas", name, []bundle.Line{{NS: "demo-schemas", Resource: name, ID: id, Kind: "rev", Patches: patches}}}
		if name == "workflow" {
			p2 := []any{map[string]any{"op": "add", "path": "/properties/version", "value": map[string]any{"type": "number"}}}
			id2 := must(client.ExpectedRevision(id, p2))
			fl.lines = append(fl.lines, bundle.Line{NS: "demo-schemas", Resource: name, ID: id2, Parent: id, Kind: "rev", Patches: p2})
			id = id2
		}
		schemaRev[name] = id
		fulls = append(fulls, fl)
	}
	nBlue := count(demoBlueprints.n)
	blueRev := make([]string, nBlue)
	blueFields := make([]int, nBlue)
	for i := 0; i < nBlue; i++ {
		r := rand.New(rand.NewSource(int64(i) + 7<<40))
		size := demoBlueprints.size(r, i)
		props := map[string]any{}
		fields := 3 + r.Intn(8)
		for f := 0; f < fields; f++ {
			t := "string"
			if f%2 == 1 {
				t = "number"
			}
			props[fmt.Sprint("f", f)] = map[string]any{"type": t, "description": words(r, 3)}
		}
		doc := padded(r, map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": props, "title": words(r, 3)}, "examples", size)
		patches := client.GenesisPatches(doc)
		blueRev[i] = must(client.ExpectedRevision("", patches))
		blueFields[i] = fields
		name := fmt.Sprint("blueprint-", i)
		fulls = append(fulls, fullLine{"demo", name, []bundle.Line{{NS: "demo", Resource: name, ID: blueRev[i], Kind: "rev", Patches: patches}}})
	}
	for _, f := range fulls {
		h.Docs[bundle.Key(f.ns, f.name)] = bundle.DocInfo{History: bundle.Full, Head: f.lines[len(f.lines)-1].ID}
	}
	kinds := append([]demoKind(nil), demoKinds...)
	if data {
		kinds = append(kinds, demoData)
	}
	for _, k := range kinds {
		for i := 0; i < count(k.n); i++ {
			name := fmt.Sprint(k.prefix, "-", i)
			h.Docs[bundle.Key(k.ns, name)] = bundle.DocInfo{History: bundle.Snapshot, Head: snapID(k.ns, name)}
		}
	}

	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	for _, f := range fulls {
		for _, l := range f.lines {
			noErr(tb, w.Line(l))
		}
	}
	blueprint := func(r *rand.Rand) string { return fmt.Sprint("/r/demo/blueprint-", r.Intn(nBlue)) }
	for ki, k := range kinds {
		for i := 0; i < count(k.n); i++ {
			name := fmt.Sprint(k.prefix, "-", i)
			r := rand.New(rand.NewSource(int64(ki)<<40 + int64(i)))
			size := k.size(r, i)
			var doc map[string]any
			switch {
			case k.ns == "demo-data":
				b := r.Intn(nBlue)
				doc = map[string]any{}
				for f := 0; f < blueFields[b]; f++ {
					if f%2 == 1 {
						doc[fmt.Sprint("f", f)] = float64(r.Intn(1e6))
					} else {
						doc[fmt.Sprint("f", f)] = words(r, 3)
					}
				}
				if r.Intn(50) != 0 {
					doc["$schema"] = rev("demo", fmt.Sprint("blueprint-", b), blueRev[b])
				}
				doc = padded(r, doc, "notes", size)
			case k.schema == "layout" || k.schema == "logic" || k.schema == "workflow" || k.schema == "transport" || k.schema == "values" || k.schema == "route":
				doc = demoTree(r, size, func() string { return blueprint(r) })
			default:
				doc = padded(r, map[string]any{"title": words(r, 4)}, "notes", size)
			}
			if k.schema != "" {
				doc["$schema"] = rev("demo-schemas", k.schema, schemaRev[k.schema])
			}
			if sizes := demoBlobs[k.prefix]; k.ns == "demo" && i < len(sizes) {
				data := filler(r, sizes[i]*3/4)
				typ := "application/octet-stream"
				bid := ids.Blob(typ, "", data).String()
				noErr(tb, w.Line(bundle.Line{NS: k.ns, Resource: name, Blob: bid, Type: typ, Data: data}))
				doc["asset"] = client.BlobRef(bid, typ, len(data), "")
			}
			noErr(tb, w.SnapshotDoc(k.ns, name, snapID(k.ns, name), json.RawMessage(must(json.Marshal(doc))), false))
		}
	}
	must(w.Close())
	return buf.Bytes()
}

var (
	demoPlayMu    sync.Mutex
	demoPlayCache = map[string][]byte{}
)

// demoPlay returns the bundle (content, or full with data), generated once
// and kept until another is asked for, which the heap it reports would
// count; PATCHLOG_DEMOPLAY_SCALE scales it, and PATCHLOG_DEMOPLAY_OUT, if
// set, names a directory to write it to (content.jsonl, full.jsonl) for
// runs of patchlog import.
func demoPlay(b *testing.B, data bool) []byte {
	demoPlayMu.Lock()
	defer demoPlayMu.Unlock()
	scale := 1.0
	if f, err := strconv.ParseFloat(os.Getenv("PATCHLOG_DEMOPLAY_SCALE"), 64); err == nil {
		scale = f
	}
	key := fmt.Sprint(scale, data)
	if bb, ok := demoPlayCache[key]; ok {
		return bb
	}
	clear(demoPlayCache)
	t0 := time.Now()
	bb := demoPlayBundle(b, scale, data)
	sum := must(bundle.Verify(bytes.NewReader(bb)))
	name := map[bool]string{false: "content", true: "full"}[data]
	b.Logf("demo play %s: %d documents, %.1f MB, generated in %s", name, len(sum.Header.Docs), float64(len(bb))/1e6, time.Since(t0).Round(time.Millisecond))
	if dir := os.Getenv("PATCHLOG_DEMOPLAY_OUT"); dir != "" {
		noErr(b, os.WriteFile(filepath.Join(dir, name+".jsonl"), bb, 0o644))
	}
	demoPlayCache[key] = bb
	return bb
}

// BenchmarkImportDemoPlay imports the synthetic Demo Play bundle (demoPlay)
// into a fresh deployment, its content alone and the full bundle, as a
// snapshot backfill under an allowance of 10,000/s (burst 20,000), as the
// measurements did; then again into the target that has it (/again). It
// reports the report's timings (planning-s, batches-s, total-s), the
// requests sent and the peak heap of the process, the server's included:
//
//	go test ./internal/bundle -run '^$' -bench ImportDemoPlay -benchtime 1x
//
// PATCHLOG_DEMOPLAY_NOAGAIN=1 skips the /again variants, and
// PATCHLOG_BENCH_DB_DIR stores the deployment in a SQLite file there
// (newDeployment).
func BenchmarkImportDemoPlay(b *testing.B) {
	allowance := map[string]any{"read": "public", "allowances": []any{map[string]any{"sub": "alice", "kid": "any",
		"bucket": map[string]any{"rate": 10000, "burst": 20000}}}}
	for _, data := range []bool{false, true} {
		name := map[bool]string{false: "content", true: "full"}[data]
		for _, variant := range []string{"", "/again"} {
			b.Run(name+variant, func(b *testing.B) {
				if variant != "" && os.Getenv("PATCHLOG_DEMOPLAY_NOAGAIN") != "" {
					// -bench 'ImportDemoPlay/full$' also matches full/again,
					// whose untimed first import a CPU profile would count.
					b.Skip("PATCHLOG_DEMOPLAY_NOAGAIN")
				}
				b.StopTimer()
				bb := demoPlay(b, data)
				var planning, batches, total float64
				var reqs int64
				var peak uint64
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					dst := newDeployment(b, cmsOrigin, fastLimits)
					imp := func(rt *countingTransport) (*bundle.Report, error) {
						c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: rt})))
						return bundle.Import(ctx, c, bundle.BytesOpener(bb), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true,
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
}
