package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// bodyLog records the requests a client sends that aren't GETs, with
// their bodies, in order. The batches' signatures are recorded, and
// removed before the server sees them, which has no grant listing the
// importer's key (as captured does).
type bodyLog struct {
	mu   sync.Mutex
	reqs []string
}

func (l *bodyLog) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "GET" {
		var b []byte
		if r.Body != nil {
			b, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}
		rec := string(b)
		if strings.Contains(r.Header.Get("Content-Type"), "json") || json.Valid(b) {
			rec = string(b)
		} else {
			sum := sha256.Sum256(b)
			rec = fmt.Sprintf("%d bytes %x", len(b), sum[:8])
		}
		l.mu.Lock()
		l.reqs = append(l.reqs, r.Method+" "+r.URL.RequestURI()+"\n"+rec)
		l.mu.Unlock()
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") {
			v := jsonv.MustParse(b).(map[string]any)
			for _, it := range v["items"].([]any) {
				for _, s := range it.(map[string]any)["steps"].([]any) {
					if m, ok := s.(map[string]any); ok {
						delete(m, "signature")
					}
				}
			}
			b = jsonv.Canonical(v)
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}
	return transport.RoundTrip(r)
}

func (l *bodyLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.reqs
	l.reqs = nil
	return out
}

// goldenSet writes snapshot bundles for TestImportSnapshotCanonical: the
// schema gs/doc (full history), and snapshot documents in ga (untyped, a
// blob, a JSON null, a string, a deleted one), gb (typed: pins of ga's,
// rewritten on import, of ga's and of a gn's, a blob, an undeclared pin),
// gn (imported into a namespace that requires nonces, its upstream too: a
// pin, a snapshot that carries its own $nonce) and gx (sealed).
type goldenSet struct {
	t          *testing.T
	schemaID   string
	blob, blb2 []byte
}

func (g *goldenSet) blobRef(data []byte) map[string]any {
	return client.BlobRef(ids.Blob("text/plain", "", data).String(), "text/plain", len(data), "")
}

// write writes a bundle of docs (ns → name → document; deletedDoc for a
// deleted one), version v naming the namespaces' at.
func (g *goldenSet) write(v int, docs map[string]map[string]any) []byte {
	t := g.t
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{}, Docs: map[string]bundle.DocInfo{},
		Access: map[string]string{}}
	for _, ns := range []string{"gs", "ga", "gb", "gn", "gx"} {
		h.At[ns], h.Access[ns] = fakeID(fmt.Sprint("at ", ns, v)), bundle.AccessPublic
	}
	h.Access["gx"] = bundle.AccessSealed
	schemaDoc := g.schema()
	h.Docs["gs/doc"] = bundle.DocInfo{History: bundle.Full, Head: g.schemaID}
	snapIDs := map[string]string{}
	for _, ns := range sortedNames(map[string]any{"ga": 0, "gb": 0, "gn": 0, "gx": 0}) {
		for name, doc := range docs[ns] {
			k := bundle.Key(ns, name)
			snapIDs[k] = fakeID(k + string(must(json.Marshal(doc))))
			h.Docs[k] = bundle.DocInfo{History: bundle.Snapshot, Head: snapIDs[k]}
		}
	}
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	noErr(t, w.Line(bundle.Line{NS: "gs", Resource: "doc", ID: g.schemaID, Kind: "rev", Patches: client.GenesisPatches(schemaDoc)}))
	for _, ns := range []string{"ga", "gb", "gn", "gx"} {
		names := make([]string, 0, len(docs[ns]))
		for name := range docs[ns] {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			doc := docs[ns][name]
			if s, ok := doc.(string); ok && s == deletedDoc {
				noErr(t, w.SnapshotDoc(ns, name, snapIDs[bundle.Key(ns, name)], nil, true))
				continue
			}
			for _, data := range [][]byte{g.blob, g.blb2} {
				ref := g.blobRef(data)
				if strings.Contains(string(must(json.Marshal(doc))), ref["$blob"].(string)) {
					noErr(t, w.Line(bundle.Line{NS: ns, Resource: name, Blob: ref["$blob"].(string), Type: "text/plain", Data: data}))
				}
			}
			noErr(t, w.SnapshotDoc(ns, name, snapIDs[bundle.Key(ns, name)], doc, false))
		}
	}
	must(w.Close())
	return buf.Bytes()
}

const deletedDoc = "\x00deleted"

func (g *goldenSet) schema() map[string]any {
	pinned := map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}}
	return map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": map[string]any{
		"pin":  pinned,
		"pins": map[string]any{"type": "array", "items": pinned},
		"link": map[string]any{"type": "string", "x-ref": map[string]any{}},
		"parts": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
			"ref": map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true, "key": "/parts"}}}}},
	}}
}

// pin is a pinned reference to ns/name as docs bundles it.
func (g *goldenSet) pin(docs map[string]map[string]any, ns, name string) string {
	k := bundle.Key(ns, name)
	return rev(ns, name, fakeID(k+string(must(json.Marshal(docs[ns][name])))))
}

// allHeads lists every resource's head in the namespaces that exist.
func allHeads(t *testing.T, c *client.Client, nss ...string) []string {
	t.Helper()
	var out []string
	for _, ns := range nss {
		if _, err := c.NSHead(ctx, ns); client.IsNotFound(err) {
			out = append(out, ns+" absent")
			continue
		}
		out = append(out, heads(t, c, ns)...)
	}
	return out
}

type goldenStep struct {
	name   string
	reqs   []string
	report []byte
	heads  []string
	rep    *bundle.Report
}

// An import that holds its snapshot documents as their canonical bytes
// (Line.docCanon, jsonv.Raw) sends the requests one holding them as trees
// sends, byte for byte, reports the same, and leaves the target as it
// does: imports of part of a bundle (with snapshot documents held for the
// pins of those imported, one in an upstream that requires nonces), of the
// whole, with take and replay resolutions, into a namespace that requires
// nonces and a sealed one, signed, and a re-run.
// Not parallel: the nonces the imports generate come from the same
// deterministic sequence in both (DeterministicNonces; the rest of the
// importer's randomness from cryptotest.SetGlobalRandom).
func TestImportSnapshotCanonical(t *testing.T) {
	g := &goldenSet{t: t, blob: []byte("blob one"), blb2: []byte("blob two")}
	g.schemaID = must(client.ExpectedRevision("", client.GenesisPatches(g.schema())))
	typed := func(m map[string]any) map[string]any {
		m["$schema"] = rev("gs", "doc", g.schemaID)
		return m
	}
	const nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	d1 := map[string]map[string]any{"ga": {
		"a0":    map[string]any{"t": "a0", "v": 1},
		"a1":    map[string]any{"t": "a1", "img": g.blobRef(g.blob), "list": []any{1, 2, 3}},
		"a2":    map[string]any{"t": "a2", "x": "x0", "u": "u0"},
		"a3":    map[string]any{"t": "a3", "x": "x0"},
		"anull": nil,
		"agone": deletedDoc,
		"astr":  "a string \u2028 \"quoted\"",
	}}
	gb := func(docs map[string]map[string]any, s string) map[string]any {
		return map[string]any{
			"b0": typed(map[string]any{"pin": g.pin(docs, "ga", "a1") + "#e-1", "link": "/r/ga/a2"}),
			"b1": typed(map[string]any{"pins": []any{g.pin(docs, "ga", "a2")}, "s": s, "parts": []any{map[string]any{"ref": g.pin(docs, "ga", "a3")}}}),
			"b2": typed(map[string]any{"img": g.blobRef(g.blb2), "pin": g.pin(docs, "ga", "anull"), "pins": []any{g.pin(docs, "gn", "n1")}}),
			"b3": typed(map[string]any{"note": g.pin(docs, "ga", "a1")}), // undeclared
		}
	}
	d1["gn"] = map[string]any{
		"n0": typed(map[string]any{"pin": g.pin(d1, "ga", "a2")}),
		"n1": map[string]any{"v": 1, "$nonce": nonce},
		"n2": map[string]any{"v": 2},
	}
	d1["gb"] = gb(d1, "s0")
	d1["gx"] = map[string]any{"x0": map[string]any{"v": 1}}
	b1 := g.write(1, d1)

	// The second: a0 deleted, a1, a2, astr, n2 and x0 changed, a3 and b1
	// changed where the target changes them too, a5 new; b0 and n0 pin
	// a1's and a2's new snapshots.
	d2 := map[string]map[string]any{"ga": {}, "gn": {}, "gx": {}}
	for k, v := range d1["ga"] {
		d2["ga"][k] = v
	}
	d2["ga"]["a0"] = deletedDoc
	d2["ga"]["a1"] = map[string]any{"t": "a1", "img": g.blobRef(g.blob), "list": []any{1, 2, 3, 4}}
	d2["ga"]["a2"] = map[string]any{"t": "a2", "x": "x0", "u": "u1"}
	d2["ga"]["a3"] = map[string]any{"t": "a3", "x": "x1"}
	d2["ga"]["a5"] = map[string]any{"t": "a5"}
	d2["ga"]["astr"] = "another string"
	d2["gn"]["n0"] = typed(map[string]any{"pin": g.pin(d2, "ga", "a2")})
	d2["gn"]["n1"] = d1["gn"]["n1"]
	d2["gn"]["n2"] = map[string]any{"v": 3}
	d2["gb"] = gb(d2, "s1")
	d2["gx"]["x0"] = map[string]any{"v": 2}
	b2 := g.write(2, d2)
	// The third: a0 again.
	d2["ga"]["a0"] = map[string]any{"t": "a0", "v": 2}
	b3 := g.write(3, d2)

	signer := signerKey(t, "importer-key", 9)
	nss := []string{"gs", "ga", "ga-upstream", "gb", "gb-upstream", "gn", "gn-upstream", "gx", "gx-upstream"}
	run := func(trees bool) []goldenStep {
		dst := newEncDeployment(t, cmsOrigin)
		dst.ns("gn", map[string]any{"read": "public", "nonce": "required"})
		var log bodyLog
		c := must(client.New(dst.url, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)), client.WithHTTPClient(&http.Client{Transport: &log})))
		var steps []goldenStep
		imp := func(name string, b []byte, opt bundle.ImportOptions) {
			t.Helper()
			opt.Mode, opt.CreateNamespaces, opt.Concurrency, opt.Signer = bundle.Atomic, true, 1, &signer
			if trees {
				bundle.KeepSnapshotTrees(&opt)
			}
			cryptotest.SetGlobalRandom(t, 7)
			bundle.DeterministicNonces(t, uint64(7+len(steps))) // each import its own
			log.take()
			rep, err := bundle.Import(ctx, c, bundle.BytesOpener(b), opt)
			if err != nil {
				t.Fatalf("trees %v, %s: %v\nreport: %s", trees, name, err, reportJSON(rep))
			}
			for _, br := range rep.Batches {
				br.NSID = ""
			}
			steps = append(steps, goldenStep{name: name, reqs: log.take(), report: reportJSON(rep), heads: allHeads(t, dst.c, nss...), rep: rep})
		}
		imp("part: gs, ga, gn, gx", b1, bundle.ImportOptions{Only: []string{"gs", "ga", "gn", "gx"}})
		imp("part: gb, with ga's held", b1, bundle.ImportOptions{Only: []string{"gb"}})
		// The target changes a2 where the bundle doesn't, a3, b1 and n2
		// where it does.
		dst.append("ga", "a2", op("replace", "/t", "a2 in the target"))
		dst.append("ga", "a3", op("replace", "/x", "x in the target"))
		dst.append("gb", "b1", op("replace", "/s", "s in the target"))
		dst.append("gn", "n2", op("replace", "/v", 20), op("add", "/$nonce", "cccccccccccccccccccccccccc"))
		imp("whole, resolved", b2, bundle.ImportOptions{Resolutions: map[string]bundle.Resolution{
			"ga/a3": bundle.ResolveReplay, "gb/b1": bundle.ResolveTake, "gn/n2": bundle.ResolveTake}})
		imp("whole, a0 restored", b3, bundle.ImportOptions{})
		imp("again", b3, bundle.ImportOptions{})
		return steps
	}
	trees, canon := run(true), run(false)

	for i, want := range trees {
		got := canon[i]
		if !slices.Equal(got.reqs, want.reqs) {
			for k := 0; k < len(got.reqs) && k < len(want.reqs); k++ {
				if got.reqs[k] != want.reqs[k] {
					t.Fatalf("%s: request %d differs:\ncanonical: %.2000s\ntrees:     %.2000s", want.name, k, got.reqs[k], want.reqs[k])
				}
			}
			t.Fatalf("%s: %d requests, with trees %d", want.name, len(got.reqs), len(want.reqs))
		}
		if !bytes.Equal(got.report, want.report) {
			t.Fatalf("%s: report differs:\ncanonical: %s\ntrees:     %s", want.name, got.report, want.report)
		}
		if !slices.Equal(got.heads, want.heads) {
			t.Fatalf("%s: heads differ:\ncanonical: %v\ntrees:     %v", want.name, got.heads, want.heads)
		}
	}

	// The imports did what they're said to.
	batches := func(s goldenStep) (n int) {
		for _, r := range s.reqs {
			if strings.HasPrefix(r, "POST ") && strings.Contains(r, "/batch") {
				n++
			}
		}
		return n
	}
	doc := func(s goldenStep, k string) *bundle.DocReport {
		d := s.rep.Doc(k)
		if d == nil {
			t.Fatalf("%s: no report of %s", s.name, k)
		}
		return d
	}
	s := canon[0]
	if d := doc(s, "gn/n0"); d.Class != "create" || d.Upstream.Class != "create" || len(d.Rewritten) != 1 {
		t.Fatalf("%s: n0 %+v %+v", s.name, d, d.Upstream)
	}
	if d := doc(s, "ga/anull"); d.Class != "create" || d.Upstream.Class != "create" {
		t.Fatalf("%s: anull %+v", s.name, d)
	}
	if d := doc(s, "ga/a1"); d.Class != "create" {
		t.Fatalf("%s: a1 %+v", s.name, d)
	}
	s = canon[1]
	if d := doc(s, "gb/b0"); d.Class != "create" || len(d.Rewritten) != 1 || len(s.rep.Docs) != 4 || len(s.rep.Undeclared) != 1 {
		t.Fatalf("%s: b0 %+v, %d docs, undeclared %v", s.name, d, len(s.rep.Docs), s.rep.Undeclared)
	}
	s = canon[2]
	for k, want := range map[string]string{"ga/a0": "fast-forward/delete", "ga/a1": "fast-forward/append", "ga/a2": "replay/append",
		"ga/a3": "replay/append", "ga/a5": "create/create", "ga/anull": "present/unchanged", "ga/agone": "present/absent",
		"ga/astr": "fast-forward/append", "gb/b0": "fast-forward/append", "gb/b1": "take/append", "gb/b2": "present/unchanged",
		"gn/n0": "fast-forward/append", "gn/n1": "present/unchanged", "gn/n2": "take/append", "gx/x0": "fast-forward/append"} {
		if d := doc(s, k); d.Class+"/"+d.Upstream.Class != want {
			t.Errorf("%s: %s %s/%s, want %s", s.name, k, d.Class, d.Upstream.Class, want)
		}
	}
	if doc(s, "ga/a3").Resolution != bundle.ResolveReplay || len(doc(s, "gb/b0").Rewritten) != 1 {
		t.Fatalf("%s: a3 %+v, b0 %+v", s.name, doc(s, "ga/a3"), doc(s, "gb/b0"))
	}
	s = canon[3]
	if d := doc(s, "ga/a0"); d.Upstream.Class != "restore" || d.Class != "fast-forward" {
		t.Fatalf("%s: a0 %+v %+v", s.name, d, d.Upstream)
	}
	if s := canon[4]; batches(s) != 0 {
		t.Fatalf("%s: %d batches", s.name, batches(s))
	}
}
