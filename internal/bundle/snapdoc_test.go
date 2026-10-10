package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// docCanonBundle is a bundle of snapshot documents of every kind of value
// (escapes, U+2028, blob references, null, a string, an empty array, a
// deleted one), many of them, between history and blob lines.
func docCanonBundle(t *testing.T) []byte {
	t.Helper()
	data := []byte("blob bytes")
	bid := ids.Blob("text/plain", "", data).String()
	docs := []any{
		map[string]any{"z": "é \"\\ \u2028 \x01", "a": []any{1.5, nil, true, map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}}},
		"a string",
		[]any{},
		nil, // JSON null
		map[string]any{},
		// A schema document's references aren't blobs (docBlobs), though
		// its genesis revision's ops write one (stepBlobs).
		map[string]any{"$schema": schema.Dialect2020, "default": map[string]any{"$blob": fakeBlob}},
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 400; i++ {
		doc := map[string]any{"i": float64(i), "s": strings.Repeat("x", r.Intn(3000))}
		if i%7 == 0 {
			doc["nested"] = map[string]any{"k": []any{"v", float64(i) / 3, map[string]any{"deep": i%2 == 0}}}
		}
		docs = append(docs, doc)
	}
	h := Header{Origin: "https://a.example", Created: "2026-10-01T00:00:00Z", At: map[string]string{}, Docs: map[string]DocInfo{}}
	h.At["n"] = must(client.ExpectedRevision("", client.GenesisPatches("n")))
	full := client.GenesisPatches(map[string]any{"history": true})
	fullID := must(client.ExpectedRevision("", full))
	h.Docs["n/full"] = DocInfo{History: Full, Head: fullID}
	for i := range docs {
		h.Docs[Key("n", fmt.Sprint("d", i))] = DocInfo{History: Snapshot, Head: fakeSnapID(i)}
	}
	h.Docs["n/gone"] = DocInfo{History: Snapshot, Head: fakeSnapID(-1)}
	var buf bytes.Buffer
	w := must(NewWriter(&buf, h))
	if err := w.Line(Line{NS: "n", Resource: "full", ID: fullID, Kind: "rev", Patches: full}); err != nil {
		t.Fatal(err)
	}
	if err := w.Line(Line{NS: "n", Resource: "d0", Blob: bid, Type: "text/plain", Data: data}); err != nil {
		t.Fatal(err)
	}
	for i, doc := range docs {
		if err := w.SnapshotDoc("n", fmt.Sprint("d", i), fakeSnapID(i), doc, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SnapshotDoc("n", "gone", fakeSnapID(-1), nil, true); err != nil {
		t.Fatal(err)
	}
	must(w.Close())
	return buf.Bytes()
}

var fakeBlob = ids.Blob("text/plain", "", []byte("not in the bundle")).String()

func fakeSnapID(i int) string {
	return must(client.ExpectedRevision("", client.GenesisPatches(float64(i))))
}

// readLines reads a whole bundle and returns all its lines, kept.
func readLines(t *testing.T, b []byte, workers int, keep bool) []*Line {
	t.Helper()
	rd := must(NewReader(bytes.NewReader(b)))
	if keep {
		rd.keepDocCanon()
	}
	rd.parallel(workers)
	defer rd.Close()
	var out []*Line
	for {
		l, err := rd.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, l)
	}
}

// A Reader asked to (keepDocCanon) keeps each snapshot document's
// canonical form (docCanon), the part of the line's own that it is, read
// in turn or ahead. It aliases the line's canonical buffer, which the Reader
// allocates afresh for each line and never reuses: checked once the whole
// bundle is read, so a buffer reused for a later line would show. Readers
// that don't ask keep none.
func TestReaderDocCanon(t *testing.T) {
	t.Parallel()
	b := docCanonBundle(t)
	for _, workers := range []int{1, 4} {
		lines := readLines(t, b, workers, true)
		snaps := 0
		for _, l := range lines {
			switch {
			case !l.IsSnapshot() || l.IsBlob():
				if l.docCanon != nil {
					t.Errorf("workers %d: %s line with a docCanon", workers, l.Key())
				}
				continue
			case l.Deleted:
				if l.docCanon != nil {
					t.Errorf("workers %d: %s: deleted, with a docCanon", workers, l.Key())
				}
				continue
			}
			snaps++
			if want := jsonv.Canonical(l.Doc); !bytes.Equal(l.docCanon, want) {
				t.Errorf("workers %d, %s: docCanon %.80s, want %.80s", workers, l.Key(), l.docCanon, want)
			}
			if cap(l.docCanon) != len(l.docCanon) {
				t.Errorf("workers %d, %s: docCanon has room after it (%d of %d)", workers, l.Key(), len(l.docCanon), cap(l.docCanon))
			}
		}
		if snaps != 406 {
			t.Fatalf("workers %d: %d snapshot documents", workers, snaps)
		}
		for _, l := range readLines(t, b, workers, false) {
			if l.docCanon != nil {
				t.Fatalf("workers %d: %s: a docCanon the reader wasn't asked for", workers, l.Key())
			}
		}
	}
	// A line of another form: serialised again, not sliced.
	l := &Line{NS: "n", Resource: "d", Snapshot: fakeSnapID(0), Doc: map[string]any{"a": 1.0}}
	if got := docPart(l, []byte(`{"doc":{"a":2},"ns":"n","resource":"e","snapshot":"x"}`)); string(got) != `{"a":1}` {
		t.Fatalf("docPart of another line: %s", got)
	}
}

// snapDoc parses the canonical form load keeps, a fresh copy each time; a
// tree kept with keepTrees is the line's own, and a JSON null document is
// null. Once the rewritten form replaces the document (dropSnap), and for
// a deleted snapshot, it fails rather than answer null.
func TestSnapDoc(t *testing.T) {
	t.Parallel()
	doc := map[string]any{"a": []any{"x", 2.0}}
	d := &bdoc{key: "n/d", snap: &Line{NS: "n", Resource: "d", Snapshot: fakeSnapID(0), docCanon: jsonv.Raw(jsonv.Canonical(doc))}}
	v1, err1 := d.snapDoc()
	v2, err2 := d.snapDoc()
	if err1 != nil || err2 != nil || !jsonv.Equal(v1, doc) || !jsonv.Equal(v2, doc) {
		t.Fatalf("snapDoc: %v %v %v %v", v1, err1, v2, err2)
	}
	v1.(map[string]any)["a"] = "changed"
	if !jsonv.Equal(v2, doc) {
		t.Fatal("snapDoc returned the same tree twice")
	}
	if h, err := d.snapHeld(); err != nil || !bytes.Equal(h.(jsonv.Raw), d.snap.docCanon) {
		t.Fatalf("snapHeld: %v %v", h, err)
	}
	d.dropSnap()
	if v, err := d.snapDoc(); err == nil || !strings.Contains(err.Error(), "no longer held") {
		t.Fatalf("after dropSnap: %v %v", v, err)
	}

	tree := &bdoc{key: "n/t", snap: &Line{NS: "n", Resource: "t", Snapshot: fakeSnapID(1), Doc: doc}}
	if v, err := tree.snapDoc(); err != nil || v.(map[string]any)["a"] == nil {
		t.Fatalf("tree: %v %v", v, err)
	}
	null := &bdoc{key: "n/null", snap: &Line{NS: "n", Resource: "null", Snapshot: fakeSnapID(2)}}
	if v, err := null.snapDoc(); err != nil || v != nil {
		t.Fatalf("null document kept as a tree: %v %v", v, err)
	}
	null.snap.docCanon = jsonv.Raw("null")
	if v, err := null.snapDoc(); err != nil || v != nil {
		t.Fatalf("null document kept canonical: %v %v", v, err)
	}
	tree.dropSnap()
	if _, err := tree.snapDoc(); err == nil {
		t.Fatal("tree after dropSnap: no error")
	}
	gone := &bdoc{key: "n/gone", snap: &Line{NS: "n", Resource: "gone", Snapshot: fakeSnapID(3), Deleted: true}}
	if _, err := gone.snapDoc(); err == nil {
		t.Fatal("deleted: no error")
	}
}

// A snapshot document held as its canonical form is only ever a value
// inside a patch set. The code that reads patch sets' ops reads it there
// (nonced, stepBlobs, sides through expandSteps, withoutNonce, merge.Diff),
// and refuses a patch set that is a Raw itself, which it would misread as
// having no ops: canonical with an error, the others by panicking.
func TestRawPatchSets(t *testing.T) {
	t.Parallel()
	data := []byte("b")
	bid := ids.Blob("text/plain", "", data).String()
	doc := map[string]any{"img": map[string]any{"$blob": bid, "type": "text/plain", "size": 1.0}, "$nonce": seal.NewNonce(), "n": 1.0}
	raw := jsonv.Raw(jsonv.Canonical(doc))
	genesis := client.PatchStep(client.GenesisPatches(raw))

	// Inside a patch set: read as the value it holds.
	if got, want := must(canonical(genesis.Patches)), jsonv.Canonical(client.GenesisPatches(doc)); !bytes.Equal(got, want) {
		t.Fatalf("canonical: %s, want %s", got, want)
	}
	if b := stepBlobs(genesis); len(b) != 1 || b[0] != bid {
		t.Fatalf("stepBlobs: %v", b)
	}
	if b := stepBlobs(client.PatchStep(client.GenesisPatches(jsonv.Raw(`{"a":"\"$blob\""}`)))); len(b) != 0 {
		t.Fatalf("stepBlobs of a string mentioning $blob: %v", b)
	}
	ns := nonced([]client.Step{genesis})
	ops := ns[0].Patches.([]any)
	if len(ops) != 2 || ops[0].(map[string]any)["value"] == nil || ops[1].(map[string]any)["path"] != seal.NoncePath {
		t.Fatalf("nonced: %v", ops)
	}
	ex := must(expandSteps([]client.Step{genesis}))
	if v := ex[0].Patches.([]any)[0].(map[string]any)["value"]; !jsonv.Equal(v, doc) {
		t.Fatalf("expandSteps: %v", v)
	} else if _, isMap := v.(map[string]any); !isMap {
		t.Fatalf("expandSteps left %T", v)
	}
	if _, ok := genesis.Patches.([]any)[0].(map[string]any)["value"].(jsonv.Raw); !ok {
		t.Fatal("expandSteps modified its argument")
	}
	if w, ok := withoutNonce(raw).(map[string]any); !ok || w["$nonce"] != nil || w["n"] != 1.0 {
		t.Fatalf("withoutNonce: %v", withoutNonce(raw))
	}
	changed := map[string]any{"img": doc["img"], "$nonce": doc["$nonce"], "n": 2.0}
	if d := merge.Diff(raw, changed); len(d) != 1 || d[0].(map[string]any)["path"] != "/n" {
		t.Fatalf("merge.Diff of a Raw: %v", d)
	}
	if d := merge.Diff(raw, doc); len(d) != 0 {
		t.Fatalf("merge.Diff of equal values: %v", d)
	}
	conflicts := sides(map[string]any{}, true, []client.Step{genesis}, []client.Step{client.PatchStep(client.GenesisPatches(doc))}, false)
	if len(conflicts) != 1 || conflicts[0].Kind != merge.ConflictOverlap {
		t.Fatalf("sides: %+v", conflicts)
	}

	// A patch set that is a Raw itself: refused.
	top := client.PatchStep(jsonv.Raw(jsonv.Canonical(client.GenesisPatches(doc))))
	if _, err := canonical(top.Patches); !errors.Is(err, errRawPatchSet) {
		t.Fatalf("canonical: %v", err)
	}
	if _, _, err := expectedIDs("", []client.Step{top}); !errors.Is(err, errRawPatchSet) {
		t.Fatalf("expectedIDs: %v", err)
	}
	for name, f := range map[string]func(){
		"nonced":      func() { nonced([]client.Step{top}) },
		"stepBlobs":   func() { stepBlobs(top) },
		"mentions":    func() { mentions(top) },
		"sealedBlobs": func() { sealedBlobs(top.Patches) },
		"sides":       func() { sides(nil, false, []client.Step{top}, nil, false) },
	} {
		func() {
			defer func() {
				if r := recover(); r != errRawPatchSet {
					t.Errorf("%s: recovered %v, want errRawPatchSet", name, r)
				}
			}()
			f()
		}()
	}
}

// load keeps each snapshot document's canonical form and drops its tree,
// with the blobs its genesis brings (stepBlobs of it); with keepTrees it
// keeps the trees, as before.
func TestLoadHoldsCanonicalForms(t *testing.T) {
	t.Parallel()
	b := docCanonBundle(t)
	for _, trees := range []bool{false, true} {
		im := &importer{opt: ImportOptions{UpstreamSuffix: "-upstream", keepTrees: trees}, docs: map[string]*bdoc{}}
		if err := im.load(BytesOpener(b)); err != nil {
			t.Fatal(err)
		}
		lines := readLines(t, b, 1, false)
		n := 0
		for _, l := range lines {
			if !l.IsSnapshot() || l.IsBlob() || l.Deleted {
				continue
			}
			n++
			d := im.docs[l.Key()]
			held := must(d.snapHeld())
			wantBlobs := stepBlobs(client.PatchStep(client.GenesisPatches(l.Doc)))
			if trees {
				if d.snap.docCanon != nil || d.snapBlobs != nil || !jsonv.Equal(held, l.Doc) {
					t.Fatalf("trees, %s: docCanon %v, blobs %v, held %T", d.key, d.snap.docCanon != nil, d.snapBlobs, held)
				}
				continue
			}
			if raw, ok := held.(jsonv.Raw); !ok || d.snap.Doc != nil || !bytes.Equal(raw, jsonv.Canonical(l.Doc)) {
				t.Fatalf("%s: held %T, tree kept %v", d.key, held, d.snap.Doc != nil)
			}
			if d.snapBlobs == nil || fmt.Sprint(d.snapBlobs) != fmt.Sprint(wantBlobs) {
				t.Fatalf("%s: blobs %v, want %v", d.key, d.snapBlobs, wantBlobs)
			}
		}
		if n != 406 {
			t.Fatalf("%d snapshot documents", n)
		}
		if b := im.docs["n/d0"].snapBlobs; !trees && len(b) != 1 {
			t.Fatalf("d0's blobs %v", b)
		}
		if s := im.docs["n/d5"]; len(s.refd) != 0 || (!trees && len(s.snapBlobs) != 1) {
			t.Fatalf("schema document: referenced %v, genesis blobs %v", s.refd, s.snapBlobs)
		}
	}
}
