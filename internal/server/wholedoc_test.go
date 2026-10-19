package server

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// §6.6 Whole documents (v0.54): an append or restore whose first operation
// other than test is a root replace or add may be as large as
// documentSize, so a document can be overwritten on purpose in one request
// (§11.3); every other append stays within patchSetSize. In a batch such
// steps still count toward batchSize.
func TestWholeDocumentAppends(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("s", map[string]any{"limits": map[string]any{"patchSetSize": 1024, "documentSize": 16384, "batchSize": 6000}})
	str := strings.Repeat("x", 1000)
	big := map[string]any{"a": str, "b": str, "c": str, "d": str}
	head := e.create("s", "r", map[string]any{"a": "old"})

	head = e.appendRev("s", "r", head, ops(op("test", "/a", "old"), op("replace", "", big)))
	if d := e.doc("s", "r"); d["d"] != str {
		t.Fatalf("overwritten %v", d)
	}
	head = e.appendRev("s", "r", head, ops(op("add", "", big), op("add", "/e", 1.0)))
	head = e.appendRev("s", "r", head, ops(op("test", "/e", 1.0), op("test", "/a", str), op("replace", "", big)))
	// The first operation other than test isn't at the root.
	for _, set := range [][]any{
		ops(op("test", "/a", str), op("replace", "/a", str+"y"), op("replace", "", big)),
		ops(op("add", "/x", 1.0), op("replace", "", big)),
		ops(op("replace", "/a", strings.Repeat("y", 1100))),
		ops(op("test", "", big), op("add", "/z", big)),
	} {
		expectCode(t, e.write("PATCH", "s", "r", head, set), 413, "limit")
	}
	// Still within documentSize.
	huge := map[string]any{"a": strings.Repeat(str, 17)}
	expectCode(t, e.write("PATCH", "s", "r", head, ops(op("replace", "", huge))), 413, "limit")
	// A restore, after a test too.
	tomb := e.del("s", "r", head)
	head = e.appendRev("s", "r", tomb, ops(op("test", "/a", str), op("add", "", big)))

	// In a batch: the same bound per step, and batchSize over them all.
	e.create("s", "q", map[string]any{})
	item := func(name, parent string, set []any) map[string]any {
		return map[string]any{"resource": name, "ifMatch": parent, "steps": []any{set}}
	}
	q := e.head("s", "q")
	expect(t, e.batchReq("s", map[string]any{"items": []any{item("r", head, ops(op("replace", "", big))), item("q", q, ops(op("add", "/k", 1.0)))}}, "alice"), 201)
	head = e.head("s", "r")
	r := e.batchReq("s", map[string]any{"items": []any{item("r", head, ops(op("add", "/k", str), op("add", "/l", str)))}}, "alice")
	expectCode(t, r, 413, "batch")
	if it := r.Obj()["items"].([]any)[0].(map[string]any); it["code"] != "limit" || it["index"] != 0.0 {
		t.Fatalf("item %v", it)
	}
	q = e.head("s", "q")
	r = e.batchReq("s", map[string]any{"items": []any{item("r", head, ops(op("replace", "", big))), item("q", q, ops(op("replace", "", big)))}}, "alice")
	expectCode(t, r, 413, "limit") // two of 4 KiB and more: over batchSize
	// A multi-step item: a whole-document step after a small one.
	r = e.batchReq("s", map[string]any{"items": []any{map[string]any{"resource": "r", "ifMatch": head,
		"steps": []any{ops(op("add", "/m", 1.0)), ops(op("replace", "", big))}}}}, "alice")
	expect(t, r, 201)
}

// At E3 the server can't see a patch set's shape (§6.6): every sealed
// create and restore may be as large as documentSize, and every sealed
// append stays within patchSetSize, whatever it holds.
func TestWholeDocumentE3(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	f.mkNS("lim", e2eDoc(map[string]any{"keys": []any{f.writer.entry("read", "create", "append", "restore", "delete")},
		"limits": map[string]any{"patchSetSize": 8192, "documentSize": 65536, "valueSize": 1000, "pathSize": 200, "blobsPerDocument": 10}}))
	g := f.grant(f.writer, "user:writer", []string{"lim"}, []string{"read", "create", "append", "restore", "delete"})
	k := seal.NewKey()
	// Random strings, which the sealed format can't compress (zip).
	doc := map[string]any{}
	for i := 0; i < 12; i++ {
		var b strings.Builder
		for b.Len() < 900 {
			b.WriteString(seal.NewNonce())
		}
		doc["k"+strings.Repeat("0", i)] = b.String()
	}
	c := f.writeRaw("lim", "p", "", sealed(t, k, "lim#1", "lim", "p", "", addRoot(doc)), g)
	expect(t, c, 201)
	head := etagOf(c)
	expectCode(t, f.writeRaw("lim", "p", head, sealed(t, k, "lim#1", "lim", "p", head, ops(op("replace", "", doc))), g), 413, "limit")
	small := etagOf(f.writeRaw("lim", "p", head, sealed(t, k, "lim#1", "lim", "p", head, ops(op("add", "/s", 1.0))), g))
	tomb := f.del("lim", "p", small, g)
	expect(t, f.writeRaw("lim", "p", tomb, sealed(t, k, "lim#1", "lim", "p", tomb, ops(op("replace", "", doc))), g), 201)
}
