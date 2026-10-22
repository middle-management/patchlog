package server

import (
	"strings"
	"testing"
)

// v0.73 §6.6: a limit refused at step 4 of §6.2 is 422 code limit, with
// limit, measured and max; 413 is only for refusals before or while a
// request is read (a body cut off, §C.8 grantSize, §7.8 blobs).
func TestV073LimitsAtStep4Are422(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("l", map[string]any{"limits": map[string]any{"patchSetSize": 4096, "documentSize": 8192,
		"valueSize": 600, "pathSize": 100, "itemsPerBatch": 2, "batchSize": 3000}})
	str := strings.Repeat("x", 500)
	head := e.create("l", "r", map[string]any{"a": 1.0})

	// patchSetSize, documentSize, valueSize and pathSize.
	set := ops(op("add", "/b", map[string]any{"a": str, "b": str, "c": str, "d": str, "e": str, "f": str, "g": str, "h": str, "i": str}))
	expectLimit(t, e.write("PATCH", "l", "r", head, set), 422, "patchSetSize", int64(len(canonical(set))), 4096)
	doc := map[string]any{}
	for _, k := range strings.Split("abcdefghijklmnopq", "") {
		doc[k] = str
	}
	expectLimit(t, e.write("PATCH", "l", "big", "", addRoot(doc)), 422, "documentSize", int64(len(canonical(addRoot(doc)))), 8192)
	expectLimit(t, e.write("PATCH", "l", "r", head, ops(op("add", "/v", strings.Repeat("v", 600)))), 422, "valueSize", 602, 600)
	expectLimit(t, e.write("PATCH", "l", "r", head, ops(op("add", "/"+strings.Repeat("p", 99), 1.0))), 422, "pathSize", 102, 100)

	// A batch's item count and size, answered as a single write's, without
	// items (§7.5).
	create := func(name string, v any) any {
		return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(v)}}
	}
	r := e.batchReq("l", map[string]any{"items": []any{create("i1", 1.0), create("i2", 2.0), create("i3", 3.0)}}, "alice")
	expectLimit(t, r, 422, "itemsPerBatch", 3, 2)
	if _, has := r.Obj()["items"]; has {
		t.Fatalf("itemsPerBatch with items: %s", r.Body)
	}
	three := map[string]any{"a": str, "b": str, "c": str}
	r = e.batchReq("l", map[string]any{"items": []any{create("s1", three), create("s2", three)}}, "alice")
	expectLimit(t, r, 422, "batchSize", 2*int64(len(canonical(addRoot(three)))), 3000)

	// A config write's patch set.
	cset := ops(op("add", "/x-a", strings.Repeat("a", 590)), op("add", "/x-b", strings.Repeat("b", 590)),
		op("add", "/x-c", strings.Repeat("c", 590)), op("add", "/x-d", strings.Repeat("d", 590)),
		op("add", "/x-e", strings.Repeat("e", 590)), op("add", "/x-f", strings.Repeat("f", 590)), op("add", "/x-g", strings.Repeat("g", 590)))
	expectLimit(t, e.patchNS("l", cset, ""), 422, "patchSetSize", int64(len(canonical(cset))), 4096)
}
