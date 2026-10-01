package server

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// §6.6: valueSize bounds the largest string, member names included, and
// pathSize the longest pointer, both as canonical JSON.
func TestValueAndPathSize(t *testing.T) {
	e := newEnv(t)
	e.mkNS("v", map[string]any{"limits": map[string]any{"valueSize": 100, "pathSize": 40}})
	mk := func(name string, doc any) *resp { return e.write("PATCH", "v", name, "", addRoot(doc)) }

	expect(t, mk("ok", map[string]any{"s": strings.Repeat("x", 98)}), 201) // 100 with quotes
	expectCode(t, mk("long", map[string]any{"s": strings.Repeat("x", 99)}), 413, "limit")
	// Canonical JSON counts escapes: 60 quotes are 120 bytes.
	expectCode(t, mk("esc", map[string]any{"s": strings.Repeat(`"`, 60)}), 413, "limit")
	expectCode(t, mk("name", map[string]any{strings.Repeat("k", 99): 1}), 413, "limit")
	expectCode(t, mk("inarr", map[string]any{"a": []any{map[string]any{"b": strings.Repeat("x", 99)}}}), 413, "limit")

	// Pointer "/aaaa…/b": 38 + 2 quotes fits, one more doesn't. "/" and
	// "~" in names are escaped in the pointer, so they count twice.
	expect(t, mk("p1", map[string]any{strings.Repeat("a", 35): map[string]any{"b": 1}}), 201)
	expectCode(t, mk("p2", map[string]any{strings.Repeat("a", 37): map[string]any{"b": 1}}), 413, "limit")
	expectCode(t, mk("p3", map[string]any{strings.Repeat("/", 20): map[string]any{"b": 1}}), 413, "limit")

	// Both are limits like the others: bounded by the deployment's.
	cid := e.configID("v")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/v", ifMatch: cid, author: "admin",
		body: ops(op("replace", "/limits/valueSize", 1<<20))}), 422, "limit")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/v", ifMatch: cid, author: "admin",
		body: ops(op("replace", "/limits/pathSize", "big"))}), 422, "invalid")
}

// §6.6: creates, and restores from scratch, may be as large as documentSize.
func TestCreatesFromScratch(t *testing.T) {
	e := newEnv(t)
	e.mkNS("s", map[string]any{"limits": map[string]any{"patchSetSize": 1024, "documentSize": 16384}})
	str := strings.Repeat("x", 1000)
	big := map[string]any{"a": str, "b": str, "c": str, "d": str}

	head := etagOf(e.write("PATCH", "s", "r", "", addRoot(big)))
	if head == "" {
		t.Fatal("no create")
	}
	expectCode(t, e.write("PATCH", "s", "huge", "", addRoot(map[string]any{"a": strings.Repeat(str, 17)[:16400]})), 413, "limit")
	// An append stays within patchSetSize.
	expectCode(t, e.write("PATCH", "s", "r", head, ops(op("replace", "/a", str), op("replace", "/b", str))), 413, "limit")
	// A restore is large only from scratch.
	tomb := e.del("s", "r", head)
	expectCode(t, e.write("PATCH", "s", "r", tomb, ops(op("add", "/a", str), op("add", "/b", str))), 413, "limit")
	expect(t, e.write("PATCH", "s", "r", tomb, ops(op("replace", "", big))), 201)
}

// §6.6: a config write to an e2e namespace needs room for a sealed patch set
// that replaces one string.
func TestE2EConfigLimits(t *testing.T) {
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	put := func(ns string, limits map[string]any) *resp {
		return e.do(req{method: "PATCH", path: "/ns/" + ns, ifNoneMatch: "*", author: "admin",
			body: addRoot(e2eDoc(map[string]any{"limits": limits}))})
	}
	// 3 × (1000 + 100) + 1024 + 36 × 10 = 4684.
	l := map[string]any{"valueSize": 1000, "pathSize": 100, "blobsPerDocument": 10, "patchSetSize": 4684}
	expect(t, put("e1", l), 201)
	l["patchSetSize"] = 4683
	expectCode(t, put("e2", l), 422, "limit")
	// The defaults fit.
	expect(t, put("e3", map[string]any{}), 201)
	expectCode(t, put("e4", map[string]any{"patchSetSize": 200 << 10}), 422, "limit")
	// Other namespaces have no such rule.
	expect(t, e.do(req{method: "PATCH", path: "/ns/plain", ifNoneMatch: "*", author: "admin",
		body: addRoot(map[string]any{"limits": map[string]any{"patchSetSize": 4683}})}), 201)
}

func blobRef(id string, extra map[string]any) map[string]any {
	m := map[string]any{"$blob": id, "type": "image/jpeg", "size": 1843302}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// §6.5: $blob is reserved at any depth, and a reference must be well-formed.
func TestBlobReferencesWellFormed(t *testing.T) {
	e := newEnv(t)
	e.mkNS("b", map[string]any{"limits": map[string]any{"blobsPerDocument": 2}})
	id := ids.Of([]byte("one")).String()
	id2 := ids.Of([]byte("two")).String()
	id3 := ids.Of([]byte("three")).String()
	n := 0
	mk := func(doc any) *resp {
		n++
		return e.write("PATCH", "b", "r"+string(rune('a'+n)), "", addRoot(doc))
	}
	nonce := strings.Repeat("a", 26)

	// Well-formed references to blobs that aren't available are 422 too
	// (§7.8); blob_test.go has the available ones.
	for _, doc := range []map[string]any{
		{"hero": blobRef(id, nil)},
		{"l": []any{map[string]any{"deep": blobRef(id, map[string]any{"nonce": nonce})}}},
		{"size": 0, "x": blobRef(id, map[string]any{"size": 0})},
	} {
		r := mk(doc)
		if r.Code != 422 || r.Str("code") != "blob" || !strings.Contains(r.Str("message"), "not available") {
			t.Errorf("%v: %d %s", doc, r.Code, r.Body)
		}
	}
	// Not a string: an ordinary member.
	expect(t, mk(map[string]any{"x": map[string]any{"$blob": 1, "any": "thing"}}), 201)

	bad := map[string]any{
		"extra member": blobRef(id, map[string]any{"name": "x"}),
		"no type":      map[string]any{"$blob": id, "size": 1},
		"no size":      map[string]any{"$blob": id, "type": "image/jpeg"},
		"bad id":       blobRef("1abc", nil),
		"not an id":    blobRef("hello", nil),
		"upper type":   blobRef(id, map[string]any{"type": "Image/JPEG"}),
		"param":        blobRef(id, map[string]any{"type": "text/plain; charset=utf-8"}),
		"no subtype":   blobRef(id, map[string]any{"type": "image"}),
		"negative":     blobRef(id, map[string]any{"size": -1}),
		"fraction":     blobRef(id, map[string]any{"size": 1.5}),
		"string size":  blobRef(id, map[string]any{"size": "10"}),
		"bad nonce":    blobRef(id, map[string]any{"nonce": "short"}),
		"upper nonce":  blobRef(id, map[string]any{"nonce": strings.Repeat("A", 26)}),
	}
	for name, ref := range bad {
		r := mk(map[string]any{"a": []any{map[string]any{"b": ref}}})
		if r.Code != 422 || r.Str("code") != "blob" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// Appends are checked too.
	head := e.create("b", "ap", map[string]any{"n": 1})
	expectCode(t, e.write("PATCH", "b", "ap", head, ops(op("add", "/x", map[string]any{"$blob": id}))), 422, "blob")

	// A schema document is not searched.
	expect(t, e.write("PATCH", "b", "schema", "", addRoot(map[string]any{
		"$schema": dialect, "const": map[string]any{"$blob": "not a blob id"}})), 201)

	// blobsPerDocument counts distinct blobs, before availability.
	expectCode(t, mk(map[string]any{"a": blobRef(id, nil), "b": blobRef(id, nil), "c": blobRef(id2, nil)}), 422, "blob")
	expectCode(t, mk(map[string]any{"a": blobRef(id, nil), "b": blobRef(id2, nil), "c": blobRef(id3, nil)}), 422, "limit")
}

// §6.6: an allowance's `until` ends it.
func TestAllowanceUntil(t *testing.T) {
	until := t0.Add(20 * time.Minute).Format(time.RFC3339)
	f := newAuthFixture(t, map[string]any{
		"limits": map[string]any{"itemsPerBatch": 2},
		"allowances": []any{map[string]any{"sub": "user:bob", "kid": "issuer",
			"itemsPerBatch": 20, "until": until}},
	})
	e := f.tenv
	batch := func(prefix string, n int) *resp {
		return e.do(req{method: "POST", path: "/ns/sec/batch", body: batchOf(prefix, n), bearer: f.issuerG})
	}
	expect(t, batch("a", 20), 201)
	e.clock.Advance(19 * time.Minute)
	expect(t, batch("b", 20), 201)
	e.clock.Advance(time.Minute) // now == until: ignored
	expectCode(t, batch("c", 20), 413, "limit")
	expect(t, batch("d", 2), 201)

	// Malformed values are config errors.
	cid := e.configID("sec", f.adminG)
	for _, v := range []any{"tomorrow", "2026-12-31", "2026-12-31T23:59:59", 5} {
		expectCode(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
			body: ops(op("replace", "/allowances/0/until", v))}), 422, "invalid")
	}
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("replace", "/allowances/0/until", "2030-01-01T00:00:00+02:00"))}), 201)
}
