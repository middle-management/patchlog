package annot

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/keys.golden from the current walks")

var pathGolden = "/r/s/golden/rev/" + rev('g')

func init() {
	store[pathGolden] = `{` + d2020 + `,
		"type": "object",
		"$defs": {
			"node": {
				"type": "object",
				"properties": {
					"id":   { "type": "string", "x-index": "facet" },
					"pin":  { "type": "string", "x-ref": { "pinned": true } },
					"live": { "type": "string", "x-ref": {}, "x-index": "text" },
					"kids": { "type": "array", "items": { "$ref": "#/$defs/node" } },
					"grid": { "type": "array", "items": { "type": "array", "items": { "type": "string", "x-ref": { "pinned": true, "key": "/cells" } } } },
					"tags": { "type": "array", "prefixItems": [ { "type": "string", "x-index": "first" } ], "items": { "type": "string", "x-ref": {} } },
					"x_a":  { "x-index": "prop" }
				},
				"patternProperties": {
					"^x_": { "type": "string", "x-ref": { "pinned": true }, "x-index": "pattern" }
				},
				"additionalProperties": {
					"anyOf": [
						{ "type": "string", "x-ref": {} },
						{ "type": "object", "additionalProperties": { "$ref": "#/$defs/node" }, "x-index": "map" }
					]
				},
				"allOf": [ { "properties": { "id": { "x-index": "allof" } } } ],
				"if":   { "required": ["live"] },
				"then": { "properties": { "live": { "x-index": "then" } } },
				"else": { "properties": { "id": { "x-index": "else" } } },
				"dependentSchemas": { "pin": { "properties": { "pin": { "x-index": "dep" } } } }
			}
		},
		"properties": {
			"$schema": { "type": "string" },
			"root":    { "$ref": "#/$defs/node" },
			"list":    { "type": "array", "items": { "$ref": "#/$defs/node" },
			             "contains": { "type": "object", "required": ["pin"], "x-index": "contains" } },
			"player":  { "$ref": "` + pathPlayer + `" }
		},
		"propertyNames": { "x-ref": {} },
		"unevaluatedProperties": { "x-ref": { "pinned": true } }
	}`
}

// goldenDocs are documents of the golden schema with x-ref strings and
// x-index locations in sibling and nested positions: arrays of objects,
// arrays of arrays, members that properties and patternProperties both
// match, maps of nodes, several levels deep. They are generated from a
// seed, so they are the same every time.
func goldenDocs() []any {
	var docs []any
	for i, shape := range []struct{ depth, breadth int }{{1, 1}, {2, 2}, {3, 2}, {4, 2}, {8, 1}, {2, 4}} {
		r := rand.New(rand.NewSource(int64(i) + 1))
		doc := map[string]any{"$schema": pathGolden, "root": goldenNode(r, shape.depth, shape.breadth)}
		var list []any
		for k := 0; k < shape.breadth+1; k++ {
			list = append(list, goldenNode(r, shape.depth-1, shape.breadth))
		}
		doc["list"] = list
		doc["player"] = map[string]any{"name": "p" + fmt.Sprint(i), "id": fmt.Sprint("id-", i)}
		doc["extra"] = goldenRef(r, true)
		docs = append(docs, doc)
	}
	return docs
}

func goldenRef(r *rand.Rand, pinned bool) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	s := fmt.Sprintf("/r/ns%d/doc-%d", r.Intn(3), r.Intn(50))
	if pinned {
		id := make([]byte, 32)
		for i := range id {
			id[i] = alphabet[r.Intn(len(alphabet))]
		}
		s += "/rev/1" + string(id)
	}
	if r.Intn(3) == 0 {
		s += "#e-" + fmt.Sprint(r.Intn(9))
	}
	return s
}

func goldenNode(r *rand.Rand, depth, breadth int) map[string]any {
	n := map[string]any{"id": fmt.Sprint("n-", r.Intn(1000))}
	if r.Intn(2) == 0 {
		n["pin"] = goldenRef(r, true)
	}
	if r.Intn(2) == 0 {
		n["live"] = goldenRef(r, false)
	}
	if r.Intn(2) == 0 {
		var grid []any
		for i := 0; i < 1+r.Intn(3); i++ {
			var row []any
			for k := 0; k < 1+r.Intn(3); k++ {
				row = append(row, goldenRef(r, true))
			}
			grid = append(grid, row)
		}
		n["grid"] = grid
	}
	if r.Intn(2) == 0 {
		tags := []any{"first"}
		for i := 0; i < r.Intn(4); i++ {
			tags = append(tags, goldenRef(r, false))
		}
		n["tags"] = tags
	}
	if r.Intn(2) == 0 {
		n["x_a"] = goldenRef(r, true) // properties and patternProperties
	}
	if r.Intn(2) == 0 {
		n["x_b"] = goldenRef(r, true) // patternProperties only
	}
	if r.Intn(3) == 0 {
		n["other"] = goldenRef(r, r.Intn(2) == 0) // additionalProperties, a string
	}
	if depth > 1 {
		var kids []any
		for i := 0; i < breadth; i++ {
			kids = append(kids, goldenNode(r, depth-1, breadth))
		}
		n["kids"] = kids
		if depth <= 3 && r.Intn(2) == 0 {
			n["map"] = map[string]any{"a": goldenNode(r, depth-1, 1), "b": goldenNode(r, depth-1, 1)} // additionalProperties, nodes
		}
	}
	return n
}

// TestWalkKeysGolden: Collect and FindRefs on a varied document set return
// the annotations and references of testdata/keys.golden, in its order:
// what the walks returned when every instance location key was a fresh
// copy, before keys shared their backing arrays (appendKey, keepKey).
// internal/index builds its rows from these results.
func TestWalkKeysGolden(t *testing.T) {
	t.Parallel()
	hash := func(v any) string {
		sum := sha256.Sum256(jsonv.Canonical(v))
		return fmt.Sprintf("%x", sum[:4])
	}
	short := func(sp string) string { return strings.TrimPrefix(sp, pathGolden) }
	var b strings.Builder
	for i, doc := range goldenDocs() {
		anns, err := Collect(doc, loader)
		if err != nil {
			t.Fatalf("doc %d: collect: %v", i, err)
		}
		fmt.Fprintf(&b, "# doc %d: %d annotations\n", i, len(anns))
		for _, a := range anns {
			fmt.Fprintf(&b, "%s %s %s %s %s\n", a.Keyword, a.Pointer, short(a.SchemaPath), jsonv.Canonical(a.Value), hash(a.Instance))
		}
		refs, err := FindRefs(doc, loader)
		if err != nil {
			t.Fatalf("doc %d: refs: %v", i, err)
		}
		fmt.Fprintf(&b, "# doc %d: %d references\n", i, len(refs))
		for _, r := range refs {
			fmt.Fprintf(&b, "%s %s %v %q %q %s\n", r.Pointer, r.Raw, r.Pinned, r.Key, r.Entry, short(r.SchemaPath))
		}
	}
	path := filepath.Join("testdata", "keys.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("line %d:\n got %s\nwant %s", i+1, gl[i], wl[i])
			}
		}
		t.Fatalf("%d lines, want %d", len(gl), len(wl))
	}
}
