package schemaimport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

// fixtures is a set of schemas exercising relative refs, $id bases in
// subschemas, anchors, a cycle, draft-07 and draft-04 documents and a
// meta-schema ref. HOST is replaced by the test server's URL.
var fixtures = map[string]string{
	"/a/root.json": `{
	  "$schema": "https://json-schema.org/draft/2020-12/schema",
	  "$id": "HOST/a/root.json",
	  "type": "object",
	  "required": ["addr"],
	  "properties": {
	    "addr":       { "$ref": "common/address.json" },
	    "zip":        { "$ref": "common/address.json#zip" },
	    "pos":        { "$ref": "../legacy/d7.json#/definitions/pos" },
	    "name":       { "$ref": "../legacy/d7.json#name" },
	    "pct":        { "$ref": "../legacy/d4.json#/definitions/pct" },
	    "nested":     { "$ref": "#/$defs/inner/properties/x" },
	    "local":      { "$ref": "#here" },
	    "meta":       { "$ref": "https://json-schema.org/draft/2020-12/schema" },
	    "node":       { "$ref": "cyc/a.json" },
	    "odd":        { "$ref": "common/address.json#/$defs/we%20ird~1key" }
	  },
	  "$defs": {
	    "here":  { "$anchor": "here", "type": "boolean" },
	    "inner": { "$id": "../b/inner.json", "properties": { "x": { "$ref": "sib.json" } } }
	  }
	}`,
	"/a/common/address.json": `{
	  "$schema": "https://json-schema.org/draft/2020-12/schema",
	  "type": "object",
	  "properties": { "street": { "type": "string" }, "zip": { "$ref": "#zip" } },
	  "$defs": {
	    "zip": { "$anchor": "zip", "type": "string", "pattern": "^[0-9]{5}$" },
	    "we ird/key": { "type": "null" }
	  },
	  "markdownDescription": "an editor annotation"
	}`,
	"/legacy/d7.json": `{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "definitions": {
	    "pos":  { "type": "array", "items": [ { "type": "number" }, { "type": "number" } ], "additionalItems": false },
	    "name": { "$id": "#name", "type": "string", "minLength": 1 }
	  },
	  "dependencies": { "a": ["b"], "c": { "required": ["d"] } }
	}`,
	"/legacy/d4.json": `{
	  "$schema": "http://json-schema.org/draft-04/schema#",
	  "id": "HOST/legacy/d4.json",
	  "definitions": { "pct": { "type": "number", "maximum": 100, "exclusiveMaximum": true, "minimum": 0, "exclusiveMinimum": false } }
	}`,
	"/b/sib.json":   `{ "type": "integer" }`,
	"/a/cyc/a.json": `{ "type": "object", "properties": { "next": { "$ref": "b.json" }, "self": { "$ref": "a.json#/properties/next" } } }`,
	"/a/cyc/b.json": `{ "type": "object", "properties": { "prev": { "$ref": "a.json" }, "val": { "type": "string" } } }`,

	"/dup/x/common.json":  `{ "properties": { "y": { "$ref": "../y/common.json" } } }`,
	"/dup/y/common.json":  `{ "type": "object" }`,
	"/bad/lookahead.json": `{ "type": "string", "pattern": "^(?!x)" }`,
	"/bad/local.json":     `{ "$ref": "file:///etc/passwd" }`,
	"/bad/dynamic.json":   `{ "$dynamicRef": "other.json#meta" }`,
	"/bad/anchor.json":    `{ "$ref": "#nowhere" }`,
}

type fixtureServer struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string]string
}

func newFixtureServer(t *testing.T) *fixtureServer {
	fs := &fixtureServer{files: map[string]string{}}
	for k, v := range fixtures {
		fs.files[k] = v
	}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		body, ok := fs.files[r.URL.Path]
		fs.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/schema+json")
		w.Write([]byte(strings.ReplaceAll(body, "HOST", fs.URL)))
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fixtureServer) set(path, body string) {
	fs.mu.Lock()
	fs.files[path] = body
	fs.mu.Unlock()
}

func get(t *testing.T, v any, ptr string) any {
	t.Helper()
	x, ok := pointer.Get(v, pointer.MustParse(ptr))
	if !ok {
		t.Fatalf("no %s in %s", ptr, jsonv.Canonical(v))
	}
	return x
}

func byName(t *testing.T, res *schemaimport.Result, name string) *schemaimport.Resource {
	t.Helper()
	for _, r := range res.Resources {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no resource %s", name)
	return nil
}

func TestPlanFixtures(t *testing.T) {
	ctx := context.Background()
	fs := newFixtureServer(t)
	res, err := schemaimport.Plan(ctx, nil, []string{fs.URL + "/a/root.json"}, schemaimport.Options{NS: "schemas", Name: "person"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range res.Resources {
		names = append(names, r.Name)
		if r.Action != schemaimport.Create {
			t.Errorf("%s: action %s", r.Name, r.Action)
		}
	}
	// Dependency order: every revision path a resource references belongs
	// to a resource before it.
	seen := map[string]bool{}
	for _, r := range res.Resources {
		for _, ref := range schema.Refs(r.Content) {
			if !seen[ref.Path()] {
				t.Errorf("%s references %s before it is written", r.Name, ref.Path())
			}
		}
		seen[r.Path("schemas")] = true
	}
	if got, want := len(res.Resources), 6; got != want {
		t.Fatalf("resources %v, want %d", names, want)
	}
	root := byName(t, res, "person")
	if res.Resources[len(res.Resources)-1] != root {
		t.Errorf("root is not last: %v", names)
	}
	path := func(n string) string { return byName(t, res, n).Path("schemas") }
	rc := root.Content
	for ptr, want := range map[string]string{
		"/properties/addr/$ref":          path("address"),
		"/properties/zip/$ref":           path("address") + "#/$defs/zip",
		"/properties/pos/$ref":           path("d7") + "#/$defs/pos",
		"/properties/name/$ref":          path("d7") + "#/$defs/name",
		"/properties/pct/$ref":           path("d4") + "#/$defs/pct",
		"/properties/nested/$ref":        "#/$defs/inner/properties/x",
		"/properties/local/$ref":         "#/$defs/here",
		"/properties/node/$ref":          path("a"),
		"/properties/odd/$ref":           path("address") + "#/$defs/we%20ird~1key",
		"/$defs/inner/properties/x/$ref": path("sib"),
		"/$schema":                       schema.Dialect2020,
	} {
		if got := get(t, rc, ptr); got != want {
			t.Errorf("root %s = %v, want %s", ptr, got, want)
		}
	}
	for _, ptr := range []string{"/$id", "/$defs/inner/$id", "/$defs/here/$anchor", "/properties/meta/$ref"} {
		if _, ok := pointer.Get(rc, pointer.MustParse(ptr)); ok {
			t.Errorf("root still has %s", ptr)
		}
	}
	if get(t, rc, "/properties/meta/x-meta-ref") != schema.Dialect2020 {
		t.Errorf("meta ref annotation missing")
	}
	// Same-document anchor refs become pointers too.
	addr := byName(t, res, "address").Content
	if get(t, addr, "/properties/zip/$ref") != "#/$defs/zip" || get(t, addr, "/x-markdownDescription") != "an editor annotation" {
		t.Errorf("address: %s", jsonv.Canonical(addr))
	}
	// Draft-07: definitions, items arrays, additionalItems, dependencies, $id anchors.
	d7 := byName(t, res, "d7").Content
	want7 := `{"$defs":{"name":{"minLength":1,"type":"string"},"pos":{"items":false,"prefixItems":[{"type":"number"},{"type":"number"}],"type":"array"}},"$schema":"https://json-schema.org/draft/2020-12/schema","dependentRequired":{"a":["b"]},"dependentSchemas":{"c":{"required":["d"]}},"x-source":"` + fs.URL + `/legacy/d7.json"}`
	if got := string(jsonv.Canonical(d7)); got != want7 {
		t.Errorf("d7:\n got %s\nwant %s", got, want7)
	}
	d4 := byName(t, res, "d4").Content
	want4 := `{"$defs":{"pct":{"exclusiveMaximum":100,"minimum":0,"type":"number"}},"$schema":"https://json-schema.org/draft/2020-12/schema","x-source":"` + fs.URL + `/legacy/d4.json"}`
	if got := string(jsonv.Canonical(d4)); got != want4 {
		t.Errorf("d4:\n got %s\nwant %s", got, want4)
	}
	// The cycle a ↔ b is one resource, b under $defs.
	if len(res.Bundled) != 1 || len(res.Bundled[0]) != 2 {
		t.Fatalf("bundled %v", res.Bundled)
	}
	cyc := byName(t, res, "a").Content
	for ptr, want := range map[string]string{
		"/properties/next/$ref":         "#/$defs/b",
		"/properties/self/$ref":         "#/properties/next",
		"/$defs/b/properties/prev/$ref": "#",
	} {
		if got := get(t, cyc, ptr); got != want {
			t.Errorf("cycle %s = %v, want %s", ptr, got, want)
		}
	}
	// Entries: one per source document, the root last; b's path points
	// into a's bundle.
	if n := len(res.Entries); n != 7 || !res.Entries[n-1].Root || res.Entries[n-1].Path != root.Path("schemas") {
		t.Fatalf("entries %+v", res.Entries)
	}
	for _, e := range res.Entries {
		if strings.HasSuffix(e.Source, "/cyc/b.json") && e.Path != path("a")+"#/$defs/b" {
			t.Errorf("b entry %+v", e)
		}
	}
	joined := strings.Join(res.Warnings, "\n")
	for _, w := range []string{"meta-schema https://json-schema.org/draft/2020-12/schema", `"markdownDescription"`} {
		if !strings.Contains(joined, w) {
			t.Errorf("no warning about %s in %s", w, joined)
		}
	}
	// The converted root validates instances as intended.
	planned := map[string]any{}
	for _, r := range res.Resources {
		planned[r.Path("schemas")] = r.Content
	}
	load := func(ref schema.Ref) (any, error) {
		if d, ok := planned[ref.Path()]; ok {
			return d, nil
		}
		return nil, schema.ErrUnavailable
	}
	v := schema.NewValidator()
	ok := map[string]any{"$schema": root.Path("schemas"), "addr": map[string]any{"street": "Main", "zip": "12345"},
		"pos": []any{1.0, 2.0}, "pct": 99.5, "name": "x", "nested": 3.0, "node": map[string]any{"next": map[string]any{"val": "v"}}}
	if err := v.Validate(ok, load); err != nil {
		t.Errorf("valid instance: %v", err)
	}
	for field, bad := range map[string]any{
		"addr": map[string]any{"zip": "abc"}, "pos": []any{1.0, 2.0, 3.0}, "pct": 100.0, "name": "",
		"nested": 1.5, "node": map[string]any{"next": map[string]any{"prev": map[string]any{"next": map[string]any{"val": 1.0}}}},
	} {
		doc := jsonv.Clone(ok).(map[string]any)
		doc[field] = bad
		if err := v.Validate(doc, load); err == nil {
			t.Errorf("invalid %s accepted", field)
		}
	}

	// Deterministic: the same plan again.
	again, err := schemaimport.Plan(ctx, nil, []string{fs.URL + "/a/root.json"}, schemaimport.Options{NS: "schemas", Name: "person"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Resources[len(again.Resources)-1].ID != root.ID {
		t.Errorf("plan is not deterministic")
	}
}

func TestPlanNames(t *testing.T) {
	fs := newFixtureServer(t)
	res, err := schemaimport.Plan(context.Background(), nil, []string{fs.URL + "/dup/x/common.json"}, schemaimport.Options{NS: "schemas"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resources) != 2 {
		t.Fatalf("%d resources", len(res.Resources))
	}
	dep, root := res.Resources[0], res.Resources[1]
	if root.Name != "common" || !strings.HasPrefix(dep.Name, "common-") || len(dep.Name) != len("common-")+8 {
		t.Errorf("names %s, %s", root.Name, dep.Name)
	}
	if _, err := schemaimport.Plan(context.Background(), nil, []string{fs.URL + "/dup/x/common.json"}, schemaimport.Options{NS: "schemas", Name: "Bad Name"}); err == nil {
		t.Error("invalid -name accepted")
	}
}

func TestPlanErrors(t *testing.T) {
	fs := newFixtureServer(t)
	for _, tc := range []struct {
		src  string
		opt  schemaimport.Options
		want string
	}{
		{"/bad/lookahead.json", schemaimport.Options{}, "not a schema the server accepts"},
		{"/bad/local.json", schemaimport.Options{}, "local file from a remote document"},
		{"/bad/dynamic.json", schemaimport.Options{}, "$dynamicRef"},
		{"/bad/anchor.json", schemaimport.Options{}, `no anchor "nowhere"`},
		{"/missing.json", schemaimport.Options{}, "404"},
		{"/a/root.json", schemaimport.Options{MaxDocs: 3}, "more than 3 documents"},
		{"/a/root.json", schemaimport.Options{MaxBytes: 1500}, "exceed 1500 bytes"},
	} {
		tc.opt.NS = "schemas"
		_, err := schemaimport.Plan(context.Background(), nil, []string{fs.URL + tc.src}, tc.opt)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.src, err, tc.want)
		}
	}
}

func TestPlanLocalFiles(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "defs"), 0o755)
	os.WriteFile(filepath.Join(dir, "main.json"), []byte(`{"properties":{"n":{"$ref":"defs/num.json#/$defs/n"}}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "defs", "num.json"), []byte(`{"$defs":{"n":{"type":"number"}}}`), 0o644)
	res, err := schemaimport.Plan(context.Background(), nil, []string{filepath.Join(dir, "main.json")}, schemaimport.Options{NS: "schemas"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resources) != 2 || res.Resources[1].Name != "main" {
		t.Fatalf("%+v", res.Entries)
	}
	if got := get(t, res.Resources[1].Content, "/properties/n/$ref"); got != res.Resources[0].Path("schemas")+"#/$defs/n" {
		t.Errorf("ref %v", got)
	}
	if _, err := schemaimport.Plan(context.Background(), nil, []string{"ftp://x/y.json"}, schemaimport.Options{NS: "schemas"}); err == nil {
		t.Error("ftp accepted")
	}
}
