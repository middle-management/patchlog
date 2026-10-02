package schemaimport_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

func planFiles(t *testing.T, files map[string]string, root string, opt schemaimport.Options) *schemaimport.Result {
	t.Helper()
	opt.NS = "schemas"
	opt.Files = map[string][]byte{}
	for n, b := range files {
		opt.Files[n] = []byte(b)
	}
	res, err := schemaimport.Plan(context.Background(), nil, []string{schemaimport.FileURL(root).String()}, opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func has(v any, ptr string) bool {
	_, ok := pointer.Get(v, pointer.MustParse(ptr))
	return ok
}

func warned(res *schemaimport.Result, sub string) bool {
	for _, w := range res.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

const declared = `{"type":"string"}`

func TestDeclareSchema(t *testing.T) {
	type tc struct {
		name    string
		src     string
		patched []string // pointers that gain properties/$schema
		absent  []string // closed or not, these must not gain it
		warn    string   // a substring some warning has ("" for none about declaring)
	}
	for _, c := range []tc{
		{name: "closed root", src: `{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}`,
			patched: []string{""}, warn: "declared $schema in 1 closed schema "},
		{name: "closed root without properties", src: `{"additionalProperties":false}`, patched: []string{""}},
		{name: "schemastore root ref", src: `{"$ref":"#/definitions/X","definitions":{"X":{"type":"object","properties":{"a":{}},"additionalProperties":false},"Y":{"additionalProperties":false}}}`,
			patched: []string{"/$defs/X"}, absent: []string{"", "/$defs/Y"}, warn: "declared $schema in 1 closed schema "},
		{name: "allOf", src: `{"allOf":[{"properties":{"a":{}},"additionalProperties":false},{"properties":{"b":{}}}]}`,
			patched: []string{"/allOf/0"}, absent: []string{"", "/allOf/1"}},
		{name: "branches", src: `{"oneOf":[{"additionalProperties":false},{"unevaluatedProperties":false}],"if":{"additionalProperties":false},"then":{"additionalProperties":false}}`,
			patched: []string{"/oneOf/0", "/oneOf/1", "/if", "/then"}, warn: "declared $schema in 4 closed schemas"},
		{name: "unevaluatedProperties", src: `{"properties":{"a":{}},"unevaluatedProperties":false}`, patched: []string{""}},
		{name: "already declared", src: `{"properties":{"$schema":{"type":"string","format":"uri"}},"additionalProperties":false}`,
			absent: []string{""}},
		{name: "pattern covers", src: `{"patternProperties":{"^\\$":{}},"additionalProperties":false}`, absent: []string{""}},
		{name: "not closed", src: `{"properties":{"a":{}},"additionalProperties":{"type":"string"}}`, absent: []string{""}},
		{name: "nested object is not the root", src: `{"properties":{"a":{"additionalProperties":false}}}`, absent: []string{"/properties/a"}},
		{name: "propertyNames refuses", src: `{"propertyNames":{"pattern":"^[a-z]+$"},"additionalProperties":false}`,
			absent: []string{""}, warn: "propertyNames rejects $schema"},
		{name: "propertyNames allows", src: `{"propertyNames":{"minLength":1},"additionalProperties":false}`, patched: []string{""}},
		{name: "maxProperties", src: `{"maxProperties":2,"additionalProperties":false}`, absent: []string{""}, warn: "maxProperties"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := planFiles(t, map[string]string{"x.json": c.src}, "x.json", schemaimport.Options{DeclareSchema: true})
			content := res.Resources[0].Content
			for _, p := range c.patched {
				if got := jsonv.Canonical(get(t, content, p+"/properties/$schema")); string(got) != declared {
					t.Errorf("%q: $schema property %s", p, got)
				}
			}
			for _, p := range c.absent {
				if has(content, p+"/properties/$schema") && !strings.Contains(c.src, `"$schema"`) {
					t.Errorf("%q gained $schema", p)
				}
			}
			if c.warn != "" && !warned(res, c.warn) {
				t.Errorf("warnings %q lack %q", res.Warnings, c.warn)
			}
			if c.warn == "" && warned(res, "declared $schema") != (len(c.patched) > 0) {
				t.Errorf("warnings %q for %d patched", res.Warnings, len(c.patched))
			}

			// Opting out leaves the bytes (but for x-source) alone.
			off := planFiles(t, map[string]string{"x.json": c.src}, "x.json", schemaimport.Options{})
			for _, p := range c.patched {
				if has(off.Resources[0].Content, p+"/properties/$schema") {
					t.Errorf("without -declare-schema: %q gained $schema", p)
				}
			}
			if warned(off, "declared $schema") || warned(off, "can't type documents") {
				t.Errorf("without -declare-schema, warned: %q", off.Warnings)
			}
		})
	}
}

// A closed schema used both at the root and below it is patched, and the
// side effect is reported.
func TestDeclareSchemaShared(t *testing.T) {
	res := planFiles(t, map[string]string{"x.json": `{
	  "$ref": "#/$defs/C",
	  "properties": { "child": { "$ref": "#/$defs/C" } },
	  "$defs": { "C": { "properties": { "a": {} }, "additionalProperties": false },
	             "OnlyBelow": { "additionalProperties": false } }
	}`}, "x.json", schemaimport.Options{DeclareSchema: true})
	c := res.Resources[0].Content
	if !has(c, "/$defs/C/properties/$schema") {
		t.Error("C not patched")
	}
	if has(c, "/$defs/OnlyBelow/properties/$schema") {
		t.Error("an unreachable closed schema was patched")
	}
	if !warned(res, "declared $schema in 1 closed schema ") || !warned(res, "also used below the document root") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

// Every resource can be a document's $schema, and a closed schema reached by
// $ref from another resource's root is patched in its own resource, before
// the ids the references pin are computed.
func TestDeclareSchemaCrossResource(t *testing.T) {
	files := map[string]string{
		"root.json":   `{"$ref":"closed.json","properties":{"extra":{"type":"integer"}}}`,
		"closed.json": `{"properties":{"a":{}},"$ref":"deeper.json#/$defs/D","additionalProperties":false}`,
		"deeper.json": `{"$defs":{"D":{"allOf":[{"unevaluatedProperties":false}]}}}`,
	}
	res := planFiles(t, files, "root.json", schemaimport.Options{DeclareSchema: true})
	if len(res.Resources) != 3 {
		t.Fatalf("%d resources", len(res.Resources))
	}
	byN := map[string]any{}
	for _, r := range res.Resources {
		byN[r.Name] = r.Content
	}
	if has(byN["root"], "/properties/$schema") {
		t.Error("root gained $schema")
	}
	if !has(byN["closed"], "/properties/$schema") || !has(byN["deeper"], "/$defs/D/allOf/0/properties/$schema") {
		t.Errorf("closed: %s deeper: %s", jsonv.Canonical(byN["closed"]), jsonv.Canonical(byN["deeper"]))
	}
	if !warned(res, "declared $schema in 2 closed schemas") {
		t.Errorf("warnings %q", res.Warnings)
	}
	// The pins follow the patched content: the root refers to closed's revision.
	closedRes := byName(t, res, "closed")
	if got := get(t, byN["root"], "/$ref"); got != closedRes.Path("schemas") {
		t.Errorf("root $ref %v, want %s", got, closedRes.Path("schemas"))
	}
	// A cycle is bundled; the member under $defs is patched and keeps its source.
	cyc := planFiles(t, map[string]string{
		"a.json": `{"properties":{"b":{"$ref":"b.json"}}}`,
		"b.json": `{"additionalProperties":false,"properties":{"a":{"$ref":"a.json"}}}`,
	}, "a.json", schemaimport.Options{DeclareSchema: true})
	if len(cyc.Resources) != 1 {
		t.Fatalf("%d resources", len(cyc.Resources))
	}
	// b is only reached below a's root: not patched, but its source is kept.
	cc := cyc.Resources[0].Content
	if has(cc, "/$defs/b/properties/$schema") || get(t, cc, "/$defs/b/x-source") != "b.json" || get(t, cc, "/x-source") != "a.json" {
		t.Errorf("bundle %s", jsonv.Canonical(cc))
	}
	// ...but a document can name the bundle's root only; a root that
	// refers to b at the root does patch it.
	cyc = planFiles(t, map[string]string{
		"a.json": `{"$ref":"b.json"}`,
		"b.json": `{"additionalProperties":false,"allOf":[{"$ref":"a.json"}]}`,
	}, "a.json", schemaimport.Options{DeclareSchema: true})
	if !has(cyc.Resources[0].Content, "/$defs/b/properties/$schema") {
		t.Errorf("bundle %s", jsonv.Canonical(cyc.Resources[0].Content))
	}
}

func TestSourceKept(t *testing.T) {
	res := planFiles(t, map[string]string{
		"blueprints/door.json": `{"$id":"https://doors.example/blueprints/door","type":"object"}`,
		"plain.json":           `{"$id":"file:///upload/plain.json","type":"object"}`,
		"d4.json":              `{"$schema":"http://json-schema.org/draft-04/schema#","id":"http://old.example/d4#"}`,
	}, "blueprints/door.json", schemaimport.Options{DeclareSchema: true})
	c := res.Resources[0].Content
	if get(t, c, "/x-source") != "blueprints/door.json" || get(t, c, "/x-source-id") != "https://doors.example/blueprints/door" {
		t.Errorf("%s", jsonv.Canonical(c))
	}
	if _, ok := pointer.Get(c, pointer.MustParse("/$id")); ok {
		t.Error("$id kept")
	}
	res = planFiles(t, map[string]string{
		"plain.json": `{"$id":"file:///upload/plain.json","type":"object"}`,
	}, "plain.json", schemaimport.Options{DeclareSchema: true})
	if c := res.Resources[0].Content; get(t, c, "/x-source") != "plain.json" || has(c, "/x-source-id") {
		t.Errorf("%s", jsonv.Canonical(c))
	}
	// A draft-04 id counts too; and the source of an imported dependency is kept.
	res = planFiles(t, map[string]string{
		"main.json": `{"properties":{"o":{"$ref":"d4.json"}}}`,
		"d4.json":   `{"$schema":"http://json-schema.org/draft-04/schema#","id":"http://old.example/d4#"}`,
	}, "main.json", schemaimport.Options{DeclareSchema: true})
	d4 := byName(t, res, "d4").Content
	if get(t, d4, "/x-source") != "d4.json" || get(t, d4, "/x-source-id") != "http://old.example/d4#" {
		t.Errorf("%s", jsonv.Canonical(d4))
	}
}

// A closed blueprint imported with the tool can type documents as it is,
// since validation leaves out $schema and a fresh $nonce (§6.2 step 5, spec
// v0.36); an invalid one still fails; re-running is a no-op.
func TestImportClosedBlueprintEndToEnd(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("importer"))
	for _, ns := range []string{"schemas", "docs"} {
		if _, err := c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		"door.json": []byte(`{
		  "$schema": "http://json-schema.org/draft-07/schema#",
		  "$id": "https://doors.example/blueprints/door.json",
		  "$ref": "#/definitions/Door",
		  "definitions": { "Door": { "type": "object", "required": ["height"],
		    "properties": { "height": { "type": "integer", "minimum": 1 } },
		    "additionalProperties": false } }
		}`),
	}
	src := []string{schemaimport.FileURL("door.json").String()}
	opt := schemaimport.Options{NS: "schemas", Files: files, NoDisk: true}
	res, err := schemaimport.Plan(ctx, c, src, opt)
	if err != nil {
		t.Fatal(err)
	}
	if warned(res, "declared $schema") {
		t.Errorf("declared without -declare-schema: %q", res.Warnings)
	}
	if err := res.Write(ctx, c); err != nil {
		t.Fatal(err)
	}
	r := res.Resources[0]
	if get(t, r.Content, "/x-source") != "door.json" || get(t, r.Content, "/x-source-id") != "https://doors.example/blueprints/door.json" {
		t.Errorf("%s", jsonv.Canonical(r.Content))
	}
	path := r.Path("schemas")
	if _, err := c.CreateDoc(ctx, "docs", "front", map[string]any{"$schema": path, "height": 200, "$nonce": "abcdefghijklmnopqrstuvwxyz"}); err != nil {
		t.Fatalf("typed document: %v", err)
	}
	_, err = c.CreateDoc(ctx, "docs", "bad", map[string]any{"$schema": path, "height": 0})
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 || ae.Code != "invalid" {
		t.Fatalf("invalid document: %v", err)
	}
	_, err = c.CreateDoc(ctx, "docs", "extra", map[string]any{"$schema": path, "height": 2, "color": "red"})
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 {
		t.Fatalf("closedness lost: %v", err)
	}
	again, err := schemaimport.Plan(ctx, c, src, opt)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed() || again.Resources[0].ID != r.ID {
		t.Fatalf("re-run: changed=%v id %s want %s", again.Changed(), again.Resources[0].ID, r.ID)
	}

	// A $nonce not of the fresh-nonce form is data, and the closed schema
	// refuses it.
	_, err = c.CreateDoc(ctx, "docs", "nonce", map[string]any{"$schema": path, "height": 2, "$nonce": "x"})
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 {
		t.Fatalf("$nonce of another form: %v", err)
	}

	// -declare-schema adds the declaration for older servers; documents
	// still validate.
	opt.NS = "docs"
	opt.DeclareSchema = true
	decl, err := schemaimport.Plan(ctx, c, src, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !warned(decl, "declared $schema in 1 closed schema ") {
		t.Errorf("warnings %q", decl.Warnings)
	}
	if err := decl.Write(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDoc(ctx, "docs", "declared", map[string]any{"$schema": decl.Resources[0].Path("docs"), "height": 2}); err != nil {
		t.Fatalf("declared blueprint: %v", err)
	}
}
