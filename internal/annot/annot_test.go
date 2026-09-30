package annot

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

func rev(c byte) string { return "1" + strings.Repeat(string(c), 32) }

var (
	pathMain   = "/r/s/main/rev/" + rev('a')
	pathPlayer = "/r/s/player/rev/" + rev('b')
	pathXref   = "/r/s/xref/rev/" + rev('c')
)

func j(s string) any { return jsonv.MustParse([]byte(s)) }

const d2020 = `"$schema": "https://json-schema.org/draft/2020-12/schema"`

var store = map[string]string{
	pathPlayer: `{` + d2020 + `,
		"type": "object",
		"properties": {"name": {"type": "string", "x-index": "text"}, "id": {"$ref": "#/$defs/id"}},
		"$defs": {"id": {"type": "string", "x-index": "facet"}}
	}`,
	pathMain: `{` + d2020 + `,
		"type": "object",
		"properties": {
			"$schema": {"type": "string"},
			"title": {"type": "string", "x-index": "text"},
			"players": {"type": "array", "items": {"$ref": "` + pathPlayer + `"}}
		}
	}`,
	pathXref: `{` + d2020 + `,
		"type": "object",
		"properties": {
			"$schema": {"type": "string"},
			"hero":    { "type": "string", "x-ref": { "pinned": true } },
			"related": { "type": "array", "items": { "type": "string", "x-ref": {} } }
		}
	}`,
}

func loader(r schema.Ref) (any, error) {
	s, ok := store[r.Path()]
	if !ok {
		return nil, schema.ErrUnavailable
	}
	return j(s), nil
}

// short renders annotations as "keyword pointer=value" lines.
func short(as []Annotation) []string {
	var out []string
	for _, a := range as {
		out = append(out, fmt.Sprintf("%s %s=%s", a.Keyword, a.Pointer, jsonv.Canonical(a.Value)))
	}
	return out
}

func TestCollectWith(t *testing.T) {
	cases := []struct {
		name     string
		schema   string
		doc      string
		keywords []string
		want     []string
	}{
		{
			name: "nested properties",
			schema: `{"type":"object","x-index":"facet","properties":{"a":{"type":"object","properties":{
				"b":{"type":"string","x-index":"text"},"c":{"type":"number","x-index":"sort"}}}}}`,
			doc:  `{"a":{"b":"hi","c":3}}`,
			want: []string{`x-index ="facet"`, `x-index /a/b="text"`, `x-index /a/c="sort"`},
		},
		{
			name:   "ref to defs",
			schema: `{"properties":{"k":{"$ref":"#/$defs/kw"}},"$defs":{"kw":{"type":"string","x-index":"facet"}}}`,
			doc:    `{"k":"x"}`,
			want:   []string{`x-index /k="facet"`},
		},
		{
			name:   "ref to anchor",
			schema: `{"properties":{"k":{"$ref":"#kw"}},"$defs":{"kw":{"$anchor":"kw","x-index":"facet"}}}`,
			doc:    `{"k":"x"}`,
			want:   []string{`x-index /k="facet"`},
		},
		{
			name:   "revision path ref",
			schema: `{"properties":{"p":{"$ref":"` + pathPlayer + `"}}}`,
			doc:    `{"p":{"name":"Ann","id":"7"}}`,
			want:   []string{`x-index /p/id="facet"`, `x-index /p/name="text"`},
		},
		{
			name:   "prefixItems and items",
			schema: `{"type":"array","prefixItems":[{"x-index":"sort"},{"x-index":"facet"}],"items":{"x-index":"text"}}`,
			doc:    `[1,2,3,4,5,6,7,8,9,10,11]`,
			want: []string{`x-index /0="sort"`, `x-index /1="facet"`, `x-index /2="text"`, `x-index /3="text"`,
				`x-index /4="text"`, `x-index /5="text"`, `x-index /6="text"`, `x-index /7="text"`,
				`x-index /8="text"`, `x-index /9="text"`, `x-index /10="text"`},
		},
		{
			name: "oneOf only matching branch",
			schema: `{"properties":{"v":{"oneOf":[
				{"type":"string","x-index":"text"},
				{"type":"number","x-index":"sort"}]}}}`,
			doc:  `{"v":5}`,
			want: []string{`x-index /v="sort"`},
		},
		{
			name: "anyOf two branches match",
			schema: `{"anyOf":[
				{"type":"object","x-a":1},
				{"required":["x"],"x-b":2},
				{"required":["nope"],"x-c":3}]}`,
			doc:  `{"x":1}`,
			want: []string{`x-a =1`, `x-b =2`},
		},
		{
			name: "failing anyOf branch drops nested annotations",
			schema: `{"properties":{"v":{"anyOf":[
				{"type":"object","properties":{"n":{"type":"string","x-index":"text"}},"required":["missing"]},
				{"type":"object"}]}}}`,
			doc:  `{"v":{"n":"s"}}`,
			want: nil,
		},
		{
			name: "if then",
			schema: `{"if":{"properties":{"kind":{"const":"a"}},"x-if":true},
				"then":{"properties":{"val":{"x-index":"text"}}},
				"else":{"properties":{"val":{"x-index":"sort"}}}}`,
			doc:  `{"kind":"a","val":1}`,
			want: []string{`x-if =true`, `x-index /val="text"`},
		},
		{
			name: "if else",
			schema: `{"if":{"properties":{"kind":{"const":"a"}},"x-if":true},
				"then":{"properties":{"val":{"x-index":"text"}}},
				"else":{"properties":{"val":{"x-index":"sort"}}}}`,
			doc:  `{"kind":"b","val":1}`,
			want: []string{`x-index /val="sort"`},
		},
		{
			name: "patternProperties and additionalProperties",
			schema: `{"properties":{"id":{"x-index":"facet"}},
				"patternProperties":{"^n_":{"x-index":"sort"}},
				"additionalProperties":{"x-index":"text"}}`,
			doc:  `{"id":1,"n_a":2,"other":3}`,
			want: []string{`x-index /id="facet"`, `x-index /n_a="sort"`, `x-index /other="text"`},
		},
		{
			name:   "contains",
			schema: `{"type":"array","contains":{"type":"string","x-index":"facet"}}`,
			doc:    `[1,"a",2,"b"]`,
			want:   []string{`x-index /1="facet"`, `x-index /3="facet"`},
		},
		{
			name:   "dependentSchemas",
			schema: `{"dependentSchemas":{"a":{"properties":{"b":{"x-index":"text"}}}}}`,
			doc:    `{"a":1,"b":2}`,
			want:   []string{`x-index /b="text"`},
		},
		{
			name:     "keyword filter",
			schema:   `{"properties":{"a":{"x-index":"text","x-ref":{},"x-other":1}}}`,
			doc:      `{"a":"s"}`,
			keywords: []string{"x-ref"},
			want:     []string{`x-ref /a={}`},
		},
		{
			name:   "recursive schema",
			schema: `{"$defs":{"node":{"properties":{"label":{"x-index":"text"},"kids":{"items":{"$ref":"#/$defs/node"}}}}},"$ref":"#/$defs/node"}`,
			doc:    `{"label":"r","kids":[{"label":"c","kids":[{"label":"g"}]}]}`,
			want:   []string{`x-index /kids/0/kids/0/label="text"`, `x-index /kids/0/label="text"`, `x-index /label="text"`},
		},
		{
			name:   "escaped property names",
			schema: `{"properties":{"a/b":{"x-index":"text"},"c d~":{"oneOf":[{"type":"string","x-index":"facet"},{"type":"number"}]}}}`,
			doc:    `{"a/b":1,"c d~":"s"}`,
			want:   []string{`x-index /a~1b="text"`, `x-index /c d~0="facet"`},
		},
		{
			name:   "dynamicRef to anchor",
			schema: `{"$dynamicAnchor":"root","properties":{"x":{"x-index":"text"},"child":{"$dynamicRef":"#root"}}}`,
			doc:    `{"child":{"x":1}}`,
			want:   []string{`x-index /child/x="text"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CollectWith(j(tc.schema), "", j(tc.doc), loader, tc.keywords...)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := strings.Join(short(got), "\n"), strings.Join(tc.want, "\n"); g != w {
				t.Errorf("got:\n%s\nwant:\n%s", g, w)
			}
		})
	}
}

func TestCollect(t *testing.T) {
	doc := j(`{"$schema":"` + pathMain + `","title":"Cup","players":[{"name":"A","id":"1"},{"name":"B"},{"name":"C"}]}`)
	got, err := Collect(doc, loader, "x-index")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`x-index /players/0/id="facet"`, `x-index /players/0/name="text"`,
		`x-index /players/1/name="text"`, `x-index /players/2/name="text"`, `x-index /title="text"`,
	}
	if g, w := strings.Join(short(got), "\n"), strings.Join(want, "\n"); g != w {
		t.Fatalf("got:\n%s\nwant:\n%s", g, w)
	}
	last := got[3]
	if last.Instance != "C" {
		t.Errorf("instance = %v", last.Instance)
	}
	if last.SchemaPath != pathPlayer+"#/properties/name" {
		t.Errorf("schema path = %q", last.SchemaPath)
	}
	if got[0].SchemaPath != pathPlayer+"#/$defs/id" {
		t.Errorf("schema path = %q", got[0].SchemaPath)
	}
}

func TestXRefExamples(t *testing.T) {
	photo := "/r/media/photo-12/rev/" + rev('q')
	doc := j(`{"$schema":"` + pathXref + `","hero":"` + photo + `","related":["/r/matches/cup","/r/matches/final"]}`)
	got, err := Collect(doc, loader, "x-ref")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %v", short(got))
	}
	if got[0].Pointer != "/hero" || got[0].Instance != photo || !jsonv.Equal(got[0].Value, j(`{"pinned":true}`)) {
		t.Errorf("hero: %+v", got[0])
	}
	for i, want := range []string{"/r/matches/cup", "/r/matches/final"} {
		a := got[i+1]
		if a.Pointer != fmt.Sprintf("/related/%d", i) || a.Instance != want || !jsonv.Equal(a.Value, j(`{}`)) {
			t.Errorf("related %d: %+v", i, a)
		}
		if a.SchemaPath != pathXref+"#/properties/related/items" {
			t.Errorf("schema path %q", a.SchemaPath)
		}
	}
}

func TestUntyped(t *testing.T) {
	for _, d := range []string{`{"a":1}`, `[1]`, `"s"`, `{` + d2020 + `,"x-index":"text"}`} {
		got, err := Collect(j(d), loader)
		if err != nil || got != nil {
			t.Errorf("%s: got %v, %v", d, got, err)
		}
	}
}

func TestErrors(t *testing.T) {
	// Invalid document.
	_, err := Collect(j(`{"$schema":"`+pathMain+`","title":5}`), loader)
	var ve *schema.ValidationError
	if !errors.As(err, &ve) || len(ve.Errors) == 0 || ve.Errors[0].Pointer != "/title" {
		t.Errorf("invalid doc: %v", err)
	}
	// Unavailable schema.
	_, err = Collect(j(`{"$schema":"/r/s/missing/rev/`+rev('z')+`"}`), loader)
	var ue *schema.UnavailableError
	if !errors.As(err, &ue) {
		t.Errorf("missing schema: %v", err)
	}
	// Bad $schema.
	_, err = Collect(j(`{"$schema":"http://example.com/x"}`), loader)
	var re *schema.RefError
	if !errors.As(err, &re) {
		t.Errorf("bad $schema: %v", err)
	}
	// Reference cycle without instance progress terminates.
	got, err := CollectWith(j(`{"$defs":{"a":{"$ref":"#/$defs/b","x-a":1},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`), "", j(`1`), loader)
	var se *schema.SchemaError
	if got != nil || !errors.As(err, &se) {
		t.Errorf("cycle: %v %v", short(got), err)
	}
	// The walker's own guard also terminates it (the library rejects it first).
	c := newCollector(loader, nil)
	c.docs[localBase] = j(`{"$defs":{"a":{"$ref":"#/$defs/b","x-a":1},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`)
	if err := c.walk(loc{base: localBase}, 1.0, nil, 0, nil); err != nil || len(c.out) != 1 {
		t.Errorf("walk guard: %v %d", err, len(c.out))
	}
}

var (
	pathFragUser = "/r/s/fraguser/rev/" + rev('f')
	pathFragLib  = "/r/s/fraglib/rev/" + rev('h')
)

func init() {
	store[pathFragLib] = `{` + d2020 + `,
		"$defs": {
			"tag":  {"type": "string", "x-index": "facet"},
			"a b":  {"type": "string", "x-index": "sort"},
			"link": {"type": "string", "x-ref": {"pinned": true}}
		}
	}`
	store[pathFragUser] = `{` + d2020 + `,
		"type": "object",
		"properties": {
			"$schema": {"type": "string"},
			"tag":  {"$ref": "` + pathFragLib + `#/$defs/tag"},
			"sp":   {"$ref": "` + pathFragLib + `#/$defs/a%20b"},
			"link": {"$ref": "` + pathFragLib + `#/$defs/link"}
		}
	}`
}

func TestCollectThroughRevisionFragment(t *testing.T) {
	doc := j(`{"$schema":"` + pathFragUser + `","tag":"t","sp":"s","link":"/r/m/x/rev/` + rev('q') + `"}`)
	got, err := Collect(doc, loader)
	if err != nil {
		t.Fatal(err)
	}
	g := strings.Join(short(got), "\n")
	for _, w := range []string{`x-index /tag="facet"`, `x-index /sp="sort"`, `x-ref /link=`} {
		if !strings.Contains(g, w) {
			t.Errorf("missing %q in\n%s", w, g)
		}
	}
	refs, err := FindRefs(doc, loader)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Pointer != "/link" || !refs[0].Pinned || refs[0].Rev != rev('q') {
		t.Errorf("FindRefs = %+v", refs)
	}
}

func TestResolveRefFragmentErrors(t *testing.T) {
	c := newCollector(loader, nil)
	base := syntheticBase + pathFragUser
	for _, ref := range []string{
		pathFragLib + "#tag", pathFragLib + "#$defs/tag", pathFragLib + "#/$defs/%zz",
		pathFragLib + "#/$defs/x~2", pathFragLib + "#/a b", "/r/s/x/../y/rev/" + rev('a') + "#/x",
	} {
		_, err := c.resolveRef(base, ref)
		var re *schema.RefError
		if !errors.As(err, &re) {
			t.Errorf("%q: got %v, want RefError", ref, err)
		}
	}
	l, err := c.resolveRef(base, pathFragLib+"#/$defs/a%20b")
	if err != nil || l.base != syntheticBase+pathFragLib || l.ptr.String() != "/$defs/a b" {
		t.Errorf("resolveRef = %+v, %v", l, err)
	}
	l, err = c.resolveRef(base, pathFragLib)
	if err != nil || len(l.ptr) != 0 {
		t.Errorf("bare = %+v, %v", l, err)
	}
	// Missing target surfaces as a schema error when walked.
	doc := `{"$ref":"` + pathFragLib + `#/$defs/nope"}`
	_, err = CollectWith(j(doc), "", j(`1`), loader)
	if err == nil {
		t.Error("missing fragment target accepted")
	}
}
