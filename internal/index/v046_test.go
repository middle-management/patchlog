package index_test

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// final follows redirects and returns the last response, whatever it is.
func (s *svc) final(path string) resp {
	s.t.Helper()
	for range 5 {
		r := s.raw(path, "")
		if r.status != 302 {
			return r
		}
		path = r.header.Get("Location")
	}
	s.t.Fatalf("GET %s: too many redirects", path)
	return resp{}
}

func hitOf(t *testing.T, body map[string]any, resource string) map[string]any {
	t.Helper()
	for _, h := range body["hits"].([]any) {
		if m := h.(map[string]any); m["resource"] == resource {
			return m
		}
	}
	t.Fatalf("no hit %s in %v", resource, body["hits"])
	return nil
}

// TestSortFacetArray: x-index as an array, and hits carrying facet and sort
// values and the fields asked for (v0.46 §A.2, §A.4).
func TestSortFacetArrayAndFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "items", map[string]any{"read": "public"}))
	sch := must(c.CreateDoc(ctx, "schemas", "item", map[string]any{
		"$schema": d2020, "type": "object",
		"properties": map[string]any{
			"$schema": map[string]any{"type": "string"},
			"name":    map[string]any{"type": "string", "x-index": "text"},
			"title":   map[string]any{"type": "string", "x-index": []any{"text"}},
			"rank":    map[string]any{"type": "number", "x-index": []any{"facet", "sort"}},
			"due":     map[string]any{"type": "string", "x-index": "sort"},
			"notes":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "x-index": "text"},
			"plain":   map[string]any{"type": "string"},
		},
	}))
	p := "/r/schemas/item/rev/" + sch.ID
	mk := func(name string, f map[string]any) {
		f["$schema"] = p
		must(c.CreateDoc(ctx, "items", name, f))
	}
	mk("a", map[string]any{"name": "Alpha", "title": "First", "rank": 2, "due": "2026-10-05T12:00:00+02:00", "notes": []any{"x1", "x2"}})
	mk("b", map[string]any{"name": "Beta", "title": "Second", "rank": 1, "plain": "p"})
	mk("c", map[string]any{"name": "Gamma", "title": "Third", "rank": 3})
	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")

	// Both kinds from one array.
	x.expect("/items?facet[/rank]=2", "a")
	x.expect("/items?sort=-/rank", "c", "a", "b")
	x.expect("/items?ge[/rank]=2&sort=/rank", "a", "c")
	x.expect("/items?q=second", "b")

	// Hits carry facet and sort values; text only when asked for.
	b := x.expect("/items?sort=/rank", "b", "a", "c")
	a := hitOf(t, b, "a")
	if got := a["/rank"].([]any); len(got) != 1 || got[0] != float64(2) {
		t.Errorf("/rank %v", a["/rank"])
	}
	if got := a["/due"].([]any); len(got) != 1 || got[0] != "2026-10-05T12:00:00+02:00" {
		t.Errorf("/due as written: %v", a["/due"])
	}
	for _, k := range []string{"/name", "/title", "/notes", "/plain"} {
		if _, ok := a[k]; ok {
			t.Errorf("%s without fields=", k)
		}
	}
	b = x.expect("/items?sort=/rank&fields="+url.QueryEscape("/name,/notes,/title"), "b", "a", "c")
	a = hitOf(t, b, "a")
	if got := a["/name"].([]any); len(got) != 1 || got[0] != "Alpha" {
		t.Errorf("/name %v", a["/name"])
	}
	if got := a["/notes"].([]any); len(got) != 2 || got[0] != "x1" || got[1] != "x2" {
		t.Errorf("/notes %v", a["/notes"])
	}
	if got := hitOf(t, b, "b")["/title"].([]any); len(got) != 1 || got[0] != "Second" {
		t.Errorf("/title %v", got)
	}
	if _, ok := hitOf(t, b, "b")["/notes"]; ok {
		t.Error("notes on a document without any")
	}
	// A field that is also a facet is simply shown.
	x.expect("/items?fields=/rank&sort=/rank", "b", "a", "c")

	// A path no schema marks with x-index is 400, so is a malformed one,
	// and a repeated parameter.
	for _, q := range []string{"fields=/plain", "fields=/nothing", "fields=/name,/plain", "fields=name", "fields=", "fields=/name&fields=/title"} {
		if r := x.final("/items?" + q); r.status != 400 {
			t.Errorf("%s: %d %v", q, r.status, r.body)
		}
	}
	// Fields are part of the cache key: a different list is another URL.
	r1 := x.raw("/items?fields=/name", "")
	r2 := x.raw("/items?fields=/title", "")
	if r1.header.Get("Location") == r2.header.Get("Location") {
		t.Errorf("same location %q", r1.header.Get("Location"))
	}
}

// TestSchemaDocumentsAndSelf: schema documents are indexed against their
// dialect with their $refs as references; a self-reference is flagged.
func TestSchemaDocumentsAndSelf(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	base := must(c.CreateDoc(ctx, "schemas", "base", map[string]any{"$schema": d2020, "type": "string", "$defs": map[string]any{"x": map[string]any{"type": "string"}}}))
	other := must(c.CreateDoc(ctx, "schemas", "other", map[string]any{"$schema": d2020, "type": "number"}))
	pb := "/r/schemas/base/rev/" + base.ID
	po := "/r/schemas/other/rev/" + other.ID
	must(c.CreateDoc(ctx, "schemas", "uses", map[string]any{
		"$schema": d2020, "type": "object",
		"properties": map[string]any{
			"a":    map[string]any{"$ref": pb},
			"b":    map[string]any{"type": "array", "items": map[string]any{"$ref": pb + "#/$defs/x"}},
			"c":    map[string]any{"const": map[string]any{"$ref": pb}, "default": map[string]any{"$ref": pb}},
			"d":    map[string]any{"enum": []any{map[string]any{"$ref": pb}}, "examples": []any{map[string]any{"$ref": pb}}},
			"$ref": map[string]any{"type": "string"}, // a property named $ref is not a keyword
		},
		"allOf":       []any{map[string]any{"$ref": po}},
		"$defs":       map[string]any{"l": map[string]any{"$ref": "#/properties/a"}},
		"not":         map[string]any{"$ref": po},
		"description": pb,
	}))
	must(c.CreateDoc(ctx, "schemas", "plain", map[string]any{"$schema": d2020, "type": "boolean"}))
	must(c.CreateDoc(ctx, "schemas", "untyped", map[string]any{"note": pb}))
	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"schemas"}})
	x.caughtUp("schemas")
	enc := url.QueryEscape

	// schema= with the dialect URL lists the schema documents.
	x.expect("/schemas?schema="+enc(d2020), "base", "other", "plain", "uses")

	// "Which schemas $ref this one".
	b := x.expect("/schemas?ref="+enc("/r/schemas/base"), "uses")
	got := map[string]string{}
	for _, r := range hitOf(t, b, "uses")["refs"].([]any) {
		m := r.(map[string]any)
		got[m["path"].(string)] = m["ref"].(string)
	}
	want := map[string]string{"/properties/a/$ref": pb, "/properties/b/items/$ref": pb + "#/$defs/x"}
	if len(got) != len(want) {
		t.Errorf("refs %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("refs[%s] = %q, want %q", k, got[k], v)
		}
	}
	x.expect("/schemas?ref="+enc(pb), "uses")
	b = x.expect("/schemas?ref="+enc("/r/schemas/other"), "uses")
	if n := len(hitOf(t, b, "uses")["refs"].([]any)); n != 2 {
		t.Errorf("other refs: %d", n)
	}
	if _, ok := hitOf(t, b, "uses")["self"]; ok {
		t.Error("self on a hit that doesn't reference itself")
	}
	x.expect("/schemas?ref=" + enc("/r/schemas/plain"))
}

func TestSelfReferenceFlag(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	for _, ns := range []string{"schemas", "pages"} {
		must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
	}
	sch := must(c.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	p := "/r/schemas/page/rev/" + sch.ID
	must(c.CreateDoc(ctx, "pages", "a", map[string]any{"$schema": p, "title": "A", "related": []any{"/r/pages/a", "/r/pages/b"}}))
	must(c.CreateDoc(ctx, "pages", "b", map[string]any{"$schema": p, "title": "B", "related": []any{"/r/pages/a"}}))
	must(c.CreateDoc(ctx, "pages", "c", map[string]any{"$schema": p, "title": "C", "related": []any{"/r/pages/b"}}))
	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pages"}})
	x.caughtUp("pages")
	enc := url.QueryEscape

	b := x.expect("/pages?ref="+enc("/r/pages/a"), "a", "b")
	if hitOf(t, b, "a")["self"] != true {
		t.Errorf("a: %v", hitOf(t, b, "a"))
	}
	if _, ok := hitOf(t, b, "b")["self"]; ok {
		t.Errorf("b: %v", hitOf(t, b, "b"))
	}
	b = x.expect("/pages?ref="+enc("/r/pages/b"), "a", "c")
	for _, n := range []string{"a", "c"} {
		if _, ok := hitOf(t, b, n)["self"]; ok {
			t.Errorf("%s flagged self for b", n)
		}
	}
	// Without ref there is no self.
	if _, ok := hitOf(t, x.search("/pages", ""), "a")["self"]; ok {
		t.Error("self without ref=")
	}
}
