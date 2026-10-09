package index_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// TestFieldsBySchema (v0.47 §A.4): fields= is checked against the x-index
// marks of the schemas the namespace's documents use, not against values:
// a marked path no document has values at is accepted and left out of the
// hits, and a path no schema marks is 400 whatever the data. Marks are
// found through $ref (to another revision, a local pointer, an anchor),
// anyOf, items, patternProperties and additionalProperties. Hits carry
// facet and sort values as lists, and a path marked both shows its facet
// values.
func TestFieldsBySchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "items", map[string]any{"read": "public"}))
	part := must(c.CreateDoc(ctx, "schemas", "part", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"label": map[string]any{"type": "string", "x-index": "text"}}}))
	str := func(kinds ...any) map[string]any {
		m := map[string]any{"type": "string"}
		if len(kinds) > 0 {
			m["x-index"] = kinds[0]
		}
		return m
	}
	sch := must(c.CreateDoc(ctx, "schemas", "item", map[string]any{
		"$schema": d2020, "type": "object",
		"properties": map[string]any{
			"$schema": str(),
			"name":    str("text"),
			"ranks":   map[string]any{"type": "array", "items": map[string]any{"type": "number"}, "x-index": []any{"facet", "sort"}},
			"parts":   map[string]any{"type": "array", "items": map[string]any{"$ref": "/r/schemas/part/rev/" + part.ID}},
			"meta":    map[string]any{"type": "object", "patternProperties": map[string]any{"^x-": str("facet")}, "additionalProperties": map[string]any{"$ref": "#/$defs/note"}},
			"alias":   map[string]any{"$ref": "#tagged"},
			"never":   str("text"),
			"plain":   str(),
		},
		"anyOf": []any{map[string]any{"properties": map[string]any{"extra": str("text")}}, map[string]any{"required": []any{"name"}}},
		"$defs": map[string]any{
			"note":   str("text"),
			"tagged": map[string]any{"$anchor": "tagged", "type": "string", "x-index": "facet"},
		},
	}))
	p := "/r/schemas/item/rev/" + sch.ID
	must(c.CreateDoc(ctx, "items", "a", map[string]any{"$schema": p, "name": "Alpha", "ranks": []any{3, 1, 2},
		"parts": []any{map[string]any{"label": "L1"}}, "meta": map[string]any{"x-a": "va", "other": "note"}, "alias": "al", "plain": "p"}))
	must(c.CreateDoc(ctx, "items", "b", map[string]any{"$schema": p, "name": "Beta", "ranks": []any{5}}))
	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")

	// Facet and sort values are lists; /ranks shows all its facet values,
	// not its one sort value (3).
	b := x.expect("/items", "a", "b")
	if got := fmt.Sprint(hitOf(t, b, "a")["/ranks"]); got != "[1 2 3]" {
		t.Errorf("/ranks of a: %s", got)
	}
	if got := fmt.Sprint(hitOf(t, b, "b")["/ranks"]); got != "[5]" {
		t.Errorf("/ranks of b: %s", got)
	}

	// Values by hit and path; a path not listed is left out of the hit.
	for f, want := range map[string]map[string]string{
		"/never":       {},
		"/extra":       {},
		"/name,/never": {"a /name": "[Alpha]", "b /name": "[Beta]"},
		"/parts/label": {"a /parts/label": "[L1]"},
		"/meta/other":  {"a /meta/other": "[note]"},
		"/meta/x-b":    {},
		"/meta/x-a":    {"a /meta/x-a": "[va]"},
		"/alias":       {"a /alias": "[al]"},
	} {
		b := x.expect("/items?fields="+url.QueryEscape(f), "a", "b")
		for _, n := range []string{"a", "b"} {
			h := hitOf(t, b, n)
			for _, path := range strings.Split(f, ",") {
				v, ok := h[path]
				w := want[n+" "+path]
				if got := fmt.Sprint(v); w == "" && ok || w != "" && got != w {
					t.Errorf("fields=%s: %s of %s is %v (%v), want %q", f, path, n, got, ok, w)
				}
			}
		}
	}
	for _, f := range []string{"/plain", "/nothing", "/parts", "/parts/0/label", "/meta", "/name/x"} {
		if r := x.final("/items?fields=" + url.QueryEscape(f)); r.status != 400 {
			t.Errorf("fields=%s: %d %v", f, r.status, r.body)
		}
	}
}

// TestPurgedBranchHeads (v0.47 §8.5, §10): /heads of a purged namespace is
// 410 purged. An index that reaches a branch only after it was purged learns
// that there, as from the purge-ns entry, and answers 410 for it.
func TestPurgedBranchHeads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// The core's answer since v0.47, whether or not this one gives it yet.
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/ns/rel/rev/") && strings.HasSuffix(r.URL.Path, "/heads") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGone)
				w.Write([]byte(`{"code":"purged","message":"namespace purged"}`))
				return
			}
			h.ServeHTTP(w, r)
		})
	}})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 1}))
	must(c.CreateBranch(ctx, "main", client.BranchRequest{Name: "rel"}))
	must(c.PatchConfig(ctx, "rel", must(c.NSHead(ctx, "rel")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(c.PurgeNamespace(ctx, "rel", must(c.NSHead(ctx, "rel")).ID))

	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"main"}, untyped: true, branches: true})
	x.caughtUp("main")
	waitFor(t, "the branch's purge", func() bool { return x.ix.Checkpoint("rel") == purged })
	if r := x.raw("/rel", ""); r.status != 410 {
		t.Errorf("purged branch: %d %v", r.status, r.body)
	}
	x.expect("/main", "a")
}
