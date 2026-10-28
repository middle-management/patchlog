package index

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v073Rev is a revision path of schemas/name.
func v073Rev(name string, b byte) string {
	return "/r/schemas/" + name + "/rev/" + ids.FromBytes(bytes.Repeat([]byte{b}, ids.Size)).String()
}

// v073Loader loads the schema documents of ds by revision path.
func v073Loader(ds map[string]any) schema.Loader {
	return func(ref schema.Ref) (any, error) {
		if d, ok := ds[ref.Path()]; ok {
			return d, nil
		}
		return nil, schema.ErrUnavailable
	}
}

// TestV073MarkKinds (IX-3, §A.4): a facet[…] or counts path must be marked
// facet, a sort path sort, and a fields path with any kind; CIS-18 (§6.5):
// definitions holds subschemas, so an anchor inside it marks too.
func TestV073MarkKinds(t *testing.T) {
	t.Parallel()
	root := v073Rev("root", 1)
	for _, c := range []struct {
		name, schema, path, kind string
		want                     bool
	}{
		{"facet marks facet", `{"properties": {"a": {"x-index": "facet"}}}`, "/a", "facet", true},
		{"facet doesn't mark sort", `{"properties": {"a": {"x-index": "facet"}}}`, "/a", "sort", false},
		{"text doesn't mark facet", `{"properties": {"a": {"x-index": "text"}}}`, "/a", "facet", false},
		{"sort doesn't mark facet", `{"properties": {"a": {"x-index": "sort"}}}`, "/a", "facet", false},
		{"text marks any kind", `{"properties": {"a": {"x-index": "text"}}}`, "/a", "", true},
		{"a list marks each kind", `{"properties": {"a": {"x-index": ["facet", "sort"]}}}`, "/a", "sort", true},
		{"one branch facet, another sort", `{"anyOf": [{"properties": {"a": {"x-index": "facet"}}}, {"properties": {"a": {"x-index": "sort"}}}]}`, "/a", "sort", true},
		{"not never marks", `{"properties": {"a": {"not": {"x-index": "facet"}}}}`, "/a", "facet", false},
		{"$ref to an anchor in definitions", `{"properties": {"a": {"$ref": "#m"}}, "definitions": {"m": {"$anchor": "m", "x-index": "facet"}}}`, "/a", "facet", true},
		{"$ref to a pointer into definitions", `{"properties": {"a": {"$ref": "#/definitions/m"}}, "definitions": {"m": {"x-index": "sort"}}}`, "/a", "sort", true},
		{"$dynamicRef to a dynamic anchor in definitions", `{"properties": {"a": {"$dynamicRef": "#n"}}, "definitions": {"m": {"$dynamicAnchor": "n", "x-index": "text"}}}`, "/a", "text", true},
		{"definitions alone", `{"definitions": {"a": {"x-index": "facet"}}}`, "/a", "facet", false},
	} {
		w := &markWalk{load: v073Loader(map[string]any{root: parse(t, c.schema)}), docs: map[string]any{}, seen: map[string]bool{}, kind: c.kind}
		w.path = must(pointer.Parse(c.path))
		if got := w.marked(root, nil, 0); got != c.want {
			t.Errorf("%s: %s marks %s %q: %v, want %v", c.name, c.schema, c.path, c.kind, got, c.want)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// v073Collect runs the static x-index walk of doc (§A.2) with schema s at
// root, other revisions in more, and returns its rows as strings.
func v073Collect(t *testing.T, s string, doc string, more map[string]any) (text, facet, sorts []string) {
	t.Helper()
	root := v073Rev("root", 1)
	ds := map[string]any{root: parse(t, s)}
	for k, v := range more {
		ds[k] = v
	}
	d := parse(t, doc)
	d.(map[string]any)["$schema"] = root
	rows := collectValues(d, root, &markWalk{load: v073Loader(ds), docs: map[string]any{}})
	for _, r := range rows.text {
		text = append(text, r.path+"="+r.body)
	}
	for _, r := range rows.facet {
		facet = append(facet, r.path+"="+r.value)
	}
	for _, r := range rows.sort {
		sorts = append(sorts, fmt.Sprintf("%s=%v %s", r.path, r.value, r.raw))
	}
	return text, facet, sorts
}

// TestV073ValueWalk (IX-7, §A.2, §A.4, §6.5): x-index values are collected
// by a static walk through only the keywords that mark a path, every branch
// whatever the document's validity; only strings, numbers and booleans, an
// array's scalars at the array's path; text collects strings only.
func TestV073ValueWalk(t *testing.T) {
	t.Parallel()
	other := v073Rev("other", 2)
	more := map[string]any{other: parse(t, `{"properties": {"label": {"x-index": "facet"}}}`)}
	for _, c := range []struct {
		name, schema, doc  string
		text, facet, sorts string
	}{
		{"a failing anyOf branch still marks",
			`{"properties": {"a": {"anyOf": [{"type": "string", "x-index": "facet"}, {"type": "number"}]}}}`, `{"a": 5}`,
			"", "/a=5", ""},
		{"a document that doesn't validate gets rows",
			`{"properties": {"a": {"type": "string", "x-index": ["facet", "text"]}}, "required": ["zz"]}`, `{"a": "x"}`,
			"/a=x", "/a=x", ""},
		{"if, then and else, whichever is taken",
			`{"if": {"required": ["k"]}, "then": {"properties": {"a": {"x-index": "facet"}}}, "else": {"properties": {"b": {"x-index": "facet"}}}}`, `{"a": "1", "b": "2"}`,
			"", "/a=1,/b=2", ""},
		{"objects and null are never collected",
			`{"properties": {"o": {"x-index": "facet"}, "n": {"x-index": "facet"}}}`, `{"o": {"k": "v"}, "n": null}`,
			"", "", ""},
		{"an object marked text indexes nothing",
			`{"properties": {"notes": {"type": "object", "x-index": "text"}}}`, `{"notes": {"summary": "a tense evening"}}`,
			"", "", ""},
		{"text collects strings only",
			`{"properties": {"t": {"x-index": "text"}}}`, `{"t": 42}`,
			"", "", ""},
		{"an array's scalars at its path, not nested values",
			`{"properties": {"tags": {"x-index": "facet"}}}`, `{"tags": ["a", 1, true, {"k": "v"}, ["n"], null]}`,
			"", "/tags=a,/tags=1,/tags=true", ""},
		{"items at the array's path, each once",
			`{"properties": {"tags": {"x-index": "facet", "items": {"x-index": "facet"}}}}`, `{"tags": ["a", "b"]}`,
			"", "/tags=a,/tags=b", ""},
		{"not, propertyNames, unevaluated* and contentSchema don't mark",
			`{"properties": {"a": {"not": {"x-index": "facet"}}, "b": {"propertyNames": {"x-index": "facet"}}, "c": {"contentSchema": {"x-index": "facet"}}}, "unevaluatedProperties": {"x-index": "facet"}}`,
			`{"a": "1", "b": {"k": "2"}, "c": "3", "d": "4"}`,
			"", "", ""},
		{"patternProperties and additionalProperties",
			`{"properties": {"a": {}}, "patternProperties": {"^x-": {"x-index": "facet"}}, "additionalProperties": {"x-index": "sort"}}`, `{"a": 1, "x-b": "p", "z": 7}`,
			"", "/x-b=p", "/z=7 [7]"},
		{"dependentSchemas of a member present",
			`{"dependentSchemas": {"k": {"properties": {"a": {"x-index": "facet"}}}, "m": {"properties": {"b": {"x-index": "facet"}}}}}`, `{"k": 1, "a": "1", "b": "2"}`,
			"", "/a=1", ""},
		{"$ref to another revision",
			`{"properties": {"o": {"$ref": "` + other + `"}}}`, `{"o": {"label": "l"}}`,
			"", "/o/label=l", ""},
		{"$ref to an anchor in definitions (CIS-18)",
			`{"properties": {"a": {"$ref": "#m"}}, "definitions": {"m": {"$anchor": "m", "x-index": "facet"}}}`, `{"a": "x"}`,
			"", "/a=x", ""},
		{"recursion without instance progress",
			`{"$ref": "#/$defs/n", "$defs": {"n": {"$ref": "#/$defs/n", "properties": {"v": {"x-index": "facet"}}}}}`, `{"v": "1"}`,
			"", "/v=1", ""},
		{"sort: the least value, every value as written",
			`{"properties": {"r": {"x-index": "sort"}}}`, `{"r": ["x", 9, 1, true]}`,
			"", "", "/r=1 [\"x\",9,1,true]"},
		{"sort: booleans as BLOBs, false before true",
			`{"properties": {"r": {"x-index": "sort"}}}`, `{"r": [true, false]}`,
			"", "", "/r=[0] [true,false]"},
		{"sort: strings as bytes, no date-time normalisation",
			`{"properties": {"r": {"x-index": "sort"}}}`, `{"r": ["2026-10-04T18:00:00+02:00", "2026-10-04T17:00:00Z"]}`,
			"", "", "/r=2026-10-04T17:00:00Z [\"2026-10-04T18:00:00+02:00\",\"2026-10-04T17:00:00Z\"]"},
	} {
		text, facet, sorts := v073Collect(t, c.schema, c.doc, more)
		if strings.Join(text, ",") != c.text || strings.Join(facet, ",") != c.facet || strings.Join(sorts, ",") != c.sorts {
			t.Errorf("%s:\n text %q, want %q\n facet %q, want %q\n sort %q, want %q", c.name, text, c.text, facet, c.facet, sorts, c.sorts)
		}
	}
}

// TestV073SortLess (IX-6, §A.2): numbers before strings before booleans;
// numbers by value, strings by UTF-8 bytes, false before true.
func TestV073SortLess(t *testing.T) {
	t.Parallel()
	order := []any{-1.5, 0.0, 2.0, 10.0, "", "B", "a", "b", "é", false, true}
	for i, a := range order {
		for j, b := range order {
			if got := sortLess(a, b); got != (i < j) {
				t.Errorf("sortLess(%#v, %#v) = %v", a, b, got)
			}
		}
	}
}

// TestV073Unavailable (IX-22, §A.1): a schema revision that answers a 4xx
// other than 429, or can't be opened for want of keys, is unavailable (the
// document is indexed as one without $schema), a 401 to the service's own
// grant too since v0.74 (Open 86); failures asking again may mend are
// not.
func TestV073Unavailable(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&client.APIError{Status: http.StatusForbidden}, true},
		{&client.APIError{Status: http.StatusNotFound}, true},
		{&client.APIError{Status: http.StatusGone, Code: "purged"}, true},
		{&client.APIError{Status: http.StatusGone, Code: "pruned"}, true},
		{fmt.Errorf("resolving: %w", client.ErrNoKeys), true},
		{&client.APIError{Status: http.StatusUnauthorized}, true},
		{&client.APIError{Status: http.StatusBadRequest}, true},
		{&client.APIError{Status: http.StatusTooManyRequests}, false},
		{&client.APIError{Status: http.StatusServiceUnavailable}, false},
		{errors.New("connection reset"), false},
	} {
		if got := unavailable(c.err); got != c.want {
			t.Errorf("unavailable(%v) = %v", c.err, got)
		}
	}
}

// TestV073FormatRebuild (IX-6, IX-7, IX-8): a database whose rows predate
// the v0.73 format (its user_version) is rebuilt (§A.6); one of the
// current format is kept.
func TestV073FormatRebuild(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "i.db")
	open := func() *Index {
		db, err := sql.Open("sqlite", sqlitedsn.DSN(path, "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		ix := &Index{opt: Options{Logf: t.Logf, UntypedListing: true}, db: db, cps: follow.SQLCheckpoints{DB: db}, sealed: derived.NewCache(0, db)}
		if err := ix.initSchema(ctx); err != nil {
			t.Fatal(err)
		}
		return ix
	}
	count := func(ix *Index) (docs, format int) {
		if err := ix.db.QueryRow(`SELECT count(*) FROM docs`).Scan(&docs); err != nil {
			t.Fatal(err)
		}
		if err := ix.db.QueryRow(`PRAGMA user_version`).Scan(&format); err != nil {
			t.Fatal(err)
		}
		return docs, format
	}
	ix := open()
	if _, err := ix.db.Exec(`INSERT INTO docs (ns, resource, head, schema) VALUES ('n', 'r', 'h', 's')`); err != nil {
		t.Fatal(err)
	}
	if docs, format := count(open()); docs != 1 || format != indexFormat {
		t.Fatalf("current format: %d docs, format %d", docs, format)
	}
	if _, err := ix.db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if docs, format := count(open()); docs != 0 || format != indexFormat {
		t.Fatalf("older format: %d docs left, format %d", docs, format)
	}
}
