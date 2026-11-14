package jsv

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestValidationError(t *testing.T) {
	sch, err := Compile(mustJSON(`{
		"type": "object",
		"properties": {
			"list": {"type": "array", "prefixItems": [{"type": "string"}], "items": {"$ref": "#/$defs/item"}},
			"a/b": {"allOf": [{"type": "integer"}, {"maximum": 3}]},
			"u": {"anyOf": [{"type": "string"}, {"type": "null"}]}
		},
		"additionalProperties": false,
		"$defs": {"item": {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer", "minimum": 1}}}}
	}`), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ doc, instance, keyword, message string }{
		{`5`, "", "/type", "got integer, want object"},
		{`{"list": [1]}`, "/list/0", "/properties/list/prefixItems/0/type", "got integer, want string"},
		{`{"list": ["x", {"id": 1}, {"id": 0}]}`, "/list/2/id", "/properties/list/items/$ref/properties/id/minimum", "minimum: got 0, want 1"},
		{`{"list": ["x", {}]}`, "/list/1", "/properties/list/items/$ref/required", `missing property "id"`},
		{`{"a/b": 4}`, "/a~1b", "/properties/a~1b/allOf/1/maximum", "maximum: got 4, want 3"},
		{`{"u": 1}`, "/u", "/properties/u/anyOf", "anyOf failed, none matched"},
		{`{"zz": 1}`, "", "/additionalProperties", `additional property "zz" not allowed`},
	} {
		err := sch.Validate(mustJSON(tc.doc), ValidateOptions{})
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: %v", tc.doc, err)
			continue
		}
		if ve.InstancePath != tc.instance || ve.KeywordPath != tc.keyword || ve.Message != tc.message {
			t.Errorf("%s: got %q %q %q, want %q %q %q", tc.doc, ve.InstancePath, ve.KeywordPath, ve.Message, tc.instance, tc.keyword, tc.message)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	var ue *UnsupportedError
	for schema, keyword := range map[string]string{
		`{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}`: "$schema",
		`{"$recursiveRef": "#"}`: "$recursiveRef",
		`{"properties": {"a": {"$id": "sub", "$schema": "https://json-schema.org/draft/2019-09/schema"}}}`: "$schema",
	} {
		if _, err := Compile(mustJSON(schema), "", Options{}); !errors.As(err, &ue) || ue.Keyword != keyword {
			t.Errorf("%s: %v, want an UnsupportedError for %s", schema, err, keyword)
		}
	}
	var ce *CompileError
	for _, schema := range []string{
		`5`,
		`{"type": "integr"}`,
		`{"type": 5}`,
		`{"minLength": -1}`,
		`{"maximum": "3"}`,
		`{"pattern": "("}`,
		`{"patternProperties": {"(": true}}`,
		`{"properties": []}`,
		`{"properties": {"a": 5}}`,
		`{"allOf": []}`,
		`{"required": [1]}`,
		`{"multipleOf": 0}`,
		`{"$ref": "#/$defs/missing"}`,
		`{"$ref": "#nowhere"}`,
		`{"$ref": "https://elsewhere.test/schema"}`,
		`{"$defs": {"a": {"type": "nope"}}}`,
		`{"$schema": "https://elsewhere.test/dialect"}`,
	} {
		if _, err := Compile(mustJSON(schema), "", Options{}); !errors.As(err, &ce) {
			t.Errorf("%s: %v, want a CompileError", schema, err)
		}
	}
}

func TestOptions(t *testing.T) {
	loads := 0
	opts := Options{
		Load: func(uri string) (any, error) {
			loads++
			if uri != "https://example.test/defs/item.json" {
				return nil, fmt.Errorf("unexpected load of %s", uri)
			}
			return mustJSON(`{"$defs": {"code": {"type": "string", "format": "shout", "pattern": "^a"}}}`), nil
		},
		Regexp: func(p string) (Matcher, error) {
			return matcherFunc(func(s string) bool { return strings.HasPrefix(s, "A") }), nil
		},
		Formats:      map[string]func(string) bool{"shout": func(s string) bool { return s == strings.ToUpper(s) }},
		AssertFormat: true,
	}
	raw := mustJSON(`{"properties": {"a": {"$ref": "defs/item.json#/$defs/code"}, "b": {"$ref": "defs/item.json#/$defs/code"}, "when": {"format": "date"}, "other": {"format": "no-such-format"}}}`)
	sch, err := Compile(raw, "https://example.test/root.json", opts)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 1 {
		t.Errorf("%d loads, want 1", loads)
	}
	for doc, valid := range map[string]bool{
		`{"a": "ABC"}`:           true,
		`{"a": "Abc"}`:           false, // format shout
		`{"a": "BBC"}`:           false, // the custom regexp engine
		`{"when": "2026-02-29"}`: false,
		`{"when": "2024-02-29"}`: true,
		`{"other": "anything"}`:  true,
	} {
		if err := sch.Validate(mustJSON(doc), ValidateOptions{}); (err == nil) != valid {
			t.Errorf("%s: %v, want valid=%v", doc, err, valid)
		}
	}
	opts.AssertFormat = false
	if sch, err = Compile(raw, "https://example.test/root.json", opts); err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(mustJSON(`{"a": "Abc", "when": "x"}`), ValidateOptions{}); err != nil {
		t.Errorf("format as an annotation: %v", err)
	}
}

type matcherFunc func(string) bool

func (f matcherFunc) MatchString(s string) bool { return f(s) }

func TestMultipleOf(t *testing.T) {
	for _, tc := range []struct {
		x, d float64
		want bool
	}{
		{10, 2, true}, {7, 2, false}, {0, 3, true}, {-9, 3, true},
		{0.0075, 0.0001, true}, {0.00751, 0.0001, false}, {4.5, 1.5, true}, {35, 1.5, false},
		{1e308, 0.123456789, false}, {12391239123, 1e-8, true}, {1e300, 1e-5, true},
		{0.1, 0.01, true}, {0.3, 0.1, true}, {1.1, 0.1, true}, {19.99, 0.01, true}, {1, 10, false},
		{3, 0.5, true}, {9007199254740993, 3, false}, {1e22, 7, false}, {2.5e-7, 5e-8, true},
	} {
		if got := newMultiple(tc.d).divides(tc.x); got != tc.want {
			t.Errorf("%v multipleOf %v = %v, want %v", tc.x, tc.d, got, tc.want)
		}
	}
}

func TestUniqueItems(t *testing.T) {
	sch, err := Compile(mustJSON(`{"uniqueItems": true}`), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	big := make([]any, 5000)
	for i := range big {
		big[i] = map[string]any{"i": float64(i), "s": []any{fmt.Sprint(i)}}
	}
	if err := sch.Validate(big, ValidateOptions{}); err != nil {
		t.Errorf("distinct items: %v", err)
	}
	big[4999] = map[string]any{"s": []any{"17"}, "i": 17.0}
	var ve *ValidationError
	if err := sch.Validate(big, ValidateOptions{}); !errors.As(err, &ve) || ve.Message != "items at 17 and 4999 are equal" {
		t.Errorf("equal items: %v", err)
	}
	for doc, valid := range map[string]bool{
		`[1, 1.0]`: false, `[0, -0]`: false, `[1, "1"]`: true, `[[1, 2], [2, 1]]`: true, `[{"a": 1, "b": 2}, {"b": 2, "a": 1}]`: false,
		`[null, false, 0, "", [], {}]`: true, `[[], []]`: false,
	} {
		if err := sch.Validate(mustJSON(doc), ValidateOptions{}); (err == nil) != valid {
			t.Errorf("%s: %v, want valid=%v", doc, err, valid)
		}
	}
}

// TestConcurrent: one compiled schema validates from many goroutines.
func TestConcurrent(t *testing.T) {
	sch, err := Compile(mustJSON(mixedSchema), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	good := mustJSON(`{"kind": "a", "title": "x", "nums": [1, 2], "meta": {"a": 1, "b": "s", "c": true}}`)
	bad := mustJSON(`{"kind": "a", "title": "x", "nums": [1, 1], "meta": {"a": 1, "b": "s", "d": true}}`)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if err := sch.Validate(good, ValidateOptions{}); err != nil {
					t.Errorf("valid document: %v", err)
					return
				}
				if err := sch.Validate(bad, ValidateOptions{}); err == nil {
					t.Error("invalid document passed")
					return
				}
			}
		}()
	}
	wg.Wait()
}
