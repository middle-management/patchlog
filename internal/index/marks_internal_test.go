package index

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// TestMarks (§A.4 "marks"): a schema marks a path when an x-index is
// reachable from its root along that path, whatever the data: through $ref
// and $dynamicRef, properties, patternProperties, additionalProperties,
// dependentSchemas, items, prefixItems and contains, and every branch of
// allOf, anyOf, oneOf, if, then and else, never through not, propertyNames
// or unevaluated*; array items count at their array's path.
func TestMarks(t *testing.T) {
	t.Parallel()
	rev := func(name string, b byte) string {
		return "/r/schemas/" + name + "/rev/" + ids.FromBytes(bytes.Repeat([]byte{b}, ids.Size)).String()
	}
	root, other, gone := rev("root", 1), rev("other", 2), rev("gone", 3)
	docs := map[string]any{
		other: parse(t, `{"properties": {"label": {"x-index": "text"}}, "$defs": {"deep": {"x-index": "sort"}}}`),
	}
	const m = `{"type": "string", "x-index": "facet"}`
	for _, c := range []struct {
		name, schema, path string
		want               bool
	}{
		{"properties", `{"properties": {"a": M}}`, "/a", true},
		{"another property", `{"properties": {"a": M}}`, "/b", false},
		{"a kind that isn't one", `{"properties": {"a": {"x-index": "other"}}}`, "/a", false},
		{"kinds as a list", `{"properties": {"a": {"x-index": ["other", "sort"]}}}`, "/a", true},
		{"only above the path", `{"properties": {"a": M}}`, "/a/b", false},
		{"only below the path", `{"properties": {"a": {"properties": {"b": M}}}}`, "/a", false},
		{"nested properties", `{"properties": {"a": {"properties": {"b": M}}}}`, "/a/b", true},
		{"$ref, a local pointer", `{"properties": {"a": {"$ref": "#/$defs/m"}}, "$defs": {"m": M}}`, "/a", true},
		{"$ref, an anchor", `{"properties": {"a": {"$ref": "#m"}}, "$defs": {"m": {"$anchor": "m", "x-index": "text"}}}`, "/a", true},
		{"$ref, another revision", `{"properties": {"a": {"$ref": "OTHER"}}}`, "/a/label", true},
		{"$ref, a pointer into another revision", `{"properties": {"a": {"$ref": "OTHER#/$defs/deep"}}}`, "/a", true},
		{"$ref, an unavailable revision", `{"properties": {"a": {"$ref": "GONE"}}}`, "/a", false},
		{"$ref beside properties", `{"properties": {"a": {"$ref": "#/$defs/n", "properties": {"b": M}}}, "$defs": {"n": {}}}`, "/a/b", true},
		{"$dynamicRef", `{"properties": {"a": {"$dynamicRef": "#node"}}, "$defs": {"n": {"$dynamicAnchor": "node", "x-index": "facet"}}}`, "/a", true},
		{"recursion", `{"$ref": "#/$defs/n", "$defs": {"n": {"properties": {"c": {"$ref": "#/$defs/n"}, "v": M}}}}`, "/c/c/v", true},
		{"recursion, unmarked", `{"$ref": "#/$defs/n", "$defs": {"n": {"properties": {"c": {"$ref": "#/$defs/n"}, "v": M}}}}`, "/c/c/w", false},
		{"patternProperties", `{"patternProperties": {"^x-": M}}`, "/x-a", true},
		{"patternProperties, no match", `{"patternProperties": {"^x-": M}}`, "/y", false},
		{"additionalProperties", `{"additionalProperties": M}`, "/anything", true},
		{"additionalProperties, not for a listed property", `{"properties": {"a": {}}, "additionalProperties": M}`, "/a", false},
		{"additionalProperties, not for a matched pattern", `{"patternProperties": {"^a": {}}, "additionalProperties": M}`, "/ab", false},
		{"dependentSchemas", `{"dependentSchemas": {"a": {"properties": {"b": M}}}}`, "/b", true},
		{"items, at the array's path", `{"properties": {"a": {"type": "array", "items": M}}}`, "/a", true},
		{"items' properties", `{"properties": {"a": {"items": {"properties": {"b": M}}}}}`, "/a/b", true},
		{"no indices in paths", `{"properties": {"a": {"items": {"properties": {"b": M}}}}}`, "/a/0/b", false},
		{"nested arrays", `{"properties": {"a": {"items": {"items": M}}}}`, "/a", true},
		{"prefixItems", `{"properties": {"a": {"prefixItems": [{}, M]}}}`, "/a", true},
		{"contains", `{"properties": {"a": {"contains": M}}}`, "/a", true},
		{"allOf", `{"allOf": [{}, {"properties": {"a": M}}]}`, "/a", true},
		{"anyOf", `{"anyOf": [{"required": ["a"]}, {"properties": {"a": M}}]}`, "/a", true},
		{"oneOf", `{"oneOf": [{"properties": {"a": M}}, {}]}`, "/a", true},
		{"if", `{"if": {"properties": {"a": M}}}`, "/a", true},
		{"then", `{"if": {"required": ["b"]}, "then": {"properties": {"a": M}}}`, "/a", true},
		{"else", `{"if": {"required": ["b"]}, "else": {"properties": {"a": M}}}`, "/a", true},
		{"not", `{"not": {"properties": {"a": M}}}`, "/a", false},
		{"propertyNames", `{"properties": {"a": {"propertyNames": M}}}`, "/a", false},
		{"propertyNames, below", `{"propertyNames": {"properties": {"a": M}}}`, "/a", false},
		{"unevaluatedProperties", `{"unevaluatedProperties": M}`, "/a", false},
		{"unevaluatedItems", `{"properties": {"a": {"unevaluatedItems": M}}}`, "/a", false},
		{"$defs alone", `{"$defs": {"a": M}}`, "/a", false},
		{"a boolean schema", `{"properties": {"a": true}}`, "/a", false},
	} {
		s := strings.NewReplacer("M", m, "OTHER", other, "GONE", gone).Replace(c.schema)
		ds := map[string]any{root: parse(t, s)}
		for k, v := range docs {
			ds[k] = v
		}
		w := &markWalk{docs: map[string]any{}, seen: map[string]bool{}, load: func(ref schema.Ref) (any, error) {
			if d, ok := ds[ref.Path()]; ok {
				return d, nil
			}
			return nil, schema.ErrUnavailable
		}}
		p, err := pointer.Parse(c.path)
		if err != nil {
			t.Fatal(err)
		}
		w.path = p
		if got := w.marked(root, nil, 0); got != c.want {
			t.Errorf("%s: %s marks %s: %v, want %v", c.name, s, c.path, got, c.want)
		}
	}
}

func parse(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return v
}
