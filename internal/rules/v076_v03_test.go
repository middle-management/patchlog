package rules

import (
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §B.11.5 (v0.76): a test's schema "has only contains, of only const or
// enum, and optionally "type": "array", or is an allOf of such schemas".
// Any other mix keeps every group.
func TestV076V03GroupTestShapes(t *testing.T) {
	t.Parallel()
	test := func(schema string) string {
		return `{"op":"test","path":"/principal/groups","schema":` + schema + `}`
	}
	for _, c := range []struct {
		schema string
		named  []string
		ok     bool
	}{
		// The listed forms.
		{`{"contains":{"const":"a"}}`, []string{"a"}, true},
		{`{"type":"array","contains":{"enum":["b","a"]}}`, []string{"a", "b"}, true},
		{`{"allOf":[{"contains":{"const":"a"}},{"type":"array","contains":{"const":"b"}}]}`, []string{"a", "b"}, true},
		// Mixes v0.76 doesn't list.
		{`{"allOf":[{"type":"array"},{"contains":{"const":"a"}}]}`, nil, false},
		{`{"type":"array","allOf":[{"contains":{"const":"a"}}]}`, nil, false},
		{`{"contains":{"const":"a"},"allOf":[{"contains":{"const":"b"}}]}`, nil, false},
		{`{"allOf":[{"allOf":[{"contains":{"const":"a"}}]}]}`, nil, false},
		{`{"allOf":[]}`, nil, false},
		{`{"allOf":[{"contains":{"const":"a"}},"x"]}`, nil, false},
		{`{"contains":{"enum":[]}}`, nil, false},
		{`{"contains":{"const":"a","enum":["a"]}}`, nil, false},
	} {
		named, ok := GroupTests(jsonv.MustParse([]byte(test(c.schema))))
		if ok != c.ok || !slices.Equal(named, c.named) {
			t.Errorf("GroupTests(%s) = %v, %v; want %v, %v", c.schema, named, ok, c.named, c.ok)
		}
	}
}
