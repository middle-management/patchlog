package rules

import (
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §B.11.5: a group is left out of the deciding subjects only where every
// rule refers to /principal/groups solely by positive tests, outside not
// and if, that it holds a group named by value (GroupTests).
func TestV075GroupTests(t *testing.T) {
	t.Parallel()
	ca := `{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"a"}}}`
	cb := `{"op":"test","path":"/principal/groups","schema":{"type":"array","contains":{"const":"b"}}}`
	for _, c := range []struct {
		json  string
		named []string
		ok    bool
	}{
		{ca, []string{"a"}, true},
		{cb, []string{"b"}, true},
		{`{"any":[` + ca + `,` + cb + `]}`, []string{"a", "b"}, true},
		{`{"all":[` + cb + `,` + ca + `]}`, []string{"a", "b"}, true},
		{`{"op":"test","path":"/principal/groups","schema":{"contains":{"enum":["x","w","x"]}}}`, []string{"w", "x"}, true},
		{`{"op":"test","path":"/principal/groups","schema":{"allOf":[{"contains":{"const":"a"}},{"type":"array","contains":{"const":"c"}}]}}`, []string{"a", "c"}, true},
		// Rules that never touch /principal/groups.
		{`{"op":"test","path":"/resource","schema":{"type":"string"}}`, nil, true},
		{`{"op":"test","path":"/principal/roles","schema":{"minItems":1}}`, nil, true},
		{`{"not":{"op":"test","path":"/principal/sub","value":"user:li"}}`, nil, true},
		{`{"op":"writes","within":["/a"]}`, nil, true},
		{`{"op":"compare","path":"/principal/attrs/n","lt":{"value":3}}`, nil, true},
		// Every other reference is not only positive.
		{`{"not":` + ca + `}`, nil, false},
		{`{"if":[` + ca + `],"then":[{"op":"test","path":"/action","value":"read"}]}`, nil, false},
		{`{"if":[{"op":"test","path":"/action","value":"read"}],"then":[` + ca + `]}`, nil, false},
		{`{"op":"test","path":"/principal/groups","schema":{"minItems":1,"contains":{"const":"a"}}}`, nil, false},
		{`{"op":"test","path":"/principal/groups","schema":{"contains":{"pattern":"^a"}}}`, nil, false},
		{`{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"a"},"type":"object"}}`, nil, false},
		{`{"op":"test","path":"/principal/groups","schema":{"contains":{"enum":["a",1]}}}`, nil, false},
		{`{"op":"test","path":"/principal/groups","schema":{"type":"array"}}`, nil, false},
		{`{"op":"test","path":"/principal/groups/0","value":"a"}`, nil, false},
		{`{"op":"test","path":"/principal/groups","value":["a"]}`, nil, false},
		{`{"op":"test","path":"/principal/groups","exists":true}`, nil, false},
		{`{"op":"test","path":"/principal","schema":{"type":"object"}}`, nil, false},
		{`{"op":"test","path":"","schema":{"type":"object"}}`, nil, false},
		{`{"op":"compare","path":"/principal/groups","eq":{"value":["a"]}}`, nil, false},
		{`{"op":"compare","path":"/principal/sub","in":{"path":"/principal/groups"}}`, nil, false},
		{`{"any":[` + ca + `,{"not":` + cb + `}]}`, nil, false},
		{`"not a rule"`, nil, false},
	} {
		named, ok := GroupTests(jsonv.MustParse([]byte(c.json)))
		if ok != c.ok || !slices.Equal(named, c.named) {
			t.Errorf("GroupTests(%s) = %v, %v; want %v, %v", c.json, named, ok, c.named, c.ok)
		}
	}
	named, ok := GroupTestsList([]any{jsonv.MustParse([]byte(ca)), jsonv.MustParse([]byte(cb))})
	if !ok || !slices.Equal(named, []string{"a", "b"}) {
		t.Errorf("GroupTestsList = %v, %v", named, ok)
	}
	if named, ok := GroupTestsList([]any{jsonv.MustParse([]byte(ca)), jsonv.MustParse([]byte(`{"not":` + cb + `}`))}); ok || named != nil {
		t.Errorf("GroupTestsList with a negated test = %v, %v", named, ok)
	}
	if named, ok := GroupTestsList(nil); !ok || named != nil {
		t.Errorf("GroupTestsList(nil) = %v, %v", named, ok)
	}
}
