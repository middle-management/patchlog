package rules

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §2.1 Refers to (v0.82): "A rule refers to every pointer at, above or
// below a path that it, or a rule nested in it, tests or compares, so a
// rule on the whole envelope ("") refers to every pointer". Refs reports
// the whole envelope as "*", which every caller counts as /now, /resource
// and the rest (grant-scope 71); a rule on /principal/groups refers to
// /principal alone, neither to /now nor to /resource (conformance 131).
func TestV082RefersTo(t *testing.T) {
	for _, c := range []struct {
		rule string
		refs []string
	}{
		{`{"op":"test","path":"","schema":{"required":["action"]}}`, []string{"*"}},
		{`{"not":{"op":"test","path":"","schema":{"type":"object"}}}`, []string{"*"}},
		{`{"any":[{"op":"test","path":"/action","value":"read"},{"op":"compare","path":"","eq":{"value":1}}]}`, []string{"*", "action"}},
		{`{"op":"compare","path":"/action","eq":{"path":""}}`, []string{"*", "action"}},
		{`{"op":"test","path":"/now","schema":{"type":"string"}}`, []string{"now"}},
		{`{"all":[{"not":{"op":"compare","path":"/now","gt":{"value":"2026-01-01T00:00:00Z"}}}]}`, []string{"now"}},
		{`{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"editors"}}}`, []string{"principal"}},
		{`{"op":"compare","path":"/principal/id","eq":{"path":"/resource"}}`, []string{"principal", "resource"}},
	} {
		r, err := Compile(jsonv.MustParse([]byte(c.rule)))
		if err != nil {
			t.Fatalf("%s: %v", c.rule, err)
		}
		refs := r.Refs()
		if len(refs) != len(c.refs) {
			t.Errorf("%s: refs %v, want %v", c.rule, refs, c.refs)
		}
		for _, want := range c.refs {
			if !refs[want] {
				t.Errorf("%s: refs %v, want %v", c.rule, refs, c.refs)
			}
		}
		if only := r.OnlyRefs("action", "principal"); only != (!refs["*"] && !refs["now"] && !refs["resource"]) {
			t.Errorf("%s: OnlyRefs(action, principal) %v with refs %v", c.rule, only, refs)
		}
	}
}
