package rules

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §6.4.2: in is true when the left value equals an element of the
// right-hand array, and false when the right-hand side isn't an array,
// a literal as much as a path: the rule is valid, so a grant carrying it
// isn't refused at decode (§6.6).
func TestV073P02CompareInNonArray(t *testing.T) {
	run(t, []tc{
		{`{"op":"compare","path":"/a","in":{"value":3}}`, `{"a":3}`, false},
		{`{"op":"compare","path":"/a","in":{"value":"a"}}`, `{"a":"a"}`, false},
		{`{"op":"compare","path":"/a","in":{"value":{"a":1}}}`, `{"a":"a"}`, false},
		{`{"op":"compare","path":"/a","in":{"value":null}}`, `{"a":null}`, false},
		{`{"not":{"op":"compare","path":"/a","in":{"value":"a"}}}`, `{"a":"a"}`, true},
	})
	if _, err := Compile(jsonv.MustParse([]byte(`{"op":"compare","path":"/a","in":{"value":"a"}}`))); err != nil {
		t.Fatalf("in with a literal that isn't an array: %v", err)
	}
}
