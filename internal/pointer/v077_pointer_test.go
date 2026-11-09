package pointer

import (
	"reflect"
	"testing"
)

// OTHER-1 (§F.3 Conflicts inside arrays, §11.2): WidenArray widens a write
// whose last segment indexes an array, judged before the op or after it,
// to the outermost array holding it; an object member, even one named "-",
// stays as written.
func TestV077WidenArray(t *testing.T) {
	t.Parallel()
	pre := map[string]any{
		"a": []any{map[string]any{"b": []any{1.0}, "c": 0.0, "o": map[string]any{"-": 1.0}}},
		"o": map[string]any{"-": 1.0, "x": 2.0},
		"l": []any{},
	}
	post := map[string]any{"n": []any{1.0}}
	for _, c := range []struct {
		pre, post any
		w, want   string
	}{
		{pre, pre, "/a/0/b/1", "/a"},
		{pre, pre, "/a/0/b", "/a/0/b"},
		{pre, pre, "/a/0/c", "/a/0/c"},
		{pre, pre, "/a/0/o/-", "/a/0/o/-"},
		{pre, pre, "/o/-", "/o/-"},
		{pre, pre, "/l/-", "/l"},
		{pre, pre, "/a/0/b/-", "/a"},
		// An element the op added exists only after it.
		{map[string]any{}, post, "/n/0", "/n"},
		{pre, pre, "", ""},
		// A root array document widens to the root.
		{[]any{[]any{1.0}}, nil, "/0/0", ""},
	} {
		if got := WidenArray(c.pre, c.post, MustParse(c.w)); !reflect.DeepEqual(got, MustParse(c.want)) {
			t.Errorf("%s: %q, want %q", c.w, got.String(), c.want)
		}
	}
}
