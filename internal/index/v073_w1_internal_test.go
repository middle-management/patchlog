package index

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/pointer"
)

// Wave-1 integration (P03 x P08, §6.6, §A.2, §A.4): a patternProperties
// pattern is read as the core reads it when it validates the document, so
// \uXXXX is a code point (pattern.Translate), and since v0.74 a pattern
// RE2 accepted as written before the translation, which every schema now
// refuses (§6.1), matches no name. Both judging a path and collecting
// values match member names with it.
func TestV073PatternPropertiesAsValidated(t *testing.T) {
	t.Parallel()
	root := v073Rev("root", 1)
	for _, c := range []struct {
		name, pat, member string
		want              bool
	}{
		{"a \\u escape", "^" + u("00e9") + "t", "été", true},
		{"a \\u escape, no match", "^" + u("00e9") + "t", "etc", false},
		{"a surrogate pair", "^" + u("d83d") + u("de00"), "😀x", true},
		{"plain RE2", `^x-`, "x-a", true},
		{`stored before: \x{D800}, refused now`, `^a|\x{D800}`, "ab", false},
	} {
		s := `{"patternProperties": {` + quote(c.pat) + `: {"type": "string", "x-index": "facet"}}}`
		w := &markWalk{load: v073Loader(map[string]any{root: parse(t, s)}), docs: map[string]any{}, seen: map[string]bool{}, kind: "facet"}
		w.path = must(pointer.Parse("/" + c.member))
		if got := w.marked(root, nil, 0); got != c.want {
			t.Errorf("%s: %s marks /%s: %v, want %v", c.name, s, c.member, got, c.want)
		}
		_, facet, _ := v073Collect(t, s, `{`+quote(c.member)+`: "v"}`, nil)
		if got := strings.Join(facet, ","); (got == "/"+c.member+"=v") != c.want {
			t.Errorf("%s: %s collects %q", c.name, s, got)
		}
	}
}

// u is a backslash, "u" and hex: the escape as a schema writes it.
func u(hex string) string { return string(rune(92)) + "u" + hex }

// quote writes s as a JSON string, its backslashes escaped.
func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}
