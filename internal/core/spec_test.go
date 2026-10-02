package core

import "testing"

// §7.4: spec versions compare as dotted decimal numbers; a remote base's
// deployment implementing a later version is refused only for a member of
// a namespace document B reads that B doesn't know (§G.3).
func TestSpecNewer(t *testing.T) {
	for _, c := range []struct {
		a, b      string
		newer, ok bool
	}{
		{"0.38", "0.37", true, true},
		{"0.37", "0.37", false, true},
		{"0.36", "0.37", false, true},
		{"0.100", "0.37", true, true},
		{"1", "0.37", true, true},
		{"0.37.1", "0.37", true, true},
		{"0.37.0", "0.37", false, true},
		{"0.37-rc", "0.37", false, false},
		{"v0.37", "0.37", false, false},
		{"0.037", "0.37", false, false},
		{"", "0.37", false, false},
	} {
		newer, ok := specNewer(c.a, c.b)
		if newer != c.newer || ok != c.ok {
			t.Errorf("specNewer(%q, %q) = %v, %v", c.a, c.b, newer, ok)
		}
	}
	// A remote base's namespace documents are judged by their members, and
	// only from a deployment of a later (or unknown) version (§G.3).
	odd := map[string]any{"read": "public", "x-team": "a", "wardens": []any{}}
	for _, c := range []struct {
		spec string
		doc  map[string]any
		ok   bool
	}{
		{"", odd, true},
		{"0.36", odd, true},
		{SpecVersion, odd, true},
		{"0.38", map[string]any{"read": "public", "x-team": "a", "encryption": map[string]any{"level": "at-rest"}}, true},
		{"0.38", odd, false},
		{"0.37.1", odd, false},
		{"0.37-rc", odd, false},
	} {
		err := checkRemoteDoc("https://a.example", c.spec, "main", c.doc)
		if (err == nil) != c.ok || (err != nil && err.Status != 422) {
			t.Errorf("checkRemoteDoc(%q, %v) = %v", c.spec, c.doc, err)
		}
	}
}
