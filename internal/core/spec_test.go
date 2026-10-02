package core

import "testing"

// §7.4: spec versions compare as dotted decimal numbers; a remote base's
// deployment implementing a later version is refused (§G.3).
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
	if err := checkRemoteSpec("https://a.example", ""); err != nil {
		t.Fatalf("no version: %v", err)
	}
	if err := checkRemoteSpec("https://a.example", SpecVersion); err != nil {
		t.Fatalf("our version: %v", err)
	}
	if err := checkRemoteSpec("https://a.example", "99"); err == nil || err.Status != 422 {
		t.Fatalf("a later version: %v", err)
	}
}
