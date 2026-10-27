package files

import "testing"

// Titles compare after NFC and Unicode simple case folding (§H.2
// "Siblings", §B.5 lookup), or NFC alone for a case-sensitive tool.
func TestTitleKey(t *testing.T) {
	for _, c := range []struct {
		a, b          string
		caseSensitive bool
		same          bool
	}{
		{"Report.txt", "REPORT.TXT", false, true},
		{"Report.txt", "REPORT.TXT", true, false},
		{"Kelvin", "kelvin", false, true}, // the Kelvin sign's orbit holds k and K
		{"café", "café", false, true},
		{"café", "café", true, true},
		{"Straße", "STRASSE", false, false}, // full folding, not simple
		{"ﬁle", "file", false, false},
		{"Σ", "ς", false, true}, // Σ, ς and σ are one orbit
		{"a", "b", false, false},
	} {
		if got := TitleKey(c.a, c.caseSensitive) == TitleKey(c.b, c.caseSensitive); got != c.same {
			t.Errorf("TitleKey(%q) == TitleKey(%q) (case-sensitive %v): %v", c.a, c.b, c.caseSensitive, got)
		}
	}
}
