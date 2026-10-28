package vectors_test

import "testing"

// TOOLS-9 (Addendum I.11, v0.74): "\ud800, \udc00, \ud83dA and \x{D800}
// are refused". re2.json has each of them refused, \ud83dA with a literal
// A after the high surrogate, and \x{D800} as a rule, not the
// reference's choice.
func TestV074RE2RefusedRows(t *testing.T) {
	t.Parallel()
	refused := map[string]bool{}
	for _, v := range loadVectors(t, "re2").Vectors {
		p, _ := v["pattern"].(string)
		if v["verdict"] == "refused" {
			refused[p] = true
		}
		if _, ok := v["informative"]; ok && p == `\x{D800}` {
			t.Errorf("%s: still informative", p)
		}
	}
	for _, p := range []string{`\ud800`, `\udc00`, `\ud83dA`, `\x{D800}`} {
		if !refused[p] {
			t.Errorf("no refused row %s", p)
		}
	}
}
