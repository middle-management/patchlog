package rules

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §12.2: rulesPerNamespace and rulesPerGrant count every rule form, those
// nested in all, any, not, if and then included.
func TestV073CountForms(t *testing.T) {
	t.Parallel()
	leaf := `{"op":"test","path":"/action","schema":{"type":"string","allOf":[{"not":{}}]}}`
	for _, c := range []struct {
		json string
		want int
	}{
		{`[]`, 0},
		{leaf, 1},
		{`[` + leaf + `,` + leaf + `]`, 2},
		{`{"all":[` + leaf + `,` + leaf + `,` + leaf + `]}`, 4},
		{`{"any":[]}`, 1},
		{`{"not":` + leaf + `}`, 2},
		{`{"if":[` + leaf + `],"then":[` + leaf + `,{"not":{"any":[` + leaf + `]}}]}`, 6},
		{`[{"all":[{"all":[{"all":[` + leaf + `]}]}]}]`, 4},
		// Not rule forms: counted as nothing.
		{`[1, "x", {"other": []}]`, 0},
	} {
		if got := CountForms(jsonv.MustParse([]byte(c.json))); got != c.want {
			t.Errorf("CountForms(%s) = %d, want %d", c.json, got, c.want)
		}
	}
}
