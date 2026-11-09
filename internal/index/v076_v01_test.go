package index

import (
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grant"
)

// TestV076V01IndexGSPerKey (§B.11.9 gs, §C.4): grants through two keys
// with the same scope rules get different subject sets, each bound to its
// key's kid and pub as the origin's are (catvis.KeySubject), so that no
// stored row judges another key's cookies, and the index's gs stays the
// origin's (TestV075IndexSubjectSets).
func TestV076V01IndexGSPerKey(t *testing.T) {
	t.Parallel()
	view := func(kid, pub string) *fview {
		t.Helper()
		v := &grant.Verified{Grant: &grant.Grant{}, Key: &grant.Key{Kid: kid, Raw: map[string]any{"kid": kid, "pub": pub}},
			Principal: grant.Principal{ID: "user:li", Groups: []string{"fans"}}, Can: map[string]bool{"read": true}}
		fv, err := grantFview(&fcp{}, v)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(fv.subjects, catvis.KeySubject(kid, pub)) {
			t.Fatalf("subjects %v lack %s", fv.subjects, catvis.KeySubject(kid, pub))
		}
		return fv
	}
	a, b, c := view("fan", "pubA"), view("fan2", "pubA"), view("fan", "pubB")
	if a.gs == b.gs || a.gs == c.gs || b.gs == c.gs {
		t.Fatalf("gs shared across keys: %s %s %s", a.gs, b.gs, c.gs)
	}
	if again := view("fan", "pubA"); again.gs != a.gs {
		t.Fatalf("the same key gives %s, then %s", a.gs, again.gs)
	}
}
