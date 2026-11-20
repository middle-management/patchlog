package index

import (
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// TestV076V01IndexGSPerKey (§7.9 view, §C.4): grants through two keys
// with the same scope rules get different views, each bound to its
// key's kid and pub as the origin's are (grantcheck.KeySubject), so that no
// stored row judges another key's cookies, and the index's view stays the
// origin's (TestV075IndexSubjectSets).
func TestV076V01IndexGSPerKey(t *testing.T) {
	t.Parallel()
	view := func(kid, pub string) *fview {
		t.Helper()
		v := &grant.Verified{Grant: &grant.Grant{}, Key: &grant.Key{Kid: kid, Raw: map[string]any{"kid": kid, "pub": pub}},
			Principal: grant.Principal{ID: "user:li", Groups: []string{"fans"}}, Can: map[string]bool{"read": true}}
		fv, err := (&Index{}).grantFview(&fcp{}, v, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(fv.subjects, grantcheck.KeySubject(kid, pub)) {
			t.Fatalf("subjects %v lack %s", fv.subjects, grantcheck.KeySubject(kid, pub))
		}
		return fv
	}
	a, b, c := view("fan", "pubA"), view("fan2", "pubA"), view("fan", "pubB")
	if a.vid == b.vid || a.vid == c.vid || b.vid == c.vid {
		t.Fatalf("vid shared across keys: %s %s %s", a.vid, b.vid, c.vid)
	}
	if again := view("fan", "pubA"); again.vid != a.vid {
		t.Fatalf("the same key gives %s, then %s", a.vid, again.vid)
	}
}
