package index

import (
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// Cross-review (conformance lens), §B.11.9 gs: a gs's subjects carry "the
// string scope:{digest} of §A.4's marker for {ns}": the digest of the
// index's scope marker for the same grant, covering the key's key:
// string, not the rules' digest alone.
func TestV077XrevGSScopeSubjectIsMarkerDigest(t *testing.T) {
	t.Parallel()
	v := &grant.Verified{Grant: &grant.Grant{}, Key: &grant.Key{Kid: "fan", Raw: map[string]any{"kid": "fan", "pub": "pubA"}},
		Principal: grant.Principal{ID: "user:li", Groups: []string{"fans"}}, Can: map[string]bool{"read": true}}
	fv, err := grantFview(&fcp{}, v)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := grantcheck.ReadsScope(v)
	if !ok {
		t.Fatal("reads refer to /now")
	}
	_, marker, _ := strings.Cut(scopeMarker("matches", d, "fan", "pubA"), ":scope:")
	if !slices.Contains(fv.subjects, catvis.ScopePrefix+marker) {
		t.Errorf("subjects %v, want scope:%s, the digest of §A.4's marker", fv.subjects, marker)
	}
	if slices.Contains(fv.subjects, catvis.ScopePrefix+d) {
		t.Errorf("subjects %v carry the rules' digest alone", fv.subjects)
	}
}
