package index

import (
	"testing"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// SERVICES §A.4 gs (v0.85): "reads:{ns}:{k}, k the key: string (§7.9
// gs) of the key that verified the grant in {ns}". The marker and the gs
// of its subject set are those the proposed vector C.4 computes
// (docs/VECTORS-PROPOSED.md) for demo's key ops-2026.
func TestV085ReadsMarkerVector(t *testing.T) {
	m := readsMarker("demo", "ops-2026", "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
	if m != "reads:demo:key:1gorsoawpfk76fdd6bdqtgqkial3qgvl4" {
		t.Errorf("marker %s", m)
	}
	if gs := grantcheck.ViewID([]string{m}); gs != "1qt3t7wcs3jfhqrrkkunh3mvoi4tyjsrt" {
		t.Errorf("gs %s", gs)
	}
	if isGMarker(m) {
		t.Errorf("%s reads as a g: marker", m)
	}
}

// A cookie for the marker of before v0.85, reads:{ns}, reads nothing: its
// reader exchanges again.
func TestV085OldReadsMarkerReadsNothing(t *testing.T) {
	ix := &Index{}
	if a, err := ix.markerAccess(t.Context(), "docs", "reads:docs", 0); a != nil || err == nil {
		t.Errorf("reads:docs: %v %v, want a refusal", a, err)
	}
}
