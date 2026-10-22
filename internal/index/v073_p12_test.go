package index

import "testing"

// I.8 (§B.5, §A.4): the at the index service gives _refs is the combined
// checkpoint of §B.5, so its combinedAt reproduces I.8's, as the tree
// service's does (internal/vectors).
func TestI8CombinedAt(t *testing.T) {
	t.Parallel()
	const (
		nsID1 = "1vmctae4vewju6nvxi374rkrkmyzpdrif" // I.2's ns_id₁
		nsID2 = "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm" // I.2's ns_id₂
		at    = "1vwnfnoyshruyx4lul4a25rtctooiph5v"
	)
	if got := combinedAt(map[string]string{"cat": nsID1, "matches": nsID2}); got != at {
		t.Errorf("combinedAt = %s, want %s (I.8)", got, at)
	}
}
