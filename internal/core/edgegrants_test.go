package core

import (
	"fmt"
	"testing"
)

// An exchange's edge grants are gathered only up to the cap (§C.5): a
// grant naming many namespaces and fixing /resource to many names gives
// their product, and past maxEdgePrefixes distinct prefixes only the 400
// is left to answer, so no more are kept. A prefix given again still
// counts once and keeps its edge grant, whose exp the cookie needs.
func TestEdgeCollectStopsAtTheCap(t *testing.T) {
	t.Parallel()
	c := &edgeCollect{seen: map[string]bool{}}
	for i := 0; i < maxEdgePrefixes-1; i++ {
		if !c.add(EdgeGrant{NS: "a", Resource: fmt.Sprintf("n%d", i)}) {
			t.Fatalf("refused at %d", i)
		}
	}
	if !c.add(EdgeGrant{NS: "a", Resource: "n0"}) || len(c.grants) != maxEdgePrefixes {
		t.Fatalf("a repeated prefix: over %v, %d grants", c.over, len(c.grants))
	}
	// A namespace-wide grant gives two, one more than is left.
	if c.add(EdgeGrant{NS: "b"}) || !c.over {
		t.Fatalf("namespace-wide past the cap: over %v", c.over)
	}
	for ns := 0; ns < 1000; ns++ {
		for i := 0; i < 1000; i++ {
			if c.add(EdgeGrant{NS: fmt.Sprintf("ns%d", ns), Resource: fmt.Sprintf("n%d", i)}) {
				t.Fatal("added past the cap")
			}
		}
	}
	if len(c.grants) != maxEdgePrefixes || len(c.seen) != maxEdgePrefixes {
		t.Fatalf("%d grants, %d prefixes kept", len(c.grants), len(c.seen))
	}

	// Exactly the cap fits.
	c = &edgeCollect{seen: map[string]bool{}}
	for i := 0; i < maxEdgePrefixes/2; i++ {
		if !c.add(EdgeGrant{NS: fmt.Sprintf("ns%d", i)}) {
			t.Fatalf("refused at %d", i)
		}
	}
	if c.over || len(c.seen) != maxEdgePrefixes {
		t.Fatalf("at the cap: over %v, %d prefixes", c.over, len(c.seen))
	}
	if c.add(EdgeGrant{NS: "x", Resource: "y"}) || !c.over {
		t.Fatal("one past the cap")
	}
}
