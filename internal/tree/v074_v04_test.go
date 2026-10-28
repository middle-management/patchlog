package tree_test

import (
	"testing"
)

// TestV074RootsWithoutVisibleParent (Open 101, §B.11.5): for a subject
// set, a visible node with no visible parent is a root even when it has
// no walkable parent at all: lost, whose one parent doesn't exist, is a
// root for a reader who sees it, and its one path, empty, ends at it, not
// counted incomplete. Unfiltered, it stays an orphan (§B.5).
func TestV074RootsWithoutVisibleParent(t *testing.T) {
	t.Parallel()
	x, scope, whole := scopedWorld(t)
	bob := scope("lost")
	if got := names(x.get("/cat/roots", bob)["roots"]); got != "lost" {
		t.Errorf("roots for a reader who sees lost: %s", got)
	}
	if b := x.get("/cat/ancestors?of=lost", bob); len(b["paths"].([]any)) != 1 || pathsOf(b["paths"]) != "" || b["incomplete"] != nil {
		t.Errorf("ancestors of a root for the reader: %v", b)
	}
	if b := x.get("/cat/ancestors?of=lost", whole); len(b["paths"].([]any)) != 0 || b["incomplete"] != 1.0 {
		t.Errorf("unfiltered ancestors of an orphan: %v", b)
	}
	if got := names(x.get("/cat/orphans", whole)["orphans"]); got != "lost" {
		t.Errorf("unfiltered orphans: %s", got)
	}
}
