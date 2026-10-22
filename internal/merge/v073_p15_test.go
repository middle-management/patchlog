package merge_test

import (
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// §7.2, §8.1 (GB-55): a create on a resource deleted between plan and
// apply gets 410 gone with head, the tombstone, where it used to get 412;
// Apply re-classifies it as a target that moved instead of failing.
func TestV073P15ApplyAfterTargetDeleted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.create("r7", "final", map[string]any{"title": "Final"})
	p := e.plan("matches", "r7", merge.Options{})
	if f := p.Resource("final"); f.Class != merge.FastForward || !f.IfNoneMatch {
		t.Fatalf("final: %+v", f)
	}
	e.create("matches", "final", map[string]any{"title": "Other"})
	tomb := e.del("matches", "final")
	_, err := p.Apply(ctx)
	if ae, ok := client.AsAPIError(err); ok {
		t.Fatalf("apply answered %d %s: the moved target wasn't re-classified", ae.Status, ae.Code)
	}
	// Re-classified against the tombstone: a person decides between the
	// target's delete and the branch's document.
	if !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("apply: %v, want ErrConflicts", err)
	}
	if f := p.Resource("final"); f.Class == merge.FastForward || !f.NeedsPerson() {
		t.Fatalf("final not re-classified: %+v", f)
	}
	if h := e.head("matches", "final"); h.State != client.Tombstoned || h.ID != tomb {
		t.Fatalf("final: %+v", h)
	}
}
