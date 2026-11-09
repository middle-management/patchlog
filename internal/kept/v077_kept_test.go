package kept

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
)

// TestV077PutOutcome (FSVC-9; §A.1: "drop kept results (§A.4), serving or
// keeping none computed from what was read before it"): PutOutcome tells a
// result refused for a purge since its generation (PurgedSince, never to be
// served) from one already kept (Existing), one kept (Kept) and one
// dropped at once for size (Evicted); Put's answers are unchanged.
func TestV077PutOutcome(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	k := New(func() time.Time { return now }, 64)
	st := func(body, tags string) derived.Stored {
		return derived.Stored{Body: []byte(body), JSON: true, Tags: tags}
	}
	gen := k.Generation("a")
	if _, o := k.PutOutcome("/a/1", "a", gen, false, st("one", "idx:a,r:a/x")); o != Kept {
		t.Errorf("first put: %v, want Kept", o)
	}
	if got, o := k.PutOutcome("/a/1", "a", gen, false, st("two", "idx:a,r:a/x")); o != Existing || string(got.Body) != "one" {
		t.Errorf("second put: %v %s, want Existing one", o, got.Body)
	}
	k.Purge("a", []string{"r:a/y"})
	if _, o := k.PutOutcome("/a/2", "a", gen, false, st("late", "idx:a,r:a/y")); o != PurgedSince {
		t.Errorf("put after a purge of its tag: %v, want PurgedSince", o)
	}
	if _, ok := k.Put("/a/2", "a", gen, false, st("late", "idx:a,r:a/y")); ok {
		t.Error("Put kept a result read before a purge of what it shows")
	}
	big := make([]byte, 100)
	if _, o := k.PutOutcome("/a/3", "a", k.Generation("a"), false, derived.Stored{Body: big, Tags: "idx:a"}); o != Evicted {
		t.Errorf("put over the size: %v, want Evicted", o)
	}
	if _, ok := k.Put("/a/4", "a", k.Generation("a"), false, derived.Stored{Body: big, Tags: "idx:a"}); ok {
		t.Error("Put says an evicted result is kept")
	}
}
