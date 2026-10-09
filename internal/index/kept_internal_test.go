package index

import (
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
)

func TestKeptStore(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	k := newKept(func() time.Time { return now })
	st := func(body, tags string) derived.Stored {
		return derived.Stored{Body: []byte(body), JSON: true, Tags: tags}
	}
	has := func(url string) bool { _, _, ok := k.get(url); return ok }

	// The first writer wins.
	gen := k.generation("a")
	k.put("/a/at/1?q=x", "a", gen, false, st("one", "idx:a,r:a/x"))
	if got := k.put("/a/at/1?q=x", "a", gen, false, st("two", "idx:a,r:a/x")); string(got.Body) != "one" {
		t.Errorf("second put returned %s", got.Body)
	}
	// A result read before purges isn't kept if one in its namespace
	// purged a tag it carries; one that shows none of what they purged is.
	k.purge("a", []string{"r:a/y", "idx:a:counts"})
	k.purge("b", []string{"idx:b", "ns:b"})
	if got := k.put("/a/at/2?q=x", "a", gen, false, st("late", "idx:a,r:a/y")); string(got.Body) != "late" || has("/a/at/2?q=x") {
		t.Error("kept a result read before a purge of what it shows")
	}
	if k.put("/a/at/2?q=z", "a", gen, false, st("z", "idx:a,r:a/z")); !has("/a/at/2?q=z") {
		t.Error("a result read before a purge of what it doesn't show isn't kept")
	}
	// A purge drops the namespace's results carrying a tag it purges.
	k.put("/b/at/1?q=x", "b", k.generation("b"), true, st("b", "idx:b,r:b/x"))
	k.put("/a/at/3?q=y", "a", k.generation("a"), false, st("three", "idx:a,r:a/z"))
	k.purge("a", []string{"r:a/x", "r:b/x"})
	if has("/a/at/1?q=x") || !has("/a/at/3?q=y") || !has("/b/at/1?q=x") {
		t.Error("purge dropped the wrong results")
	}
	if _, bound, _ := k.get("/b/at/1?q=x"); !bound {
		t.Error("not bound")
	}
	// At most maxSize bytes, the oldest out first.
	k.maxSize = 200
	for i := range 10 {
		k.put(fmt.Sprintf("/c/at/%d", i), "c", 0, false, st(fmt.Sprintf("%040d", i), "idx:c"))
	}
	if k.size > k.maxSize || has("/c/at/0") || !has("/c/at/9") {
		t.Errorf("size %d of %d", k.size, k.maxSize)
	}
	// keepFor after a put, the result is gone.
	now = now.Add(keepFor)
	if has("/c/at/9") || k.size != 0 || k.order.Len() != 0 {
		t.Errorf("expired results kept: %d bytes", k.size)
	}
	// A result read before a purge recorded no longer isn't kept.
	gen = k.generation("a")
	k.purge("a", []string{"r:a/y"})
	now = now.Add(keepFor)
	k.purge("a", []string{"r:a/y"})
	if k.put("/a/at/4?q=z", "a", gen, false, st("z", "idx:a,r:a/z")); has("/a/at/4?q=z") || len(k.purges["a"]) != 1 {
		t.Errorf("kept a result read before a purge no longer recorded (%d recorded)", len(k.purges["a"]))
	}
}
