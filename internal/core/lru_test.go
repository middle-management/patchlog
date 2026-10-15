package core

import (
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
)

// lru keeps the most recently used entries within both bounds; replacing
// an entry counts its new cost; an entry over a quarter of the bytes isn't
// kept.
func TestLRU(t *testing.T) {
	c := lru[string, int]{maxEntries: 3, maxBytes: 100}
	c.put("a", 1, 10)
	c.put("b", 2, 10)
	c.put("c", 3, 10)
	c.get("a")
	c.put("d", 4, 10) // evicts b, the least recently used
	if _, ok := c.get("b"); ok || c.len() != 3 {
		t.Fatalf("after a fourth entry: b kept %v, %d entries", ok, c.len())
	}
	c.put("a", 5, 20)
	if v, _ := c.get("a"); v != 5 || c.bytes != 40 {
		t.Fatalf("replaced: %d, %d bytes", v, c.bytes)
	}
	c.put("big", 6, 26)
	if _, ok := c.get("big"); ok {
		t.Fatal("an entry over a quarter of the bytes is kept")
	}
	c.put("e", 7, 25)
	c.put("f", 8, 25)
	c.put("g", 9, 25)
	if c.bytes > 100 || c.len() > 3 {
		t.Fatalf("over the bounds: %d entries, %d bytes", c.len(), c.bytes)
	}
	c.flush()
	if c.len() != 0 || c.bytes != 0 {
		t.Fatal("flush kept entries")
	}
}

// The document cache is bounded by bytes: large documents don't pile up
// past it, whatever their number.
func TestDocCacheBytes(t *testing.T) {
	c := newDocCache(1 << 20)
	for i := 0; i < 100; i++ {
		var id ids.ID
		copy(id[:], fmt.Sprintf("%020d", i))
		c.put(id, make([]byte, 100<<10))
	}
	if c.lru.bytes > 1<<20 || c.lru.len() != 10 {
		t.Fatalf("%d documents, %d bytes", c.lru.len(), c.lru.bytes)
	}
}

// The read cache evicts some entries when full rather than all of them,
// and counts a replaced revision once.
func TestReadCacheRoom(t *testing.T) {
	c := &readCache{maxBytes: 1 << 20}
	g := c.load("n")
	for i := 0; i < 50; i++ {
		c.putRev(g, "n", fmt.Sprint(i), "r", make([]byte, 100<<10), true)
	}
	if c.bytes > 1<<20 || len(c.revs) == 0 || len(c.revs) < 5 {
		t.Fatalf("%d revisions, %d bytes", len(c.revs), c.bytes)
	}
	c.revs, c.bytes = nil, 0
	for i := 0; i < 3; i++ {
		c.putRev(g, "n", "a", "r", make([]byte, 1000), true)
	}
	if c.bytes != 1000 || len(c.revs) != 1 {
		t.Fatalf("a replaced revision: %d revisions, %d bytes", len(c.revs), c.bytes)
	}
	c.putRev(g, "n", "huge", "r", make([]byte, 300<<10), true)
	if _, ok := c.revs[revKey("n", "huge", "r")]; ok {
		t.Fatal("a revision over a quarter of the bytes is kept")
	}
}
