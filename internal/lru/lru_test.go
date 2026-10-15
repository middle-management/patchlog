package lru

import "testing"

// Cache keeps the most recently used entries within both bounds; replacing
// an entry counts its new cost; an entry over a quarter of the bytes isn't
// kept.
func TestCache(t *testing.T) {
	c := Cache[string, int]{MaxEntries: 3, MaxBytes: 100}
	c.Put("a", 1, 10)
	c.Put("b", 2, 10)
	c.Put("c", 3, 10)
	c.Get("a")
	c.Put("d", 4, 10) // evicts b, the least recently used
	if _, ok := c.Get("b"); ok || c.Len() != 3 {
		t.Fatalf("after a fourth entry: b kept %v, %d entries", ok, c.Len())
	}
	c.Put("a", 5, 20)
	if v, _ := c.Get("a"); v != 5 || c.Bytes() != 40 {
		t.Fatalf("replaced: %d, %d bytes", v, c.Bytes())
	}
	c.Put("big", 6, 26)
	if _, ok := c.Get("big"); ok {
		t.Fatal("an entry over a quarter of the bytes is kept")
	}
	c.Put("e", 7, 25)
	c.Put("f", 8, 25)
	c.Put("g", 9, 25)
	if c.Bytes() > 100 || c.Len() > 3 {
		t.Fatalf("over the bounds: %d entries, %d bytes", c.Len(), c.Bytes())
	}
	c.Flush()
	if c.Len() != 0 || c.Bytes() != 0 {
		t.Fatal("flush kept entries")
	}
}

// Without MaxBytes, only the entries are bounded.
func TestCacheEntriesOnly(t *testing.T) {
	c := Cache[int, int]{MaxEntries: 2}
	for i := 0; i < 5; i++ {
		c.Put(i, i, 1<<30)
	}
	if c.Len() != 2 {
		t.Fatalf("%d entries", c.Len())
	}
	if _, ok := c.Get(4); !ok {
		t.Fatal("the latest entry evicted")
	}
}
