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

// RemoveOldest and Remove drop entries without OnEvict, which reports
// only the entries Put evicts for the bounds.
func TestCacheRemove(t *testing.T) {
	var evicted []string
	c := Cache[string, int]{MaxEntries: 2, OnEvict: func(k string, _ int) { evicted = append(evicted, k) }}
	c.Put("a", 1, 5)
	c.Put("b", 2, 7)
	c.Put("c", 3, 9) // evicts a
	if len(evicted) != 1 || evicted[0] != "a" {
		t.Fatalf("evicted %v", evicted)
	}
	if k, v, n, ok := c.RemoveOldest(); !ok || k != "b" || v != 2 || n != 7 {
		t.Fatalf("RemoveOldest: %q %d %d %v", k, v, n, ok)
	}
	if !c.Remove("c") || c.Remove("c") || c.Len() != 0 || c.Bytes() != 0 {
		t.Fatalf("Remove: %d entries, %d bytes", c.Len(), c.Bytes())
	}
	if _, _, _, ok := c.RemoveOldest(); ok {
		t.Fatal("RemoveOldest of an empty cache")
	}
	if len(evicted) != 1 {
		t.Fatalf("evicted %v", evicted)
	}
}

// Keys lists the keys, the most recently used first, and marks none used.
func TestCacheKeys(t *testing.T) {
	var c Cache[string, int]
	if k := c.Keys(); len(k) != 0 {
		t.Fatalf("an empty cache's keys: %q", k)
	}
	c.MaxEntries = 3
	c.Put("a", 1, 1)
	c.Put("b", 2, 1)
	c.Put("c", 3, 1)
	c.Get("a")
	if k := c.Keys(); len(k) != 3 || k[0] != "a" || k[1] != "c" || k[2] != "b" {
		t.Fatalf("keys %q", k)
	}
	c.Put("d", 4, 1) // evicts b, which Keys didn't mark used
	if _, ok := c.Get("b"); ok {
		t.Fatal("Keys marked b used")
	}
}
