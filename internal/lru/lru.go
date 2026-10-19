// Package lru is a cache bounded by its number of entries and, optionally,
// by their total cost (bytes), evicting the least recently used.
package lru

import "container/list"

// Cache isn't safe for concurrent use: its owner locks. The zero value
// holds nothing until MaxEntries is set.
type Cache[K comparable, V any] struct {
	// MaxEntries bounds the entries; MaxBytes, if positive, their total
	// cost, and an entry costing more than a quarter of it isn't kept: it
	// would push out a quarter of the cache.
	MaxEntries, MaxBytes int
	// OnEvict, if set, is called with each entry Put evicts to keep the
	// bounds (not one replaced, removed or flushed).
	OnEvict func(K, V)

	l     *list.List
	m     map[K]*list.Element
	bytes int
}

type item[K comparable, V any] struct {
	k K
	v V
	n int
}

// Get returns k's value, marking it the most recently used.
func (c *Cache[K, V]) Get(k K) (V, bool) {
	if e, ok := c.m[k]; ok {
		c.l.MoveToFront(e)
		return e.Value.(*item[K, V]).v, true
	}
	var zero V
	return zero, false
}

// Put keeps v under k at cost n, evicting the least recently used entries
// as the bounds need.
func (c *Cache[K, V]) Put(k K, v V, n int) {
	if c.MaxEntries <= 0 || c.MaxBytes > 0 && n > c.MaxBytes/4 {
		return
	}
	if c.m == nil {
		c.l, c.m = list.New(), map[K]*list.Element{}
	}
	if e, ok := c.m[k]; ok {
		it := e.Value.(*item[K, V])
		c.bytes += n - it.n
		it.v, it.n = v, n
		c.l.MoveToFront(e)
	} else {
		c.m[k] = c.l.PushFront(&item[K, V]{k, v, n})
		c.bytes += n
	}
	for len(c.m) > c.MaxEntries || c.MaxBytes > 0 && c.bytes > c.MaxBytes {
		k, v, _, _ := c.RemoveOldest()
		if c.OnEvict != nil {
			c.OnEvict(k, v)
		}
	}
}

// RemoveOldest drops the least recently used entry and returns it with
// its cost; false if there is none.
func (c *Cache[K, V]) RemoveOldest() (K, V, int, bool) {
	if len(c.m) == 0 {
		var k K
		var v V
		return k, v, 0, false
	}
	it := c.l.Remove(c.l.Back()).(*item[K, V])
	delete(c.m, it.k)
	c.bytes -= it.n
	return it.k, it.v, it.n, true
}

// Remove drops k's entry, reporting whether there was one.
func (c *Cache[K, V]) Remove(k K) bool {
	e, ok := c.m[k]
	if !ok {
		return false
	}
	it := c.l.Remove(e).(*item[K, V])
	delete(c.m, k)
	c.bytes -= it.n
	return true
}

// Keys returns the keys, the most recently used first, marking none used.
func (c *Cache[K, V]) Keys() []K {
	out := make([]K, 0, len(c.m))
	if c.l == nil {
		return out
	}
	for e := c.l.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(*item[K, V]).k)
	}
	return out
}

// Len is the number of entries, Bytes their total cost.
func (c *Cache[K, V]) Len() int   { return len(c.m) }
func (c *Cache[K, V]) Bytes() int { return c.bytes }

// Flush drops every entry.
func (c *Cache[K, V]) Flush() { c.l, c.m, c.bytes = nil, nil, 0 }
