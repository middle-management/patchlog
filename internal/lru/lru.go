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
		e := c.l.Back()
		it := e.Value.(*item[K, V])
		c.l.Remove(e)
		delete(c.m, it.k)
		c.bytes -= it.n
	}
}

// Len is the number of entries, Bytes their total cost.
func (c *Cache[K, V]) Len() int   { return len(c.m) }
func (c *Cache[K, V]) Bytes() int { return c.bytes }

// Flush drops every entry.
func (c *Cache[K, V]) Flush() { c.l, c.m, c.bytes = nil, nil, 0 }
