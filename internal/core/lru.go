package core

import "container/list"

// lru is a cache bounded by its number of entries and by their total
// cost (bytes), evicting the least recently used. It isn't safe for
// concurrent use: its owner locks. The zero value is usable once its
// bounds are set.
type lru[K comparable, V any] struct {
	maxEntries, maxBytes int

	l     *list.List
	m     map[K]*list.Element
	bytes int
}

type lruItem[K comparable, V any] struct {
	k K
	v V
	n int
}

func (c *lru[K, V]) get(k K) (V, bool) {
	if e, ok := c.m[k]; ok {
		c.l.MoveToFront(e)
		return e.Value.(*lruItem[K, V]).v, true
	}
	var zero V
	return zero, false
}

// put keeps v under k at cost n, evicting the least recently used entries
// as the bounds need. An entry costing more than a quarter of maxBytes isn't
// kept: it would push out a quarter of the cache.
func (c *lru[K, V]) put(k K, v V, n int) {
	if c.maxEntries <= 0 || n > c.maxBytes/4 {
		return
	}
	if c.m == nil {
		c.l, c.m = list.New(), map[K]*list.Element{}
	}
	if e, ok := c.m[k]; ok {
		it := e.Value.(*lruItem[K, V])
		c.bytes += n - it.n
		it.v, it.n = v, n
		c.l.MoveToFront(e)
	} else {
		c.m[k] = c.l.PushFront(&lruItem[K, V]{k, v, n})
		c.bytes += n
	}
	for len(c.m) > c.maxEntries || c.bytes > c.maxBytes {
		e := c.l.Back()
		it := e.Value.(*lruItem[K, V])
		c.l.Remove(e)
		delete(c.m, it.k)
		c.bytes -= it.n
	}
}

func (c *lru[K, V]) len() int { return len(c.m) }

func (c *lru[K, V]) flush() { c.l, c.m, c.bytes = nil, nil, 0 }
