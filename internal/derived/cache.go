package derived

import "sync"

// Cache keeps sealed views, so that a view is sealed once per epoch and
// served as identical bytes until it is dropped (§E.2.2 "stored once,
// served forever", within the process). It holds ciphertext only, in
// memory; entries name the namespaces they derive from, and DropNS removes
// them on a purge. When full, the oldest entry goes.
type Cache struct {
	mu    sync.Mutex
	max   int
	m     map[string]cacheEntry
	order []string
}

type cacheEntry struct {
	nss []string
	b   []byte
}

// NewCache returns a cache of at most max entries (default 4096).
func NewCache(max int) *Cache {
	if max <= 0 {
		max = 4096
	}
	return &Cache{max: max, m: map[string]cacheEntry{}}
}

// Get returns the cached bytes of key.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	return e.b, ok
}

// Put stores b under key unless key is already cached, and returns what is
// cached (the first writer wins, so concurrent readers see the same bytes).
func (c *Cache) Put(key string, nss []string, b []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[key]; ok {
		return e.b
	}
	for len(c.m) >= c.max && len(c.order) > 0 {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
	c.m[key] = cacheEntry{nss: nss, b: b}
	c.order = append(c.order, key)
	return b
}

// DropNS removes every entry derived from ns.
func (c *Cache) DropNS(ns string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := c.order[:0]
	for _, k := range c.order {
		e, ok := c.m[k]
		if !ok {
			continue
		}
		drop := false
		for _, n := range e.nss {
			if n == ns {
				drop = true
				break
			}
		}
		if drop {
			delete(c.m, k)
			continue
		}
		keep = append(keep, k)
	}
	c.order = keep
}
