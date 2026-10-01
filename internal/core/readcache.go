package core

import (
	"sync"
	"sync/atomic"
	"time"
)

// Transaction-free reads of public namespaces.
//
// A read of a public namespace doesn't depend on credentials (§7: public
// reads ignore grants), so its answer depends only on the database. Two
// answers are cached and served without opening a transaction:
//
//   - a revision (GET /r/{ns}/{name}/rev/{id}): immutable, until a purge,
//     prune, restore, key destruction or configuration change;
//   - a head pointer (GET /r/{ns}/{name}): valid until the namespace's
//     next write, or any of the above.
//
// Validity is tracked with generation counters used as seqlocks: a write
// transaction bumps them just before and just after its commit, so they are
// odd while a commit may be in flight. A reader loads them before its
// transaction begins (so its snapshot is at least that new) and stores its
// answer under them only if they were even. A cached answer is served only
// while the counters still hold the values it was stored under: no commit
// that could change it has happened since the snapshot it was read from.
// (Concurrent commits, on Postgres, can leave the counters even while one
// is in flight; that commit's second bump still invalidates whatever was
// stored meanwhile, so the rule holds.)
//
// On Postgres, other instances commit too, and this instance learns of
// their commits from its tailer (tailer.go), which moves the counters
// (by two, keeping their parity) for every commit it sees. Between such a
// commit and the poll that sees it, cached answers can be stale, so:
//
//   - nothing is served unless the tailer's last successful poll started
//     within freshFor (fresh): a commit that changes what reads may return
//     beyond a namespace's log (configuration, purge, prune, restore, key
//     destruction) bumps a counter row that every poll reads, so it stops
//     being served at most freshFor after it commits, whatever holds back
//     the log the tailer follows, and not at all while the tailer is
//     failing;
//   - head pointers are kept at most headTTL (micro-cached), since a write
//     on another instance is seen only once older transactions have
//     finished.
type readCache struct {
	// meta moves on commits that change what any read may return:
	// configuration (read mode, level), purges, prunes, restores and key
	// destruction.
	meta atomic.Uint64
	// ns moves on every commit that appends to a namespace's log, per
	// namespace name.
	ns sync.Map // string -> *atomic.Uint64

	// fresh, if set, gates serving (Postgres: see above); headTTL, if
	// positive, bounds how long a head pointer is served.
	fresh   func() bool
	headTTL time.Duration

	mu    sync.Mutex
	revs  map[string]revEntry
	heads map[string]headEntry
	bytes int
}

type revEntry struct {
	meta uint64
	doc  []byte
}

type headEntry struct {
	meta, ns uint64
	head     Head
	at       time.Time
}

// Bounds on what is kept; past them the maps start over.
const (
	maxReadCacheEntries = 1 << 16
	maxReadCacheBytes   = 64 << 20
)

// gens is a pair of counter values loaded before a transaction, and when.
type gens struct {
	meta, ns uint64
	at       time.Time
}

func (g gens) stable() bool { return g.meta%2 == 0 && g.ns%2 == 0 }

func (c *readCache) nsGen(name string) *atomic.Uint64 {
	if v, ok := c.ns.Load(name); ok {
		return v.(*atomic.Uint64)
	}
	v, _ := c.ns.LoadOrStore(name, new(atomic.Uint64))
	return v.(*atomic.Uint64)
}

func (c *readCache) load(ns string) gens {
	g := gens{meta: c.meta.Load(), ns: c.nsGen(ns).Load()}
	if c.headTTL > 0 {
		g.at = time.Now()
	}
	return g
}

func revKey(ns, name, id string) string { return ns + "\x00" + name + "\x00" + id }
func headKey(ns, name string) string    { return ns + "\x00" + name }

func (c *readCache) serving() bool { return c.fresh == nil || c.fresh() }

func (c *readCache) rev(ns, name, id string) []byte {
	if !c.serving() {
		return nil
	}
	c.mu.Lock()
	e, ok := c.revs[revKey(ns, name, id)]
	c.mu.Unlock()
	if !ok || e.meta != c.meta.Load() {
		return nil
	}
	return e.doc
}

func (c *readCache) head(ns, name string) (Head, bool) {
	if !c.serving() {
		return Head{}, false
	}
	c.mu.Lock()
	e, ok := c.heads[headKey(ns, name)]
	c.mu.Unlock()
	if !ok || e.meta != c.meta.Load() || e.ns != c.nsGen(ns).Load() {
		return Head{}, false
	}
	if c.headTTL > 0 && time.Since(e.at) > c.headTTL {
		return Head{}, false
	}
	return e.head, true
}

func (c *readCache) putRev(g gens, ns, name, id string, doc []byte) {
	if !g.stable() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.room(len(doc))
	if c.revs == nil {
		c.revs = map[string]revEntry{}
	}
	c.revs[revKey(ns, name, id)] = revEntry{meta: g.meta, doc: doc}
	c.bytes += len(doc)
}

func (c *readCache) putHead(g gens, ns, name string, h Head) {
	if !g.stable() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.room(0)
	if c.heads == nil {
		c.heads = map[string]headEntry{}
	}
	c.heads[headKey(ns, name)] = headEntry{meta: g.meta, ns: g.ns, head: h, at: g.at}
}

// room starts over when an entry of n bytes would exceed the bounds.
func (c *readCache) room(n int) {
	if len(c.revs)+len(c.heads) >= maxReadCacheEntries || c.bytes+n > maxReadCacheBytes {
		c.revs, c.heads, c.bytes = nil, nil, 0
	}
}

// begin and bump bracket a write transaction's commit: begin before
// committing, bump after the commit (or its failure). The tailer moves the
// counters for a commit it sees with see.
func (c *readCache) begin(inv invalidation) { c.add(inv, 1) }
func (c *readCache) bump(inv invalidation)  { c.add(inv, 1) }
func (c *readCache) see(inv invalidation)   { c.add(inv, 2) }

func (c *readCache) add(inv invalidation, n uint64) {
	if inv.meta {
		c.meta.Add(n)
	}
	for _, name := range inv.nss {
		c.nsGen(name).Add(n)
	}
}
