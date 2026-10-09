package core

import "sync"

// Open referrers, memoised.
//
// Whether a referrer in a namespace schemaReads lists that is open to
// everyone opens a schema revision (§6.1, schemaReadsRev) is the same for
// every request, anonymous ones included, and deciding it reads every
// revision of those namespaces. So the answer is kept by revision path,
// and served while what it was decided from holds:
//
//   - the read cache's meta counter (readcache.go), loaded before the
//     transaction began: it moves with configuration (schemaReads, which
//     namespaces are open), namespaces made and purged, and resources
//     purged, pruned or restored;
//   - the log heads of the listed namespaces open to everyone that it
//     looked at, read in the transaction: they move with any other write
//     to them.
//
// As the read cache's answers, none is served while the tailer is late
// (Postgres).
type openRefs struct {
	mu    sync.Mutex
	m     map[string]openRefsEntry
	heads int // the total number of heads in m
}

type openRefsEntry struct {
	meta  uint64
	heads []nsHead
	ok    bool
}

// nsHead is a namespace's log head.
type nsHead struct{ ns, seq int64 }

// Past either bound the memo starts over.
const (
	maxOpenRefs      = 1 << 14
	maxOpenRefsHeads = 1 << 16
)

// openRefers reports whether a referrer in a namespace n's schemaReads
// lists that is open to everyone opens path, to every request (§6.1). g
// holds the read cache's counters, loaded before the transaction began.
func (t *tx) openRefers(n *nsRow, cfg *Config, path string, g gens, closures map[string]bool) bool {
	if m, ok := t.e.rc.refsFor(g, path); ok && t.headsHold(m.heads) {
		return m.ok
	}
	m := openRefsEntry{meta: g.meta}
	for _, l := range t.schemaReadsListed(n, cfg) {
		if !openToAll(t.config(l.configSeq)) {
			continue
		}
		m.heads = append(m.heads, nsHead{l.id, l.headSeq.Int64})
		if m.ok = t.refersIn(l, nil, path, closures); m.ok {
			break
		}
	}
	t.e.rc.putRefs(g, path, m)
	return m.ok
}

// headsHold reports whether the namespaces' log heads are still those.
func (t *tx) headsHold(heads []nsHead) bool {
	for _, h := range heads {
		if t.nsByID(h.ns).headSeq.Int64 != h.seq {
			return false
		}
	}
	return true
}

// refsFor returns path's answer if it was decided under g's meta value,
// which still holds.
func (c *readCache) refsFor(g gens, path string) (openRefsEntry, bool) {
	if !c.serving() {
		return openRefsEntry{}, false
	}
	c.refs.mu.Lock()
	m, ok := c.refs.m[path]
	c.refs.mu.Unlock()
	return m, ok && m.meta == g.meta && m.meta == c.meta.Load()
}

// putRefs keeps path's answer, decided in a transaction begun after g was
// loaded, if no commit that changes it beyond the heads it names may have
// happened since (putRev).
func (c *readCache) putRefs(g gens, path string, m openRefsEntry) {
	if !g.stable() || !c.unchanged(g, "") || len(m.heads) > maxOpenRefsHeads {
		return
	}
	c.refs.mu.Lock()
	defer c.refs.mu.Unlock()
	if old, ok := c.refs.m[path]; ok {
		c.refs.heads -= len(old.heads)
	}
	if c.refs.m == nil || len(c.refs.m) >= maxOpenRefs || c.refs.heads+len(m.heads) > maxOpenRefsHeads {
		c.refs.m, c.refs.heads = map[string]openRefsEntry{}, 0
	}
	c.refs.m[path] = m
	c.refs.heads += len(m.heads)
}
