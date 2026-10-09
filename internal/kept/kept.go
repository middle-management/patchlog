// Package kept keeps the results a derived service computed past their
// checkpoint (§A.4 "Bounded redirects", §B.5). Such a service holds current
// state only, so it can compute a result only at its current checkpoint;
// under a steady write rate the checkpoint often moves between a redirect
// to /at/{current} and the reader following it, which made readers chase
// it. So every result computed is kept, under its canonical URL, for For:
// the at a redirect names is answered 200 from it however far the
// checkpoint moves meanwhile (as §B.5 has a service answer an at "if that
// exact result was stored"). Results are immutable per URL, so keeping them
// never serves newer content under an older at. They are kept in memory
// only, up to a size, oldest out first; a purge drops those carrying a
// cache tag it purges, as caches drop them.
package kept

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
)

// For is how long a Store keeps a result.
const For = time.Minute

// Store keeps results in memory. Its purges are per scope: a namespace,
// or a catalog for the listings over it and the namespaces it trusts.
type Store struct {
	now func() time.Time

	mu      sync.Mutex
	m       map[string]*list.Element // URL → *entry
	order   *list.List               // oldest first
	size    int
	gens    map[string]uint64  // scope → purges applied so far
	purges  map[string][]purge // scope → its purges of the last For, oldest first
	maxSize int
}

// purge is a purge applied to a scope, with the tags it purged: Put checks
// the results read before it against them, for For.
type purge struct {
	exp  time.Time
	tags []string
}

type entry struct {
	url, scope string
	tags       map[string]bool
	exp        time.Time
	bound      bool // a sealed result, bound to its URL (§E.2.6)
	st         derived.Stored
}

// New returns an empty Store on the clock now that keeps at most maxBytes.
func New(now func() time.Time, maxBytes int) *Store {
	return &Store{now: now, m: map[string]*list.Element{}, order: list.New(), gens: map[string]uint64{}, purges: map[string][]purge{}, maxSize: maxBytes}
}

// Generation is the number of purges applied to scope so far. A result is
// kept unless a purge applied between the generation taken before its read
// transaction and Put purged one of its tags, so no result read before a
// purge outlives it if the purge would have dropped it, kept; results that
// show none of what is purged are kept however often scope is purged.
func (k *Store) Generation(scope string) uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.gens[scope]
}

// Get returns the result kept for url, and whether it is bound to url.
func (k *Store) Get(url string) (derived.Stored, bool, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expire()
	el, ok := k.m[url]
	if !ok {
		return derived.Stored{}, false, false
	}
	e := el.Value.(*entry)
	return e.st, e.bound, true
}

// Put keeps st as url's result unless one is kept already, or a purge of
// scope since generation gen purged one of st's tags, and returns the
// result kept for url (st if none) and whether one is: the first writer
// wins, so every reader of url gets the same bytes.
func (k *Store) Put(url, scope string, gen uint64, bound bool, st derived.Stored) (derived.Stored, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expire()
	if el, ok := k.m[url]; ok {
		return el.Value.(*entry).st, true
	}
	tags := splitTags(st.Tags)
	if k.purgedSince(scope, gen, tags) {
		return st, false
	}
	e := &entry{url: url, scope: scope, tags: tags, exp: k.now().Add(For), bound: bound, st: st}
	k.m[url] = k.order.PushBack(e)
	k.size += e.bytes()
	for k.size > k.maxSize {
		k.remove(k.order.Front())
	}
	return st, k.m[url] != nil
}

// Purge drops scope's results carrying any of tags, after the apply that
// purges them commits and before its checkpoint is published, and records
// the purge for Put.
func (k *Store) Purge(scope string, tags []string) {
	if len(tags) == 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	ps := k.purges[scope]
	for len(ps) > 0 && !now.Before(ps[0].exp) {
		ps = ps[1:]
	}
	k.purges[scope] = append(ps, purge{exp: now.Add(For), tags: tags})
	k.gens[scope]++
	for el := k.order.Front(); el != nil; {
		next := el.Next()
		e := el.Value.(*entry)
		for _, t := range tags {
			if e.scope == scope && e.tags[t] {
				k.remove(el)
				break
			}
		}
		el = next
	}
}

// purgedSince reports whether a purge of scope since generation gen purged
// one of tags, or may have: one recorded no longer (For) is taken to.
func (k *Store) purgedSince(scope string, gen uint64, tags map[string]bool) bool {
	n := k.gens[scope] - gen // purges since gen, the last n
	ps := k.purges[scope]
	if n > uint64(len(ps)) {
		return true
	}
	for _, p := range ps[uint64(len(ps))-n:] {
		for _, t := range p.tags {
			if tags[t] {
				return true
			}
		}
	}
	return false
}

// expire drops the results kept longer than For (the oldest first).
func (k *Store) expire() {
	now := k.now()
	for el := k.order.Front(); el != nil && !now.Before(el.Value.(*entry).exp); el = k.order.Front() {
		k.remove(el)
	}
}

func (k *Store) remove(el *list.Element) {
	e := k.order.Remove(el).(*entry)
	delete(k.m, e.url)
	k.size -= e.bytes()
}

func (e *entry) bytes() int { return len(e.url) + len(e.st.Body) + len(e.st.Tags) }

func splitTags(tags string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Split(tags, ",") {
		if t != "" {
			out[t] = true
		}
	}
	return out
}
