package index

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
)

// Kept results (B9). The index holds current state only (§A.3), so a result
// can be computed only at the current checkpoint; under a steady write rate
// the checkpoint often moves between a redirect to /at/{current} and the
// reader following it, which made readers chase it. So every result computed
// is kept, under its canonical URL, for keepFor: the at a redirect names is
// answered 200 from it however far the checkpoint moves meanwhile (§A.4, as
// §B.5 has the tree service answer an at "if that exact result was stored").
// Results are immutable per URL, so keeping them never serves newer content
// under an older at. They are kept in memory only, at most keepBytes, oldest
// out first; a purge drops those carrying a cache tag it purges, as caches
// drop them.
const (
	keepFor   = time.Minute
	keepBytes = 64 << 20
)

type kept struct {
	now func() time.Time

	mu      sync.Mutex
	m       map[string]*list.Element // URL → *keptEntry
	order   *list.List               // oldest first
	size    int
	purges  map[string]uint64 // ns → purges applied so far
	maxSize int
}

type keptEntry struct {
	url, ns string
	tags    map[string]bool
	exp     time.Time
	bound   bool // a sealed result, bound to its URL (§E.2.6)
	st      derived.Stored
}

func newKept(now func() time.Time) *kept {
	return &kept{now: now, m: map[string]*list.Element{}, order: list.New(), purges: map[string]uint64{}, maxSize: keepBytes}
}

// generation is the number of purges applied to ns so far. A result is
// kept only if it is unchanged from before the result's read transaction
// until put, so no result read before a purge outlives it.
func (k *kept) generation(ns string) uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.purges[ns]
}

// get returns the result kept for url, and whether it is bound to url.
func (k *kept) get(url string) (derived.Stored, bool, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expire()
	el, ok := k.m[url]
	if !ok {
		return derived.Stored{}, false, false
	}
	e := el.Value.(*keptEntry)
	return e.st, e.bound, true
}

// put keeps st as url's result unless one is kept already, or ns had a purge
// since generation gen, and returns the result kept for url (st if none):
// the first writer wins, so every reader of url gets the same bytes.
func (k *kept) put(url, ns string, gen uint64, bound bool, st derived.Stored) derived.Stored {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expire()
	if el, ok := k.m[url]; ok {
		return el.Value.(*keptEntry).st
	}
	if k.purges[ns] != gen {
		return st
	}
	e := &keptEntry{url: url, ns: ns, tags: splitTags(st.Tags), exp: k.now().Add(keepFor), bound: bound, st: st}
	k.m[url] = k.order.PushBack(e)
	k.size += e.bytes()
	for k.size > k.maxSize {
		k.remove(k.order.Front())
	}
	return st
}

// purge drops ns's results carrying any of tags, after the apply that
// purges them commits and before its checkpoint is published.
func (k *kept) purge(ns string, tags []string) {
	if len(tags) == 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.purges[ns]++
	for el := k.order.Front(); el != nil; {
		next := el.Next()
		e := el.Value.(*keptEntry)
		for _, t := range tags {
			if e.ns == ns && e.tags[t] {
				k.remove(el)
				break
			}
		}
		el = next
	}
}

// expire drops the results kept longer than keepFor (the oldest first).
func (k *kept) expire() {
	now := k.now()
	for el := k.order.Front(); el != nil && !now.Before(el.Value.(*keptEntry).exp); el = k.order.Front() {
		k.remove(el)
	}
}

func (k *kept) remove(el *list.Element) {
	e := k.order.Remove(el).(*keptEntry)
	delete(k.m, e.url)
	k.size -= e.bytes()
}

func (e *keptEntry) bytes() int { return len(e.url) + len(e.st.Body) + len(e.st.Tags) }

func splitTags(tags string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Split(tags, ",") {
		if t != "" {
			out[t] = true
		}
	}
	return out
}
