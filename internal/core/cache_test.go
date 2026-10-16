package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// The document cache is bounded by bytes: large documents don't pile up
// past it, whatever their number.
func TestDocCacheBytes(t *testing.T) {
	c := newDocCache(1 << 20)
	for i := 0; i < 100; i++ {
		var id ids.ID
		copy(id[:], fmt.Sprintf("%020d", i))
		c.put(id, make([]byte, 100<<10))
	}
	if c.lru.Bytes() > 1<<20 || c.lru.Len() != 10 {
		t.Fatalf("%d documents, %d bytes", c.lru.Len(), c.lru.Bytes())
	}
}

// The read cache evicts some entries when full rather than all of them,
// and counts a replaced revision once.
func TestReadCacheRoom(t *testing.T) {
	c := &readCache{maxBytes: 1 << 20}
	g := c.load("n")
	for i := 0; i < 50; i++ {
		c.putRev(g, "n", fmt.Sprint(i), "r", make([]byte, 100<<10), true)
	}
	if c.bytes > 1<<20 || len(c.revs) == 0 || len(c.revs) < 5 {
		t.Fatalf("%d revisions, %d bytes", len(c.revs), c.bytes)
	}
	c.revs, c.bytes = nil, 0
	for i := 0; i < 3; i++ {
		c.putRev(g, "n", "a", "r", make([]byte, 1000), true)
	}
	if c.bytes != 1000 || len(c.revs) != 1 {
		t.Fatalf("a replaced revision: %d revisions, %d bytes", len(c.revs), c.bytes)
	}
	c.putRev(g, "n", "huge", "r", make([]byte, 300<<10), true)
	if _, ok := c.revs[revKey("n", "huge", "r")]; ok {
		t.Fatal("a revision over a quarter of the bytes is kept")
	}
}

// The rate limiter drops buckets that have refilled to their burst, which
// are the same as new ones, and keeps those still refilling.
func TestRateLimiterSweep(t *testing.T) {
	rl := newRateLimiter()
	now := time.Unix(1e9, 0)
	r := Rate{Rate: 10, Burst: 20}
	for i := 0; i < sweepAbove+10; i++ {
		if _, _, ok := rl.admit(now, []draw{{key: fmt.Sprint(i), rate: r, cost: 20}}); !ok {
			t.Fatal("refused")
		}
	}
	// One bucket is drawn deep into debt (a large batch), so it hasn't
	// refilled when the sweep runs; the rest have.
	later := now.Add(2 * time.Second)
	rl.admit(later, []draw{{key: "0", rate: r, cost: 2000}})
	rl.admit(later.Add(time.Minute+time.Second), []draw{{key: "new", rate: r, cost: 1}})
	if _, ok := rl.b["0"]; !ok || len(rl.b) != 2 {
		t.Fatalf("%d buckets after a sweep, the indebted one kept: %v", len(rl.b), ok)
	}
	// A dropped bucket comes back full, as if never dropped.
	if _, _, ok := rl.admit(later.Add(time.Minute+time.Second), []draw{{key: "5", rate: r, cost: 20}}); !ok {
		t.Fatal("a swept bucket isn't full")
	}
}
