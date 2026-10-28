package janitor

import (
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
)

// The grants read from successors' /grants (§F.6, §8.5) are bounded: past
// seenCap the least recently used one is dropped, which only keeps a
// branch for a manual purge, so a long-running janitor doesn't grow with
// every grant it ever checked.
func TestV074SeenGrantsBounded(t *testing.T) {
	j := New(nil, Options{})
	if j.seenCap != maxSeen {
		t.Fatalf("seenCap %d", j.seenCap)
	}
	j.seenCap = 2
	g := map[string]*grant.Grant{"a": {}, "b": {}, "c": {}}
	j.remember("r7-b", "a", g["a"])
	j.remember("r7-b", "b", g["b"])
	if got, ok := j.recalled("r7-b", "a"); !ok || got != g["a"] {
		t.Fatal("a not recalled")
	}
	// a was used last, so c drops b.
	j.remember("r8-b", "c", g["c"])
	if _, ok := j.recalled("r7-b", "b"); ok {
		t.Fatal("b kept past the bound")
	}
	for _, k := range []seenKey{{"r7-b", "a"}, {"r8-b", "c"}} {
		if got, ok := j.recalled(k.ns, k.gid); !ok || got != g[k.gid] {
			t.Fatalf("%v not recalled", k)
		}
	}
	if len(j.seen) != 2 || j.order.Len() != 2 {
		t.Fatalf("%d grants, %d in order", len(j.seen), j.order.Len())
	}
	// Remembering one again replaces it without growing.
	j.remember("r8-b", "c", g["a"])
	if got, _ := j.recalled("r8-b", "c"); got != g["a"] || j.order.Len() != 2 {
		t.Fatalf("replaced: %p, %d in order", got, j.order.Len())
	}
}
