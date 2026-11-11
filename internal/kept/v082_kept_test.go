package kept

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
)

// SVC-13 (SERVICES §A.1, §B.5): PurgedSince tells a caller that doesn't
// keep a result, such as a listing for one reader, what PutOutcome tells
// one that does: whether a purge of the scope since the generation taken
// before the result was read purged one of its tags, or may have.
func TestV082PurgedSince(t *testing.T) {
	now := time.Unix(1000, 0)
	k := New(func() time.Time { return now }, 1<<20)
	gen := k.Generation("cat")
	tags := []string{"ns:cat", "ns:matches", "r:cat/root", ""}
	if k.PurgedSince("cat", gen, tags) {
		t.Fatal("purged with no purge")
	}
	// A purge of something the result doesn't show, or of another scope.
	k.Purge("cat", []string{"r:cat/other"})
	k.Purge("other", []string{"ns:matches"})
	if k.PurgedSince("cat", gen, tags) {
		t.Error("a purge of another resource, or another scope, counts")
	}
	// An empty tag matches nothing.
	k.Purge("cat", []string{""})
	if k.PurgedSince("cat", gen, tags) {
		t.Error("an empty tag counts")
	}
	k.Purge("cat", []string{"ns:matches"})
	if !k.PurgedSince("cat", gen, tags) {
		t.Error("a purge of one of its tags since gen doesn't count")
	}
	// Read after that purge: not purged since.
	if k.PurgedSince("cat", k.Generation("cat"), tags) {
		t.Error("a purge before gen counts")
	}
	// It agrees with PutOutcome.
	if _, o := k.PutOutcome("/u", "cat", gen, false, derived.Stored{Body: []byte("x"), JSON: true, Tags: "ns:cat,ns:matches,r:cat/root"}); o != PurgedSince {
		t.Errorf("PutOutcome %v, want PurgedSince", o)
	}
	// A purge recorded no longer (For) is taken to have purged it.
	gen = k.Generation("cat")
	k.Purge("cat", []string{"r:cat/other"})
	now = now.Add(For + time.Second)
	k.Purge("cat", []string{"r:cat/another"})
	if !k.PurgedSince("cat", gen, tags) {
		t.Error("a purge since gen that is no longer recorded doesn't count")
	}
}
