package follow_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
)

// §10 Catch up, page by page (§7.1 Paging): a follower more than a page
// behind delivers each page as it arrives, its checkpoint advancing with
// each, and the batches chain as one range.
func TestCatchUpPaged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	id := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0})).ID
	for i := 1; i < 6; i++ {
		id = must(c.Append(ctx, "main", "a", id, rep("/n", i))).ID
	}
	cp := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp}
	r := start(follow.New(c, "main", cp, rec, follow.WithMaxUnits(0)))
	waitFor(t, "catch-up", checkpointIs(t, cp, c, "main"))
	r.stop(t)
	bs := rec.snapshot()
	prev, n := "", 0
	for i, b := range bs {
		if len(b.Units) > 2 || b.From != prev {
			t.Fatalf("batch %d: %d units from %q, want at most a page from %q", i, len(b.Units), b.From, prev)
		}
		for _, u := range b.Units {
			if u.Entry.Prev != prev {
				t.Fatalf("entry %s doesn't follow %s", u.Entry.ID, prev)
			}
			prev = u.Entry.ID
			n++
		}
		if b.NewCheckpoint != prev {
			t.Fatalf("batch %d: checkpoint %s, last entry %s", i, b.NewCheckpoint, prev)
		}
	}
	if n != 7 || len(bs) != 4 {
		t.Fatalf("%d entries in %d batches", n, len(bs))
	}
	var units []follow.Unit
	for _, b := range bs {
		units = append(units, b.Units...)
	}
	if co := follow.Coalesce(units); len(co.Changes) != 1 || co.Changes[0].Target != id {
		t.Fatalf("coalesced %+v", co)
	}
}

// The follower's flows with a log page size of 2: catch-up ranges, branch
// bootstraps (first page only) and snapshot starts all read paged logs.
//
// Paged sets the environment, so these flows run serially and call the
// tests' bodies, not the parallel TestX.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"long-poll": func(t *testing.T) { testFollow(t) }, "sse": func(t *testing.T) { testFollow(t, follow.WithSSE()) },
		"branches": testBranchDiscovery,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
