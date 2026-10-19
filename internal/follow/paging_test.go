package follow_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
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

// WithOnCatchUp reports the head a catch-up replays to once it is read,
// before any page is delivered, and again once the checkpoint reaches it,
// after the last page: a checkpoint alone (the first page's) isn't caught
// up (§10 Catch up).
func TestCatchUpReported(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	id := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0})).ID
	for i := 1; i < 6; i++ {
		id = must(c.Append(ctx, "main", "a", id, rep("/n", i))).ID
	}
	head := must(c.NSHead(ctx, "main")).ID
	cp := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp}
	var mu sync.Mutex
	var got []string
	r := start(follow.New(c, "main", cp, rec, follow.WithMaxUnits(0), follow.WithOnCatchUp(func(ns, h string, done bool) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, fmt.Sprintf("%s %s %v after %d", ns, h, done, len(rec.snapshot())))
	})))
	waitFor(t, "catch-up", checkpointIs(t, cp, c, "main"))
	waitFor(t, "the catch-up reported", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
	r.stop(t)
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"main " + head + " false after 0", "main " + head + " true after 4"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reported %q, want %q", got, want)
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

// pages is a Handler that records batches, saving each with SaveBatch,
// and the checkpoint the store reports after each; stop, if set, is
// called after the n-th batch.
type pages struct {
	mu      sync.Mutex
	h       follow.Handler
	cp      follow.Checkpoint
	batches []*follow.Batch
	after   []string // the checkpoint after each batch
	n       int
	stop    func()
}

func (p *pages) Apply(ctx context.Context, b *follow.Batch) error {
	if err := p.h.Apply(ctx, b); err != nil {
		return err
	}
	cp, _ := p.cp.Load(ctx, b.Origin, b.NS)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.batches = append(p.batches, b)
	p.after = append(p.after, cp)
	if p.stop != nil && len(p.batches) == p.n {
		p.stop()
	}
	return nil
}

func (p *pages) snapshot() ([]*follow.Batch, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*follow.Batch(nil), p.batches...), append([]string(nil), p.after...)
}

func pagedNS(t *testing.T, names ...string) *client.Client {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	for _, n := range names {
		must(c.CreateDoc(ctx, "main", n, map[string]any{"n": n}))
	}
	return c
}

// A snapshot bootstrap whose /heads listing spans pages (§7.1 Paging) is
// delivered a page per batch, all at the namespace's head: the first
// replaces what the consumer holds, each until the last is Partial, and
// the checkpoint is recorded only with the last.
func TestSnapshotPaged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := pagedNS(t, "a", "b", "c", "d", "e")
	head := must(c.NSHead(ctx, "main")).ID
	cp := &follow.MemoryCheckpoints{}
	p := &pages{h: &recorder{cp: cp}, cp: cp}
	r := start(follow.New(c, "main", cp, p, follow.WithSnapshot(), follow.WithMaxUnits(0)))
	waitFor(t, "snapshot", checkpointIs(t, cp, c, "main"))
	r.stop(t)
	bs, after := p.snapshot()
	if len(bs) != 3 {
		t.Fatalf("%d batches, want 3 pages", len(bs))
	}
	var names []string
	prev := ""
	for i, b := range bs {
		last := i == len(bs)-1
		if !b.Snapshot || b.NewCheckpoint != head || b.From != "" || b.After != prev || b.Partial() == last ||
			b.Replaces() != (i == 0) || len(b.Units) > 2 {
			t.Fatalf("batch %d: %+v", i, b)
		}
		if want := map[bool]string{true: head}[last]; after[i] != want {
			t.Fatalf("checkpoint after batch %d: %q, want %q", i, after[i], want)
		}
		for _, u := range b.Units {
			names = append(names, u.Entry.Resource)
		}
		prev = b.More
	}
	if fmt.Sprint(names) != "[a b c d e]" {
		t.Fatalf("listed %v", names)
	}
	if at, next, _ := cp.LoadBootstrap(ctx, clienttest.Origin, "main"); at != "" || next != "" {
		t.Fatalf("bootstrap left recorded: %q %q", at, next)
	}
}

// A snapshot bootstrap interrupted after a page resumes after the last
// page recorded (SQLCheckpoints.SaveBatch, Resumer), not from the first,
// and once complete leaves no progress behind.
func TestSnapshotResumes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := pagedNS(t, "a", "b", "c", "d", "e")
	head := must(c.NSHead(ctx, "main")).ID
	db := must(sql.Open("sqlite", ":memory:"))
	db.SetMaxOpenConns(1)
	defer db.Close()
	cp := follow.SQLCheckpoints{DB: db}
	if err := cp.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE docs (name TEXT PRIMARY KEY, rev TEXT)`); err != nil {
		t.Fatal(err)
	}
	h := &sqlHandler{db: db, cp: cp}

	rctx, cancel := context.WithCancel(ctx)
	p := &pages{h: h, cp: cp, n: 1, stop: cancel}
	if err := follow.New(c, "main", cp, p, follow.WithSnapshot(), follow.WithMaxUnits(0)).Run(rctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted run: %v", err)
	}
	at, next, err := cp.LoadBootstrap(ctx, clienttest.Origin, "main")
	if err != nil || at != head || next == "" {
		t.Fatalf("progress %q %q %v", at, next, err)
	}
	if got, _ := cp.Load(ctx, clienttest.Origin, "main"); got != "" {
		t.Fatalf("checkpoint %q after a partial snapshot", got)
	}

	p = &pages{h: h, cp: cp}
	r := start(follow.New(c, "main", cp, p, follow.WithSnapshot(), follow.WithMaxUnits(0)))
	waitFor(t, "resumed snapshot", checkpointIs(t, cp, c, "main"))
	r.stop(t)
	bs, _ := p.snapshot()
	if len(bs) != 2 || bs[0].After != next || bs[0].Replaces() || bs[1].Partial() {
		t.Fatalf("resumed batches %+v", bs)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM docs`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("%d docs %v", n, err)
	}
	if at, next, _ := cp.LoadBootstrap(ctx, clienttest.Origin, "main"); at != "" || next != "" {
		t.Fatalf("bootstrap left recorded: %q %q", at, next)
	}
}

// Progress the origin no longer lists (here, a position that isn't in
// the namespace's log) is dropped, and the snapshot starts again from its
// first page.
func TestSnapshotResumeStartsAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := pagedNS(t, "a", "b", "c")
	must(c.CreateNamespace(ctx, "other", map[string]any{"read": "public", "x-other": true}))
	elsewhere := must(c.NSHead(ctx, "other")).ID
	cp := &follow.MemoryCheckpoints{}
	cp.SaveBatch(clienttest.Origin, "main", &follow.Batch{Snapshot: true, NewCheckpoint: elsewhere, More: "a"})
	p := &pages{h: &recorder{cp: cp}, cp: cp}
	r := start(follow.New(c, "main", cp, p, follow.WithSnapshot(), follow.WithMaxUnits(0)))
	waitFor(t, "snapshot", checkpointIs(t, cp, c, "main"))
	r.stop(t)
	bs, _ := p.snapshot()
	if len(bs) != 2 || !bs[0].Replaces() || bs[1].Partial() {
		for _, b := range bs {
			t.Logf("%+v", *b)
		}
		t.Fatalf("%d batches", len(bs))
	}
}
