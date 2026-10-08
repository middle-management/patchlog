package follow_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func rep(path string, v any) []any {
	return []any{map[string]any{"op": "replace", "path": path, "value": v}}
}

// recorder is a Handler that records batches and saves memory checkpoints.
type recorder struct {
	mu      sync.Mutex
	cp      *follow.MemoryCheckpoints
	batches []*follow.Batch
	fail    int // fail this many Apply calls first
	calls   int
}

func (r *recorder) Apply(_ context.Context, b *follow.Batch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail > 0 {
		r.fail--
		return errors.New("transient")
	}
	r.batches = append(r.batches, b)
	r.cp.Save(b.Origin, b.NS, b.NewCheckpoint)
	return nil
}

func (r *recorder) snapshot() []*follow.Batch {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*follow.Batch(nil), r.batches...)
}

func (r *recorder) kinds(ns string) []string {
	var out []string
	for _, b := range r.snapshot() {
		if b.NS != ns {
			continue
		}
		for _, u := range b.Units {
			out = append(out, u.Entry.Kind)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func checkpointIs(t *testing.T, cp follow.Checkpoint, c *client.Client, ns string) func() bool {
	return func() bool {
		h, err := c.NSHead(context.Background(), ns)
		if err != nil {
			return false
		}
		got, _ := cp.Load(context.Background(), clienttest.Origin, ns)
		return got == h.ID
	}
}

type run struct {
	cancel context.CancelFunc
	done   chan error
}

func start(f *follow.Follower) *run {
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- f.Run(ctx) }()
	return r
}

func (r *run) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func setup(t *testing.T) (*clienttest.Server, *client.Client) {
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(context.Background(), "main", map[string]any{"read": "public"}))
	return s, c
}

func testFollow(t *testing.T, opts ...follow.Option) {
	ctx := context.Background()
	_, c := setup(t)
	a := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	must(c.Append(ctx, "main", "a", a.ID, rep("/n", 1)))

	cp := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp, fail: 2}
	opts = append(opts, follow.WithBackoff(time.Millisecond, 10*time.Millisecond))
	r := start(follow.New(c, "main", cp, rec, opts...))
	waitFor(t, "catch-up", checkpointIs(t, cp, c, "main"))
	if got := rec.kinds("main"); fmt.Sprint(got) != "[config head head]" {
		t.Fatalf("catch-up kinds %v", got)
	}
	rec.mu.Lock()
	calls := rec.calls
	rec.mu.Unlock()
	if calls != 5 {
		t.Fatalf("handler failures not retried: %d calls", calls)
	}
	// Live: a batch arrives as one unit.
	must(c.Batch(ctx, "main", client.BatchRequest{Items: []client.BatchItem{
		{Resource: "b", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{}))}},
		{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{}))}},
	}}, false))
	waitFor(t, "batch", checkpointIs(t, cp, c, "main"))
	bs := rec.snapshot()
	last := bs[len(bs)-1]
	if len(last.Units) != 1 || last.Units[0].Entry.Kind != "batch" || len(last.Units[0].Changes()) != 2 || last.From == "" {
		t.Fatalf("batch unit %+v", last)
	}
	r.stop(t)

	// Restart: resumes from the checkpoint, delivering only new entries.
	n := len(rec.snapshot())
	cr := must(c.PatchConfig(ctx, "main", must(c.NSHead(ctx, "main")).Config, []any{map[string]any{"op": "add", "path": "/x-v", "value": 1}}))
	r = start(follow.New(c, "main", cp, rec, opts...))
	waitFor(t, "config", checkpointIs(t, cp, c, "main"))
	bs = rec.snapshot()[n:]
	if len(bs) != 1 || bs[0].Units[0].Entry.Kind != "config" || bs[0].Units[0].Config == nil ||
		bs[0].Units[0].Config.Value["x-v"] != 1.0 || bs[0].NewCheckpoint != cr.NSID {
		t.Fatalf("after restart %+v", bs)
	}
	r.stop(t)
}

func TestFollowLongPoll(t *testing.T) { t.Parallel(); testFollow(t) }
func TestFollowSSE(t *testing.T)      { t.Parallel(); testFollow(t, follow.WithSSE()) }

func TestSnapshotBootstrapAndRange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, c := setup(t)
	a := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	must(c.Append(ctx, "main", "a", a.ID, rep("/n", 1)))
	b := must(c.CreateDoc(ctx, "main", "b", map[string]any{}))
	must(c.Delete(ctx, "main", "b", b.ID))

	cp := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp}
	r := start(follow.New(c, "main", cp, rec, follow.WithSnapshot(), follow.WithMaxUnits(0)))
	waitFor(t, "snapshot", checkpointIs(t, cp, c, "main"))
	bs := rec.snapshot()
	if len(bs) != 1 || !bs[0].Snapshot || len(bs[0].Units) != 2 || !bs[0].Units[0].Synthetic ||
		bs[0].Units[0].Entry.Resource != "a" || bs[0].Units[1].Entry.Kind != "tombstone" {
		t.Fatalf("snapshot %+v", bs)
	}
	// Range delivery: several entries in one Apply, coalesced by the handler.
	h := must(c.Head(ctx, "main", "a"))
	id := h.ID
	for i := 2; i < 5; i++ {
		id = must(c.Append(ctx, "main", "a", id, rep("/n", i))).ID
	}
	// Wait until everything arrived (possibly over several pages).
	waitFor(t, "range", checkpointIs(t, cp, c, "main"))
	var units []follow.Unit
	for _, b := range rec.snapshot()[1:] {
		units = append(units, b.Units...)
	}
	co := follow.Coalesce(units)
	if len(co.Changes) != 1 || co.Changes[0].Target != id {
		t.Fatalf("coalesced %+v", co)
	}
	r.stop(t)
}

func TestBranchDiscovery(t *testing.T) { t.Parallel(); testBranchDiscovery(t) }

func testBranchDiscovery(t *testing.T) {
	ctx := context.Background()
	_, c := setup(t)
	must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	// A branch that exists before the follower starts.
	must(c.CreateBranch(ctx, "main", client.BranchRequest{Name: "old"}))

	cp := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp}
	var smu sync.Mutex
	var states []follow.State
	r := start(follow.New(c, "main", cp, rec, follow.WithBranches(),
		follow.WithOnState(func(s follow.State) { smu.Lock(); states = append(states, s); smu.Unlock() })))
	waitFor(t, "main", checkpointIs(t, cp, c, "main"))
	waitFor(t, "old", checkpointIs(t, cp, c, "old"))

	// A branch created while following, with a write of its own.
	br := must(c.CreateBranch(ctx, "main", client.BranchRequest{Name: "rel"}))
	waitFor(t, "rel", checkpointIs(t, cp, c, "rel"))
	var boot *follow.Batch
	for _, b := range rec.snapshot() {
		if b.NS == "rel" {
			boot = b
			break
		}
	}
	first := must(client.FirstBranchEntry(br.Config))
	if boot == nil || !boot.Snapshot || boot.NewCheckpoint != first || boot.Units[0].Entry.Kind != "config" ||
		boot.Units[0].Config == nil || len(boot.Units) != 2 || boot.Units[1].Entry.Resource != "a" || !boot.Units[1].Synthetic {
		t.Fatalf("branch bootstrap %+v", boot)
	}
	h := must(c.Head(ctx, "rel", "a"))
	must(c.Append(ctx, "rel", "a", h.ID, rep("/n", 7)))
	waitFor(t, "rel write", checkpointIs(t, cp, c, "rel"))
	// Branch of a branch.
	must(c.CreateBranch(ctx, "rel", client.BranchRequest{Name: "rel2"}))
	waitFor(t, "rel2", checkpointIs(t, cp, c, "rel2"))

	// Freeze and purge rel2: reported as states.
	bh := must(c.NSHead(ctx, "rel2"))
	must(c.PatchConfig(ctx, "rel2", bh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	bh = must(c.NSHead(ctx, "rel2"))
	must(c.PurgeNamespace(ctx, "rel2", bh.ID))
	waitFor(t, "rel2 purge", checkpointIs(t, cp, c, "rel2"))
	waitFor(t, "states", func() bool {
		smu.Lock()
		defer smu.Unlock()
		var frozen, purged bool
		for _, s := range states {
			frozen = frozen || s.NS == "rel2" && s.Frozen
			purged = purged || s.NS == "rel2" && s.Purged
		}
		return frozen && purged
	})
	if k := rec.kinds("rel2"); k[len(k)-1] != "purge-ns" {
		t.Fatalf("rel2 kinds %v", k)
	}
	r.stop(t)
}

func TestRootErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, c := setup(t)
	// A checkpoint not in the chain is permanent.
	cp := &follow.MemoryCheckpoints{}
	cp.Save(clienttest.Origin, "main", "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	err := follow.New(c, "main", cp, &recorder{cp: cp}).Run(ctx)
	if !client.IsNotFound(err) {
		t.Fatalf("bad checkpoint: %v", err)
	}
	// An unknown namespace too.
	if err := follow.New(c, "nope", cp, &recorder{cp: cp}).Run(ctx); !client.IsNotFound(err) {
		t.Fatalf("unknown ns: %v", err)
	}
	// A purged root ends Run with ErrPurged.
	head := must(c.NSHead(ctx, "main"))
	must(c.PatchConfig(ctx, "main", head.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(c.PurgeNamespace(ctx, "main", must(c.NSHead(ctx, "main")).ID))
	cp2 := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp2}
	if err := follow.New(c, "main", cp2, rec).Run(ctx); !errors.Is(err, follow.ErrPurged) {
		t.Fatalf("purged: %v", err)
	}
	if k := rec.kinds("main"); fmt.Sprint(k) != "[config config purge-ns]" {
		t.Fatalf("kinds %v", k)
	}
}

// sqlHandler keeps derived rows and the checkpoint in one transaction.
type sqlHandler struct {
	db *sql.DB
	cp follow.SQLCheckpoints
}

func (h *sqlHandler) Apply(ctx context.Context, b *follow.Batch) error {
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, ch := range b.Coalesce().Changes {
		if ch.Kind == "head" {
			_, err = tx.ExecContext(ctx, `INSERT INTO docs (name, rev) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET rev = excluded.rev`, ch.Resource, ch.Target)
		} else {
			_, err = tx.ExecContext(ctx, `DELETE FROM docs WHERE name = ?`, ch.Resource)
		}
		if err != nil {
			return err
		}
	}
	if err := h.cp.Save(ctx, tx, b.Origin, b.NS, b.NewCheckpoint); err != nil {
		return err
	}
	return tx.Commit()
}

func TestSQLCheckpoints(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, c := setup(t)
	a := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
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
	r := start(follow.New(c, "main", cp, h, follow.WithMaxUnits(0)))
	waitFor(t, "sql", checkpointIs(t, cp, c, "main"))
	r.stop(t)
	a2 := must(c.Append(ctx, "main", "a", a.ID, rep("/n", 1)))
	r = start(follow.New(c, "main", cp, h))
	waitFor(t, "sql again", checkpointIs(t, cp, c, "main"))
	r.stop(t)
	var rev string
	if err := db.QueryRow(`SELECT rev FROM docs WHERE name = 'a'`).Scan(&rev); err != nil || rev != a2.ID {
		t.Fatalf("derived rev %q %v", rev, err)
	}
}

func TestCoalesce(t *testing.T) {
	t.Parallel()
	e := func(id, kind, res, target string) client.NSEntry {
		return client.NSEntry{ID: id, Kind: kind, Resource: res, Target: target}
	}
	units := []follow.Unit{
		{Entry: e("1", "head", "a", "a1")},
		{Entry: e("2", "head", "b", "b1")},
		{Entry: client.NSEntry{ID: "3", Kind: "batch", Entries: []client.NSEntry{
			{Kind: "config", Target: "c1"}, e("", "head", "a", "a2"), e("", "tombstone", "c", "c1")}}},
		{Entry: e("4", "purge", "b", "b1")},
		{Entry: e("5", "prune", "a", "a1")},
	}
	co := follow.Coalesce(units)
	got := fmt.Sprint(co.Changes)
	want := "[{a head a2 3 false} {c tombstone c1 3 false} {b purge b1 4 true}]"
	if got != want {
		t.Fatalf("changes %s\nwant    %s", got, want)
	}
	if len(co.Others) != 2 || co.Others[0].Kind != "config" || co.Others[0].ID != "3" || co.Others[1].Kind != "prune" {
		t.Fatalf("others %+v", co.Others)
	}
	co = follow.Coalesce(append(units, follow.Unit{Entry: client.NSEntry{ID: "6", Kind: "purge-ns"}}))
	if !co.PurgedNS || len(co.Changes) != 0 {
		t.Fatalf("purge-ns %+v", co)
	}
}

func TestFetchDocPruned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, c := setup(t)
	a := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	a1 := must(c.Append(ctx, "main", "a", a.ID, rep("/n", 1)))
	s.Clock.Advance(10 * time.Minute)
	a2 := must(c.Append(ctx, "main", "a", a1.ID, rep("/n", 2)))
	must(c.Prune(ctx, "main", "a", client.PruneRequest{Horizon: a1.ID}))
	d := must(follow.FetchDoc(ctx, c, "main", "a", a.ID))
	if d.ID != a2.ID || string(d.Raw) != `{"n":2}` {
		t.Fatalf("fallback %s %s", d.ID, d.Raw)
	}
	d = must(follow.FetchDoc(ctx, c, "main", "a", a1.ID))
	if d.ID != a1.ID {
		t.Fatalf("horizon doc %s", d.ID)
	}
	must(c.Delete(ctx, "main", "a", a2.ID))
	if _, err := follow.FetchDoc(ctx, c, "main", "a", a.ID); !errors.Is(err, follow.ErrNotLive) {
		t.Fatalf("not live: %v", err)
	}
}
