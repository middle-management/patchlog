package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

func stackGestures(t *testing.T, c *client.Client, ns, author string) []string {
	t.Helper()
	st := must(c.UndoStack(context.Background(), ns, author))
	var out []string
	for _, it := range st.Done {
		out = append(out, it.Gesture)
	}
	return out
}

func has(list []string, g string) bool {
	for _, x := range list {
		if x == g {
			return true
		}
	}
	return false
}

// §11.2, §F.3: a gesture a merge carried into the base counts for the
// author who wrote it in the branch, but only for a batch that counts as a
// merge; otherwise for whoever wrote the batch.
func TestUndoStackMergedGestures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	admin := s.Client(t, client.WithAuthor("admin"))
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	bot := s.Client(t, client.WithAuthor("merge-bot"))
	other := s.Client(t, client.WithAuthor("someone"))
	must(admin.CreateNamespace(ctx, "m", map[string]any{
		"merge": map[string]any{"authors": []any{map[string]any{"sub": "merge-bot", "kid": "k1"}}},
	}))
	for _, n := range []string{"a", "b", "c", "d"} {
		must(admin.CreateDoc(ctx, "m", n, map[string]any{"v": 0}))
	}
	must(admin.CreateBranch(ctx, "m", client.BranchRequest{Name: "r1"}))

	// Alice and Bob work in the branch.
	ga, gb := client.NewGesture(), client.NewGesture()
	ha, hb := head(t, alice, "r1", "a"), head(t, alice, "r1", "b")
	must(alice.Append(ctx, "r1", "a", ha, ops(op("replace", "/v", 1)), client.WithGesture(ga)))
	must(bob.Append(ctx, "r1", "b", hb, ops(op("replace", "/v", 1)), client.WithGesture(gb)))
	at := must(alice.NSHead(ctx, "r1")).ID

	// Fast-forward both into the base as one merge batch by the bot.
	ffItem := func(c *client.Client, res, g string) client.BatchItem {
		return client.BatchItem{Resource: res, IfMatch: head(t, c, "m", res), Steps: []client.Step{client.PatchStep(ops(op("replace", "/v", 1)))}, Gesture: g}
	}
	merge := must(bot.Batch(ctx, "m", client.BatchRequest{
		Items:  []client.BatchItem{ffItem(bot, "a", ga), ffItem(bot, "b", gb)},
		Source: map[string]any{"ns": "r1", "at": at},
	}, false))
	if merge.Status != 201 {
		t.Fatalf("merge %+v", merge)
	}
	if got := stackGestures(t, admin, "m", "alice"); len(got) != 1 || got[0] != ga {
		t.Errorf("alice's stack %v", got)
	}
	if got := stackGestures(t, admin, "m", "bob"); len(got) != 1 || got[0] != gb {
		t.Errorf("bob's stack %v", got)
	}
	if got := stackGestures(t, admin, "m", "merge-bot"); len(got) != 0 {
		t.Errorf("the merger's stack %v", got)
	}
	// The record says who, and where.
	it := must(admin.UndoStack(ctx, "m", "alice")).Done[0]
	if it.Author != "alice" || len(it.Resources) != 1 || it.Resources[0] != "a" {
		t.Errorf("item %+v", it)
	}

	// Not a merge under §F.3: a merger that isn't listed, a source with
	// origin, a source.at that isn't in the branch's chain, a gesture the
	// branch never had. Each counts for whoever wrote the batch.
	g1, g2, g3, g4 := client.NewGesture(), client.NewGesture(), client.NewGesture(), client.NewGesture()
	item := func(c *client.Client, res, g string) client.BatchItem {
		return client.BatchItem{Resource: res, IfMatch: head(t, c, "m", res), Steps: []client.Step{client.PatchStep(ops(op("replace", "/v", 2)))}, Gesture: g}
	}
	must(other.Batch(ctx, "m", client.BatchRequest{Items: []client.BatchItem{item(other, "a", g1)}, Source: map[string]any{"ns": "r1", "at": at}}, false))
	must(bot.Batch(ctx, "m", client.BatchRequest{Items: []client.BatchItem{item(bot, "b", g2)}, Source: map[string]any{"origin": "https://elsewhere.example", "ns": "r1", "at": at}}, false))
	bad := "1" + at[1:len(at)-1] + "a"
	if bad == at {
		bad = "1" + at[1:len(at)-1] + "b"
	}
	if _, err := bot.Batch(ctx, "m", client.BatchRequest{Items: []client.BatchItem{item(bot, "c", g3)}, Source: map[string]any{"ns": "r1", "at": bad}}, false); err == nil {
		// The server accepted a source.at outside the chain: it must not count.
		if got := stackGestures(t, admin, "m", "alice"); has(got, g3) {
			t.Errorf("alice's stack %v", got)
		}
	}
	must(bot.Batch(ctx, "m", client.BatchRequest{Items: []client.BatchItem{item(bot, "d", g4)}, Source: map[string]any{"ns": "r1", "at": at}}, false))

	if got := stackGestures(t, admin, "m", "someone"); !has(got, g1) {
		t.Errorf("an unlisted merger's gesture is its own: %v", got)
	}
	if got := stackGestures(t, admin, "m", "merge-bot"); !has(got, g2) {
		t.Errorf("a source with origin is the batch writer's: %v", got)
	}
	// g4 was never written in the branch, so it stays with the merger.
	if got := stackGestures(t, admin, "m", "merge-bot"); !has(got, g4) {
		t.Errorf("a gesture the branch never had: %v", got)
	}
	for _, g := range []string{g1, g2, g4} {
		if has(stackGestures(t, admin, "m", "alice"), g) || has(stackGestures(t, admin, "m", "bob"), g) {
			t.Errorf("%s attributed to a branch author", g)
		}
	}
}

// Undoing a merged gesture as its source author (§11.2): UndoAuthor names
// the author who wrote it in the branch, though the base's entries are the
// merger's.
func TestUndoMergedGestureAsItsAuthor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	admin := s.Client(t, client.WithAuthor("admin"))
	alice := s.Client(t, client.WithAuthor("alice"))
	bot := s.Client(t, client.WithAuthor("merge-bot"))
	must(admin.CreateNamespace(ctx, "m", map[string]any{
		"merge": map[string]any{"authors": []any{map[string]any{"sub": "merge-bot", "kid": "k1"}}},
	}))
	must(admin.CreateDoc(ctx, "m", "a", map[string]any{"v": 0}))
	must(admin.CreateBranch(ctx, "m", client.BranchRequest{Name: "r1"}))
	g := client.NewGesture()
	must(alice.Append(ctx, "r1", "a", head(t, alice, "r1", "a"), ops(op("replace", "/v", 1)), client.WithGesture(g)))
	at := must(alice.NSHead(ctx, "r1")).ID
	must(bot.Batch(ctx, "m", client.BatchRequest{
		Items:  []client.BatchItem{{Resource: "a", IfMatch: head(t, bot, "m", "a"), Steps: []client.Step{client.PatchStep(ops(op("replace", "/v", 1)))}, Gesture: g}},
		Source: map[string]any{"ns": "r1", "at": at},
	}, false))

	res, err := alice.Undo(ctx, "m", g, client.UndoAuthor("alice"))
	if err != nil {
		t.Fatalf("undo as alice: %v", err)
	}
	if res.Batch == nil || res.Batch.Status != 201 {
		t.Fatalf("undo %+v", res)
	}
	_, d, err := alice.Load(ctx, "m", "a")
	if err != nil {
		t.Fatal(err)
	}
	if v := d.Value.(map[string]any)["v"]; v != 0.0 && v != int64(0) {
		t.Fatalf("after undo %v", d.Value)
	}
	// Someone else's name finds nothing.
	if _, err := alice.Undo(ctx, "m", g, client.UndoAuthor("bob")); err == nil {
		t.Fatal("undo as bob found the gesture")
	}
}
