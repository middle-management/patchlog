package verify_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/verify"
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

// populate writes every kind of namespace entry into "main" and a branch.
func populate(t *testing.T, s *clienttest.Server, c *client.Client) (aRevs []string) {
	ctx := context.Background()
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	a := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	aRevs = append(aRevs, a.ID)
	head := a.ID
	for i := 1; i <= 3; i++ {
		head = must(c.Append(ctx, "main", "a", head, rep("/n", i))).ID
		aRevs = append(aRevs, head)
	}
	b := must(c.CreateDoc(ctx, "main", "b", map[string]any{"x": "y"}))
	tb := must(c.Delete(ctx, "main", "b", b.ID))
	must(c.Purge(ctx, "main", "b", tb.ID, false))
	nh := must(c.NSHead(ctx, "main"))
	must(c.Batch(ctx, "main", client.BatchRequest{
		Items: []client.BatchItem{
			{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"k": 1})), client.DeleteStep()}},
			{Resource: "d", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"k": 2}))}},
		},
		Config: &client.BatchConfig{IfMatch: nh.Config, Patches: []any{map[string]any{"op": "add", "path": "/x-v", "value": 2}}},
		Source: map[string]any{"ns": "main", "at": nh.ID, "ids": map[string]any{"d": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
	}, false))
	br := must(c.CreateBranch(ctx, "main", client.BranchRequest{Name: "rel"}))
	// First write in the branch: a foreign parent.
	must(c.Append(ctx, "rel", "a", head, rep("/n", 100)))
	// Prune a (past the retry window).
	s.Clock.Advance(10 * time.Minute)
	head = must(c.Append(ctx, "main", "a", head, rep("/n", 4))).ID
	aRevs = append(aRevs, head)
	_ = br
	// Freeze and purge the branch.
	bh := must(c.NSHead(ctx, "rel"))
	must(c.PatchConfig(ctx, "rel", bh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	bh = must(c.NSHead(ctx, "rel"))
	must(c.PurgeNamespace(ctx, "rel", bh.ID))
	return aRevs
}

func TestVerifyGenuineChains(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("admin"))
	aRevs := populate(t, s, c)

	entries, head, err := verify.Namespace(ctx, c, "main", "")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, e := range entries {
		kinds[e.Kind] = true
	}
	for _, k := range []string{"config", "head", "tombstone", "purge", "batch", "branch"} {
		if !kinds[k] {
			t.Fatalf("kind %s not exercised: %v", k, kinds)
		}
	}
	// From a checkpoint in the middle.
	mid := entries[3].ID
	rest, head2, err := verify.Namespace(ctx, c, "main", mid)
	if err != nil || head2 != head || len(rest) != len(entries)-4 {
		t.Fatalf("from checkpoint: %v %s %d", err, head2, len(rest))
	}
	// Already at head.
	if r, h, err := verify.Namespace(ctx, c, "main", head); err != nil || h != head || len(r) != 0 {
		t.Fatalf("at head: %v", err)
	}
	// The branch's own chain, including config, frozen config and purge-ns.
	bentries, _, err := verify.Namespace(ctx, c, "rel", "")
	if err != nil {
		t.Fatal(err)
	}
	if bentries[len(bentries)-1].Kind != "purge-ns" || bentries[0].Kind != "config" {
		t.Fatalf("branch log %+v", bentries)
	}

	// Resource logs, from genesis and from a trusted revision; document check.
	lg, last, err := verify.Resource(ctx, c, "main", "a", "", "")
	if err != nil || last != aRevs[len(aRevs)-1] || len(lg) != len(aRevs) {
		t.Fatalf("resource log: %v %s", err, last)
	}
	d := must(c.Doc(ctx, "main", "a", last))
	if err := verify.Document(lg, d.Raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verify.Resource(ctx, c, "main", "a", "", aRevs[1]); err != nil {
		t.Fatal(err)
	}
	// Tombstone, restore (with the log crossing it).
	h := must(c.Head(ctx, "main", "d"))
	del := must(c.Delete(ctx, "main", "d", h.ID))
	must(c.Restore(ctx, "main", "d", del.ID, rep("/k", 3)))
	dl, dlast, err := verify.Resource(ctx, c, "main", "d", "", "")
	if err != nil || len(dl) != 3 {
		t.Fatalf("d log: %v", err)
	}
	if err := verify.Document(dl, must(c.Doc(ctx, "main", "d", dlast)).Raw); err != nil {
		t.Fatal(err)
	}

	// Prune: the log from genesis is 410; the patch-less form stops with a horizon.
	must(c.Prune(ctx, "main", "a", client.PruneRequest{Horizon: aRevs[2]}))
	if _, _, err := verify.Resource(ctx, c, "main", "a", "", ""); !client.IsPruned(err) {
		t.Fatalf("pruned log: %v", err)
	}
	if _, _, err := verify.Resource(ctx, c, "main", "a", "", aRevs[2]); err != nil {
		t.Fatalf("from the horizon: %v", err)
	}
	stripped := append([]client.LogEntry(nil), lg...)
	stripped[1].HasPatches, stripped[1].Patches = false, nil
	got, err := verify.VerifyResourceLog(stripped, "")
	var pe *verify.PrunedError
	if !errors.Is(err, verify.ErrPruned) || !errors.As(err, &pe) || pe.Index != 1 || got != aRevs[0] || pe.Verified != aRevs[0] {
		t.Fatalf("stripped: %v %s", err, got)
	}
	// The namespace chain still verifies (it hashes ids only), including the prune entry.
	all, _, err := verify.Namespace(ctx, c, "main", "")
	if err != nil || all[len(all)-1].Kind != "prune" {
		t.Fatalf("after prune: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("admin"))
	populate(t, s, c)
	head := must(c.NSHead(ctx, "main"))
	entries := must(c.NSLog(ctx, "main", head.ID, ""))
	if _, err := verify.VerifyNSChain(entries, ""); err != nil {
		t.Fatal(err)
	}
	clone := func() []client.NSEntry {
		out := make([]client.NSEntry, len(entries))
		copy(out, entries)
		return out
	}
	find := func(kind string) int {
		for i, e := range entries {
			if e.Kind == kind {
				return i
			}
		}
		t.Fatalf("no %s", kind)
		return -1
	}
	cases := map[string]func([]client.NSEntry){
		"target":   func(es []client.NSEntry) { es[1].Target = es[2].Target },
		"resource": func(es []client.NSEntry) { es[1].Resource = "zzz" },
		"kind":     func(es []client.NSEntry) { es[find("tombstone")].Kind = "head" },
		"reorder":  func(es []client.NSEntry) { es[1], es[2] = es[2], es[1] },
		"drop":     func(es []client.NSEntry) { copy(es[2:], es[3:]); es[len(es)-1] = es[len(es)-2] },
		"batch source": func(es []client.NSEntry) {
			i := find("batch")
			src := jsonv.Clone(es[i].Source).(map[string]any)
			src["ns"] = "other"
			es[i].Source = src
		},
		"batch drops source": func(es []client.NSEntry) { es[find("batch")].HasSource = false },
		"batch sub-entry": func(es []client.NSEntry) {
			i := find("batch")
			subs := append([]client.NSEntry(nil), es[i].Entries...)
			subs[1].Target = subs[2].Target
			es[i].Entries = subs
		},
		"branch at":   func(es []client.NSEntry) { i := find("branch"); es[i].At = es[1].ID },
		"branch name": func(es []client.NSEntry) { es[find("branch")].Name = "evil" },
	}
	for name, mutate := range cases {
		es := clone()
		mutate(es)
		if _, err := verify.VerifyNSChain(es, ""); err == nil {
			t.Errorf("%s: tampering not detected", name)
		}
	}
	// A wrong trusted start.
	if _, err := verify.VerifyNSChain(entries[1:], entries[1].ID); err == nil {
		t.Error("wrong start accepted")
	}

	// Resource logs.
	lg := must(c.Log(ctx, "main", "a", "", ""))
	if _, err := verify.VerifyResourceLog(lg, ""); err != nil {
		t.Fatal(err)
	}
	tamper := append([]client.LogEntry(nil), lg...)
	tamper[1].Patches = rep("/n", 42)
	if _, err := verify.VerifyResourceLog(tamper, ""); err == nil {
		t.Error("patch tampering not detected")
	}
	tamper = append([]client.LogEntry(nil), lg...)
	tamper[2].Parent = tamper[0].ID
	if _, err := verify.VerifyResourceLog(tamper, ""); err == nil {
		t.Error("parent tampering not detected")
	}
	if _, err := verify.VerifyResourceLog(lg[1:], ""); err == nil {
		t.Error("missing genesis not detected")
	}
	d := must(c.Doc(ctx, "main", "a", lg[len(lg)-1].ID))
	if err := verify.Document(lg, []byte(`{"n":999}`)); err == nil {
		t.Error("document tampering not detected")
	} else if err := verify.Document(lg, d.Raw); err != nil {
		t.Error(err)
	}
}
