package schemaimport_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

// An import into a real server: the schemas land at the predicted
// revisions, documents validate against the root, a re-run is a no-op and a
// changed source appends.
func TestImportEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fs := newFixtureServer(t)
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("importer"))
	for _, ns := range []string{"schemas", "docs"} {
		if _, err := c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}); err != nil {
			t.Fatal(err)
		}
	}
	src := []string{fs.URL + "/a/root.json"}
	opt := schemaimport.Options{NS: "schemas", Name: "person"}

	res, err := schemaimport.Plan(ctx, c, src, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed() {
		t.Fatal("nothing to write")
	}
	if err := res.Write(ctx, c); err != nil {
		t.Fatal(err)
	}
	if len(res.NSIDs) != 1 {
		t.Errorf("%d batches, want one atomic batch", len(res.NSIDs))
	}
	for _, r := range res.Resources {
		h, err := c.Head(ctx, "schemas", r.Name)
		if err != nil || h.State != client.Live || h.ID != r.ID {
			t.Fatalf("%s: head %+v %v, want %s", r.Name, h, err, r.ID)
		}
		// Every external ref is a revision path (§6.1).
		for _, ref := range schema.Refs(r.Content) {
			if ref.NS != "schemas" {
				t.Errorf("%s: ref %s", r.Name, ref.Path())
			}
		}
	}
	root := res.Resources[len(res.Resources)-1]
	rootPath := root.Path("schemas")
	if res.Entries[len(res.Entries)-1].Path != rootPath {
		t.Fatalf("last entry %+v", res.Entries[len(res.Entries)-1])
	}

	valid := map[string]any{"$schema": rootPath, "addr": map[string]any{"street": "Main", "zip": "12345"},
		"pos": []any{1, 2}, "pct": 50, "node": map[string]any{"next": map[string]any{"val": "v"}}}
	if _, err := c.CreateDoc(ctx, "docs", "ok", valid); err != nil {
		t.Fatalf("valid document: %v", err)
	}
	invalid := map[string]any{"$schema": rootPath, "addr": map[string]any{"zip": "nope"}, "pct": 100}
	_, err = c.CreateDoc(ctx, "docs", "bad", invalid)
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 || ae.Code != "invalid" {
		t.Fatalf("invalid document: %v", err)
	}

	// Re-run with unchanged sources: nothing to write, same paths.
	again, err := schemaimport.Plan(ctx, c, src, opt)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed() {
		for _, r := range again.Resources {
			t.Logf("%s %s", r.Name, r.Action)
		}
		t.Fatal("re-run would write")
	}
	if again.Entries[len(again.Entries)-1].Path != rootPath {
		t.Errorf("re-run root path %s", again.Entries[len(again.Entries)-1].Path)
	}

	// A changed source appends a revision to it and to everything that pins it.
	fs.set("/b/sib.json", `{ "type": "integer", "minimum": 0 }`)
	changed, err := schemaimport.Plan(ctx, c, src, opt)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, r := range changed.Resources {
		actions[r.Name] = r.Action
	}
	if actions["sib"] != schemaimport.Append || actions["person"] != schemaimport.Append || actions["address"] != schemaimport.Unchanged || actions["a"] != schemaimport.Unchanged {
		t.Fatalf("actions %v", actions)
	}
	if err := changed.Write(ctx, c); err != nil {
		t.Fatal(err)
	}
	newRoot := changed.Resources[len(changed.Resources)-1]
	if h, _ := c.Head(ctx, "schemas", "person"); h.ID != newRoot.ID || newRoot.Parent != root.ID {
		t.Fatalf("person head %s, want %s on %s", h.ID, newRoot.ID, root.ID)
	}
	// The old revision still validates documents pinned to it; the new one
	// applies the new constraint.
	neg := map[string]any{"$schema": newRoot.Path("schemas"), "addr": map[string]any{}, "nested": -1}
	if _, err := c.CreateDoc(ctx, "docs", "neg", neg); err == nil {
		t.Error("new constraint not applied")
	}
	neg["$schema"] = rootPath
	if _, err := c.CreateDoc(ctx, "docs", "neg-old", neg); err != nil {
		t.Errorf("old revision: %v", err)
	}
}

// Beyond the namespace's batch limits, the writes go in dependency-ordered
// chunks.
func TestImportChunked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fs := newFixtureServer(t)
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("importer"))
	if _, err := c.CreateNamespace(ctx, "small", map[string]any{"read": "public", "limits": map[string]any{"itemsPerBatch": 2}}); err != nil {
		t.Fatal(err)
	}
	res, err := schemaimport.Plan(ctx, c, []string{fs.URL + "/a/root.json"}, schemaimport.Options{NS: "small"})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Write(ctx, c); err != nil {
		t.Fatal(err)
	}
	if want := (len(res.Resources) + 1) / 2; len(res.NSIDs) != want {
		t.Errorf("%d batches, want %d", len(res.NSIDs), want)
	}
	for _, r := range res.Resources {
		if h, err := c.Head(ctx, "small", r.Name); err != nil || h.ID != r.ID {
			t.Errorf("%s: %+v %v", r.Name, h, err)
		}
	}
}
