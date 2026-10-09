package schemaimport_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/schemaimport"
	"github.com/middle-management/patchlog/internal/seal"
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

// §C.7: into a namespace that requires nonces, every create, append and
// restore adds a fresh $nonce, the predicted ids include it, and a head
// that differs from the content only in its $nonce is unchanged.
func TestImportRequiredNonces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fs := newFixtureServer(t)
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("importer"))
	if _, err := c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "nonce": "required"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateNamespace(ctx, "docs", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	src := []string{fs.URL + "/a/root.json"}
	opt := schemaimport.Options{NS: "schemas", Name: "person"}
	// write plans and writes the import, and returns each resource's
	// $nonce, checking it is fresh and the head is the predicted one.
	write := func() (*schemaimport.Result, map[string]string) {
		t.Helper()
		res, err := schemaimport.Plan(ctx, c, src, opt)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Write(ctx, c); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range res.Resources {
			h, d, err := c.Load(ctx, "schemas", r.Name)
			if err != nil || h.ID != r.ID {
				t.Fatalf("%s: head %+v %v, want %s", r.Name, h, err, r.ID)
			}
			n, _ := d.Value.(map[string]any)["$nonce"].(string)
			if !seal.ValidNonce(n) {
				t.Fatalf("%s: $nonce %q", r.Name, n)
			}
			out[r.Name] = n
		}
		return res, out
	}
	res, first := write()
	if len(res.NSIDs) != 1 {
		t.Errorf("%d batches, want one atomic batch", len(res.NSIDs))
	}
	rootPath := res.Resources[len(res.Resources)-1].Path("schemas")
	if _, err := c.CreateDoc(ctx, "docs", "ok", map[string]any{"$schema": rootPath, "addr": map[string]any{"zip": "12345"}}); err != nil {
		t.Fatalf("valid document: %v", err)
	}
	if again, err := schemaimport.Plan(ctx, c, src, opt); err != nil || again.Changed() {
		t.Fatalf("re-run: %v", err)
	}

	// A changed source appends, and a deleted resource is restored.
	fs.set("/b/sib.json", `{ "type": "integer", "minimum": 0 }`)
	h, err := c.Head(ctx, "schemas", "address")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Delete(ctx, "schemas", "address", h.ID); err != nil {
		t.Fatal(err)
	}
	res, second := write()
	if a := byName(t, res, "sib").Action; a != schemaimport.Append {
		t.Fatalf("sib %s", a)
	}
	if a := byName(t, res, "address").Action; a != schemaimport.Restore {
		t.Fatalf("address %s", a)
	}
	for _, n := range []string{"sib", "address", "person"} {
		if first[n] == second[n] {
			t.Errorf("%s kept its $nonce", n)
		}
	}
}

// §C.7: an importer whose grant can't read the namespace document (its
// rules refer to /resource, §C.5) doesn't know the setting, so in a
// private namespace every write adds a fresh $nonce: one that requires
// them takes it, and so does one that doesn't. A boolean schema has no
// member to add, so it is written as is where nonces are optional.
func TestImportUnreadableNonces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fs := newFixtureServer(t)
	fs.set("/c/solo.json", `{ "type": "string", "maxLength": 20 }`)
	fs.set("/c/any.json", `true`)
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("k")
	for _, setting := range []string{"required", "optional"} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()
			ns := "schemas-" + setting
			admin := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
			if _, err := admin.CreateNamespace(ctx, ns, map[string]any{"read": "grant", "nonce": setting, "keys": []any{k.Entry("*")}}); err != nil {
				t.Fatal(err)
			}
			c := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:importer", []string{ns}, []string{"read", "create", "append"},
				map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"solo", "any"}}}}})))
			if _, err := c.NonceRequired(ctx, ns); err == nil {
				t.Fatal("the importer reads the namespace document")
			}
			res, err := schemaimport.Plan(ctx, c, []string{fs.URL + "/c/solo.json"}, schemaimport.Options{NS: ns, Name: "solo"})
			if err != nil {
				t.Fatal(err)
			}
			if err := res.Write(ctx, c); err != nil {
				t.Fatal(err)
			}
			h, d, err := c.Load(ctx, ns, "solo")
			if err != nil || h.ID != byName(t, res, "solo").ID {
				t.Fatalf("head %+v %v", h, err)
			}
			if n, _ := d.Value.(map[string]any)["$nonce"].(string); !seal.ValidNonce(n) {
				t.Fatalf("$nonce %q", n)
			}

			res, err = schemaimport.Plan(ctx, c, []string{fs.URL + "/c/any.json"}, schemaimport.Options{NS: ns, Name: "any"})
			if err != nil {
				t.Fatal(err)
			}
			err = res.Write(ctx, c)
			if setting == "required" {
				if err == nil || !strings.Contains(err.Error(), "code:nonce") {
					t.Fatalf("boolean schema where nonces are required: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h, d, err := c.Load(ctx, ns, "any"); err != nil || h.ID != byName(t, res, "any").ID || d.Value != true {
				t.Fatalf("boolean schema: head %+v %v %v", h, d, err)
			}
		})
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
