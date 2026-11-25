package verify_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/verify"
)

// v0.90 (§7.4, §3.5, HTTP-82): a head entry carries its revision's
// schema, a batch's items included, and it is not hashed: the chain
// verifies with it, and an entry's id is the same with or without it.
func TestV090SchemaUnhashed(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	sc := must(c.CreateDoc(ctx, "main", "s", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}))
	ref := "/r/main/s/rev/" + sc.ID
	must(c.CreateDoc(ctx, "main", "a", map[string]any{"$schema": ref, "n": 1}))
	must(c.CreateDoc(ctx, "main", "plain", map[string]any{"n": 1}))
	must(c.Batch(ctx, "main", client.BatchRequest{Items: []client.BatchItem{
		{Resource: "b", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"$schema": ref, "k": 1}))}},
		{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"k": 2}))}},
		{Resource: "d", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"$schema": ref})), client.DeleteStep()}},
	}}, false))

	entries, _, err := verify.Namespace(ctx, c, "main", "")
	if err != nil {
		t.Fatalf("the chain with schema members: %v", err)
	}
	got := map[string]string{}
	for _, e := range entries {
		if e.Kind == "head" {
			got[e.Resource] = e.Schema
		}
		for _, s := range e.Entries {
			got[s.Resource] = s.Schema
			if s.Kind == "tombstone" && s.Raw["schema"] != nil {
				t.Fatalf("a tombstone carries schema: %v", s.Raw)
			}
		}
		if e.Kind == "batch" && (e.Raw["schema"] != nil || e.Raw["schemas"] != nil) {
			t.Fatalf("a batch entry carries schema members: %v", e.Raw)
		}
	}
	want := map[string]string{"s": "https://json-schema.org/draft/2020-12/schema", "a": ref, "plain": "", "b": ref, "c": "", "d": ""}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: schema %q, want %q", name, got[name], w)
		}
	}
	if hs := client.SchemaHeads(entries, ref); len(hs) != 2 || hs[0].Resource != "a" || hs[1].Resource != "b" {
		t.Fatalf("SchemaHeads: %+v", hs)
	}

	// The id is the same without the member, and with another value.
	for i, e := range entries {
		if e.Kind != "head" || e.Schema == "" {
			continue
		}
		prev := ""
		if i > 0 {
			prev = entries[i-1].ID
		}
		for _, sc := range []string{"", "/r/other/x/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
			e2 := e
			e2.Schema = sc
			if id, err := verify.NSEntryID(prev, e2); err != nil || id != e.ID {
				t.Fatalf("%s with schema %q: %s %v, want %s", e.Resource, sc, id, err, e.ID)
			}
		}
	}
}
