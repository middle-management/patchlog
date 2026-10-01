package index_test

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/schema"
)

// §6.1: the schema cache finds a draft for a document of a branch, as the
// server resolved it, and never for a namespace that isn't a branch.
func TestSchemaCacheDrafts(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	for _, ns := range []string{"schemas", "matches"} {
		if _, err := c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateBranch(ctx, "schemas", client.BranchRequest{Name: "schemas-r7",
		Patches: []any{map[string]any{"op": "add", "path": "/drafts", "value": map[string]any{"for": []any{"matches-r7"}}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}); err != nil {
		t.Fatal(err)
	}
	w, err := c.CreateDoc(ctx, "schemas-r7", "team", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := schema.ParseRef("/r/schemas/team/rev/" + w.ID)
	sc := index.NewSchemaCache(c)
	var transient error
	if _, err := sc.LoaderFor(ctx, "matches", &transient)(ref); !errors.Is(err, schema.ErrUnavailable) {
		t.Fatalf("for a namespace that isn't a branch: %v", err)
	}
	if d, err := sc.LoaderFor(ctx, "matches-r7", &transient)(ref); err != nil || d == nil {
		t.Fatalf("for a branch: %v", err)
	}
	if transient != nil {
		t.Fatal(transient)
	}
}
