package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// CIS-17, INV-2: a fold re-validates a stored revision under the rules it
// was written under (§6.1, §E.3.2): Legacy, until revisions keep their
// markers. A schema document an earlier version accepted (a format draft
// 2020-12 doesn't define, a nested dialect $schema) still folds, though a
// write now refuses it; one no version accepted is still flagged.
func TestV073FoldStoredSchemaDocument(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, _ := seal.GenerateRecipient()
	x := c.E2E(priv)
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	must(x.InitKeyring(ctx, "e"))

	const d2020 = "https://json-schema.org/draft/2020-12/schema"
	old := map[string]any{"$schema": d2020, "type": "object", "properties": map[string]any{
		"c": map[string]any{"type": "string", "format": "color"},
		"n": map[string]any{"$schema": d2020, "type": "string"}}}
	if _, err := x.CreateDocSealed(ctx, "e", "s", old); err == nil || !strings.Contains(err.Error(), "$schema") {
		t.Fatalf("written now: %v", err)
	}
	// Stored as an earlier version's client wrote it.
	w := must(x.WithoutValidation().CreateDocSealed(ctx, "e", "s", old))
	d := must(x.DocE2E(ctx, "e", "s", w.ID))
	if d.ValidID != w.ID || len(d.Flagged) != 0 {
		t.Fatalf("fold of a schema document an earlier version accepted: %+v", d)
	}
	sameJSON(t, d.Value, old)

	bad := must(x.WithoutValidation().AppendSealed(ctx, "e", "s", w.ID, ops(op("add", "/foo", 1))))
	d = must(x.DocE2E(ctx, "e", "s", bad.ID))
	if d.ValidID != w.ID || len(d.Flagged) != 1 || d.Flagged[0].ID != bad.ID {
		t.Fatalf("fold of a schema document no version accepted: %+v", d)
	}
}
