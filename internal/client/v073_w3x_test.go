package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schema"
)

// W3X (P27 CIS-17 x P29 ENC-25; §6.1, §E.3.2): a typed document is
// validated under the rules marker of each schema revision its closure
// reaches, which the server serves with the revision (Doc.Rules). A schema
// written now asserts idn-email, so the core refuses a plain namespace's
// document whose e isn't one; at E3 the writer's own client refuses it
// before sealing, and a reader's fold flags it when a writer skipped
// validation.
func TestW3XE3ValidatesUnderSchemaRules(t *testing.T) {
	ctx := context.Background()
	v := newP29Env(t, nil)
	for _, ns := range []string{"schemas", "plain"} {
		must(v.s.Client(t, client.WithBearer(v.s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "public", "keys": []any{v.k.Entry("*")}}))
	}
	admin := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:a", []string{"schemas", "plain"}, p29Verbs)))
	sch := must(admin.CreateDoc(ctx, "schemas", "contact", map[string]any{"$schema": schema.Dialect2020,
		"type": "object", "properties": map[string]any{"e": map[string]any{"type": "string", "format": "idn-email"}}}))
	if d := must(admin.Doc(ctx, "schemas", "contact", sch.ID)); !d.RulesKnown || d.Rules != schema.V073 {
		t.Fatalf("a schema revision written now: Rules %v known %v, want v0.73", d.Rules, d.RulesKnown)
	}
	doc := map[string]any{"$schema": "/r/schemas/contact/rev/" + sch.ID, "e": "not an email"}
	var ae *client.APIError
	if _, err := admin.CreateDoc(ctx, "plain", "c", doc); !errors.As(err, &ae) || ae.Status != 422 {
		t.Fatalf("plain namespace: %v, want 422", err)
	}
	if d := must(admin.Doc(ctx, "plain", "ok", must(admin.CreateDoc(ctx, "plain", "ok", map[string]any{"$schema": "/r/schemas/contact/rev/" + sch.ID, "e": "a@b.example"})).ID)); d.RulesKnown {
		t.Errorf("a typed document, which isn't a schema: Rules %v known", d.Rules)
	}
	if w, err := v.x.CreateDocSealed(ctx, "e", "c", doc); err == nil {
		t.Errorf("the E3 writer sealed %s, a document its schema (written now, idn-email asserted) refuses", w.ID)
	}
	w := must(v.x.WithoutValidation().CreateDocSealed(ctx, "e", "skipped", doc))
	if d := must(v.x.DocE2E(ctx, "e", "skipped", w.ID)); len(d.Flagged) == 0 {
		t.Errorf("the fold of that document flags nothing: %+v", d)
	}
	// A valid one is sealed and folds unflagged.
	ok := must(v.x.CreateDocSealed(ctx, "e", "ok", map[string]any{"$schema": "/r/schemas/contact/rev/" + sch.ID, "e": "a@b.example"}))
	if d := must(v.x.DocE2E(ctx, "e", "ok", ok.ID)); len(d.Flagged) != 0 {
		t.Errorf("a valid document's fold flags %v", d.Flagged)
	}
}
