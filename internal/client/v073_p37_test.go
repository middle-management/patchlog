package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// ENC-32 (§E.2.2, §E.2.6): a document read sealed carries the kid it is
// served under (Doc.Kid), an E3 fold the kid of the sealed op its document
// comes from (E2EDoc.Kid), skipping a restore's [], so derived views seal
// under the revision's epoch, not the current one. In the clear there is
// none.
func TestV073P37DocKids(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	for ns, enc := range map[string]string{"s": "sealed", "e": "e2e", "p": ""} {
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
		if enc != "" {
			doc["encryption"] = map[string]any{"level": enc}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	wJWK, wPriv, _ := seal.GenerateRecipient()
	c := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"s", "e", "p"}, []string{"read", "create", "append", "delete", "restore", "config"},
		map[string]any{"enc": wJWK})), client.WithKeys(client.NewKeys(wPriv)), client.WithKeyringSenders(wPriv.PublicKey()))

	a := must(c.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"n": 0}))))
	must(c.Doc(ctx, "s", "a", a.ID)) // epoch 1's key, while it is current
	must(s.Engine.RotateEpoch(ctx, "s", "system:rotate"))
	b := must(c.Append(ctx, "s", "a", a.ID, nonced(ops(op("replace", "/n", 1)))))
	if d := must(c.Doc(ctx, "s", "a", a.ID)); d.Kid != "s#1" {
		t.Errorf("revision of epoch 1: kid %q", d.Kid)
	}
	if d := must(c.Doc(ctx, "s", "a", b.ID)); d.Kid != "s#2" {
		t.Errorf("revision of epoch 2: kid %q", d.Kid)
	}
	p := must(c.Create(ctx, "p", "a", client.GenesisPatches(map[string]any{"n": 0})))
	if d := must(c.Doc(ctx, "p", "a", p.ID)); d.Kid != "" {
		t.Errorf("a document in the clear: kid %q", d.Kid)
	}

	x := c.E2E(wPriv)
	must(x.InitKeyring(ctx, "e"))
	e1 := must(x.CreateDocSealed(ctx, "e", "a", map[string]any{"n": 0}))
	if e := must(x.RotateEpoch(ctx, "e")); e != 2 {
		t.Fatalf("rotated to %d", e)
	}
	if d := must(x.DocE2E(ctx, "e", "a", e1.ID)); d.Kid() != "e#1" {
		t.Errorf("e2e revision of epoch 1: kid %q", d.Kid())
	}
	// A delete and a restore with [] after the rotation keep the document
	// of the epoch-1 op.
	del := must(c.Delete(ctx, "e", "a", e1.ID))
	r := must(c.Append(ctx, "e", "a", del.ID, []any{}))
	if d := must(x.DocE2E(ctx, "e", "a", r.ID)); d.Kid() != "e#1" {
		t.Errorf("e2e restore with []: kid %q", d.Kid())
	}
}
