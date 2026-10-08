package client_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/sig"
)

// §C.3.1: a client with a signer signs its writes, deletes and batch
// steps, which a namespace requiring signatures accepts.
func TestWithSigner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	admin := clienttest.NewKey("admin")
	oper := s.Client(t, client.WithBearer(s.OperatorGrant(t, "req")))
	must(oper.CreateNamespace(ctx, "req", map[string]any{"keys": []any{admin.Entry("*")}, "signatures": "required"}))

	k := sig.Key{Kid: "k1", Priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
	g := admin.Grant(t, s.Now(), "user:alice", []string{"req"}, []string{"read", "create", "append", "delete"},
		map[string]any{"signers": []any{k.Entry()}})
	unsigned := s.Client(t, client.WithBearer(g))
	if _, err := unsigned.Create(ctx, "req", "a", client.GenesisPatches(map[string]any{})); err == nil {
		t.Fatal("an unsigned write was accepted")
	}
	c := unsigned.With(client.WithSigner(k))
	w := must(c.Create(ctx, "req", "a", client.GenesisPatches(map[string]any{"n": 1})))
	w = must(c.Append(ctx, "req", "a", w.ID, ops(op("replace", "/n", 2))))
	log := must(c.Log(ctx, "req", "a", w.ID, ""))
	if len(log) != 2 || log[1].Signature == "" || log[1].Grant == nil || log[1].Grant.Sub != "user:alice" {
		t.Fatalf("log %+v", log)
	}
	must(c.Delete(ctx, "req", "a", w.ID))

	b := must(c.Batch(ctx, "req", client.BatchRequest{Items: []client.BatchItem{{Resource: "b", IfNoneMatch: true,
		Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{})), client.PatchStep(ops(op("add", "/x", 1))), client.DeleteStep()}}}}, false))
	if b.Status != 201 || len(b.Items[0].IDs) != 3 {
		t.Fatalf("batch %+v", b)
	}

	// The grant is served to a reader with unrestricted read.
	ag := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"req"}, []string{"read"})))
	gd := must(ag.Grant(ctx, "req", log[1].Grant.ID))
	if gd.ID != log[1].Grant.ID || gd.Root["sub"] != "user:alice" || len(must(gd.Blocks())) != 1 {
		t.Fatalf("grant %+v", gd)
	}
	if root := must(c.Root(ctx)); root.JWKSURI != clienttest.Origin+"/.well-known/patchlog-keys" {
		t.Fatalf("root %+v", root)
	}
}
