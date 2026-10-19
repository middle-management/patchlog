package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// Moves (§8.1, §11): Head.Successor is what a plain namespace's 410 names,
// and Moved falls back to the document at Last where the 410 names none:
// a sealed namespace, read with the client's keys. E2E.Moved always folds
// it, ignoring a successor a 410 names. ResolveSuccessor resolves a bare name against the
// namespace serving the 410. At E3 the client's validation leaves a
// well-formed $successor out of the instance, as the server's does
// (§6.2 step 5, §E.3.2), so a closed schema needn't declare it.
func TestSuccessor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "p", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	for _, ns := range []string{"p", "s"} {
		for old, succ := range map[string]string{"a": "a2", "b": "/r/q/b"} {
			w := must(c.Create(ctx, ns, old, nonced(client.GenesisPatches(map[string]any{"x": 1}))))
			must(c.Batch(ctx, ns, client.BatchRequest{Items: []client.BatchItem{{Resource: old, IfMatch: w.ID, Steps: []client.Step{
				{Patches: nonced(ops(op("add", "/$successor", succ)))}, {Delete: true}}}}}, false))
			h := must(c.Head(ctx, ns, old))
			if h.State != client.Tombstoned || (ns == "p") != (h.Successor == succ) || ns == "s" && h.Successor != "" {
				t.Fatalf("%s/%s: head %+v", ns, old, h)
			}
			if m := must(c.Moved(ctx, ns, old, h)); m != succ {
				t.Fatalf("%s/%s: moved to %q, want %q", ns, old, m, succ)
			}
		}
		if n2, name2, ok := client.ResolveSuccessor(ns, "a2"); !ok || n2 != ns || name2 != "a2" {
			t.Fatalf("resolve bare: %s %s %v", n2, name2, ok)
		}
	}
	if n2, name2, ok := client.ResolveSuccessor("p", "/r/q/b"); !ok || n2 != "q" || name2 != "b" {
		t.Fatalf("resolve /r/: %s %s %v", n2, name2, ok)
	}
	if _, _, ok := client.ResolveSuccessor("p", "/r/q/b/c"); ok {
		t.Fatal("resolved a malformed successor")
	}
	if m := must(c.Moved(ctx, "p", "a", &client.Head{State: client.Live, ID: "x"})); m != "" {
		t.Fatalf("live head moved to %q", m)
	}
	if client.SuccessorOf(map[string]any{"$successor": "Bad"}) != "" || client.SuccessorOf(map[string]any{"$successor": "ok"}) != "ok" || client.SuccessorOf("x") != "" {
		t.Fatal("SuccessorOf")
	}

	// End to end, under a closed schema.
	_, priv, _ := seal.GenerateRecipient()
	x := c.E2E(priv)
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	sch := must(c.CreateDoc(ctx, "schemas", "closed", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object", "properties": map[string]any{"n": map[string]any{"type": "number"}}, "additionalProperties": false}))
	ref := "/r/schemas/closed/rev/" + sch.ID
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	must(x.InitKeyring(ctx, "e"))
	d := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"$schema": ref, "n": 1}))
	if _, err := x.AppendSealed(ctx, "e", "d", d.ID, ops(op("add", "/$successor", "Not A Name"))); err == nil {
		t.Fatal("a malformed $successor passed a closed schema")
	}
	d = must(x.AppendSealed(ctx, "e", "d", d.ID, ops(op("add", "/$successor", "d2"))))
	must(c.Delete(ctx, "e", "d", d.ID))
	h := must(c.Head(ctx, "e", "d"))
	if h.State != client.Tombstoned || h.Successor != "" || h.Last != d.ID {
		t.Fatalf("e2e head %+v", h)
	}
	if m := must(x.Moved(ctx, "e", "d", h)); m != "d2" {
		t.Fatalf("e2e moved to %q", m)
	}
	// A successor in an e2e 410 is made up by the server or a cache: the
	// verified document says where it moved.
	forged := *h
	forged.Successor = "/r/attacker/inbox"
	if m := must(x.Moved(ctx, "e", "d", &forged)); m != "d2" {
		t.Fatalf("e2e moved to %q, as a forged 410 says", m)
	}
	if _, err := x.Validate(ctx, map[string]any{"$schema": ref, "n": 2, "$successor": "/r/x/y", "$nonce": seal.NewNonce()}); err != nil {
		t.Fatalf("E3 validation: %v", err)
	}
}
