package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/schema"
)

// §6.1: several Source-Authorization grants reach the server (resource
// writes and batches), drafts resolve with them, and an in_use refusal
// names the referencing namespaces.
func TestClientDrafts(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	kS, kM := clienttest.NewKey("ks"), clienttest.NewKey("km")
	op := s.Client(t)
	for ns, k := range map[string]clienttest.Key{"schemas": kS, "matches": kM} {
		if _, err := op.With(client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}); err != nil {
			t.Fatal(err)
		}
	}
	all := []string{"read", "create", "append", "purge", "config", "branch"}
	sc := s.Client(t, client.WithBearer(kS.Grant(t, s.Now(), "user:s", []string{"schemas", "schemas-r7"}, all)))
	mc := s.Client(t, client.WithBearer(kM.Grant(t, s.Now(), "user:m", []string{"matches", "matches-r7"}, all)))
	if _, err := sc.CreateBranch(ctx, "schemas", client.BranchRequest{Name: "schemas-r7",
		Patches: []any{map[string]any{"op": "add", "path": "/drafts", "value": map[string]any{"for": []any{"matches-r7"}}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}); err != nil {
		t.Fatal(err)
	}
	w, err := sc.CreateDoc(ctx, "schemas-r7", "team", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"$schema": "/r/schemas/team/rev/" + w.ID}
	if _, err := mc.CreateDoc(ctx, "matches-r7", "a", doc); err == nil {
		t.Fatal("a draft the writer can't read resolved")
	}
	reader := kS.Grant(t, s.Now(), "user:m", []string{"schemas-r7"}, []string{"read"})
	unrelated := kM.Grant(t, s.Now(), "user:m", []string{"matches"}, []string{"read"})
	if _, err := mc.CreateDoc(ctx, "matches-r7", "a", doc, client.WithSourceGrants(unrelated, reader)); err != nil {
		t.Fatal(err)
	}
	withSA := mc.With(client.WithSourceAuthorization(unrelated, reader))
	if _, err := withSA.CreateDoc(ctx, "matches-r7", "b", doc); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.Batch(ctx, "matches-r7", client.BatchRequest{SourceAuthorizations: []string{unrelated, reader},
		Items: []client.BatchItem{{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep([]any{map[string]any{"op": "add", "path": "", "value": doc}})}}}}, false); err != nil {
		t.Fatal(err)
	}
	// The resolver finds the draft for a caller that can read the branch.
	ref, _ := schema.ParseRef("/r/schemas/team/rev/" + w.ID)
	if b, err := sc.FindDraft(ctx, ref); err != nil || b != "schemas-r7" {
		t.Fatalf("FindDraft: %q %v", b, err)
	}
	if b, err := sc.IsBranch(ctx, "schemas-r7"); err != nil || !b {
		t.Fatalf("IsBranch: %v %v", b, err)
	}
	// The last copy can't be purged.
	_, err = sc.Purge(ctx, "schemas-r7", "team", w.ID, false)
	if !client.IsInUse(err) {
		t.Fatalf("purge: %v", err)
	}
	if ae, _ := client.AsAPIError(err); len(ae.Referencing()) != 0 {
		t.Fatalf("referencing %v shown to a caller who can't read it", ae.Referencing())
	}
}
