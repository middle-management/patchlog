package merge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// SERVICES-14/TOOLS-3 (§F.8, Open 106): any catalog batch of an
// end-to-end catalog goes only with an approver in catalog-admins. A
// batch that only unplaces an item, which needs no catalog-admins
// elsewhere, is submitted under the admin's grant narrowed with the merge
// service's via (not refused as not offered); without an admin's grant,
// or with a grant of someone outside catalog-admins, it is ErrAdminNeeded.
func TestV074E2ECatalogUnplaceUnderAdminGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	x := c.E2E(priv)
	mustDo := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mustDo(c.CreateNamespace(ctx, "cat", map[string]any{"encryption": map[string]any{"level": "e2e"},
		"catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"},
		"roles":   map[string]any{"desk": map[string]any{"move": true, "place": true}}}))
	mustDo(x.InitKeyring(ctx, "cat"))
	mustDo(x.CreateDocSealed(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	mustDo(x.CreateDocSealed(ctx, "cat", "matches.cup", map[string]any{"parents": []any{map[string]any{"href": "/r/cat/root"}}}))
	mustDo(c.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-r1"}))
	mustDo(x.InitKeyring(ctx, "cat-r1"))
	h, err := c.Head(ctx, "cat-r1", "matches.cup")
	if err != nil {
		t.Fatal(err)
	}
	mustDo(c.Delete(ctx, "cat-r1", "matches.cup", h.ID))
	p, err := NewPlan(ctx, c, "cat", "cat-r1", Options{E2E: x, Resources: []string{"matches.cup"}})
	if err != nil || p.TargetLevel != "e2e" || len(p.Items()) != 1 {
		t.Fatalf("plan %+v: %v", p, err)
	}
	idp := clienttest.NewKey("idp")
	admin := idp.Grant(t, time.Now(), "user:ada", []string{"cat"}, []string{"create", "append", "delete", "restore"},
		map[string]any{"groups": []any{"catalog-admins"}})
	opt := ReleaseOptions{Granter: noGranter{t}, AdminGrant: admin, Via: "svc:merge"}
	if err := grantFor(ctx, c, opt, "cat", p); err != nil || p.opt.BatchClient == nil {
		t.Fatalf("an unplace under the admin's grant: %v", err)
	}
	g, err := grant.Decode(p.opt.BatchClient.Bearer(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if g.Blocks[0].Sub != "user:ada" || len(g.Blocks) != 2 || g.Blocks[1].Via != "svc:merge" {
		t.Fatalf("the batch's grant: %+v", g.Blocks)
	}
	for name, ag := range map[string]string{
		"no admin grant":     "",
		"not catalog-admins": idp.Grant(t, time.Now(), "user:eve", []string{"cat"}, []string{"delete"}, map[string]any{"groups": []any{"match-desk"}}),
	} {
		p.opt.BatchClient = nil
		opt.AdminGrant = ag
		if err := grantFor(ctx, c, opt, "cat", p); !errors.Is(err, ErrAdminNeeded) || p.opt.BatchClient != nil {
			t.Errorf("%s: %v, want ErrAdminNeeded", name, err)
		}
	}
}
