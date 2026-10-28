package merge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// noGranter fails a test that asks a catalog service for a merge grant.
type noGranter struct{ t *testing.T }

func (g noGranter) MergeGrant(context.Context, string, map[string]any, string) (*MergeGrantResult, error) {
	g.t.Fatal("asked the catalog service of an end-to-end catalog for a merge grant")
	return nil, nil
}

// TestV073E2ECatalogBatchesUnderAdminGrant (TC-45, scenario 48): an
// end-to-end catalog gets no merge grants and no batch check (§F.8), so
// the merge service submits a batch that needs catalog-admins (a widening
// move, a $access change, a restored node) under its AdminGrant, narrowed
// with its via, without asking the catalog service. Since v0.74 so does
// it any other batch of an end-to-end catalog (an unplace, a narrowing
// move), which goes only under a catalog-admins grant, never refused as
// not offered; without AdminGrant every one is ErrAdminNeeded.
func TestV073E2ECatalogBatchesUnderAdminGrant(t *testing.T) {
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
	parents := func(ps ...string) []any {
		out := []any{}
		for _, p := range ps {
			out = append(out, map[string]any{"href": "/r/cat/" + p})
		}
		return out
	}
	step := func(ops ...map[string]any) []any {
		out := []any{}
		for _, o := range ops {
			out = append(out, o)
		}
		return out
	}
	mustDo := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	headOf := func(ns, name string) *client.Head {
		t.Helper()
		h, err := c.Head(ctx, ns, name)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	mustDo(c.CreateNamespace(ctx, "cat", map[string]any{"encryption": map[string]any{"level": "e2e"},
		"catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"},
		"roles":   map[string]any{"desk": map[string]any{"move": true, "place": true}, "reader": map[string]any{}}}))
	mustDo(x.InitKeyring(ctx, "cat"))
	mustDo(x.CreateDocSealed(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	mustDo(x.CreateDocSealed(ctx, "cat", "season", map[string]any{"title": "Season", "parents": parents("root"),
		"$access": map[string]any{"group:match-desk": []any{"desk"}, "group:fan-club": []any{"reader"}}}))
	mustDo(x.CreateDocSealed(ctx, "cat", "derbies", map[string]any{"title": "Derbies", "parents": parents("root"),
		"$access": map[string]any{"group:match-desk": []any{"desk"}, "group:fan-club": []any{"desk"}}}))
	for _, n := range []string{"derby", "cup", "gone"} {
		mustDo(x.CreateDocSealed(ctx, "cat", "matches."+n, map[string]any{"parents": parents("season")}))
	}
	h := headOf("cat", "matches.gone")
	mustDo(c.Delete(ctx, "cat", "matches.gone", h.ID))
	admin := clienttest.NewKey("idp").Grant(t, time.Now(), "user:ada", []string{"cat"}, []string{"create", "append", "delete", "restore"},
		map[string]any{"groups": []any{"catalog-admins"}})

	for i, c2 := range []struct {
		name     string
		resource string
		write    func(ns string)
	}{
		{"a widening move", "matches.derby", func(ns string) {
			h := headOf(ns, "matches.derby")
			mustDo(x.AppendSealed(ctx, ns, "matches.derby", h.ID, step(map[string]any{"op": "replace", "path": "/parents", "value": parents("derbies")})))
		}},
		{"a $access change", "season", func(ns string) {
			h := headOf(ns, "season")
			mustDo(x.AppendSealed(ctx, ns, "season", h.ID, step(map[string]any{"op": "remove", "path": "/$access/group:fan-club"})))
		}},
		{"a re-placing", "matches.gone", func(ns string) {
			h := headOf(ns, "matches.gone")
			mustDo(x.RestoreSealed(ctx, ns, "matches.gone", h.ID, step(map[string]any{"op": "replace", "path": "", "value": map[string]any{"parents": parents("season")}})))
		}},
		{"an unplace", "matches.cup", func(ns string) {
			h := headOf(ns, "matches.cup")
			mustDo(c.Delete(ctx, ns, "matches.cup", h.ID))
		}},
		{"a narrowing move", "matches.cup", func(ns string) {
			h := headOf(ns, "matches.cup")
			mustDo(x.AppendSealed(ctx, ns, "matches.cup", h.ID, step(map[string]any{"op": "replace", "path": "/parents", "value": parents("root")})))
		}},
	} {
		br := "cat-r" + string(rune('1'+i))
		mustDo(c.CreateBranch(ctx, "cat", client.BranchRequest{Name: br}))
		mustDo(x.InitKeyring(ctx, br))
		c2.write(br)
		p, err := NewPlan(ctx, c, "cat", br, Options{E2E: x, Resources: []string{c2.resource}})
		if err != nil {
			t.Fatalf("%s: %v", c2.name, err)
		}
		if p.TargetLevel != "e2e" || len(p.Items()) != 1 {
			t.Fatalf("%s: plan %+v", c2.name, p)
		}
		opt := ReleaseOptions{Granter: noGranter{t}, AdminGrant: admin, Via: "svc:merge"}
		err = grantFor(ctx, c, opt, "cat", p)
		if err != nil || p.opt.BatchClient == nil {
			t.Errorf("%s: %v (batch client %v)", c2.name, err, p.opt.BatchClient)
		}
		// Without an admin's grant, every one is refused.
		p.opt.BatchClient = nil
		opt.AdminGrant = ""
		if err := grantFor(ctx, c, opt, "cat", p); !errors.Is(err, ErrAdminNeeded) || p.opt.BatchClient != nil {
			t.Errorf("%s without an admin's grant: %v", c2.name, err)
		}
	}
}
