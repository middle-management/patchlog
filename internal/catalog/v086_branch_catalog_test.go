package catalog_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/tree"
)

// CONFORMANCE Tree 150 (SERVICES §B.5 Previews, §B.3, TOOLS §F.8, v0.86):
// "No content grant is issued from cat-b". A catalog service whose
// catalog is branch cat-b of cat lists the base's tree, the base's links
// counting as the branch's own, so the base's $access reaches every node
// there: a match-desk caller's desk role on season would give her a
// content grant for matches/derby, from a tree nobody merged. It issues
// none: a content want, and a content item at POST /read-grants, is 404
// not_offered, with no grant and no key. The branch's own nodes are
// organised as before. Before v0.86 nothing refused; the base's nodes
// were roots and orphans in the branch, which hid most of them.
func TestV086BranchCatalogIssuesNoContentGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	all := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat", "cat-b"}, []string{"read", "branch"})))
	must(all.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-b"}))

	svcClient := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat-b", "cat", "matches"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	svc, err := catalog.Open(ctx, catalog.Options{
		Tree: tree.Options{Client: svcClient, Catalog: "cat-b", DB: filepath.Join(t.TempDir(), "branch.db"), Now: w.s.Now, CheckerTTL: time.Millisecond,
			Logf:          func(f string, a ...any) { t.Logf(f, a...) },
			FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}, Purger: w},
		Key: w.cat.Priv, Kid: "catalog-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(svc.Handler())
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.Run(rctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); svc.Close() })
	for _, ns := range []string{"cat-b", "matches"} {
		waitFor(t, "the branch's service to catch up with "+ns, func() bool {
			h, err := w.ops.NSHead(ctx, ns)
			if ns == "cat-b" {
				h, err = all.NSHead(ctx, ns)
			}
			return err == nil && svc.Tree().Checkpoint(ns) == h.ID
		})
	}
	b := &world{t: t, http: hs}

	bob := func(ns string) string {
		return w.idp.Grant(t, w.s.Now(), "user:bob", []string{ns}, idCan, map[string]any{"groups": toAny("match-desk")})
	}
	adm := w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat-b", "matches"}, []string{"read"}, map[string]any{"groups": toAny("catalog-admins")})
	// The branch lists the base's tree: derby is under season there.
	if r, _ := b.follow("/cat-b/children?of=season", adm); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared,rumours" {
		t.Fatalf("the branch's listing of season: %d %v", r.status, r.body)
	}
	for _, want := range []string{"read", "append"} {
		req := map[string]any{"item": "/r/matches/derby", "want": toAny(want)}
		if r := w.do("POST", "/grants", bob("cat"), req); r.status != 200 || r.body["grant"] == nil {
			t.Fatalf("the base's service, want %s: %d %v", want, r.status, r.body)
		}
		if r := b.do("POST", "/grants", adm, req); r.status != 404 || r.body["code"] != "not_offered" || r.body["grant"] != nil {
			t.Errorf("the branch's service, an admin's want %s: %d %v, want 404 not_offered and no grant", want, r.status, r.body)
		}
		if r := b.do("POST", "/grants", bob("cat-b"), req); r.status != 404 || r.body["code"] != "not_offered" || r.body["grant"] != nil {
			t.Errorf("the branch's service, want %s: %d %v, want 404 not_offered and no grant", want, r.status, r.body)
		}
	}
	items := map[string]any{"items": toAny("/r/matches/derby")}
	if r := w.do("POST", "/read-grants", bob("cat"), items); r.status != 200 || entry(r, 0)["grant"] == nil {
		t.Fatalf("the base's service, POST /read-grants: %d %v", r.status, r.body)
	}
	r := b.do("POST", "/read-grants", bob("cat-b"), items)
	if e := entry(r, 0); r.status != 200 || e["status"] != float64(404) || e["code"] != "not_offered" || e["grant"] != nil || e["keys"] != nil || e["public"] != nil {
		t.Errorf("the branch's service, POST /read-grants: %d %v, want its item 404 not_offered with no grant and no key", r.status, r.body)
	}
	// Organising the branch's own nodes is still offered.
	if r := b.do("POST", "/grants", adm, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}); r.status != 200 || r.body["grant"] == nil {
		t.Errorf("the branch's service, a move: %d %v, want a grant", r.status, r.body)
	}
}
