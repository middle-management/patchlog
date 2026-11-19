package tree_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// CONFORMANCE Access 85 at the tree service (SPEC §C.4 Operator grants,
// v0.86: "Any other request under one, at the origin or a service
// (§C.6), is 401, as for a key the namespace doesn't list. … Requests
// that ignore any grant, such as public reads, … ignore it too"). A
// listing of a private catalog under an operator grant, for the catalog
// or for "*", is 401, where a grant of the namespace's key reads it; a
// public catalog's listing ignores the grant. The tree service verifies
// a grant by the namespace's keys alone. (Its exchange is the catalog
// service's: catalog.TestV086OperatorGrantAtTheCatalogService.)
func TestV086OperatorGrantAtTheTreeService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	all := []string{"cat", "pubcat", "notes"}
	for ns, doc := range map[string]map[string]any{
		"notes":  {"read": "public", "keys": []any{k.Entry("*")}},
		"cat":    {"read": "grant", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"notes"}, "mode": "dag"}},
		"pubcat": {"read": "public", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"notes"}, "mode": "dag"}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})))
	must(w.CreateDoc(ctx, "notes", "a", map[string]any{"title": "A"}))
	for _, cat := range []string{"cat", "pubcat"} {
		must(w.CreateDoc(ctx, cat, "root", map[string]any{"title": "Root", "parents": []any{}}))
		must(w.CreateDoc(ctx, cat, "notes.a", map[string]any{"parents": []any{map[string]any{"href": "/r/" + cat + "/root"}}}))
	}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "notes")
	y := startSvc(t, sc, svcOpts{now: s.Now, catalog: "pubcat"})
	y.caughtUp("pubcat", "notes")

	if r := x.listingAs("/cat/children?of=root", k.Grant(t, s.Now(), "user:r", all, []string{"read"})); r.status != http.StatusOK {
		t.Fatalf("a reader of the private catalog: %d %v", r.status, r.body)
	}
	mint := func(ns ...any) string {
		return clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": ns, "can": []any{"read", "config"},
			"exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	for what, tok := range map[string]string{
		"an operator grant for the catalog": s.OperatorGrant(t, "cat"),
		"one that reads every namespace":    mint("cat", "pubcat", "notes"),
		"one for *":                         mint("*"),
	} {
		if r := x.listingAs("/cat/children?of=root", tok); r.status != http.StatusUnauthorized || r.body["children"] != nil {
			t.Errorf("%s, a listing of the private catalog: %d %v, want 401", what, r.status, r.body)
		}
		if r := y.listingAs("/pubcat/children?of=root", tok); r.status != http.StatusOK || names(r.body["children"]) != "notes.a" {
			t.Errorf("%s, a listing of the public catalog: %d %v, want it as without a grant", what, r.status, r.body)
		}
	}
}
