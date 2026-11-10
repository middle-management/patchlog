package tree_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
)

// W3X (P29 ENC-38 x the tree service; §E.2.6, §12.1): the catalog a tree
// service follows is raised from none to sealed (until v0.81 to e2e,
// which is 422 since v0.78), and the service holds no keys and fetches
// none (client.StaticKeys), so it lacks the catalog's keys as configured. Running through the raise, it skips the catalog and stops
// following it, as it does when it starts: listings answer 404, not 503
// behind forever, and a restart answers the same.
func TestW3XTreeCatalogRaisedToE2EWhileFollowed(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, KeyStore: ks})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	must(c.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	db := filepath.Join(t.TempDir(), "tree.db")
	sc := s.Client(t, client.WithAuthor("svc"), client.WithKeys(client.StaticKeys()))
	x := startSvc(t, sc, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	x.get("/cat/roots", "")
	h := must(c.NSHead(ctx, "cat"))
	must(c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/encryption",
		"value": map[string]any{"level": "sealed", "epoch": 1}}}))
	roots := func(y *svc) resp {
		r := y.raw("/cat/roots", "")
		for r.status == 302 {
			r = y.raw(r.header.Get("Location"), "")
		}
		return r
	}
	// Behind at most while the config entry is being applied, then 404
	// for good.
	waitFor(t, "404 for the raised catalog", func() bool { return roots(x).status == 404 })
	for i := 0; i < 20; i++ {
		if r := roots(x); r.status != 404 {
			t.Fatalf("running through the raise: %d %v (Retry-After %q), want 404 as after a restart", r.status, r.body, r.header.Get("Retry-After"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	x.stop()
	y := startSvc(t, sc, svcOpts{db: db})
	waitFor(t, "404 after a restart", func() bool { return roots(y).status == 404 })
}
