package tree_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// TestSealedPurged (§8.5, §10): a sealed namespace's log, long-polls and
// documents are 410 purged once it is purged, with head its purge-ns
// entry. The tree service takes that as the purge, at that head, for a
// trusted content namespace and for the catalog, following or started
// after the purge. Listings go on without the purged content namespace;
// the purged catalog answers 410 purged after the read check, which the
// core makes, as the service can't read the catalog's document any more.
func TestSealedPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"cat", "sec"} {
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat", "sec"}, []string{"read", "create", "config", "purge-ns"})),
		client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	createNonced(t, w, "sec", "a", map[string]any{"title": "A"})
	createNonced(t, w, "cat", "sec.a", map[string]any{"parents": parents("root")})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat", "sec"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	start := func() *svc { return startSvc(t, sc, svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")}) }
	x := start()
	x.caughtUp("cat", "sec")
	purge := func(ns string) string {
		must(w.PatchConfig(ctx, ns, must(w.NSHead(ctx, ns)).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		return must(w.PurgeNamespace(ctx, ns, must(w.NSHead(ctx, ns)).ID))
	}
	full := k.Grant(t, s.Now(), "user:r", []string{"cat", "sec"}, []string{"read"})

	// The content namespace: purged, and the catalog's listings go on.
	secHead := purge("sec")
	waitFor(t, "the content purge", func() bool { return x.s.Checkpoint("sec") == secHead })
	// Its items are purged, not never seen, as from the purge-ns entry.
	if st, _, err := x.s.ItemState(ctx, "sec", "a"); err != nil || st != tree.ItemPurged {
		t.Fatalf("item state of sec.a after the purge: %d %v", st, err)
	}
	// One started after the purge never sees its items, nor its log: every
	// name of the purged namespace is purged, as at the core, and so is a
	// name the following one never saw. Its placements dangle as purged.
	y := start()
	waitFor(t, "started after: the content purge", func() bool { return y.s.Checkpoint("sec") == secHead })
	for name, x := range map[string]*svc{"following": x, "started after": y} {
		for _, item := range []string{"a", "never"} {
			if st, _, err := x.s.ItemState(ctx, "sec", item); err != nil || st != tree.ItemPurged {
				t.Errorf("%s: item state of sec.%s after the purge: %d %v", name, item, st, err)
			}
		}
		x.s.View(func(g *tree.Graph, _ map[string]string) {
			if n := g.Node("sec.a"); n == nil || n.Dangling != "purged" {
				t.Errorf("%s: the placement of sec.a: %+v", name, n)
			}
		})
	}
	y.stop()
	if r := x.raw("/cat/roots", full); r.status != 302 {
		t.Fatalf("listing after the content purge: %d %v", r.status, r.body)
	}

	// The catalog.
	catHead := purge("cat")
	other := k.Grant(t, s.Now(), "user:o", []string{"sec"}, []string{"read"})
	writer := k.Grant(t, s.Now(), "user:n", []string{"cat"}, []string{"create"})
	// A grant that reads some items only passes the service's read check
	// too, as for a catalog purged at rest.
	fixed := k.Grant(t, s.Now(), "user:f", []string{"cat"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "root"}}})
	for name, x := range map[string]*svc{"following": x, "started after": start()} {
		// One started after learns no trust from a catalog it can't read.
		waitFor(t, name+": the purge", func() bool { return x.s.Checkpoint("cat") == catHead })
		for _, tok := range []string{full, fixed} {
			if r := x.raw("/cat/roots", tok); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != catHead || r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: %d %v %v", name, r.status, r.body, r.header)
			}
		}
		for tok, want := range map[string]int{"": 401, other: 403, writer: 403} {
			if r := x.raw("/cat/roots", tok); r.status != want {
				t.Errorf("%s: token %.10q: %d %v, want %d", name, tok, r.status, r.body, want)
			}
		}
	}
}
