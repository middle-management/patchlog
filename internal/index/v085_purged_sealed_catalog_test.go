package index_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// SERVICES §B.11.9 Where (v0.85, Open 88): "A purged catalog's
// catalog.trust is the last one the origin stored. A service reads it
// from the catalog's document at its purge head where the origin serves
// that, and one it can't read there counts as no catalog." matches
// trusts the sealed catalog cat-sec alone, which the index follows only
// for visibility: while cat-sec lives, li, a partial reader, is
// redirected under her g: marker; once it is purged, its document 410 at
// its purge head, matches has no catalog here, and li has no marker
// (403), on the index that saw the purge and on one started after it on
// the same database. Before v0.85 the trust the index had read while
// cat-sec lived kept matches covered and dark (302).
func TestV085PurgedSealedCatalogIsNoCatalog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k, rd, cat := clienttest.NewKey("k"), clienttest.NewKey("rd"), clienttest.NewKey("catalog-01")
	mk := func(ns string, doc map[string]any) {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	mk("schemas", map[string]any{"read": "public", "keys": []any{k.Entry("*")}})
	mk("cat-sec", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"matches"}},
		"encryption": map[string]any{"level": "sealed"}})
	e := rd.Entry("read")
	e["rules"] = []any{v77TypeRule}
	at := cat.Entry("read")
	at["requireAt"], at["maxTtl"], at["rules"] = "cat-sec", "PT15M", []any{v77TypeRule}
	mk("matches", map[string]any{"read": "grant", "keys": []any{k.Entry("*"), at, e},
		"roles":    map[string]any{"reader": map[string]any{"can": []any{"read"}}},
		"catalogs": map[string]any{"cat-sec": map[string]any{"place": []any{}}}})
	li := rd.Grant(t, s.Now(), "user:li", []string{"matches"}, []string{"read"}, map[string]any{"groups": []any{"fans"}, "roles": []any{"reader"}})
	all := []string{"schemas", "cat-sec", "matches"}
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:root", all, []string{"read", "create", "config", "purge-ns"})),
		client.WithKeys(client.NewKeys(nil)))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	r := &trustRepair{t: t, db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, now: s.Now,
		core: s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", all, []string{"read"}, map[string]any{"enc": jwk})),
			client.WithKeys(client.NewKeys(priv))),
		mods: []func(*indexOpts){func(o *indexOpts) { o.Recipient = priv }}}
	x, stop := r.start(false, nil)
	x.caughtUp("matches")
	waitFor(t, "matches covered through the live catalog", func() bool { return r.status(x, li) == 302 })
	must(admin.PatchConfig(ctx, "cat-sec", must(admin.NSHead(ctx, "cat-sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(admin.PurgeNamespace(ctx, "cat-sec", must(admin.NSHead(ctx, "cat-sec")).ID))
	settled := func(x *svc, when string) {
		t.Helper()
		waitFor(t, "matches without a catalog, "+when, func() bool { return r.status(x, li) == 403 })
		time.Sleep(400 * time.Millisecond)
		if st := r.status(x, li); st != 403 {
			t.Errorf("li %s: %d, want 403 with no marker", when, st)
		}
	}
	settled(x, "once the sealed catalog is purged")
	stop()
	x, _ = r.start(false, nil)
	x.caughtUp("matches")
	settled(x, "on an index started after the purge")
}
