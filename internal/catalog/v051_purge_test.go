package catalog_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
)

// A trusted content namespace that is purged leaves the catalog's grants
// working, sealed or not (§8.5): once a sealed one is purged its namespace
// documents are 410 purged, so the service reads no includes or keys from
// it any more. A move is decided as before, a restore of its item is 410
// as for any purged item, and other grants on its items are 410 too.
func TestSealedContentPurged(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.seed()
			w.doc("cat", "deskonly", map[string]any{"title": "Desk only", "parents": parents("root"), "$access": acc("group:match-desk", "desk")})
			w.start()
			w.caughtUp()
			ctx := context.Background()

			var copts []client.Option
			if sealed {
				copts = append(copts, client.WithKeys(client.NewKeys(nil)))
			}
			pc := w.s.Client(t, append(copts, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "config", "purge-ns"})))...)
			must(pc.PatchConfig(ctx, "matches", must(pc.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
			head := must(pc.PurgeNamespace(ctx, "matches", must(pc.NSHead(ctx, "matches")).ID))
			if _, err := pc.NSDoc(ctx, "matches", head); client.IsPurged(err) != sealed {
				t.Fatalf("the purged namespace's document: %v", err)
			}
			waitFor(t, "the purge", func() bool { return w.svc.Tree().Checkpoint("matches") == head })

			bob := w.caller("user:bob", "match-desk")
			w.issue(bob, map[string]any{"node": "rumours", "want": toAny("move"), "to": toAny("deskonly")}, 200)
			w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("restore")}, 410)
			if sealed {
				w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}, 410)
				w.issue(bob, map[string]any{"item": "/r/matches/fresh", "want": toAny("place"), "to": toAny("season")}, 410)
			}
		})
	}
}

// purge freezes and purges ns as the ops key, and waits until the service
// has taken the purge.
func (w *world) purge(ns string) string {
	w.t.Helper()
	ctx := context.Background()
	var copts []client.Option
	if w.sealed {
		copts = append(copts, client.WithKeys(client.NewKeys(nil)))
	}
	pc := w.s.Client(w.t, append(copts, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{ns}, []string{"read", "config", "purge-ns"})))...)
	must(pc.PatchConfig(ctx, ns, must(pc.NSHead(ctx, ns)).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	head := must(pc.PurgeNamespace(ctx, ns, must(pc.NSHead(ctx, ns)).ID))
	waitFor(w.t, "the purge of "+ns, func() bool { return w.svc.Tree().Checkpoint(ns) == head })
	return head
}

// TestPurgedCatalogEdgeGrants (§8.5, §B.11.5): once the catalog is purged,
// sealed or not, POST /edge-grants answers 410 purged with head after the
// read check, as its listings do; for a sealed one the core makes that
// check (its documents are 410). A read under a cookie minted before the
// purge is 410 purged too: the cookie stood for a subject set that could
// read, and is never sent to the core as an anonymous read.
func TestPurgedCatalogEdgeGrants(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
			w.seed()
			w.start()
			w.caughtUp()
			full := w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches"}, []string{"read"})
			bob := w.caller("user:bob", "match-desk")
			byName := map[string]*http.Cookie{}
			for name, tok := range map[string]string{"all": full, "bob": bob} {
				r, cks := w.exchange(tok, nil, "")
				if r.status != 200 || len(cks) != 1 {
					t.Fatalf("%s before the purge: %d %v", name, r.status, r.body)
				}
				byName[name] = cks[0]
				byName[name+" prefix"] = &http.Cookie{Name: prefixes(r)}
			}
			head := w.purge("cat")

			if r, cks := w.exchange(full, nil, ""); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != head || len(cks) != 0 ||
				r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("exchange after the purge: %d %v %v", r.status, r.body, r.header)
			}
			// The read check comes first.
			if r, _ := w.exchange("", nil, ""); r.status != 401 {
				t.Errorf("no grant: %d %v", r.status, r.body)
			}
			other := w.opsKey.Grant(t, w.s.Now(), "user:o", []string{"matches"}, []string{"read"})
			if r, _ := w.exchange(other, nil, ""); r.status != 403 {
				t.Errorf("a grant for matches only: %d %v", r.status, r.body)
			}
			for _, name := range []string{"all", "bob"} {
				path := byName[name+" prefix"].Name + "/at/" + head + "/roots"
				if r := w.withCookie(path, byName[name], nil); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != head ||
					r.header.Get("WWW-Authenticate") != "" {
					t.Errorf("%s: a cookie from before the purge: %d %v %v", name, r.status, r.body, r.header)
				}
			}
		})
	}
}

// TestPurgedContentKeepsAll (§8.5, §B.11.5): a purged trusted content
// namespace has no live items, so every reader reads it whole, sealed or
// not (its documents are 410 once a sealed one is purged): a reader of the
// catalog and every other trusted namespace keeps the unfiltered g/all
// listings and edge grants, and so does a reader that never read it.
func TestPurgedContentKeepsAll(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
			w.seed()
			w.start()
			w.caughtUp()
			full := w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches"}, []string{"read"})
			catOnly := w.opsKey.Grant(t, w.s.Now(), "user:c", []string{"cat"}, []string{"read"})
			if r := w.do("GET", "/cat/roots", full, nil); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/cat/g/all/") {
				t.Fatalf("before the purge: %d %v", r.status, r.header.Get("Location"))
			}
			if r := w.do("GET", "/cat/roots", catOnly, nil); r.status != 302 || strings.HasPrefix(r.header.Get("Location"), "/cat/g/all/") {
				t.Fatalf("a reader of the catalog only before the purge: %d %v", r.status, r.header.Get("Location"))
			}
			w.purge("matches")
			// The engine's clock stands still: a cookie issued at the very
			// instant the service came to trust a namespace counts as
			// issued before it.
			w.s.Clock.Advance(time.Second)
			for name, tok := range map[string]string{"full": full, "catalog only": catOnly} {
				r := w.do("GET", "/cat/roots", tok, nil)
				if loc := r.header.Get("Location"); r.status != 302 || !strings.HasPrefix(loc, "/cat/g/all/") {
					t.Errorf("%s after the purge: %d %v", name, r.status, loc)
					continue
				}
				if r, _ := w.follow("/cat/problems", tok); r.status != 200 {
					t.Errorf("%s: problems after the purge: %d %v", name, r.status, r.body)
				}
				r, cks := w.exchange(tok, nil, "")
				if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
					t.Errorf("%s: exchange after the purge: %d %v", name, r.status, r.body)
					continue
				}
				_, loc := w.follow("/cat/roots", tok)
				if r := w.withCookie(loc, cks[0], nil); r.status != 200 {
					t.Errorf("%s: g/all under the cookie: %d %v", name, r.status, r.body)
				}
			}
		})
	}
}
