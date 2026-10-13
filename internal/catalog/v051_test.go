package catalog_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
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
