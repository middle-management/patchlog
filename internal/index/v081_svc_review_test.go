package index_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §A.4 Unavailable namespaces, §E.2.6: a query of a sealed namespace
// whose keys the index lacks as configured is 404, running through the
// raise as after a restart, and /_status says it is skipped. Here the
// index holds no keys and fetches none (client.StaticKeys). Queried at
// once, the first query after the raise, made before the follower fails
// on the entry, reads r's document, sealed, in its read check: r is
// decided then (lacksKeys), never 502. Left alone, the follower's failure
// on the entry decides it.
func TestV081SvcIndexRaisedToSealedWhileFollowed404(t *testing.T) {
	for _, queried := range []bool{true, false} {
		name := "queried"
		if !queried {
			name = "follower"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, KeyStore: keyStore(t)})
			c := s.Client(t, client.WithAuthor("admin"))
			for _, ns := range []string{"r", "p"} {
				must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
				must(c.CreateDoc(ctx, ns, "a", map[string]any{"title": "zebra"}))
			}
			db := filepath.Join(t.TempDir(), "i.db")
			sc := s.Client(t, client.WithAuthor("svc"), client.WithKeys(client.StaticKeys()))
			x := startSvc(t, sc, svcOpts{db: db, ns: []string{"r", "p"}, untyped: true})
			x.caughtUp("r")
			x.caughtUp("p")
			h := must(c.NSHead(ctx, "r"))
			must(c.PatchConfig(ctx, "r", h.Config, []any{map[string]any{"op": "add", "path": "/encryption",
				"value": map[string]any{"level": "sealed", "epoch": 1}}}))
			skipped := func() bool {
				return x.raw("/_status", "").body["namespaces"].([]any)[1].(map[string]any)["skipped"] == true
			}
			follow := func(path string) resp {
				r := x.raw(path, "")
				for r.status == 302 {
					r = x.raw(r.header.Get("Location"), "")
				}
				return r
			}
			if !queried {
				waitFor(t, "r skipped", skipped)
			}
			var last resp
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				last = follow("/r")
				if last.status != 503 && last.status != 200 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if last.status != 404 {
				t.Fatalf("running through the raise to sealed without keys: %d %v, want 404 (§A.4)", last.status, last.body)
			}
			if !skipped() {
				t.Errorf("status of r after the raise: %v", x.raw("/_status", "").body)
			}
		})
	}
}
