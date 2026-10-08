package follow_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// A follower works over a sealed namespace (Addendum E.2) when its client
// has keys: namespace logs, long-polls, events and documents decrypt
// transparently.
func TestFollowSealed(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"long-poll", "sse"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			ks, err := keystore.New(keystore.Generate())
			if err != nil {
				t.Fatal(err)
			}
			s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, KeyStore: ks})
			c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
			must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
			nonce := func(p []any) []any {
				return append(p, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
			}
			a := must(c.Create(ctx, "main", "a", nonce(client.GenesisPatches(map[string]any{"n": 0}))))
			must(c.Append(ctx, "main", "a", a.ID, nonce(rep("/n", 1))))

			cp := &follow.MemoryCheckpoints{}
			rec := &recorder{cp: cp}
			opts := []follow.Option{follow.WithBackoff(time.Millisecond, 10*time.Millisecond)}
			if mode == "sse" {
				opts = append(opts, follow.WithSSE())
			}
			r := start(follow.New(c, "main", cp, rec, opts...))
			waitFor(t, "catch-up", checkpointIs(t, cp, c, "main"))
			if got := rec.kinds("main"); fmt.Sprint(got) != "[config head head]" {
				t.Fatalf("catch-up kinds %v", got)
			}
			first := rec.snapshot()[0].Units[0]
			if enc, _ := first.Config.Value["encryption"].(map[string]any); enc["level"] != "sealed" {
				t.Fatalf("config %+v", first.Config)
			}
			// Live entries, then the documents they point at.
			h := must(c.Head(ctx, "main", "a"))
			w := must(c.Append(ctx, "main", "a", h.ID, nonce(rep("/n", 2))))
			waitFor(t, "live", checkpointIs(t, cp, c, "main"))
			bs := rec.snapshot()
			last := bs[len(bs)-1].Units
			if tg := last[len(last)-1].Entry.Target; tg != w.ID {
				t.Fatalf("live target %s want %s", tg, w.ID)
			}
			if d := must(c.Doc(ctx, "main", "a", w.ID)); d.Value.(map[string]any)["n"] != 2.0 {
				t.Fatalf("doc %s", d.Raw)
			}
			r.stop(t)
		})
	}
}
