package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §7.3, §E.2.2 (RH-33, ENC-5): a resource stream's purge and prune events
// carry the namespace entry that records them, without id and prev, and
// no id; in a sealed namespace sealed under the resource's K_r of the
// current epoch, which a grant for that resource alone opens.
func TestV073P28ResourcePurgePruneEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, level := range []string{"", "sealed"} {
		s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
		k := clienttest.NewKey("k")
		opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "s")))
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
		if level != "" {
			doc["encryption"] = map[string]any{"level": level, "pad": true}
		}
		must(opc.CreateNamespace(ctx, "s", doc))
		w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"s"}, []string{"create", "append", "delete", "prune", "purge", "read"})))
		r1 := must(w.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"v": 1.0}))))
		s.Clock.Advance(10 * time.Minute)
		r2 := must(w.Append(ctx, "s", "a", r1.ID, nonced(ops(op("replace", "/v", 2.0)))))

		// A grant that reads only a, and so holds only its K_r.
		fixed := k.Grant(t, s.Now(), "user:li", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
		pr := s.Client(t, client.WithBearer(fixed), client.WithKeys(client.NewKeys(nil)))
		ectx, cancel := context.WithTimeout(ctx, 10*time.Second)
		events := make(chan client.Event, 16)
		done := make(chan error, 1)
		go func() {
			done <- pr.ResourceEvents(ectx, "s", "a", r2.ID, func(ev client.Event) error {
				events <- ev
				return nil
			})
		}()
		time.Sleep(100 * time.Millisecond) // the stream follows from the head

		nextEv := func() client.Event {
			t.Helper()
			select {
			case ev := <-events:
				return ev
			case err := <-done:
				// An event sent just before the stream ended comes first.
				select {
				case ev := <-events:
					done <- err
					return ev
				default:
				}
				t.Fatalf("%s: stream ended: %v", level, err)
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: no event", level)
			}
			return client.Event{}
		}
		check := func(ev client.Event, kind, target string) {
			t.Helper()
			m, _ := ev.Data.(map[string]any)
			if ev.Type != kind || ev.ID != "" || m["kind"] != kind || m["resource"] != "a" || m["target"] != target || m["id"] != nil || m["prev"] != nil {
				t.Fatalf("%s: %s event %+v", level, kind, ev)
			}
			if (ev.JWE != "") != (level == "sealed") {
				t.Fatalf("%s: %s event sealed: %q", level, kind, ev.JWE)
			}
		}
		must(w.Prune(ctx, "s", "a", client.PruneRequest{Horizon: r2.ID}))
		check(nextEv(), "prune", r2.ID)
		tomb := must(w.Delete(ctx, "s", "a", r2.ID))
		if ev := nextEv(); ev.Type != "tombstone" || ev.ID != tomb.ID {
			t.Fatalf("%s: tombstone %+v", level, ev)
		}
		must(w.Purge(ctx, "s", "a", tomb.ID, false))
		check(nextEv(), "purge", tomb.ID)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: stream after purge: %v", level, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: stream still open after the purge", level)
		}
		cancel()
		if errors.Is(ectx.Err(), context.DeadlineExceeded) {
			t.Fatalf("%s: timed out", level)
		}
	}
}
