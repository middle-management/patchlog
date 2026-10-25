package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
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

// §7.3, §E.2.2 (RH-33; review): a server older than v0.73 sends a resource
// stream's purge and prune events with the namespace entry's id as their
// id: and, sealed, as the namespace range [prev, id] of that one entry
// under K_e. ResourceEvents still opens that form for a K_e holder, checks
// the entry against the range, and delivers the events as a current
// server sends them: no ID, data without id and prev.
func TestV073P28OlderServerPurgePruneEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var body atomic.Pointer[string] // the older server's stream, once set
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if b := body.Load(); r.URL.Path == "/r/s/a/events" && b != nil {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				fmt.Fprint(w, *b)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Wrap: wrap})
	k := clienttest.NewKey("k")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "s")))
	must(opc.CreateNamespace(ctx, "s", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	g := k.Grant(t, s.Now(), "user:w", []string{"s"}, []string{"create", "append", "delete", "purge", "prune", "read"})
	w := s.Client(t, client.WithBearer(g))
	r1 := must(w.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"v": 1.0}))))
	r2 := must(w.Append(ctx, "s", "a", r1.ID, nonced(ops(op("replace", "/v", 2.0)))))
	n1 := must(w.NSHead(ctx, "s")).ID

	// K_e of the current epoch, as POST /keys gives it to this grant.
	req, _ := http.NewRequest("POST", s.URL+"/ns/s/keys", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+g)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ka struct{ Keys []struct{ Kid, Key string } }
	err = json.NewDecoder(res.Body).Decode(&ka)
	res.Body.Close()
	if err != nil || len(ka.Keys) == 0 {
		t.Fatalf("keys %+v %v", ka, err)
	}
	ke, _ := base64.RawURLEncoding.DecodeString(ka.Keys[0].Key)

	// The older form of one event: its entry sealed as the range
	// [prev, id], the entry's id as id: (unless lie names another).
	event := func(kind, prev, id, lie string, sealed bool) string {
		t.Helper()
		entry := map[string]any{"id": id, "prev": prev, "kind": kind, "resource": "a", "target": r2.ID, "author": "user:w", "created": "2026-10-04T12:00:00.000Z"}
		line := id
		if lie != "" {
			line = lie
		}
		if !sealed {
			return "event: " + kind + "\nid: " + line + "\ndata: " + string(jsonv.Canonical(jsonv.FromGo(entry))) + "\n\n"
		}
		jwe, err := seal.Seal(ke, ka.Keys[0].Kid, seal.RangePL("s", prev, line), jsonv.Canonical(jsonv.FromGo([]any{entry})))
		if err != nil {
			t.Fatal(err)
		}
		return "event: " + kind + "\nid: " + line + "\ndata: " + jwe + "\n\n"
	}
	stream := func(b string) ([]client.Event, error) {
		t.Helper()
		body.Store(&b)
		r := s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil)))
		ectx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var got []client.Event
		err := r.ResourceEvents(ectx, "s", "a", r2.ID, func(ev client.Event) error {
			got = append(got, ev)
			return nil
		})
		return got, err
	}
	check := func(what string, got []client.Event, kinds ...string) {
		t.Helper()
		if len(got) != len(kinds) {
			t.Fatalf("%s: events %+v", what, got)
		}
		for i, ev := range got {
			m, _ := ev.Data.(map[string]any)
			if ev.Type != kinds[i] || ev.ID != "" || m["kind"] != kinds[i] || m["resource"] != "a" || m["target"] != r2.ID || m["id"] != nil || m["prev"] != nil {
				t.Fatalf("%s: event %d %+v", what, i, ev)
			}
		}
	}

	// Sealed: a prune, then a purge.
	got, err := stream(event("prune", n1, r1.ID, "", true) + event("purge", r1.ID, r2.ID, "", true))
	if err != nil {
		t.Fatalf("sealed older events: %v", err)
	}
	check("sealed", got, "prune", "purge")

	// Plain: delivered as a current server sends them.
	got, err = stream(event("prune", n1, r1.ID, "", false) + event("purge", r1.ID, r2.ID, "", false))
	if err != nil {
		t.Fatalf("plain older events: %v", err)
	}
	check("plain", got, "prune", "purge")

	// An entry that is not the one its range names is refused.
	if _, err := stream(event("purge", n1, r1.ID, r2.ID, true)); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("sealed older event whose entry is another: %v", err)
	}
	// A range form without an id: line can't be bound.
	b := strings.Replace(event("purge", n1, r1.ID, "", true), "id: "+r1.ID+"\n", "", 1)
	if _, err := stream(b); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("sealed older event without id: %v", err)
	}
}
