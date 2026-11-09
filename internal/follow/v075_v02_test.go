package follow_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/ids"
)

type v075CP string

func (c v075CP) Load(context.Context, string, string) (string, error) { return string(c), nil }

// A follower whose grant has become a partial reader's is redirected from
// the namespace's long-poll and events to the filtered log (§B.11.9 URLs),
// which isn't chain-verifiable and whose batches hold only visible items
// (§10). It must not apply such a batch as the whole of it: Run stops with
// the redirect, a *client.FilteredError naming gs, and applies nothing, in
// both modes.
func TestV075FollowerRefusesFilteredLog(t *testing.T) {
	id := func(s string) string { return ids.Hash(nil, []byte(s)).String() }
	h, b, gs, at := id("H"), id("B"), id("gs"), id("at")
	// A batch that wrote pub-a and a hidden resource; the filtered log
	// shows pub-a only.
	batch := map[string]any{"id": b, "prev": h, "kind": "batch", "author": "a", "created": "2026-01-01T00:00:00.000Z",
		"entries": []any{map[string]any{"kind": "head", "resource": "pub-a", "target": id("t")}}}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch p := r.URL.Path; {
		case p == "/":
			json.NewEncoder(w).Encode(map[string]any{"spec": "0.75", "auth": "grants", "origin": "https://o.example"})
		case p == "/ns/m":
			w.Header().Set("ETag", `"`+h+`"`)
			w.Header().Set("Location", "/ns/m/rev/"+h)
			w.WriteHeader(302)
		case p == "/ns/m/rev/"+h+"/heads":
			http.Redirect(w, r, "/ns/m/g/"+gs+"/at/"+at+"/heads?"+r.URL.RawQuery, 302)
		case p == "/ns/m/log" && q.Get("live") == "long-poll", p == "/ns/m/events":
			http.Redirect(w, r, "/ns/m/g/"+gs+p[len("/ns/m"):]+"?"+r.URL.RawQuery, 302)
		case p == "/ns/m/g/"+gs+"/log" && q.Get("since") == h:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Namespace-Revision", b)
			w.Header().Set("X-Cursor", "1")
			json.NewEncoder(w).Encode([]any{batch})
		case p == "/ns/m/g/"+gs+"/events":
			w.Header().Set("Content-Type", "text/event-stream")
			d, _ := json.Marshal(batch)
			fmt.Fprintf(w, "id: %s\nevent: batch\ndata: %s\n\n", b, d)
		default:
			w.Header().Set("X-Cursor", "2")
			w.WriteHeader(204)
		}
	}))
	defer hs.Close()
	c, err := client.New(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"long-poll", "sse"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var mu sync.Mutex
		var applied []*follow.Batch
		opts := []follow.Option{follow.WithOnError(func(string, error) {}), follow.WithBackoff(time.Millisecond, time.Millisecond)}
		if mode == "sse" {
			opts = append(opts, follow.WithSSE())
		}
		f := follow.New(c, "m", v075CP(h), follow.HandlerFunc(func(_ context.Context, bt *follow.Batch) error {
			mu.Lock()
			applied = append(applied, bt)
			mu.Unlock()
			cancel()
			return nil
		}), opts...)
		err := f.Run(ctx)
		timedOut := ctx.Err() != nil
		cancel()
		mu.Lock()
		if len(applied) > 0 {
			t.Fatalf("%s: the follower applied a filtered batch as the namespace's own: checkpoint %s, %d change(s) (Run: %v)",
				mode, applied[0].NewCheckpoint, len(applied[0].Units[0].Changes()), err)
		}
		mu.Unlock()
		if fe, ok := client.AsFiltered(err); !ok || fe.GS != gs || timedOut {
			t.Fatalf("%s: Run: %v (timed out %v), not the redirect to the filtered log", mode, err, timedOut)
		}
	}
}
