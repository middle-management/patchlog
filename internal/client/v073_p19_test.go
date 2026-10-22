package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// serveJSON answers every request with body as JSON.
func serveJSON(t *testing.T, body func(r *http.Request) any) *client.Client {
	t.Helper()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body(r))
	}))
	t.Cleanup(hs.Close)
	c, err := client.New(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Resource and namespace log entries carry via, the delegatees of the
// grant they were written under (§7.1, §7.4); entries without it, and those
// of servers before v0.63, have none (RH-9).
func TestV073EntriesVia(t *testing.T) {
	t.Parallel()
	a := ids.Hash(nil, []byte("a")).String()
	b := ids.Hash(nil, []byte("b")).String()
	c := serveJSON(t, func(r *http.Request) any {
		if r.URL.Path == "/r/n/x/rev/"+b+"/log" {
			return []any{
				map[string]any{"id": a, "kind": "rev", "patches": []any{}, "author": "alice", "via": []any{"svc:a", "svc:b"}, "created": "2026-01-01T00:00:00.000Z"},
				map[string]any{"id": b, "parent": a, "kind": "rev", "patches": []any{}, "author": "alice", "created": "2026-01-01T00:00:00.000Z"},
			}
		}
		return []any{
			map[string]any{"id": a, "kind": "head", "resource": "x", "target": a, "author": "alice", "via": []any{"svc:a"}, "created": "2026-01-01T00:00:00.000Z"},
			map[string]any{"id": b, "prev": a, "kind": "head", "resource": "x", "target": b, "author": "alice", "created": "2026-01-01T00:00:00.000Z"},
		}
	})
	lg, err := c.Log(context.Background(), "n", "x", b, "")
	if err != nil || len(lg) != 2 {
		t.Fatalf("log %v, %v", lg, err)
	}
	if !slices.Equal(lg[0].Via, []string{"svc:a", "svc:b"}) || lg[1].Via != nil {
		t.Errorf("resource entries via %v, %v", lg[0].Via, lg[1].Via)
	}
	nl, err := c.NSLog(context.Background(), "n", b, "")
	if err != nil || len(nl) != 2 {
		t.Fatalf("namespace log %v, %v", nl, err)
	}
	if !slices.Equal(nl[0].Via, []string{"svc:a"}) || nl[1].Via != nil {
		t.Errorf("namespace entries via %v, %v", nl[0].Via, nl[1].Via)
	}
}

// HeadsPage reads { heads, next? } (§7.4), and { items, next? } from
// servers before v0.65, which a remote branch's base may run (RH-10).
func TestV073HeadsPageShapes(t *testing.T) {
	t.Parallel()
	nsID := ids.Hash(nil, []byte("n")).String()
	for key, want := range map[string]string{"heads": "a", "items": "b"} {
		c := serveJSON(t, func(r *http.Request) any {
			return map[string]any{key: []any{map[string]any{"resource": want, "kind": "head", "target": nsID}}, "next": want}
		})
		items, next, err := c.HeadsPage(context.Background(), "n", nsID, "")
		if err != nil || len(items) != 1 || items[0].Resource != want || next != want {
			t.Errorf("%s: %v %q %v", key, items, next, err)
		}
	}
}
