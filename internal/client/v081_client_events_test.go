package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// sseServer answers GET path with the SSE events given, each "type", "id"
// and data, and then ends the stream.
func sseServer(t *testing.T, path string, events [][3]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		for _, ev := range events {
			if ev[0] != "" {
				fmt.Fprintf(w, "event: %s\n", ev[0])
			}
			if ev[1] != "" {
				fmt.Fprintf(w, "id: %s\n", ev[1])
			}
			fmt.Fprintf(w, "data: %s\n\n", ev[2])
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// KEYS-6 = BYTES-3 (§E.2.2: "a namespace event's [plaintext] is its one
// entry"): a sealed namespace event is canonical(entry) under K_n with
// its own pl, {ns, event: id} (v0.82), and NSEvents parses it as the
// entry. The range form of v0.81, {ns, range: [prev, id]}, is refused,
// whatever its plaintext, and so is the one-element range as plaintext.
// The key is the one the client opens namespace content with
// (Keys.cached for resource "").
func TestV081NamespaceEventIsTheEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ke := seal.NewKey()
	keys := StaticKeys()
	keys.Add("s#1", ke)
	kn := keys.cached("s#1", "")
	id1, id2 := ids.Revision(nil, []byte("1")).String(), ids.Revision(nil, []byte("2")).String()
	entry := func(id, prev string) map[string]any {
		return map[string]any{"id": id, "prev": prev, "kind": "head", "resource": "a", "target": ids.Revision(nil, []byte("t"+id)).String(), "author": "x", "created": "2026-01-01T00:00:00.000Z"}
	}
	sealPL := func(pl seal.PL, plain any) string {
		jwe, err := seal.Seal(kn, "s#1", pl, jsonv.Canonical(jsonv.FromGo(plain)))
		if err != nil {
			t.Fatal(err)
		}
		return jwe
	}
	sealEv := func(id string, plain any) string { return sealPL(seal.NamespaceEventPL("s", id), plain) }
	read := func(events [][3]string) ([]NSEntry, error) {
		srv := sseServer(t, "/ns/s/events", events)
		c, err := New(srv.URL, WithKeys(keys))
		if err != nil {
			t.Fatal(err)
		}
		var got []NSEntry
		err = c.NSEvents(ctx, "s", "", func(e NSEntry) error { got = append(got, e); return nil })
		return got, err
	}
	got, err := read([][3]string{
		{"", id1, sealEv(id1, entry(id1, ""))},
		{"", id2, sealEv(id2, entry(id2, id1))},
	})
	if err != nil || len(got) != 2 || got[0].ID != id1 || got[1].ID != id2 || got[1].Prev != id1 || got[1].Resource != "a" {
		t.Fatalf("sealed entry objects: %+v %v", got, err)
	}
	// The one-element range form is not an event's plaintext.
	if _, err := read([][3]string{{"", id1, sealEv(id1, []any{entry(id1, "")})}}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a one-element range as an event: %v", err)
	}
	// v0.81's pl, the range [prev, id], is refused: with the entry and
	// with the range's own plaintext, the first event and a later one.
	for _, ev := range [][3]string{
		{"", id1, sealPL(seal.RangePL("s", "", id1), entry(id1, ""))},
		{"", id1, sealPL(seal.RangePL("s", "", id1), []any{entry(id1, "")})},
	} {
		if got, err := read([][3]string{ev}); !errors.Is(err, seal.ErrMismatch) || len(got) != 0 {
			t.Fatalf("an event under a range's pl: %+v %v", got, err)
		}
	}
	if got, err := read([][3]string{{"", id1, sealEv(id1, entry(id1, ""))}, {"", id2, sealPL(seal.RangePL("s", id1, id2), entry(id2, id1))}}); !errors.Is(err, seal.ErrMismatch) || len(got) != 1 {
		t.Fatalf("a later event under a range's pl: %+v %v", got, err)
	}
	// An event bound to another entry is refused, and one whose entry
	// isn't the one its pl names.
	if _, err := read([][3]string{{"", id2, sealEv(id1, entry(id2, id1))}}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("an event sealed for another entry: %v", err)
	}
	if _, err := read([][3]string{{"", id2, sealEv(id2, entry(id1, ""))}}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("an event carrying another entry: %v", err)
	}
}

// KEYS-6 (live.go): a resource stream's purge or prune event opens only as
// §E.2.2 seals it, under the resource's K_r with pl {ns, name, kind}. The
// namespace range form of servers before v0.73, with the entry's id as the
// event's id, is no longer opened.
func TestV081ResourceEventLegacyRangeRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ke := seal.NewKey()
	keys := StaticKeys()
	keys.Add("s#1", ke)
	nid := ids.Revision(nil, []byte("n")).String()
	m := map[string]any{"id": nid, "prev": "", "kind": "prune", "resource": "a", "author": "x", "created": "2026-01-01T00:00:00.000Z"}
	read := func(ev [3]string) (Event, error) {
		srv := sseServer(t, "/r/s/a/events", [][3]string{ev})
		c, err := New(srv.URL, WithKeys(keys))
		if err != nil {
			t.Fatal(err)
		}
		var got Event
		err = c.ResourceEvents(ctx, "s", "a", "", func(e Event) error { got = e; return nil })
		return got, err
	}
	for _, key := range [][]byte{ke, keys.cached("s#1", "")} {
		old, _ := seal.Seal(key, "s#1", seal.RangePL("s", "", nid), jsonv.Canonical(jsonv.FromGo([]any{m})))
		if _, err := read([3]string{"prune", nid, old}); !errors.Is(err, seal.ErrMismatch) && !errors.Is(err, seal.ErrDecrypt) {
			t.Fatalf("a pre-v0.73 prune event: %v", err)
		}
	}
	cur, _ := seal.Seal(keys.cached("s#1", "a"), "s#1", seal.ResourceEventPL("s", "a", seal.KindPrune), jsonv.Canonical(jsonv.FromGo(withoutIDPrev(m))))
	ev, err := read([3]string{"prune", "", cur})
	if d, _ := ev.Data.(map[string]any); err != nil || d["kind"] != "prune" || ev.ID != "" || strings.Contains(fmt.Sprint(d), nid) {
		t.Fatalf("a prune event: %+v %v", ev, err)
	}
}
