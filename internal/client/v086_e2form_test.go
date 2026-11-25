package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.86 Addendum E Levels ("accepting a base's ns only in an E3 sealed op
// read through"), §E.2.2, §E.3.1 (ENC-14: "and in nothing else";
// Encryption levels scenario 88): branch z of s. A delivery-sealed JWE
// served under z whose pl.ns or kid names s is rejected in every form
// §E.2.2 has. TestV085BaseNSNotAcceptedInE2Form shows the /rev document
// and the log entry; here are the event (a resource's revision and prune
// events, and a namespace's), the namespace range and the sealed blob
// header, each in three makes: the base's own bytes (kid and pl.ns both
// s), the base's key with the branch's pl, and the branch's key with the
// base's pl. The reader holds every key and refuses all the same; where
// the kid names s it asks nobody for a key first.
func TestV086BaseNSRejectedInEveryDeliveryForm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	keys := map[string][]byte{"s": seal.NewKey(), "z": seal.NewKey()}
	id := ids.Revision(nil, []byte("d")).String()
	nsID := ids.Revision(nil, []byte("ns")).String()
	blob := []byte("blob bytes")
	bid := client.BlobID("text/plain", "", blob)
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(blob))}
	for what, mk := range map[string]struct{ kidNS, plNS string }{
		"the base's own bytes":                {"s", "s"},
		"the base's key with the branch's pl": {"s", "z"},
		"the branch's own, which opens":       {"z", "z"},
		"the branch's key with the base's pl": {"z", "s"},
	} {
		kid := mk.kidNS + "#1"
		kr := must(seal.ResourceKey(keys[mk.kidNS], mk.kidNS, "d"))
		kn := must(seal.NamespaceKey(keys[mk.kidNS], mk.kidNS))
		// v0.89: an entry under its K_log, a blob under its K_blob (§E.2.1).
		entry := must(seal.Seal(must(seal.LogKey(kr, id)), kid, seal.ResourcePL(mk.plNS, "d", id, seal.KindRev), []byte(`{"id":"`+id+`","kind":"rev","parent":"","patches":[]}`)))
		prune := must(seal.Seal(kr, kid, seal.ResourceEventPL(mk.plNS, "d", "prune"), []byte(`{"kind":"prune","resource":"d","horizon":"`+id+`"}`)))
		nsEntry := `{"id":"` + nsID + `","prev":"","kind":"head","resource":"d","target":"` + id + `","author":"x","created":"2026-01-01T00:00:00.000Z"}`
		nsEvent := must(seal.Seal(kn, kid, seal.NamespaceEventPL(mk.plNS, nsID), []byte(nsEntry)))
		rng := must(seal.Seal(kn, kid, seal.RangePL(mk.plNS, "", nsID), []byte("["+nsEntry+"]")))
		sealedBlob := must(seal.SealBlob(must(seal.BlobKey(kr, bid)), kid, seal.BlobPL(mk.plNS, "d", bid), blob, false))
		var mu sync.Mutex
		var asked []string
		sse := func(w http.ResponseWriter, events ...[3]string) {
			w.Header().Set("Content-Type", "text/event-stream")
			for _, ev := range events {
				fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", ev[0], ev[1], ev[2])
			}
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			mu.Lock()
			asked = append(asked, r.Method+" "+p)
			mu.Unlock()
			switch {
			case r.Method == "GET" && p == "/r/z/d/events" && r.URL.Query().Get("since") == "":
				sse(w, [3]string{"revision", id, entry})
			case r.Method == "GET" && p == "/r/z/d/events":
				sse(w, [3]string{"prune", nsID, prune})
			case r.Method == "GET" && p == "/ns/z/events":
				sse(w, [3]string{"head", nsID, nsEvent})
			case r.Method == "GET" && p == "/ns/z/rev/"+nsID+"/log":
				w.Header().Set("Content-Type", seal.ContentType)
				io.WriteString(w, rng)
			case r.Method == "GET" && p == "/r/z/d/blob/"+bid+"/e/1":
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(sealedBlob)
			case r.Method == "POST" && strings.HasSuffix(p, "/keys"):
				w.Header().Set("Content-Type", "application/json")
				var ks []any
				for ns, k := range keys {
					ks = append(ks, map[string]any{"kid": ns + "#1", "key": base64.RawURLEncoding.EncodeToString(k)})
				}
				json.NewEncoder(w).Encode(map[string]any{"epoch": 1, "level": "sealed", "pad": false, "keys": ks})
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		c, err := client.New(srv.URL, client.WithKeys(client.NewKeys(nil)))
		if err != nil {
			t.Fatal(err)
		}
		if mk.kidNS == "z" && mk.plNS == "z" {
			// The stub's own check: what z seals as its own opens.
			got := 0
			count := func(client.Event) error { got++; return nil }
			if err := c.ResourceEvents(ctx, "z", "d", "", count); err != nil {
				t.Errorf("%s: a revision event: %v", what, err)
			}
			if err := c.ResourceEvents(ctx, "z", "d", id, count); err != nil {
				t.Errorf("%s: a prune event: %v", what, err)
			}
			if err := c.NSEvents(ctx, "z", "", func(client.NSEntry) error { got++; return nil }); err != nil {
				t.Errorf("%s: a namespace event: %v", what, err)
			}
			if es, _, _, err := c.NSLogPage(ctx, "z", nsID, ""); err != nil || len(es) != 1 {
				t.Errorf("%s: a namespace range: %+v %v", what, es, err)
			}
			if b, err := c.GetBlobRefEpoch(ctx, "z", "d", ref, 1); err != nil || string(b.Data) != string(blob) {
				t.Errorf("%s: a sealed blob: %+v %v", what, b, err)
			}
			if got != 3 {
				t.Errorf("%s: %d events delivered, want 3", what, got)
			}
			continue
		}
		none := func(client.Event) error { t.Errorf("%s: an event was delivered", what); return nil }
		if err := c.ResourceEvents(ctx, "z", "d", "", none); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s: a revision event: %v, want a mismatch", what, err)
		}
		if err := c.ResourceEvents(ctx, "z", "d", id, none); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s: a prune event: %v, want a mismatch", what, err)
		}
		if err := c.NSEvents(ctx, "z", "", func(client.NSEntry) error { t.Errorf("%s: a namespace event was delivered", what); return nil }); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s: a namespace event: %v, want a mismatch", what, err)
		}
		if es, _, _, err := c.NSLogPage(ctx, "z", nsID, ""); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s: a namespace range: %+v %v, want a mismatch", what, es, err)
		}
		if b, err := c.GetBlobRefEpoch(ctx, "z", "d", ref, 1); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s: a sealed blob header: %+v %v, want a mismatch", what, b, err)
		}
		mu.Lock()
		for _, a := range asked {
			if mk.kidNS == "s" && (strings.HasSuffix(a, "/keys") || strings.HasPrefix(a, "GET /ns/s")) {
				t.Errorf("%s: the reader asked %s before refusing", what, a)
			}
		}
		if len(asked) < 5 {
			t.Errorf("%s: only %v was asked", what, asked)
		}
		mu.Unlock()
	}
}
