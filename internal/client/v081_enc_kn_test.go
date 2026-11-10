package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// KEYS-3 (§E.2.1, §E.2.3): a reader holding K_e derives K_n, under which
// namespace documents, log ranges, events and grants are sealed; /keys
// never returns K_n. A stub server serves namespace s's document and log
// sealed under NamespaceKey(K_e, "s"); a StaticKeys client given K_e
// opens both, and K_e itself opens neither.
func TestV081ClientDerivesNamespaceKey(t *testing.T) {
	ke := seal.NewKey()
	kn, err := seal.NamespaceKey(ke, "s")
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"encryption":{"level":"sealed"},"read":"public"}`)
	cid := ids.Revision(nil, []byte(`[{"op":"add","path":"","value":{}}]`))
	nsID := ids.Hash(nil, []byte(`{"kind":"config"}`)).String()
	entry := map[string]any{"id": nsID, "prev": "", "kind": "config", "target": cid.String(), "author": "a", "created": "2026-10-04T12:00:00.000Z", "grant": nil}
	sealedDoc, err := seal.Seal(kn, "s#1", seal.NamespaceDocPL("s", nsID), doc)
	if err != nil {
		t.Fatal(err)
	}
	sealedRange, err := seal.Seal(kn, "s#1", seal.RangePL("s", "", nsID), jsonv.Canonical(jsonv.FromGo([]any{entry})))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ns/s/rev/" + nsID:
			w.Header().Set("Content-Type", seal.ContentType)
			w.Header().Set("X-Config-Revision", cid.String())
			w.Write([]byte(sealedDoc))
		case "/ns/s/rev/" + nsID + "/log":
			w.Header().Set("Content-Type", seal.ContentType)
			w.Write([]byte(sealedRange))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	keys := StaticKeys()
	keys.Add("s#1", ke)
	c, err := New(srv.URL, WithKeys(keys))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, err := c.NSDoc(ctx, "s", nsID)
	if err != nil {
		t.Fatalf("NSDoc: %v", err)
	}
	if d.Value["read"] != "public" {
		t.Fatalf("NSDoc %v", d.Value)
	}
	lg, err := c.NSLog(ctx, "s", nsID, "")
	if err != nil || len(lg) != 1 || lg[0].ID != nsID {
		t.Fatalf("NSLog %v %v", lg, err)
	}
	if _, err := seal.OpenExpect(sealedDoc, ke, "s#1", seal.NamespaceDocPL("s", nsID)); err == nil {
		t.Fatal("K_e opens a namespace document")
	}
}
