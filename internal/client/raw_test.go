package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Raw documents (§7.1, §7.8): RawBlobOf tells one from its value, and Raw
// asks the server which blob …/raw redirects to, at the head or at a
// revision; a document that isn't raw, and a sealed namespace's, are 404s,
// and a deleted one is gone.
func TestRaw(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "m", map[string]any{"read": "public", "nonce": "required"}))
	must(c.CreateNamespace(ctx, "s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	data := []byte("plain text file")
	for _, ns := range []string{"m", "s"} {
		bid := must(c.UploadBlob(ctx, ns, "f", "text/plain", "", data))
		ref := client.BlobRef(bid, "text/plain", len(data), "")
		w := must(c.Create(ctx, ns, "f", nonced(client.GenesisPatches(ref))))
		d := must(c.Doc(ctx, ns, "f", w.ID))
		if client.RawBlobOf(d.Value) != bid {
			t.Fatalf("%s: RawBlobOf %v", ns, d.Value)
		}
		got, err := c.Raw(ctx, ns, "f", "")
		if ns == "s" {
			if !client.IsNotFound(err) {
				t.Fatalf("sealed raw: %q %v", got, err)
			}
			continue
		}
		if err != nil || got != bid {
			t.Fatalf("raw: %q %v", got, err)
		}
		if got := must(c.Raw(ctx, ns, "f", w.ID)); got != bid {
			t.Fatalf("raw at %s: %q", w.ID, got)
		}
		b := must(c.GetBlob(ctx, ns, "f", got, ""))
		if string(b.Data) != string(data) {
			t.Fatalf("blob %q", b.Data)
		}
		x := must(c.Create(ctx, ns, "x", nonced(client.GenesisPatches(map[string]any{"title": "no"}))))
		if _, err := c.Raw(ctx, ns, "x", x.ID); !client.IsNotFound(err) {
			t.Fatalf("not raw: %v", err)
		}
		must(c.Delete(ctx, ns, "f", must(c.Head(ctx, ns, "f")).ID))
		if _, err := c.Raw(ctx, ns, "f", ""); !client.IsGone(err) {
			t.Fatalf("deleted: %v", err)
		}
	}
	if client.RawBlobOf(map[string]any{"$blob": "x"}) != "" || client.RawBlobOf("x") != "" {
		t.Fatal("RawBlobOf")
	}
}
