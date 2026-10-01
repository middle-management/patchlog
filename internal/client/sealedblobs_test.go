package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// §7.8, §E.2.2, §E.3.1 through the client: blobs of a sealed namespace are
// opened with the namespace's keys after the epoch redirect; e2e blobs are
// encrypted by the client, declared by its writes, verified by its folds
// and decrypted with the key in their reference.
func TestBlobsEncrypted(t *testing.T) {
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t), Archiver: arch})
	plain := s.Client(t, client.WithAuthor("alice"))
	c := plain.With(client.WithKeys(client.NewKeys(nil)))

	// E2: sealed for delivery.
	must(c.CreateNamespace(ctx, "s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	data := []byte("a sealed picture")
	nonce := seal.NewNonce()
	bid := must(c.UploadBlob(ctx, "s", "a", "image/png", nonce, data))
	ref := client.BlobRef(bid, "image/png", len(data), nonce)
	must(c.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"img": ref}))))
	b := must(c.GetBlobRef(ctx, "s", "a", ref))
	if string(b.Data) != string(data) || b.Type != "image/png" {
		t.Fatalf("sealed blob %+v", b)
	}
	if b := must(c.GetBlobRefEpoch(ctx, "s", "a", ref, 1)); string(b.Data) != string(data) {
		t.Fatal("epoch 1")
	}
	if _, err := c.GetBlobRefEpoch(ctx, "s", "a", ref, 2); !isStatus(err, 404) {
		t.Fatalf("unserved epoch: %v", err)
	}
	if _, err := plain.GetBlobRef(ctx, "s", "a", ref); !errors.Is(err, client.ErrNoKeys) {
		t.Fatalf("without keys: %v", err)
	}
	if _, err := c.GetBlob(ctx, "s", "a", bid, nonce); err == nil || !strings.Contains(err.Error(), "GetBlobRef") {
		t.Fatalf("GetBlob of a sealed blob: %v", err)
	}

	// E3: end to end.
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	x := plain.E2EKeys(map[string][]byte{"e#1": seal.NewKey()})
	pic := []byte("an e2e picture")
	eref := must(x.UploadBlob(ctx, "e", "d", "image/png", pic))
	ebid := eref["$blob"].(string)
	w0 := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"pic": eref, "n": 0}))
	w1 := must(x.AppendSealed(ctx, "e", "d", w0.ID, ops(op("replace", "/n", 1))))
	// Each write declares the document's blobs, also when it doesn't touch
	// them (§E.3.1).
	for _, e := range must(plain.Log(ctx, "e", "d", w1.ID, "")) {
		if _, list, ok := seal.SealedOp(e.Patches); !ok || len(list) != 1 || list[0] != ebid {
			t.Fatalf("declared list of %s: %v", e.ID, e.Patches)
		}
	}
	got := must(x.GetBlob(ctx, "e", "d", eref))
	if string(got.Data) != string(pic) || got.Type != "image/png" {
		t.Fatalf("e2e blob %+v", got)
	}
	// A revision whose list differs from its document is flagged.
	lie := must(x.SealPatches(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2))))
	w2 := must(plain.Append(ctx, "e", "d", w1.ID, lie))
	d := must(x.DocE2E(ctx, "e", "d", w2.ID))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != w2.ID || !strings.Contains(d.Flagged[0].Message, "blob list") || d.ValidID != w1.ID {
		t.Fatalf("fold %+v", d)
	}
	// A prune's snapshot declares the horizon document's blobs, so the
	// attachment stays.
	w3 := must(x.AppendSealed(ctx, "e", "d", w2.ID, ops(op("replace", "/n", 3))))
	s.Clock.Advance(10 * time.Minute)
	if _, err := x.PruneE2E(ctx, "e", "d", w3.ID); err != nil {
		t.Fatal(err)
	}
	must(x.GetBlob(ctx, "e", "d", eref))
	if _, err := client.DecryptBlob(eref, []byte("PLB1 tampered")); err == nil {
		t.Fatal("decrypted bytes that don't match the reference")
	}
}
