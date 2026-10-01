package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §7.8 through the client: upload, reference, read, ranges and copies.
func TestBlobs(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "media", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "site", map[string]any{"read": "public"}))

	data := []byte("\x89PNG not really an image")
	bid := must(c.UploadBlob(ctx, "media", "hero", "image/png", "", data))
	if bid != client.BlobID("image/png", "", data) {
		t.Fatalf("id %s", bid)
	}
	if _, err := c.GetBlob(ctx, "media", "hero", bid, ""); !isStatus(err, 404) {
		t.Fatalf("pending blob: %v", err)
	}
	must(c.Create(ctx, "media", "hero", client.GenesisPatches(map[string]any{"img": client.BlobRef(bid, "image/png", len(data), "")})))
	b := must(c.GetBlob(ctx, "media", "hero", bid, ""))
	if string(b.Data) != string(data) || b.Type != "image/png" {
		t.Fatalf("blob %+v", b)
	}
	part := must(c.GetBlobRange(ctx, "media", "hero", bid, 1, 3))
	if string(part) != "PNG" {
		t.Fatalf("range %q", part)
	}
	// A copy into another namespace, then a reference there.
	if err := c.CopyBlob(ctx, "site", "home", bid, "media", "hero", ""); err != nil {
		t.Fatal(err)
	}
	must(c.Create(ctx, "site", "home", client.GenesisPatches(map[string]any{"img": client.BlobRef(bid, "image/png", len(data), "")})))
	must(c.GetBlob(ctx, "site", "home", bid, ""))
	// A nonce is part of the id.
	nonce := "abcdefghijklmnopqrstuvwxyz"
	nb := must(c.UploadBlob(ctx, "media", "hero", "image/png", nonce, data))
	if nb == bid {
		t.Fatal("nonce ignored")
	}
}

func isStatus(err error, status int) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == status
}
