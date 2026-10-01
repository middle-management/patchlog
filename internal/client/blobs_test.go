package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
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

// §E.2.2: clients open sealed blobs only where they know the namespace is
// sealed, after the epoch redirect: anywhere else a blob of the sealed
// type, even one whose header names a kid, is bytes as stored.
func TestBlobSealedTypeInPlainNamespace(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "files", map[string]any{"read": "public"}))
	sealed, err := seal.SealBlob(seal.NewKey(), "files#1", seal.BlobPL("files", "f", "x"), []byte("looks sealed"), false)
	if err != nil {
		t.Fatal(err)
	}
	bid := must(c.UploadBlob(ctx, "files", "f", client.SealedBlobType, "", sealed))
	ref := client.BlobRef(bid, client.SealedBlobType, len(sealed), "")
	must(c.Create(ctx, "files", "f", client.GenesisPatches(map[string]any{"file": ref})))
	b := must(c.GetBlobRef(ctx, "files", "f", ref))
	if string(b.Data) != string(sealed) || b.Type != client.SealedBlobType {
		t.Fatalf("blob %q %s", b.Data, b.Type)
	}
}

// §E.3.1: declared lists are sorted by the ids' binary form, not their
// text: the base32 alphabet puts the digits after the letters.
func TestBlobIDsBinaryOrder(t *testing.T) {
	var lo, hi ids.ID
	hi[0] = 0xf8 // text "17…", which sorts before "1a…" as a string
	doc := map[string]any{"x": map[string]any{"$blob": hi.String()}, "y": map[string]any{"$blob": lo.String()}, "z": map[string]any{"$blob": hi.String()}}
	got := client.BlobIDs(doc)
	if len(got) != 2 || got[0] != lo.String() || got[1] != hi.String() {
		t.Fatalf("BlobIDs %v", got)
	}
	if hi.String() > lo.String() {
		t.Fatal("the example doesn't show the difference")
	}
}

func isStatus(err error, status int) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == status
}
