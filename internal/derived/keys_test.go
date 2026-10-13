package derived_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// A sealed namespace's epoch keys are destroyed with its content, and
// POST /keys is 410 purged once it is purged (§8.5): Check still lets the
// service consume it, so its follower learns of the purge, rather than
// skipping it for want of a key it will never get.
func TestCheckSealedPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
	if _, err := c.CreateNamespace(ctx, "sec", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	ps := append(client.GenesisPatches(map[string]any{}), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	if _, err := c.Create(ctx, "sec", "a", ps); err != nil {
		t.Fatal(err)
	}
	k := derived.NewKeys(c, nil)
	// The namespace document read while it lives; its key not yet fetched.
	if in, err := k.Info(ctx, "sec"); err != nil || !in.Protected() {
		t.Fatalf("info %+v %v", in, err)
	}
	h, err := c.NSHead(ctx, "sec")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PatchConfig(ctx, "sec", h.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}); err != nil {
		t.Fatal(err)
	}
	if h, err = c.NSHead(ctx, "sec"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PurgeNamespace(ctx, "sec", h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.EpochKey(ctx, "sec", 1); !client.IsPurged(err) {
		t.Fatalf("epoch key after the purge: %v", err)
	}
	if reason, permanent := k.Check(ctx, "sec", false); reason != "" || permanent || k.Skipped("sec") != "" {
		t.Fatalf("check: %q %v", reason, permanent)
	}
}
