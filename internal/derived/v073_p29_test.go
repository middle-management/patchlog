package derived_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 §E.3.2 (ENC-12): a service seals views, and hands out K_r, only
// under an e2e epoch key whose keyring entry is from a sender it trusts to
// distribute keys. An entry for its key from another sender it knows, but
// doesn't trust, skips the namespace for want of keys; with no trusted
// senders configured, every known sender is trusted.
func TestV073P29ServiceSealsOnlyUnderTrustedFrom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"))
	if _, err := c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	_, admin, _ := seal.GenerateRecipient()
	_, evil, _ := seal.GenerateRecipient()
	_, svc, _ := seal.GenerateRecipient()
	ax := c.E2E(admin)
	if _, err := ax.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	// The service's entry is wrapped by another sender, around a key of
	// its choosing.
	kr, head, err := ax.Keyring(ctx, "e")
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(evil, svc.PublicKey(), "e#1", seal.NewKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(ctx, "e", client.KeyringName, head, []any{map[string]any{"op": "replace", "path": "", "value": kr.Value()}}); err != nil {
		t.Fatal(err)
	}

	trusting := derived.NewKeys(s.Client(t, client.WithAuthor("svc"), client.WithKeyringSenders(evil.PublicKey()), client.WithTrustedKeyringSenders(admin.PublicKey())), svc)
	if _, err := trusting.Info(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	if _, err := trusting.EpochKey(ctx, "e", 1); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("an epoch key from an untrusted sender: %v", err)
	}
	if reason, _, retry := trusting.Check(ctx, "e", false); !strings.Contains(reason, "trust") || retry {
		t.Fatalf("Check: %q retry %v, want a skip for want of keys", reason, retry)
	}
	plain := derived.NewKeys(s.Client(t, client.WithAuthor("svc"), client.WithKeyringSenders(evil.PublicKey())), svc)
	if reason, _, _ := plain.Check(ctx, "e", false); reason != "" {
		t.Fatalf("with no trusted senders configured: %q", reason)
	}
}
