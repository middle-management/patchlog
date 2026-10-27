package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// P29, ENC-12 (§E.3.2) and the wave-2 carry-over: the tools' -keyring-sender
// flags name the admins whose keyring entries they open, and
// -trusted-sender those they trust to distribute the keys they seal under.
// A tool given an untrusted sender's entry for its key reads with it but
// won't write; one trusting no sender explicitly trusts every known one.
func TestV073P29KeyringSenderFlags(t *testing.T) {
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
	adminJWK, admin, _ := seal.GenerateRecipient()
	evilJWK, evil, _ := seal.GenerateRecipient()
	_, w, _ := seal.GenerateRecipient()
	ax := c.E2E(admin)
	if _, err := ax.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	kr, head, err := ax.Keyring(ctx, "e")
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(evil, w.PublicKey(), "e#1", seal.NewKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(ctx, "e", client.KeyringName, head, []any{map[string]any{"op": "replace", "path": "", "value": kr.Value()}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, jwk map[string]any) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, jsonv.Canonical(seal.RecipientJWK(must(seal.ParseRecipientJWK(jwk)))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	af, ef := write("admin.jwk", adminJWK), write("evil.jwk", evilJWK)
	tool := func(args ...string) *client.E2E {
		t.Helper()
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		tf := addToolFlags(fs)
		if err := fs.Parse(append([]string{"-api", s.URL, "-author", "w"}, args...)); err != nil {
			t.Fatal(err)
		}
		return tf.client().E2E(w)
	}
	strict := tool("-keyring-sender", ef, "-trusted-sender", af)
	if _, err := strict.Key(ctx, "e#1"); err != nil {
		t.Fatalf("a -keyring-sender's entry doesn't open: %v", err)
	}
	if _, err := strict.CreateDocSealed(ctx, "e", "a", map[string]any{"n": 1.0}); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("sealing under an entry from a sender not in -trusted-sender: %v", err)
	}
	if _, err := tool("-keyring-sender", ef).CreateDocSealed(ctx, "e", "b", map[string]any{"n": 1.0}); err != nil {
		t.Fatalf("with no -trusted-sender: %v", err)
	}
	if _, err := tool("-trusted-sender", ef).CreateDocSealed(ctx, "e", "c", map[string]any{"n": 1.0}); err != nil {
		t.Fatalf("with the sender trusted: %v", err)
	}
	kf := &keyringFlags{senders: multi{filepath.Join(dir, "missing")}}
	if _, err := kf.options(); err == nil {
		t.Fatal("a missing -keyring-sender file")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
