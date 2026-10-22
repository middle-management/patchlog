package main

import (
	"crypto/ecdh"
	"os"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// P18 carry-over: patchlog e2e migrate-keyring gives every epoch of the
// old keyring the -reader keys, and its newest epoch the -current-reader
// keys too, read as JWKs or bare base64url x.
func TestV073MigrateKeyringReaders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	jwk, a, _ := seal.GenerateRecipient()
	_, b, _ := seal.GenerateRecipient()
	fa, fb := filepath.Join(dir, "a.jwk"), filepath.Join(dir, "b.x")
	if err := os.WriteFile(fa, jsonv.Canonical(jwk), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fb, []byte(seal.RecipientJWK(b.PublicKey())["x"].(string)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := readPublicKeys([]string{fa, fb})
	if err != nil || len(keys) != 2 || !keys[0].Equal(a.PublicKey()) || !keys[1].Equal(b.PublicKey()) {
		t.Fatalf("keys %v %v", keys, err)
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`), 0o600)
	if _, err := readPublicKeys([]string{bad}); err == nil {
		t.Fatal("an Ed25519 key read as a reader")
	}
	m := migrationReaders([]int{3, 1, 2}, 3, []*ecdh.PublicKey{a.PublicKey()}, []*ecdh.PublicKey{b.PublicKey()})
	if len(m) != 3 || len(m[1]) != 1 || len(m[2]) != 1 || len(m[3]) != 2 || !m[3][1].Equal(b.PublicKey()) {
		t.Fatalf("readers by epoch %v", m)
	}
	if m := migrationReaders([]int{1}, 1, nil, nil); len(m) != 1 || len(m[1]) != 0 {
		t.Fatalf("an epoch without readers must be named %v", m)
	}
	// Putting back epochs a migration left out: the newest isn't among
	// them, so no epoch gets the -current-reader keys.
	if m := migrationReaders([]int{1, 2}, 3, nil, []*ecdh.PublicKey{b.PublicKey()}); len(m) != 2 || len(m[1]) != 0 || len(m[2]) != 0 {
		t.Fatalf("readers of epochs put back %v", m)
	}
}
