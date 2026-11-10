package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// P18 carry-over: public keys for -reader and -keyring-sender are read as
// JWKs or bare base64url x. (The migrate-keyring readers by epoch it
// pinned are gone with the tool, v0.78.)
func TestV073ReadPublicKeys(t *testing.T) {
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
}
