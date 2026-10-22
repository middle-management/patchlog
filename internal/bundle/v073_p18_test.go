package bundle_test

import (
	"crypto/ecdh"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// keyringOf is a keyring document (§E.3.2) holding key, the K_e of epoch
// of ns, for a fresh recipient that wrapped it itself.
func keyringOf(t *testing.T, ns string, epoch int, key []byte) *seal.KeyringV2 {
	t.Helper()
	id := identity(t)
	kr, err := seal.BuildKeyringV2(id, ns, epoch, key, []*ecdh.PublicKey{id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}
