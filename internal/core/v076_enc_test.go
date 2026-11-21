package core

import (
	"crypto/ecdh"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// §E.3.2, §C.7 (v0.76): a keyring's $nonce is of the fresh form. v0.78
// keeps no compatibility with one stored before v0.76, when the gate took
// a $nonce of any form, or mirrored from such a remote base: /keys relays
// none of its entries (keyringEntries, E2E-10), failing closed until a key
// holder wraps it again.
func TestV076EncStoredKeyringNonceRelayed(t *testing.T) {
	_, admin, _ := seal.GenerateRecipient()
	_, reader, _ := seal.GenerateRecipient()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, seal.NewKey(), []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]int{seal.NewNonce(): 1, "x": 0, "": 0} {
		d := kr.Value()
		d["$nonce"] = n
		if got := keyringEntries(d, reader.PublicKey(), []int{1}); len(got) != want {
			t.Fatalf("stored keyring with $nonce %q: relayed %v, want %d entries", n, got, want)
		}
	}
}
