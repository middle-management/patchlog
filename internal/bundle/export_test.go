package bundle

import (
	"encoding/base32"
	"math/rand/v2"
	"testing"
)

// KeepSnapshotTrees makes an import keep its snapshot documents as the
// trees the Reader parses, as imports did before they kept their canonical
// forms (ImportOptions.keepTrees), for tests that compare the two.
func KeepSnapshotTrees(opt *ImportOptions) { opt.keepTrees = true }

// DeterministicNonces makes the $nonce values imports add (nonced) a
// sequence fixed by seed, from here on, until the test ends: two runs that
// call it with the same seed before the same import generate the same
// nonces, whatever else in the process reads crypto/rand.
func DeterministicNonces(t testing.TB, seed uint64) {
	r := rand.New(rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8), byte(seed >> 16), byte(seed >> 24)}))
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	prev := newNonce
	newNonce = func() string {
		b := make([]byte, 16)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return enc.EncodeToString(b)
	}
	t.Cleanup(func() { newNonce = prev })
}
