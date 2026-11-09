package seal

import (
	"errors"
	"testing"
)

// §E.3.2, §C.7 (v0.76): a keyring document has no other members but a
// fresh $nonce, so ParseKeyringV2 refuses one that isn't of the fresh form
// (26 lowercase base32 characters) as it refuses any other member.
func TestV076KeyringNonceFresh(t *testing.T) {
	for _, n := range []any{"x", "not-a-nonce", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", NewNonce()[:25], NewNonce() + "a", ""} {
		if _, err := ParseKeyringV2(map[string]any{"keys": []any{}, "$nonce": n}); !errors.Is(err, ErrFormat) {
			t.Errorf("$nonce %q: %v, want ErrFormat", n, err)
		}
	}
	if _, err := ParseKeyringV2(map[string]any{"keys": []any{}, "$nonce": NewNonce()}); err != nil {
		t.Fatalf("fresh $nonce: %v", err)
	}
	if _, err := ParseKeyringV2([]byte(`{"keys":[],"$nonce":"x"}`)); !errors.Is(err, ErrFormat) {
		t.Fatalf("JSON text with $nonce x: %v, want ErrFormat", err)
	}
}
