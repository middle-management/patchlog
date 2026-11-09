package seal

import (
	"errors"
	"testing"
)

// §E.3.2, §C.7 (v0.76): a keyring document has no other members but a
// fresh $nonce, so CheckKeyringV2, which checks a keyring write, refuses
// one that isn't of the fresh form (26 lowercase base32 characters) as it
// refuses any other member. ParseKeyringV2 reads stored keyrings, written
// when any string was taken, and takes it.
func TestV076KeyringNonceFresh(t *testing.T) {
	for _, n := range []any{"x", "not-a-nonce", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", NewNonce()[:25], NewNonce() + "a", ""} {
		d := map[string]any{"keys": []any{}, "$nonce": n}
		if _, err := CheckKeyringV2(d); !errors.Is(err, ErrFormat) {
			t.Errorf("CheckKeyringV2, $nonce %q: %v, want ErrFormat", n, err)
		}
		if kr, err := ParseKeyringV2(d); err != nil || kr.Nonce != n {
			t.Errorf("ParseKeyringV2, $nonce %q: %v, %v; want it read", n, kr, err)
		}
	}
	for _, f := range []func(any) (*KeyringV2, error){CheckKeyringV2, ParseKeyringV2} {
		if _, err := f(map[string]any{"keys": []any{}, "$nonce": NewNonce()}); err != nil {
			t.Fatalf("fresh $nonce: %v", err)
		}
		if _, err := f(map[string]any{"keys": []any{}, "$nonce": 1.0}); !errors.Is(err, ErrFormat) {
			t.Fatalf("$nonce not a string: %v, want ErrFormat", err)
		}
	}
	if _, err := CheckKeyringV2([]byte(`{"keys":[],"$nonce":"x"}`)); !errors.Is(err, ErrFormat) {
		t.Fatalf("JSON text with $nonce x: %v, want ErrFormat", err)
	}
}
