package seal

import (
	"crypto/hpke"
	"errors"
	"testing"
)

// E2E-10: a prune snapshot is bound to exactly {ns, name, id} (§E.3.1):
// one sealed before v0.63 with {ns, name, id, kind: "snapshot"}, and a
// namespace document with kind "config", are ErrMismatch since v0.78
// ("Reading this spec": no compatibility with data from earlier drafts).
func TestV081LegacySnapshotPLMismatch(t *testing.T) {
	t.Parallel()
	k := key(21)
	snap := handJWE(t, k, `{"alg":"dir","enc":"A256GCM","kid":"m#1","pl":{"id":"1aaaa","kind":"snapshot","name":"r","ns":"m"}}`, []byte(`{"a":1}`), false)
	if _, err := OpenSnapshot(snap, k, "m#1", "m", "r", "1aaaa"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("legacy snapshot pl: %v", err)
	}
	doc := handJWE(t, k, `{"alg":"dir","enc":"A256GCM","kid":"m#1","pl":{"id":"1aaaa","kind":"config","ns":"m"}}`, []byte(`{}`), false)
	if _, err := OpenExpect(doc, k, "m#1", NamespaceDocPL("m", "1aaaa")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("legacy namespace document pl: %v", err)
	}
	h, err := ParseHeader(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Expect("m#1", SnapshotPL("m", "r", "1aaaa")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Expect: %v", err)
	}
	// The current form still opens.
	cur, _ := SealSnapshot(k, "m#1", "m", "r", "1aaaa", map[string]any{"a": 1.0})
	if _, err := OpenSnapshot(cur, k, "m#1", "m", "r", "1aaaa"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
}

// E2E-10: a header with a zip member doesn't parse (§E.2.2: sealed
// payloads are never compressed), so nothing sealed with zip "DEF" before
// v0.65 opens, a patch set included.
func TestV081ZipIsFormatError(t *testing.T) {
	t.Parallel()
	k := key(22)
	jwe := handJWE(t, k, `{"alg":"dir","enc":"A256GCM","kid":"m#1","pl":{"name":"r","ns":"m","parent":""},"zip":"DEF"}`, []byte(`[{"op":"add","path":"","value":{}}]`), true)
	if _, err := ParseHeader(jwe); !errors.Is(err, ErrFormat) {
		t.Fatalf("ParseHeader: %v", err)
	}
	if _, _, err := Open(jwe, k); !errors.Is(err, ErrFormat) {
		t.Fatalf("Open: %v", err)
	}
	ps := []any{map[string]any{"op": "sealed", "value": jwe}}
	if _, err := OpenPatchSet(ps, k, "m#1", "m", "r", ""); !errors.Is(err, ErrFormat) {
		t.Fatalf("OpenPatchSet: %v", err)
	}
}

// E2E-10: keys wrapped under the HPKE info of before v0.63 don't open
// (UnwrapKeyLegacy is gone): neither relayed without from nor from a
// keyring in the old format.
func TestV081LegacyWrapInfoRefused(t *testing.T) {
	t.Parallel()
	_, priv, _ := GenerateRecipient()
	pk, _ := hpke.NewDHKEMPublicKey(priv.PublicKey())
	k := NewKey()
	old, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-keys-v1\ne#1"), k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapRelayed(priv, WrappedKey{Kid: "e#1", Wrapped: old}, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("UnwrapRelayed: %v", err)
	}
	kr, _ := BuildKeyring("e", 1, k, nil)
	rid := RecipientID(priv.PublicKey())
	kr.Recipients[rid] = priv.PublicKey()
	kr.Epochs[1][rid] = old
	if _, err := kr.EpochKey(priv, 1); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Keyring.EpochKey: %v", err)
	}
}
