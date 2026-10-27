package core

import (
	"crypto/ecdh"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// P18, ENC-9 and ENC-11 (§E.2.3, §E.3.2): the relay takes the keyring
// document's entries to the thumbprint of enc, with from, for the epochs
// asked; a keyring stored in the format before v0.63, which the gate no
// longer takes, is relayed as stored, without from, until a key holder
// wraps it again.
func TestV073KeyringEntries(t *testing.T) {
	t.Parallel()
	_, admin, _ := seal.GenerateRecipient()
	_, reader, _ := seal.GenerateRecipient()
	_, other, _ := seal.GenerateRecipient()
	k1, k2 := seal.NewKey(), seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{reader.PublicKey(), other.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(admin, reader.PublicKey(), "e#2", k2); err != nil {
		t.Fatal(err)
	}
	got := keyringEntries(kr.Value(), reader.PublicKey(), []int{2})
	if len(got) != 1 || got[0]["kid"] != "e#2" || got[0]["from"] != seal.Thumbprint(admin.PublicKey()) {
		t.Fatalf("relayed %v", got)
	}
	if got := keyringEntries(kr.Value(), reader.PublicKey(), []int{1, 2}); len(got) != 2 {
		t.Fatalf("both epochs %v", got)
	}
	if got := keyringEntries(kr.Value(), other.PublicKey(), []int{2}); len(got) != 0 {
		t.Fatalf("no entry of e#2 for other %v", got)
	}

	old, err := seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	got = keyringEntries(old.Value(), reader.PublicKey(), []int{1})
	if len(got) != 1 || got[0]["kid"] != "e#1" || got[0]["from"] != nil {
		t.Fatalf("legacy relayed %v", got)
	}
	w, err := seal.ParseWrappedKey(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if k, err := seal.UnwrapRelayed(reader, w, nil); err != nil || string(k) != string(k1) {
		t.Fatalf("legacy unwrap %v", err)
	}
	if got := keyringEntries(map[string]any{"v": 1.0}, reader.PublicKey(), []int{1}); got != nil {
		t.Fatalf("not a keyring %v", got)
	}
}
