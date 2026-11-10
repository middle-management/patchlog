package seal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// §E.2.1, §I.7: K_n of K_e = 00..1f and ns "demo"; it is no K_r, and a key
// of the wrong size is refused.
func TestV081NamespaceKey(t *testing.T) {
	ke := make([]byte, KeySize)
	for i := range ke {
		ke[i] = byte(i)
	}
	kn, err := NamespaceKey(ke, "demo")
	if err != nil || hex.EncodeToString(kn) != "b2d9864bdf7f562d58e3638e08ec2e97e553c74995edbcef110ee9adfed62b4c" {
		t.Fatalf("K_n = %x %v", kn, err)
	}
	kr, _ := ResourceKey(ke, "demo", "derby")
	if bytes.Equal(kn, kr) || bytes.Equal(kn, ke) {
		t.Fatal("K_n equals K_r or K_e")
	}
	if _, err := NamespaceKey(ke[:31], "demo"); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short K_e: %v", err)
	}
}

// §E.2.6: a view key is HKDF-SHA256(K, "patchlog-view", view), here
// computed independently, and differs per view.
func TestV081ViewKey(t *testing.T) {
	ke := make([]byte, KeySize)
	for i := range ke {
		ke[i] = byte(i)
	}
	kn, _ := NamespaceKey(ke, "demo")
	vk, err := ViewKey(kn, "/idx/demo/at/1x/search?q=a")
	if err != nil || hex.EncodeToString(vk) != "d9ed712805ed48a84e6bb9bdc6c7f8cf1ea03ed5f0f202b1b45ff4a01d1d8942" {
		t.Fatalf("view key = %x %v", vk, err)
	}
	other, _ := ViewKey(kn, "/idx/demo/at/1x/search?q=b")
	if bytes.Equal(vk, other) || bytes.Equal(vk, kn) {
		t.Fatal("view keys don't differ per view")
	}
	if _, err := ViewKey(nil, "/x"); !errors.Is(err, ErrKeySize) {
		t.Fatalf("nil key: %v", err)
	}
}
