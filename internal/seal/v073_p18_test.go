package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// P18, ENC-8 (§E.2.3): a /keys entry is { kid, name?, from?, wrapped },
// name for a K_r and from for a relayed keyring entry, with no suite or
// resource member. ParseWrappedKey still reads the form before v0.63.
func TestV073WrappedKeyShape(t *testing.T) {
	t.Parallel()
	_, priv, _ := GenerateRecipient()
	ke := NewKey()
	w, err := WrapKey(priv.PublicKey(), "ns#3", "", ke)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(jsonv.Canonical(w.Value())); got != `{"kid":"ns#3","wrapped":"`+b64.EncodeToString(w.Wrapped)+`"}` {
		t.Fatalf("K_e entry %s", got)
	}
	kr, _ := ResourceKey(ke, "ns", "derby")
	wr, _ := WrapKey(priv.PublicKey(), "ns#3", "derby", kr)
	v := wr.Value()
	if v["name"] != "derby" || len(v) != 3 {
		t.Fatalf("K_r entry %v", v)
	}
	for _, m := range []string{"suite", "resource", "from"} {
		if _, ok := v[m]; ok {
			t.Fatalf("K_r entry has %s: %v", m, v)
		}
	}
	back, err := ParseWrappedKey(jsonv.Canonical(v))
	if err != nil || back.Resource != "derby" || back.Kid != "ns#3" {
		t.Fatalf("round trip %+v %v", back, err)
	}

	// The form before v0.63: resource and suite.
	legacy := map[string]any{"kid": "ns#3", "resource": "derby", "suite": Suite, "wrapped": b64.EncodeToString(wr.Wrapped)}
	if got, err := ParseWrappedKey(legacy); err != nil || got.Resource != "derby" {
		t.Fatalf("legacy %+v %v", got, err)
	}
	for name, m := range map[string]map[string]any{
		"other suite":           {"kid": "ns#3", "suite": "hpke-x", "wrapped": "AAAA"},
		"name and resource":     {"kid": "ns#3", "name": "a", "resource": "b", "wrapped": "AAAA"},
		"from not a thumbprint": {"kid": "ns#3", "from": "abc", "wrapped": "AAAA"},
		"empty name":            {"kid": "ns#3", "name": "", "wrapped": "AAAA"},
	} {
		if _, err := ParseWrappedKey(m); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A relayed keyring entry carries its from.
	_, admin, _ := GenerateRecipient()
	ring, err := BuildKeyringV2(admin, "ns", 3, ke, []*ecdh.PublicKey{priv.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	rv := ring.Entries[0].Relayed().Value()
	if rv["from"] != Thumbprint(admin.PublicKey()) || rv["kid"] != "ns#3" || len(rv) != 3 {
		t.Fatalf("relayed entry %v", rv)
	}
	if got, err := ParseWrappedKey(rv); err != nil || got.From != Thumbprint(admin.PublicKey()) {
		t.Fatalf("relayed parse %+v %v", got, err)
	}
}

// P18, ENC-9 and ENC-11 (§E.2.3, §E.3.2): a relayed keyring entry opens
// only with the public key of the sender its from names, in auth mode; a
// key without from (an E2 key, or an entry of a keyring stored before
// v0.63 relayed as stored) in base mode, under either HPKE info.
func TestV073UnwrapRelayed(t *testing.T) {
	t.Parallel()
	_, reader, _ := GenerateRecipient()
	_, admin, _ := GenerateRecipient()
	_, other, _ := GenerateRecipient()
	ke := NewKey()
	ring, err := BuildKeyringV2(admin, "e", 1, ke, []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	w := ring.Entries[0].Relayed()
	if k, err := UnwrapRelayed(reader, w, []*ecdh.PublicKey{other.PublicKey(), admin.PublicKey()}); err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("known sender: %v", err)
	}
	if _, err := UnwrapRelayed(reader, w, []*ecdh.PublicKey{other.PublicKey()}); err == nil {
		t.Fatal("an entry from an unknown sender opened")
	}
	// A from that names a known key that didn't wrap it fails decryption.
	forged := w
	forged.From = Thumbprint(other.PublicKey())
	if _, err := UnwrapRelayed(reader, forged, []*ecdh.PublicKey{other.PublicKey()}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("forged from: %v", err)
	}
	// Base mode: an E2 key, and a legacy entry.
	base, _ := WrapKey(reader.PublicKey(), "e#1", "", ke)
	if k, err := UnwrapRelayed(reader, base, nil); err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("base mode: %v", err)
	}
	pk, err := hpke.NewDHKEMPublicKey(reader.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	lw, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), legacyWrapInfo("e#1", ""), ke)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := UnwrapRelayed(reader, WrappedKey{Kid: "e#1", Wrapped: lw}, nil); err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("legacy info: %v", err)
	}
}

// P18, ENC-11: the keyring helpers name epochs, recipients and the newest
// epoch by the entries' kids.
func TestV073KeyringV2Helpers(t *testing.T) {
	t.Parallel()
	_, admin, _ := GenerateRecipient()
	_, r1, _ := GenerateRecipient()
	_, r2, _ := GenerateRecipient()
	k1, k2 := NewKey(), NewKey()
	kr, err := BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{r1.PublicKey(), r2.PublicKey(), r1.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.Entries) != 2 {
		t.Fatalf("a reader given twice has %d entries", len(kr.Entries))
	}
	if err := kr.Add(admin, r1.PublicKey(), "e#2", k2); err != nil {
		t.Fatal(err)
	}
	if kr.Current("e") != 2 || kr.Current("x") != 0 {
		t.Fatalf("current %d %d", kr.Current("e"), kr.Current("x"))
	}
	if got := kr.Recipients("e#1"); len(got) != 2 {
		t.Fatalf("recipients of e#1 %v", got)
	}
	if got := kr.To(Thumbprint(r1.PublicKey())); len(got) != 2 {
		t.Fatalf("entries to r1 %v", got)
	}
	if _, err := ParseKeyringV2(kr.Value()); err != nil {
		t.Fatalf("built keyring doesn't parse: %v", err)
	}
}
