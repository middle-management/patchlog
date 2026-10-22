package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Spec v0.73, package P04: the byte formats of Addendum E.

// ---- ENC-2: sealed payloads are never compressed (§E.2.2, v0.65) ----

// Every way of sealing a JWE leaves the plaintext uncompressed and the
// header without zip, whatever the payload, however compressible.
func TestV073SealNeverCompresses(t *testing.T) {
	k := key(9)
	kid := Kid("matches", 2)
	pt := bytes.Repeat([]byte(`{"a":"bbbbbbbb"},`), 600) // 10 KiB, compresses well
	check := func(name, jwe string, plainLen int) {
		t.Helper()
		h, err := ParseHeader(jwe)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h.Zip != "" || bytes.Contains(h.Raw, []byte(`"zip"`)) {
			t.Fatalf("%s: header %s", name, h.Raw)
		}
		ct, _ := b64.DecodeString(strings.Split(jwe, ".")[3])
		if len(ct) != plainLen {
			t.Fatalf("%s: %d bytes of ciphertext for %d of plaintext", name, len(ct), plainLen)
		}
	}
	for _, pl := range []PL{
		ResourcePL("matches", "derby", "1aaaa", KindDoc),
		ResourcePL("matches", "derby", "1aaaa", KindRev),
		ResourcePL("matches", "derby", "1aaaa", KindTombstone),
		NamespaceDocPL("matches", "1aaaa"),
		RangePL("matches", "", "1aaaa"),
		GrantPL("matches", "1gggg"),
		PatchSetPL("matches", "derby", ""),
		SnapshotPL("matches", "derby", "1aaaa"),
		ResourceEventPL("matches", "derby", KindPurge),
		{"ns": "matches", "view": "/matches/at/1aaaa?q=x"},
	} {
		name := string(jsonv.Canonical(map[string]any(pl)))
		jwe, err := Seal(k, kid, pl, pt)
		if err != nil {
			t.Fatal(err)
		}
		check("Seal "+name, jwe, len(pt))
		jwe, _ = SealUncompressed(k, kid, pl, pt)
		check("SealUncompressed "+name, jwe, len(pt))
		jwe, _ = SealMaybePadded(k, kid, pl, pt, false)
		check("SealMaybePadded "+name, jwe, len(pt))
		jwe, _ = SealPadded(k, kid, pl, pt)
		check("SealPadded "+name, jwe, PadLen(len(pt)))
	}
	doc := jsonv.MustParse(append(append([]byte(`{"text":"`), bytes.Repeat([]byte("patch log "), 500)...), '"', '}'))
	ps, err := SealPatchSet(k, kid, "matches", "derby", "", []any{map[string]any{"op": "add", "path": "", "value": doc}})
	if err != nil {
		t.Fatal(err)
	}
	jwe, _ := SealedJWE(ps)
	check("SealPatchSet", jwe, len(jsonv.Canonical([]any{map[string]any{"op": "add", "path": "", "value": doc}})))
	snap, err := SealSnapshot(k, kid, "matches", "derby", "1aaaa", doc)
	if err != nil {
		t.Fatal(err)
	}
	check("SealSnapshot", snap, len(jsonv.Canonical(doc)))
}

// Open still inflates bytes sealed with zip "DEF" before v0.65, which are
// stored once and served forever (§E.2.2).
func TestV073OpenInflatesLegacyZip(t *testing.T) {
	k := key(10)
	big := bytes.Repeat([]byte("abc"), 2000)
	jwe := handJWE(t, k, `{"alg":"dir","enc":"A256GCM","kid":"m#1","pl":{"id":"1a","kind":"doc","name":"r","ns":"m"},"zip":"DEF"}`, big, true)
	h, pt, err := Open(jwe, k)
	if err != nil || h.Zip != ZipDeflate || !bytes.Equal(pt, big) {
		t.Fatalf("legacy zip: zip %q, %v", h.Zip, err)
	}
	if got, err := OpenExpect(jwe, k, "m#1", ResourcePL("m", "r", "1a", KindDoc)); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("OpenExpect: %v", err)
	}
}

// ---- Deterministic hooks: a fixed IV for test vectors ----

func TestV073SealWithIV(t *testing.T) {
	k := key(11)
	iv := []byte("0123456789ab")
	pl := ResourcePL("matches", "derby", "1aaaa", KindDoc)
	a, err := SealWithIV(k, "matches#1", pl, []byte(`{"a":1}`), iv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SealWithIV(k, "matches#1", pl, []byte(`{"a":1}`), iv)
	if a != b || strings.Split(a, ".")[2] != b64.EncodeToString(iv) {
		t.Fatalf("not deterministic: %s %s", a, b)
	}
	// It is the JWE an independent RFC 7516 construction gives for the
	// canonical header.
	hdr := `{"alg":"dir","enc":"A256GCM","kid":"matches#1","pl":{"id":"1aaaa","kind":"doc","name":"derby","ns":"matches"}}`
	if want := handJWE(t, k, hdr, []byte(`{"a":1}`), false); a != want {
		t.Fatalf("SealWithIV\n %s\nwant\n %s", a, want)
	}
	if got, err := OpenExpect(a, k, "matches#1", pl); err != nil || string(got) != `{"a":1}` {
		t.Fatal(err)
	}
	if _, err := SealWithIV(k, "matches#1", pl, nil, iv[:11]); err == nil {
		t.Fatal("an 11-byte IV accepted")
	}
	// Seal itself draws a fresh IV each time.
	c, _ := Seal(k, "matches#1", pl, []byte(`{"a":1}`))
	d, _ := Seal(k, "matches#1", pl, []byte(`{"a":1}`))
	if c == d {
		t.Fatal("Seal repeated an IV")
	}
}

// ---- ENC-1, ENC-21, resource events: pl shapes (§E.2.2, §E.3.1, v0.63) ----

func TestV073PLShapes(t *testing.T) {
	for _, tc := range []struct {
		pl   PL
		want string
	}{
		{NamespaceDocPL("matches", "1aaaa"), `{"id":"1aaaa","kind":"doc","ns":"matches"}`},
		{SnapshotPL("matches", "derby", "1aaaa"), `{"id":"1aaaa","name":"derby","ns":"matches"}`},
		{ResourceEventPL("matches", "derby", KindPurge), `{"kind":"purge","name":"derby","ns":"matches"}`},
		{ResourceEventPL("matches", "derby", KindPrune), `{"kind":"prune","name":"derby","ns":"matches"}`},
	} {
		if got := string(jsonv.Canonical(map[string]any(tc.pl))); got != tc.want {
			t.Errorf("pl %s, want %s", got, tc.want)
		}
	}
	// What Seal and SealSnapshot put in the header.
	k := key(12)
	jwe, _ := Seal(k, "matches#1", NamespaceDocPL("matches", "1aaaa"), []byte(`{}`))
	if h, _ := ParseHeader(jwe); string(h.Raw) != `{"alg":"dir","enc":"A256GCM","kid":"matches#1","pl":{"id":"1aaaa","kind":"doc","ns":"matches"}}` {
		t.Errorf("namespace document header %s", h.Raw)
	}
	snap, _ := SealSnapshot(k, "matches#1", "matches", "derby", "1aaaa", map[string]any{})
	if h, _ := ParseHeader(snap); string(h.Raw) != `{"alg":"dir","enc":"A256GCM","kid":"matches#1","pl":{"id":"1aaaa","name":"derby","ns":"matches"}}` {
		t.Errorf("snapshot header %s", h.Raw)
	}
}

// Readers accept the pl of bytes sealed before v0.63 for the payloads whose
// pl changed, and for nothing else.
func TestV073LegacyPLAccepted(t *testing.T) {
	k := key(13)
	mk := func(pl string) string {
		return handJWE(t, k, `{"alg":"dir","enc":"A256GCM","kid":"m#1","pl":`+pl+`}`, []byte(`{"a":1}`), false)
	}
	legacyDoc := mk(`{"id":"1aaaa","kind":"config","ns":"m"}`)
	legacySnap := mk(`{"id":"1aaaa","kind":"snapshot","name":"r","ns":"m"}`)
	if _, err := OpenExpect(legacyDoc, k, "m#1", NamespaceDocPL("m", "1aaaa")); err != nil {
		t.Fatalf("legacy namespace document: %v", err)
	}
	if _, err := OpenSnapshot(legacySnap, k, "m#1", "m", "r", "1aaaa"); err != nil {
		t.Fatalf("legacy snapshot: %v", err)
	}
	if _, err := OpenExpect(mk(`{"id":"1aaaa","kind":"doc","ns":"m"}`), k, "m#1", NamespaceDocPL("m", "1aaaa")); err != nil {
		t.Fatalf("namespace document: %v", err)
	}
	if _, err := OpenSnapshot(mk(`{"id":"1aaaa","name":"r","ns":"m"}`), k, "m#1", "m", "r", "1aaaa"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for name, c := range map[string]struct {
		jwe  string
		kid  string
		want PL
	}{
		"legacy doc, other id":           {legacyDoc, "m#1", NamespaceDocPL("m", "1bbbb")},
		"legacy doc, other kid":          {legacyDoc, "m#2", NamespaceDocPL("m", "1aaaa")},
		"legacy doc as a resource doc":   {legacyDoc, "m#1", ResourcePL("m", "r", "1aaaa", KindDoc)},
		"legacy doc as a snapshot":       {legacyDoc, "m#1", SnapshotPL("m", "r", "1aaaa")},
		"legacy snapshot, other id":      {legacySnap, "m#1", SnapshotPL("m", "r", "1bbbb")},
		"legacy snapshot, other name":    {legacySnap, "m#1", SnapshotPL("m", "s", "1aaaa")},
		"legacy snapshot as a resource":  {legacySnap, "m#1", ResourcePL("m", "r", "1aaaa", KindDoc)},
		"resource doc as a snapshot":     {mk(`{"id":"1aaaa","kind":"doc","name":"r","ns":"m"}`), "m#1", SnapshotPL("m", "r", "1aaaa")},
		"revision entry as a snapshot":   {mk(`{"id":"1aaaa","kind":"rev","name":"r","ns":"m"}`), "m#1", SnapshotPL("m", "r", "1aaaa")},
		"config pl as a resource doc":    {mk(`{"id":"1aaaa","kind":"config","name":"r","ns":"m"}`), "m#1", ResourcePL("m", "r", "1aaaa", KindDoc)},
		"purge event as a prune event":   {mk(`{"kind":"purge","name":"r","ns":"m"}`), "m#1", ResourceEventPL("m", "r", KindPrune)},
		"resource event as a namespace":  {mk(`{"kind":"purge","name":"r","ns":"m"}`), "m#1", NamespaceDocPL("m", "1aaaa")},
		"legacy doc with an extra claim": {mk(`{"id":"1aaaa","kind":"config","ns":"m","x":1}`), "m#1", NamespaceDocPL("m", "1aaaa")},
	} {
		if _, err := OpenExpect(c.jwe, k, c.kid, c.want); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: err = %v, want ErrMismatch", name, err)
		}
	}
}

// ---- ENC-7: the HPKE info of wrapped keys (§E.2.3, v0.63) ----

// The info is "patchlog-key-v1" 0x0A kid 0x0A name, name empty for K_e, so
// that K_e's info ends in 0x0A; checked against crypto/hpke with the info
// spelled out, both ways.
func TestV073WrapInfo(t *testing.T) {
	_, priv, err := GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := hpke.NewDHKEMPublicKey(priv.PublicKey())
	sk, _ := hpke.NewDHKEMPrivateKey(priv)
	k := NewKey()
	for _, c := range []struct{ resource, info string }{
		{"", "patchlog-key-v1\nns#3\n"},
		{"derby", "patchlog-key-v1\nns#3\nderby"},
	} {
		w, err := WrapKey(priv.PublicKey(), "ns#3", c.resource, k)
		if err != nil {
			t.Fatal(err)
		}
		if len(w.Wrapped) != 32+KeySize+16 {
			t.Fatalf("wrapped is %d bytes, want enc (32) and ct (48)", len(w.Wrapped))
		}
		if got, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(c.info), w.Wrapped); err != nil || !bytes.Equal(got, k) {
			t.Fatalf("info %q: %v", c.info, err)
		}
		other, _ := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(c.info), k)
		if got, err := UnwrapKey(priv, WrappedKey{Kid: "ns#3", Resource: c.resource, Wrapped: other}); err != nil || !bytes.Equal(got, k) {
			t.Fatalf("UnwrapKey with info %q: %v", c.info, err)
		}
		// The pre-v0.63 info no longer opens.
		if _, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), legacyWrapInfo("ns#3", c.resource), w.Wrapped); err == nil {
			t.Fatalf("resource %q: opened under the legacy info", c.resource)
		}
	}
}

// Keys wrapped under the pre-v0.63 info ("patchlog-keys-v1" 0x0A kid,
// then 0x0A resource for a K_r) open with UnwrapKeyLegacy only, for
// migrating stored keyrings.
func TestV073UnwrapKeyLegacy(t *testing.T) {
	_, priv, _ := GenerateRecipient()
	pk, _ := hpke.NewDHKEMPublicKey(priv.PublicKey())
	k := NewKey()
	for _, c := range []struct{ resource, info string }{
		{"", "patchlog-keys-v1\nns#3"},
		{"derby", "patchlog-keys-v1\nns#3\nderby"},
	} {
		old, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(c.info), k)
		if err != nil {
			t.Fatal(err)
		}
		w := WrappedKey{Kid: "ns#3", Resource: c.resource, Wrapped: old}
		if got, err := UnwrapKeyLegacy(priv, w); err != nil || !bytes.Equal(got, k) {
			t.Fatalf("legacy %q: %v", c.info, err)
		}
		if _, err := UnwrapKey(priv, w); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("UnwrapKey opened a legacy wrap: %v", err)
		}
		w.Kid = "ns#4"
		if _, err := UnwrapKeyLegacy(priv, w); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("legacy wrap under another kid: %v", err)
		}
	}
}

// ---- ENC-9: key thumbprints (§E.2.3, RFC 7638, v0.63) ----

func TestV073Thumbprint(t *testing.T) {
	// RFC 8037 Appendix A.3: the RFC 7638 thumbprint of an OKP JWK.
	if got := jwkThumbprint(map[string]any{"crv": "Ed25519", "kty": "OKP", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("RFC 8037 A.3 thumbprint %s", got)
	}
	// An X25519 key: SHA-256 of {"crv":"X25519","kty":"OKP","x":…}
	// exactly, base64url without padding.
	_, priv, _ := GenerateRecipient()
	x := b64.EncodeToString(priv.PublicKey().Bytes())
	sum := sha256.Sum256([]byte(`{"crv":"X25519","kty":"OKP","x":"` + x + `"}`))
	tp := Thumbprint(priv.PublicKey())
	if tp != base64.RawURLEncoding.EncodeToString(sum[:]) || len(tp) != 43 {
		t.Fatalf("thumbprint %s", tp)
	}
	// It doesn't depend on how the JWK was written.
	pub, err := ParseRecipientJWK([]byte(`{ "x": "` + x + `", "kty": "OKP", "use": "enc", "crv": "X25519" }`))
	if err != nil || Thumbprint(pub) != tp {
		t.Fatalf("parsed JWK thumbprint: %v", err)
	}
	_, other, _ := GenerateRecipient()
	if Thumbprint(other.PublicKey()) == tp {
		t.Fatal("two keys, one thumbprint")
	}
}

// ---- ENC-10: HPKE auth mode (RFC 9180; §E.2.3, §E.3.2, v0.63) ----

// hpkeVector is one RFC 9180 test vector for DHKEM(X25519, HKDF-SHA256)
// and HKDF-SHA256, single-shot (sequence number 0), in hex.
type hpkeVector struct {
	name                                     string
	mode                                     byte
	aead                                     uint16
	info, skEm, pkEm, skRm, pkRm, skSm, pkSm string
	shared, context, secret, key, baseNonce  string
	pt, aad, ct                              string
}

var hpkeVectors = []hpkeVector{{
	name: "RFC 9180 A.1.1 (base, AES-128-GCM)", mode: hpkeModeBase, aead: hpkeAEADAES128GCM,
	info:      "4f6465206f6e2061204772656369616e2055726e",
	skEm:      "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
	pkEm:      "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
	skRm:      "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
	pkRm:      "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
	shared:    "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
	context:   "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
	secret:    "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397",
	key:       "4531685d41d65f03dc48f6b8302c05b0",
	baseNonce: "56d890e5accaaf011cff4b7d",
	pt:        "4265617574792069732074727574682c20747275746820626561757479",
	aad:       "436f756e742d30",
	ct:        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
}, {
	name: "RFC 9180 A.1.3 (auth, AES-128-GCM)", mode: hpkeModeAuth, aead: hpkeAEADAES128GCM,
	info:      "4f6465206f6e2061204772656369616e2055726e",
	skEm:      "ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518",
	pkEm:      "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76",
	skRm:      "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e",
	pkRm:      "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e",
	skSm:      "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd",
	pkSm:      "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b",
	shared:    "2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7",
	context:   "02725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
	secret:    "56c62333d9d9f7767f5b083fdfce0aa7e57e301b74029bb0cffa7331385f1dda",
	key:       "b062cb2c4dd4bca0ad7c7a12bbc341e6",
	baseNonce: "a1bc314c1942ade7051ffed0",
	pt:        "4265617574792069732074727574682c20747275746820626561757479",
	aad:       "436f756e742d30",
	ct:        "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b",
}, {
	// The CFRG test-vectors.json of RFC 9180, for this package's suite.
	name: "CFRG (base, AES-256-GCM)", mode: hpkeModeBase, aead: hpkeAEADAES256GCM,
	info:      "4f6465206f6e2061204772656369616e2055726e",
	skEm:      "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11",
	pkEm:      "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
	skRm:      "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
	pkRm:      "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
	shared:    "3101c54c3a4f87439eaac080699ed9bbcc726ffe44e860c0424ccb7e3e2ead7b",
	context:   "004ce5472ecdd5093ba0aecb8f871ff13f1fbc90ee76f0e18ace1a1b7e565bafa306f6ef962c9ee7cea40407b5d60f0f26990472faae3ac44c78366f1cac1ecde1",
	secret:    "2058ac9b02c1f52c1aaf08bedbec9198219751a94ef67b7d5f0c8b6e2b54ebfb",
	key:       "f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f",
	baseNonce: "151d9929e2449747889bc923",
	pt:        "4265617574792069732074727574682c20747275746820626561757479",
	aad:       "436f756e742d30",
	ct:        "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
}, {
	name: "CFRG (auth, AES-256-GCM)", mode: hpkeModeAuth, aead: hpkeAEADAES256GCM,
	info:      "4f6465206f6e2061204772656369616e2055726e",
	skEm:      "805b278cabd22c9dbd461bf25771703eda4950ed3ef35b369163097899555356",
	pkEm:      "9e59f4b1fa5c876f684765290c34e51145894cc4f244342b9fb1a4bdfd8bb426",
	skRm:      "47f1eee3670dfaaf27c30a83d06ee9f257af174727c17b35328ef730dfc1cd81",
	pkRm:      "3668d659cec6f338f4f8dc6da6733118d2a633f186a3c1415c895111a8eb7c7d",
	skSm:      "98fdf9b9773578a79d4ba82fbe483c74cc2e3b8d9525d148a18969fd79a74876",
	pkSm:      "4a91c3d0893433f5e31a79fc520f885527a1bc60bf2b0c72693dd7f0b2e41a5a",
	shared:    "6579475ca739247fad60b7713b0077f1e966e0eaf6f95bff8fa41e446db4b226",
	context:   "024ce5472ecdd5093ba0aecb8f871ff13f1fbc90ee76f0e18ace1a1b7e565bafa306f6ef962c9ee7cea40407b5d60f0f26990472faae3ac44c78366f1cac1ecde1",
	secret:    "27b818ee96b7941c9741853455ae0df327739b575cd858167c0649548b47ef03",
	key:       "db0218adcafe73ee2e320bd08146d232cedfbd45c7e43d1fae3f1c79dc179b40",
	baseNonce: "41da94323642095905a34938",
	pt:        "4265617574792069732074727574682c20747275746820626561757479",
	aad:       "436f756e742d30",
	ct:        "10b964283ac2cc0bdc4c85ab617291b446bf3832e9359b2c3a0facc50ea75a3c1afd08aeaacd6041d02eb560ec",
}}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func x25519Priv(t *testing.T, s string) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(unhex(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The hand-written KEM, key schedule and single-shot AEAD give RFC 9180's
// values, step by step, in base and auth mode.
func TestV073HPKEVectors(t *testing.T) {
	for _, v := range hpkeVectors {
		t.Run(v.name, func(t *testing.T) {
			skE, skR := x25519Priv(t, v.skEm), x25519Priv(t, v.skRm)
			var skS *ecdh.PrivateKey
			var pkS *ecdh.PublicKey
			if v.mode == hpkeModeAuth {
				skS = x25519Priv(t, v.skSm)
				pkS = skS.PublicKey()
				if hex.EncodeToString(pkS.Bytes()) != v.pkSm {
					t.Fatal("pkSm")
				}
			}
			if hex.EncodeToString(skE.PublicKey().Bytes()) != v.pkEm || hex.EncodeToString(skR.PublicKey().Bytes()) != v.pkRm {
				t.Fatal("pkEm or pkRm")
			}
			shared, enc, err := hpkeEncap(skR.PublicKey(), skS, skE)
			if err != nil || hex.EncodeToString(enc) != v.pkEm || hex.EncodeToString(shared) != v.shared {
				t.Fatalf("encap: enc %x shared %x, %v", enc, shared, err)
			}
			if got, err := hpkeDecap(enc, skR, pkS); err != nil || hex.EncodeToString(got) != v.shared {
				t.Fatalf("decap: %x, %v", got, err)
			}
			ks := hpkeKeySchedule(v.aead, v.mode, shared, unhex(t, v.info))
			for name, c := range map[string][2]string{
				"key_schedule_context": {hex.EncodeToString(ks.context), v.context},
				"secret":               {hex.EncodeToString(ks.secret), v.secret},
				"key":                  {hex.EncodeToString(ks.key), v.key},
				"base_nonce":           {hex.EncodeToString(ks.baseNonce), v.baseNonce},
			} {
				if c[0] != c[1] {
					t.Errorf("%s = %s, want %s", name, c[0], c[1])
				}
			}
			encct, err := hpkeSeal(v.aead, skR.PublicKey(), skS, skE, unhex(t, v.info), unhex(t, v.aad), unhex(t, v.pt))
			if err != nil || hex.EncodeToString(encct) != v.pkEm+v.ct {
				t.Fatalf("seal: %x, %v", encct, err)
			}
			if pt, err := hpkeOpen(v.aead, skR, pkS, unhex(t, v.info), unhex(t, v.aad), encct); err != nil || hex.EncodeToString(pt) != v.pt {
				t.Fatalf("open: %x, %v", pt, err)
			}
			// The other mode, another sender or another aad doesn't open.
			if v.mode == hpkeModeAuth {
				if _, err := hpkeOpen(v.aead, skR, nil, unhex(t, v.info), unhex(t, v.aad), encct); err == nil {
					t.Fatal("an auth-mode message opened in base mode")
				}
				if _, err := hpkeOpen(v.aead, skR, skR.PublicKey(), unhex(t, v.info), unhex(t, v.aad), encct); err == nil {
					t.Fatal("opened with another sender")
				}
			} else if _, err := hpkeOpen(v.aead, skR, skE.PublicKey(), unhex(t, v.info), unhex(t, v.aad), encct); err == nil {
				t.Fatal("a base-mode message opened in auth mode")
			}
			if _, err := hpkeOpen(v.aead, skR, pkS, unhex(t, v.info), nil, encct); err == nil {
				t.Fatal("opened with another aad")
			}
		})
	}
}

// Base mode as written here and crypto/hpke's agree, both ways.
func TestV073HPKEBaseInterop(t *testing.T) {
	_, priv, _ := GenerateRecipient()
	eph, _ := newEphemeral()
	k := NewKey()
	w, err := WrapKeyWithEphemeral(eph, priv.PublicKey(), "ns#2", "derby", k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Wrapped[:32], eph.PublicKey().Bytes()) || len(w.Wrapped) != 80 {
		t.Fatalf("wrapped %x", w.Wrapped)
	}
	if got, err := UnwrapKey(priv, w); err != nil || !bytes.Equal(got, k) {
		t.Fatalf("crypto/hpke opening ours: %v", err)
	}
	again, _ := WrapKeyWithEphemeral(eph, priv.PublicKey(), "ns#2", "derby", k)
	if !bytes.Equal(again.Wrapped, w.Wrapped) {
		t.Fatal("a fixed ephemeral key, yet another wrap")
	}
	std, _ := WrapKey(priv.PublicKey(), "ns#2", "", k)
	if got, err := hpkeOpen(hpkeAEADAES256GCM, priv, nil, wrapInfo("ns#2", ""), nil, std.Wrapped); err != nil || !bytes.Equal(got, k) {
		t.Fatalf("ours opening crypto/hpke's: %v", err)
	}
}

func TestV073WrapKeyAuth(t *testing.T) {
	_, admin, _ := GenerateRecipient()
	_, reader, _ := GenerateRecipient()
	_, other, _ := GenerateRecipient()
	k := NewKey()
	w, err := WrapKeyAuth(admin, reader.PublicKey(), "ns#3", "", k)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Wrapped) != 32+KeySize+16 || w.Kid != "ns#3" || w.Resource != "" {
		t.Fatalf("wrapped %+v", w)
	}
	if got, err := UnwrapKeyAuth(reader, admin.PublicKey(), w); err != nil || !bytes.Equal(got, k) {
		t.Fatalf("unwrap: %v", err)
	}
	// Two wraps differ: the ephemeral key is fresh.
	if w2, _ := WrapKeyAuth(admin, reader.PublicKey(), "ns#3", "", k); bytes.Equal(w2.Wrapped, w.Wrapped) {
		t.Fatal("ephemeral key reused")
	}
	for name, f := range map[string]func() ([]byte, error){
		"another sender":    func() ([]byte, error) { return UnwrapKeyAuth(reader, other.PublicKey(), w) },
		"another recipient": func() ([]byte, error) { return UnwrapKeyAuth(other, admin.PublicKey(), w) },
		"base mode":         func() ([]byte, error) { return UnwrapKey(reader, w) },
		"another kid": func() ([]byte, error) {
			return UnwrapKeyAuth(reader, admin.PublicKey(), WrappedKey{Kid: "ns#4", Wrapped: w.Wrapped})
		},
		"as a K_r": func() ([]byte, error) {
			return UnwrapKeyAuth(reader, admin.PublicKey(), WrappedKey{Kid: "ns#3", Resource: "derby", Wrapped: w.Wrapped})
		},
		"truncated": func() ([]byte, error) {
			return UnwrapKeyAuth(reader, admin.PublicKey(), WrappedKey{Kid: "ns#3", Wrapped: w.Wrapped[:40]})
		},
	} {
		if _, err := f(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	// A base-mode wrap isn't an auth-mode one.
	b, _ := WrapKey(reader.PublicKey(), "ns#3", "", k)
	if _, err := UnwrapKeyAuth(reader, admin.PublicKey(), b); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("base-mode wrap opened in auth mode: %v", err)
	}
	if _, err := WrapKeyAuth(admin, reader.PublicKey(), "ns#3", "", k[:16]); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short key: %v", err)
	}
}

// The project vector: X25519 private keys of 32 bytes 0x22 (recipient),
// 0x11 (sender, the admin) and 0x33 (ephemeral), and K_e = 32 bytes 0x44
// of kid "matches#3", wrapped in auth mode with info
// "patchlog-key-v1\nmatches#3\n" (§E.2.3, §E.3.2). The values were
// checked against an independent implementation over node's OpenSSL.
func TestV073WrapKeyAuthVector(t *testing.T) {
	const (
		wantTo      = "cu-DqB3hQR_-PaumpGVRb3Q5np9W9wmvoop1IYyCQPw"
		wantFrom    = "TcLDEDJ-thZLq6350vBJY7bV5_OubllM4xCrgsimCLg"
		wantWrapped = "ew1H2TQn-DERYHgcfHM_2J-IlwrvSQ2KoO4ZpMuKGxQRqEhSfMsOa9SQTxTJPiF465cdYQvc3JIAO48QGKin38ZumX65dYssclpY_TejKRs"
	)
	recipient := x25519Priv(t, strings.Repeat("22", 32))
	sender := x25519Priv(t, strings.Repeat("11", 32))
	eph := x25519Priv(t, strings.Repeat("33", 32))
	w, err := WrapKeyAuthWithEphemeral(eph, sender, recipient.PublicKey(), "matches#3", "", key(0x44))
	if err != nil {
		t.Fatal(err)
	}
	if got := b64.EncodeToString(w.Wrapped); got != wantWrapped {
		t.Fatalf("wrapped %s, want %s", got, wantWrapped)
	}
	if to, from := Thumbprint(recipient.PublicKey()), Thumbprint(sender.PublicKey()); to != wantTo || from != wantFrom {
		t.Fatalf("to %s from %s", to, from)
	}
	if got, err := UnwrapKeyAuth(recipient, sender.PublicKey(), w); err != nil || !bytes.Equal(got, key(0x44)) {
		t.Fatal(err)
	}
}

// ---- Deterministic hooks: a fixed IV for sealed blobs ----

// SealBlobWithIV gives the §E.2.2 layout "PLB1" ‖ len ‖ header ‖ iv ‖
// AES-256-GCM(size ‖ bytes ‖ padding) ‖ tag, byte for byte, with the
// additional data everything before iv.
func TestV073SealBlobWithIV(t *testing.T) {
	k := key(14)
	iv := []byte("fedcba987654")
	data := []byte("blob bytes")
	for _, c := range []struct {
		kid  string
		pl   PL
		hdr  string
		pad  bool
		size int
	}{
		{"m#2", BlobPL("m", "r", "1bbbb"), `{"enc":"A256GCM","kid":"m#2","pl":{"blob":"1bbbb","name":"r","ns":"m"}}`, false, 8 + len(data)},
		{"", nil, `{"enc":"A256GCM"}`, true, MinPadded},
	} {
		got, err := SealBlobWithIV(k, c.kid, c.pl, data, c.pad, iv)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := SealBlobWithIV(k, c.kid, c.pl, data, c.pad, iv)
		if !bytes.Equal(got, again) {
			t.Fatal("not deterministic")
		}
		plain := make([]byte, c.size)
		binary.BigEndian.PutUint64(plain, uint64(len(data)))
		copy(plain[8:], data)
		want := binary.BigEndian.AppendUint32([]byte("PLB1"), uint32(len(c.hdr)))
		want = append(want, c.hdr...)
		block, _ := aes.NewCipher(k)
		gcm, _ := cipher.NewGCM(block)
		want = gcm.Seal(append(append([]byte(nil), want...), iv...), iv, plain, want)
		if !bytes.Equal(got, want) {
			t.Fatalf("header %s: sealed blob %x, want %x", c.hdr, got, want)
		}
		if h, d, err := OpenBlob(got, k); err != nil || !bytes.Equal(d, data) || string(h.Raw) != c.hdr {
			t.Fatalf("open: %v", err)
		}
	}
	if _, err := SealBlobWithIV(k, "", nil, data, false, iv[:8]); err == nil {
		t.Fatal("an 8-byte IV accepted")
	}
}
