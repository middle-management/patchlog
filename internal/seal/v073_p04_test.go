package seal

import (
	"bytes"
	"crypto/hpke"
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
