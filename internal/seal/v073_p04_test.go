package seal

import (
	"bytes"
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
