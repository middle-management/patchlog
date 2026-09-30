package seal

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestJWERoundTrip(t *testing.T) {
	k := key(1)
	kid := Kid("matches", 3)
	pl := ResourcePL("matches", "derby", "1aaaa", KindRev)
	for _, tc := range []struct {
		name string
		pt   []byte
		zip  bool
	}{
		{"small", []byte(`{"score":"2-1"}`), false},
		{"large", bytes.Repeat([]byte(`{"a":"bbbbbbbb"},`), 200), true},
		{"large-random-ish", randBytes(4096), false}, // doesn't shrink
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwe, err := Seal(k, kid, pl, tc.pt)
			if err != nil {
				t.Fatal(err)
			}
			h, err := ParseHeader(jwe)
			if err != nil {
				t.Fatal(err)
			}
			if (h.Zip == ZipDeflate) != tc.zip {
				t.Fatalf("zip = %q, want %v", h.Zip, tc.zip)
			}
			// Header is canonical JSON.
			if want := jsonv.Canonical(jsonv.MustParse(h.Raw)); !bytes.Equal(h.Raw, want) {
				t.Fatalf("header not canonical: %s", h.Raw)
			}
			got, err := OpenExpect(jwe, k, kid, pl)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.pt) {
				t.Fatal("plaintext mismatch")
			}
			if parts := strings.Split(jwe, "."); parts[1] != "" {
				t.Fatal("encrypted key part not empty")
			}
		})
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

type ecdhPub = ecdh.PublicKey

func TestRangeNeverCompressed(t *testing.T) {
	pt := bytes.Repeat([]byte("x"), 5000)
	jwe, err := Seal(key(1), "ns#1", RangePL("ns", "1aaa", "1bbb"), pt)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := ParseHeader(jwe)
	if h.Zip != "" {
		t.Fatal("range compressed")
	}
	if _, err := OpenExpect(jwe, key(1), "ns#1", RangePL("ns", "1aaa", "1bbb")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExpect(jwe, key(1), "ns#1", RangePL("ns", "1aaa", "1ccc")); !errors.Is(err, ErrMismatch) {
		t.Fatal(err)
	}
}

// handJWE builds a JWE by following RFC 7516 §5.1 directly, with a
// non-canonical header (other member order, whitespace).
func handJWE(t *testing.T, k []byte, header string, plaintext []byte, zip bool) string {
	t.Helper()
	enc := base64.RawURLEncoding
	body := plaintext
	if zip {
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		w.Write(plaintext)
		w.Close()
		body = buf.Bytes()
	}
	protected := enc.EncodeToString([]byte(header)) // step 13
	iv := []byte("0123456789ab")                    // fixed 96-bit IV
	block, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(block)
	out := gcm.Seal(nil, iv, body, []byte(protected)) // step 14-15: AAD = ASCII(protected)
	ct, tag := out[:len(out)-16], out[len(out)-16:]
	return protected + ".." + enc.EncodeToString(iv) + "." + enc.EncodeToString(ct) + "." + enc.EncodeToString(tag)
}

func TestInteropHandBuilt(t *testing.T) {
	k := key(7)
	pt := []byte(`{"hello":"world"}`)
	hdr := `{ "pl": {"kind":"doc", "id":"1abc", "name":"derby", "ns":"matches"},
	  "kid":"matches#2", "enc":"A256GCM", "alg":"dir" }`
	jwe := handJWE(t, k, hdr, pt, false)
	got, err := OpenExpect(jwe, k, "matches#2", ResourcePL("matches", "derby", "1abc", KindDoc))
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("got %q, %v", got, err)
	}
	big := bytes.Repeat([]byte("abc"), 1000)
	hdrZ := `{"zip":"DEF","alg":"dir","enc":"A256GCM","kid":"matches#2","pl":{"ns":"matches","id":"1abc","kind":"config"}}`
	jwe = handJWE(t, k, hdrZ, big, true)
	got, err = OpenExpect(jwe, k, "matches#2", NamespaceDocPL("matches", "1abc"))
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("zip: %v", err)
	}
	// And the other direction: decrypt our output by hand.
	ours, _ := Seal(k, "matches#2", NamespaceDocPL("matches", "1abc"), pt)
	p := strings.Split(ours, ".")
	iv, _ := base64.RawURLEncoding.DecodeString(p[2])
	ct, _ := base64.RawURLEncoding.DecodeString(p[3])
	tag, _ := base64.RawURLEncoding.DecodeString(p[4])
	block, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(block)
	dec, err := gcm.Open(nil, iv, append(ct, tag...), []byte(p[0]))
	if err != nil || !bytes.Equal(dec, pt) {
		t.Fatalf("hand decrypt: %v", err)
	}
	hraw, _ := base64.RawURLEncoding.DecodeString(p[0])
	want := `{"alg":"dir","enc":"A256GCM","kid":"matches#2","pl":{"id":"1abc","kind":"config","ns":"matches"}}`
	if string(hraw) != want {
		t.Fatalf("header %s", hraw)
	}
}

func TestTamper(t *testing.T) {
	k := key(2)
	kid := "ns#1"
	pl := ResourcePL("ns", "r", "1aaa", KindRev)
	jwe, _ := Seal(k, kid, pl, []byte("secret content"))
	parts := strings.Split(jwe, ".")
	flip := func(i int) string {
		p := append([]string(nil), parts...)
		b, _ := base64.RawURLEncoding.DecodeString(p[i])
		b[len(b)-1] ^= 1
		p[i] = base64.RawURLEncoding.EncodeToString(b)
		return strings.Join(p, ".")
	}
	// Header: swap in another pl with same structure (re-encoded header).
	otherHdr := base64.RawURLEncoding.EncodeToString(jsonv.Canonical(map[string]any{
		"alg": "dir", "enc": "A256GCM", "kid": kid, "pl": map[string]any(ResourcePL("ns", "r", "1bbb", KindRev))}))
	hdrSwap := otherHdr + "." + strings.Join(parts[1:], ".")
	for name, bad := range map[string]string{
		"header": hdrSwap, "iv": flip(2), "ciphertext": flip(3), "tag": flip(4),
	} {
		if _, _, err := Open(bad, k); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, _, err := Open(jwe, key(3)); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := OpenExpect(jwe, k, "ns#2", pl); !errors.Is(err, ErrMismatch) {
		t.Errorf("kid: %v", err)
	}
	if _, err := OpenExpect(jwe, k, kid, ResourcePL("ns", "r", "1aaa", KindDoc)); !errors.Is(err, ErrMismatch) {
		t.Errorf("pl: %v", err)
	}
	if _, err := OpenExpect(jwe, k, kid, PL{"ns": "ns", "name": "r", "id": "1aaa", "kind": "rev", "x": "y"}); !errors.Is(err, ErrMismatch) {
		t.Errorf("pl extra: %v", err)
	}
	for _, bad := range []string{"", "a.b.c.d", jwe + ".x", parts[0] + ".AA." + strings.Join(parts[2:], ".")} {
		if _, _, err := Open(bad, k); !errors.Is(err, ErrFormat) {
			t.Errorf("format %q: %v", bad, err)
		}
	}
	// Unsupported alg.
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","kid":"a#1","pl":{}}`))
	if _, _, err := Open(h+"."+strings.Join(parts[1:], "."), k); !errors.Is(err, ErrFormat) {
		t.Error(err)
	}
}

func TestZipBomb(t *testing.T) {
	k := key(4)
	bomb := make([]byte, 10<<20) // 10 MiB of zeros → a few KiB compressed
	jwe, err := Seal(k, "ns#1", ResourcePL("ns", "r", "1a", KindRev), bomb)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwe) > 100<<10 {
		t.Fatalf("not compressed: %d", len(jwe))
	}
	if _, _, err := OpenLimit(jwe, k, 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, pt, err := OpenLimit(jwe, k, 10<<20); err != nil || len(pt) != len(bomb) {
		t.Fatalf("exact limit: %v", err)
	}
	// Uncompressed ciphertext above limit.
	small, _ := SealUncompressed(k, "ns#1", PL{"ns": "ns"}, make([]byte, 100))
	if _, _, err := OpenLimit(small, k, 50); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

// hkdfRFC5869 is an independent HKDF-SHA256 (RFC 5869 §2.2–2.3).
func hkdfRFC5869(ikm, salt, info []byte, l int) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	prk := m.Sum(nil)
	var okm, t []byte
	for i := byte(1); len(okm) < l; i++ {
		m = hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:l]
}

func TestResourceKey(t *testing.T) {
	// Check the reference HKDF against RFC 5869 test case 1.
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(hkdfRFC5869(ikm, salt, info, 42)); got != want {
		t.Fatalf("reference HKDF wrong: %s", got)
	}
	ke := make([]byte, 32)
	for i := range ke {
		ke[i] = byte(i)
	}
	got, err := ResourceKey(ke, "matches", "derby")
	if err != nil {
		t.Fatal(err)
	}
	exp := hkdfRFC5869(ke, []byte("patchlog-e2"), []byte("matches\nderby"), 32)
	if !bytes.Equal(got, exp) {
		t.Fatalf("K_r = %x, want %x", got, exp)
	}
	other, _ := ResourceKey(ke, "matches", "derby2")
	if bytes.Equal(other, got) {
		t.Fatal("same key for different names")
	}
	if _, err := ResourceKey(ke[:16], "a", "b"); !errors.Is(err, ErrKeySize) {
		t.Fatal(err)
	}
}

func TestKid(t *testing.T) {
	if Kid("a#b", 12) != "a#b#12" {
		t.Fatal()
	}
	ns, e, err := ParseKid("a#b#12")
	if err != nil || ns != "a#b" || e != 12 {
		t.Fatal(ns, e, err)
	}
	for _, bad := range []string{"", "ns", "ns#", "#1", "ns#01", "ns#-1", "ns#x"} {
		if _, _, err := ParseKid(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHPKEWrap(t *testing.T) {
	jwk, priv, err := GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseRecipientJWK(jsonv.Canonical(jwk))
	if err != nil {
		t.Fatal(err)
	}
	ke := NewKey()
	w, err := WrapKey(pub, "ns#3", "", ke)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Wrapped) != 32+32+16 {
		t.Fatalf("wrapped len %d", len(w.Wrapped))
	}
	// JSON round trip.
	b, _ := w.MarshalJSON()
	var w2 WrappedKey
	if err := w2.UnmarshalJSON(b); err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(priv, w2)
	if err != nil || !bytes.Equal(got, ke) {
		t.Fatalf("unwrap: %v", err)
	}
	// Wrong recipient.
	_, other, _ := GenerateRecipient()
	if _, err := UnwrapKey(other, w); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	// Context binding: another kid or resource fails.
	w3 := w
	w3.Kid = "ns#4"
	if _, err := UnwrapKey(priv, w3); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	kr, _ := ResourceKey(ke, "ns", "derby")
	wr, _ := WrapKey(pub, "ns#3", "derby", kr)
	if v := wr.Value(); v["resource"] != "derby" {
		t.Fatal(v)
	}
	if got, err := UnwrapKey(priv, wr); err != nil || !bytes.Equal(got, kr) {
		t.Fatal(err)
	}
	wr.Resource = "other"
	if _, err := UnwrapKey(priv, wr); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	// JWK validation.
	for _, bad := range []any{
		map[string]any{"kty": "EC", "crv": "X25519", "x": jwk["x"]},
		map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]},
		map[string]any{"kty": "OKP", "crv": "X25519", "x": "AAAA"},
		"not json",
	} {
		if _, err := ParseRecipientJWK(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if RecipientID(pub) != RecipientID(priv.PublicKey()) || len(RecipientID(pub)) != 33 {
		t.Fatal("recipient id")
	}
}

func TestRow(t *testing.T) {
	k := key(5)
	row := SealRow(k, []byte("patches"), []byte("revisions.patches\n42"))
	if row[0] != RowVersion || len(row) != 1+12+7+16 {
		t.Fatal(len(row))
	}
	pt, err := OpenRow(k, row, []byte("revisions.patches\n42"))
	if err != nil || string(pt) != "patches" {
		t.Fatal(err)
	}
	if _, err := OpenRow(k, row, []byte("revisions.patches\n43")); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	row[len(row)-1] ^= 1
	if _, err := OpenRow(k, row, []byte("revisions.patches\n42")); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	if _, err := OpenRow(k, []byte{2, 0}, nil); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}

func encryptFile(t *testing.T, k, aad, pt []byte, writeSize int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewFileWriter(&buf, k, aad)
	if err != nil {
		t.Fatal(err)
	}
	for p := pt; len(p) > 0; {
		n := min(writeSize, len(p))
		if _, err := w.Write(p[:n]); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decryptFile(k, aad, ct []byte) ([]byte, error) {
	r, err := NewFileReader(bytes.NewReader(ct), k, aad)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func TestFileRoundTrip(t *testing.T) {
	k := key(6)
	aad := []byte("archive/matches/derby")
	for _, n := range []int{0, 1, FileChunkSize - 1, FileChunkSize, FileChunkSize + 1, 3*FileChunkSize + 17, 2 * FileChunkSize} {
		for _, ws := range []int{1000, FileChunkSize, 1 << 20} {
			pt := pattern(n)
			ct := encryptFile(t, k, aad, pt, ws)
			chunks := max(1, (n+FileChunkSize-1)/FileChunkSize)
			if len(ct) != fileHeaderSize+n+chunks*gcmTag {
				t.Fatalf("n=%d: size %d", n, len(ct))
			}
			got, err := decryptFile(k, aad, ct)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("n=%d ws=%d: %v", n, ws, err)
			}
		}
	}
}

func TestFileTamper(t *testing.T) {
	k := key(6)
	aad := []byte("a")
	pt := pattern(3*FileChunkSize + 10) // 4 chunks: 3 full + short final
	ct := encryptFile(t, k, aad, pt, 4096)
	cs := FileChunkSize + gcmTag
	chunk := func(i int) []byte { return ct[fileHeaderSize+i*cs : min(fileHeaderSize+(i+1)*cs, len(ct))] }
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	hdr := ct[:fileHeaderSize]

	cases := map[string]struct {
		ct   []byte
		want error
	}{
		"truncated at boundary": {join(hdr, chunk(0), chunk(1)), ErrTruncated},
		"truncated mid-chunk":   {ct[:fileHeaderSize+cs+100], ErrDecrypt},
		"header only":           {hdr, ErrTruncated},
		"reordered":             {join(hdr, chunk(1), chunk(0), chunk(2), chunk(3)), ErrDecrypt},
		"dropped chunk":         {join(hdr, chunk(0), chunk(2), chunk(3)), ErrDecrypt},
		"duplicated chunk":      {join(hdr, chunk(0), chunk(0), chunk(1), chunk(2), chunk(3)), ErrDecrypt},
		"appended":              {join(ct, []byte("x")), ErrDecrypt},
		"appended final":        {join(ct, chunk(3)), ErrDecrypt},
	}
	for name, tc := range cases {
		if _, err := decryptFile(k, aad, tc.ct); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	bad := bytes.Clone(ct)
	bad[10] ^= 1 // salt
	if _, err := decryptFile(k, aad, bad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("salt: %v", err)
	}
	if _, err := decryptFile(k, []byte("b"), ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("aad: %v", err)
	}
	bad = bytes.Clone(ct)
	bad[0] = 'X'
	if _, err := decryptFile(k, aad, bad); !errors.Is(err, ErrFormat) {
		t.Errorf("magic: %v", err)
	}
	// A short, non-boundary truncation of a small file.
	small := encryptFile(t, k, aad, []byte("hello"), 10)
	if _, err := decryptFile(k, aad, small[:len(small)-1]); !errors.Is(err, ErrDecrypt) {
		t.Errorf("small: %v", err)
	}
}

func TestKeyring(t *testing.T) {
	jA, pA, _ := GenerateRecipient()
	jB, pB, _ := GenerateRecipient()
	jC, pC, _ := GenerateRecipient()
	pubA, _ := ParseRecipientJWK(jA)
	pubB, _ := ParseRecipientJWK(jB)
	pubC, _ := ParseRecipientJWK(jC)
	k1, k2 := NewKey(), NewKey()

	kr, err := BuildKeyring("secret", 1, k1, []*ecdhPub{pubA, pubB})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kr.EpochKey(pA, 1); err != nil || !bytes.Equal(got, k1) {
		t.Fatal(err)
	}
	if _, err := kr.EpochKey(pC, 1); err == nil {
		t.Fatal("C has no key yet")
	}
	if err := kr.Add(pubC, 1, k1); err != nil {
		t.Fatal(err)
	}
	// Rotate, revoking B.
	e, err := kr.Rotate(k2, []*ecdhPub{pubA, pubC})
	if err != nil || e != 2 || kr.Current != 2 {
		t.Fatal(e, err)
	}
	// Serialise and parse back.
	doc, _ := kr.MarshalJSON()
	kr2, err := ParseKeyring(doc)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := kr2.MarshalJSON(); !bytes.Equal(again, doc) {
		t.Fatal("keyring round trip")
	}
	w, err := Lookup(kr2, jC, 2)
	if err != nil || w.Kid != "secret#2" {
		t.Fatal(w, err)
	}
	if got, err := UnwrapKey(pC, w); err != nil || !bytes.Equal(got, k2) {
		t.Fatal(err)
	}
	if _, err := Lookup(kr2, jB, 2); err == nil {
		t.Fatal("revoked B found in epoch 2")
	}
	if got, err := kr2.EpochKey(pB, 1); err != nil || !bytes.Equal(got, k1) {
		t.Fatal("B keeps epoch 1", err)
	}
	if len(kr2.Readers(2)) != 2 || len(kr2.Readers(1)) != 3 {
		t.Fatal(kr2.Readers(1), kr2.Readers(2))
	}
	// A wrapped epoch-1 entry cannot be moved to epoch 2 (context = kid).
	v := jsonv.MustParse(doc).(map[string]any)
	ep := v["epochs"].(map[string]any)
	ridB := RecipientID(pubB)
	ep["2"].(map[string]any)[ridB] = ep["1"].(map[string]any)[ridB]
	kr3, err := ParseKeyring(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr3.EpochKey(pB, 2); !errors.Is(err, ErrDecrypt) {
		t.Fatal(err)
	}
	// Mismatched recipient id rejected.
	v["recipients"].(map[string]any)["1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = jA
	if _, err := ParseKeyring(v); err == nil {
		t.Fatal("bad rid accepted")
	}
}

func TestSealedPatchSet(t *testing.T) {
	ke := NewKey()
	kr, _ := ResourceKey(ke, "ns", "doc")
	patches := jsonv.MustParse([]byte(`[{"op":"add","path":"/title","value":"hi"}]`))
	ps, err := SealPatchSet(kr, "ns#1", "ns", "doc", "", patches)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(ps), `[{"op":"sealed","value":"ey`) {
		t.Fatal(string(ps))
	}
	got, err := OpenPatchSet(ps, kr, "ns#1", "ns", "doc", "")
	if err != nil || !jsonv.Equal(got, patches) {
		t.Fatal(err)
	}
	if _, err := OpenPatchSet(ps, kr, "ns#1", "ns", "doc", "1aaa"); !errors.Is(err, ErrMismatch) {
		t.Fatal(err)
	}
	if _, err := OpenPatchSet(ps, kr, "ns#1", "ns2", "doc", ""); !errors.Is(err, ErrMismatch) {
		t.Fatal(err)
	}
	if _, ok := SealedJWE([]byte(`[{"op":"sealed","value":"x","extra":1}]`)); ok {
		t.Fatal("extra member")
	}
	if _, ok := SealedJWE([]byte(`[{"op":"sealed","value":"x"},{"op":"sealed","value":"y"}]`)); ok {
		t.Fatal("two ops")
	}
	snap, err := SealSnapshot(kr, "ns#1", "ns", "doc", "1bbb", map[string]any{"title": "hi"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := OpenSnapshot(snap, kr, "ns#1", "ns", "doc", "1bbb")
	if err != nil || doc.(map[string]any)["title"] != "hi" {
		t.Fatal(err)
	}
	if _, err := OpenSnapshot(snap, kr, "ns#1", "ns", "doc", "1ccc"); !errors.Is(err, ErrMismatch) {
		t.Fatal(err)
	}
	// A patch set JWE is not accepted as a snapshot.
	jwe, _ := SealedJWE(ps)
	if _, err := OpenSnapshot(jwe, kr, "ns#1", "ns", "doc", ""); !errors.Is(err, ErrMismatch) {
		t.Fatal(err)
	}
}

func TestNonce(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		n := NewNonce()
		if !ValidNonce(n) || seen[n] {
			t.Fatal(n)
		}
		seen[n] = true
	}
	n := NewNonce()
	ok := func(js string) bool { return HasFreshNonce([]byte(js)) }
	for js, want := range map[string]bool{
		`[{"op":"add","path":"/$nonce","value":"` + n + `"}]`:                                            true,
		`[{"op":"replace","path":"/$nonce","value":"` + n + `"},{"op":"add","path":"/a","value":1}]`:     true,
		`[{"op":"add","path":"/$nonce","value":"` + n + `"},{"op":"test","path":"/$nonce","value":"x"}]`: true,
		`[{"op":"add","path":"/a","value":1}]`:                                                           false,
		`[]`:                                                                                             false,
		`[{"op":"add","path":"/$nonce","value":"ABC"}]`:                                                  false,
		`[{"op":"add","path":"/$nonce","value":"` + n[:25] + `"}]`:                                       false,
		`[{"op":"add","path":"/$nonce","value":"` + n[:25] + `1"}]`:                                      false,
		`[{"op":"add","path":"/$nonce/x","value":"` + n + `"}]`:                                          false,
		`[{"op":"add","path":"/$nonce","value":"` + n + `"},{"op":"remove","path":"/$nonce"}]`:           false,
		`[{"op":"add","path":"/$nonce","value":"` + n + `"},{"op":"move","from":"/$nonce","path":"/b"}]`: false,
		`[{"op":"copy","from":"/x","path":"/$nonce"}]`:                                                   false,
		`[{"op":"add","path":"/$nonce","value":1}]`:                                                      false,
	} {
		if ok(js) != want {
			t.Errorf("%s: want %v", js, want)
		}
	}
}
