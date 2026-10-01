package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §E.2.2: the binary sealed-blob form, at E2 and E3, padded or not.
func TestSealedBlob(t *testing.T) {
	k := key(7)
	data := []byte("blob bytes \x00\x01")
	pl := BlobPL("ns", "res", "1abc")
	for _, pad := range []bool{false, true} {
		sb, err := SealBlob(k, "ns#3", pl, data, pad)
		if err != nil {
			t.Fatal(err)
		}
		if string(sb[:4]) != "PLB1" {
			t.Fatalf("magic %q", sb[:4])
		}
		hlen := int(binary.BigEndian.Uint32(sb[4:8]))
		if want := `{"enc":"A256GCM","kid":"ns#3","pl":{"blob":"1abc","name":"res","ns":"ns"}}`; string(sb[8:8+hlen]) != want {
			t.Fatalf("header %s", sb[8:8+hlen])
		}
		plain := 8 + len(data)
		if pad {
			plain = PadLen(plain)
		}
		if len(sb) != 8+hlen+12+plain+16 {
			t.Fatalf("pad %v: length %d", pad, len(sb))
		}
		h, got, err := OpenBlob(sb, k)
		if err != nil || !bytes.Equal(got, data) || h.Expect("ns#3", pl) != nil {
			t.Fatalf("open: %v %q %+v", err, got, h)
		}
		// The header is additional data; so is everything before the iv.
		bad := append([]byte(nil), sb...)
		bad[8+hlen-3] ^= 1
		if _, _, err := OpenBlob(bad, k); err == nil {
			t.Fatal("tampered header opened")
		}
		bad = append([]byte(nil), sb...)
		bad[len(bad)-1] ^= 1
		if _, _, err := OpenBlob(bad, k); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("tampered tag: %v", err)
		}
		if _, _, err := OpenBlob(sb, key(8)); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("wrong key: %v", err)
		}
	}
	// E3: the header is {enc} only.
	sb, err := SealBlob(k, "", nil, data, false)
	if err != nil {
		t.Fatal(err)
	}
	h, got, err := OpenBlob(sb, k)
	if err != nil || h.Kid != "" || h.PL != nil || string(h.Raw) != `{"enc":"A256GCM"}` || !bytes.Equal(got, data) {
		t.Fatalf("e3: %v %+v %q", err, h, got)
	}
	if _, err := SealBlob(k, "ns#1", nil, data, false); err == nil {
		t.Fatal("kid without pl")
	}
	// Padding that isn't zeros, and a size past the plaintext, are refused.
	hand := func(header string, plain []byte) []byte {
		out := append([]byte("PLB1"), binary.BigEndian.AppendUint32(nil, uint32(len(header)))...)
		out = append(out, header...)
		aad := append([]byte(nil), out...)
		block, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(block)
		iv := make([]byte, 12)
		out = append(out, iv...)
		return g.Seal(out, iv, plain, aad)
	}
	p := make([]byte, 8+3+5)
	binary.BigEndian.PutUint64(p, 3)
	copy(p[8:], "abc")
	if _, d, err := OpenBlob(hand(`{"enc":"A256GCM"}`, p), k); err != nil || string(d) != "abc" {
		t.Fatalf("zero padding: %v %q", err, d)
	}
	p[len(p)-1] = 1
	if _, _, err := OpenBlob(hand(`{"enc":"A256GCM"}`, p), k); !errors.Is(err, ErrFormat) {
		t.Fatalf("non-zero padding: %v", err)
	}
	binary.BigEndian.PutUint64(p, 99)
	if _, _, err := OpenBlob(hand(`{"enc":"A256GCM"}`, p), k); !errors.Is(err, ErrFormat) {
		t.Fatalf("size past the plaintext: %v", err)
	}
	if _, _, err := OpenBlob(hand(`{"enc":"A128GCM"}`, p), k); !errors.Is(err, ErrFormat) {
		t.Fatalf("enc: %v", err)
	}
	if _, err := ParseBlobHeader([]byte("PLB2xxxx")); !errors.Is(err, ErrFormat) {
		t.Fatalf("magic: %v", err)
	}
}

// §E.3.1: a sealed op may carry a declared blob list.
func TestSealedOpBlobs(t *testing.T) {
	ps, err := SealPatchSet(key(1), "e#1", "e", "a", "", jsonv.MustParse([]byte(`[]`)))
	if err != nil {
		t.Fatal(err)
	}
	jwe, list, ok := SealedOp(ps)
	if !ok || list != nil || jwe == "" {
		t.Fatalf("no list: %v %v", list, ok)
	}
	withList, err := WithBlobs(ps, []string{"1b", "1a"})
	if err != nil {
		t.Fatal(err)
	}
	j2, list, ok := SealedOp(withList)
	if !ok || j2 != jwe || len(list) != 2 || list[0] != "1b" {
		t.Fatalf("list: %v %v", list, ok)
	}
	if j, ok := SealedJWE(withList); !ok || j != jwe {
		t.Fatal("SealedJWE with a list")
	}
	if again, _ := WithBlobs(withList, nil); !bytes.Equal(again, ps) {
		t.Fatalf("an empty list is omitted: %s", again)
	}
	for _, bad := range []string{
		`[{"op":"sealed","value":"x","blobs":"1a"}]`,
		`[{"op":"sealed","value":"x","blobs":[1]}]`,
		`[{"op":"sealed","value":"x","other":[]}]`,
		`[{"op":"sealed","value":"x","blobs":[],"other":1}]`,
	} {
		if _, _, ok := SealedOp([]byte(bad)); ok {
			t.Fatalf("accepted %s", bad)
		}
	}
}
