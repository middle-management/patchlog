package seal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Known answers for max(256, padmé(L)) (§E.2.2), worked by hand:
// L=257: E=8, S=4, multiple of 2^4=16 → 272; L=1000: E=9, S=4, 2^5 → 1024;
// L=1025: E=10, S=4, 2^6 → 1088; L=5000: E=12, S=4, 2^8 → 5120;
// L=70000: E=16, S=5, 2^11 → 71680; L=1<<20+1: E=20, S=5, 2^15 → 1081344.
func TestPadLenKnownAnswers(t *testing.T) {
	for _, tc := range []struct{ l, want int }{
		{0, 256}, {1, 256}, {255, 256}, {256, 256}, {257, 272}, {272, 272}, {273, 288},
		{511, 512}, {512, 512}, {513, 544}, {1000, 1024}, {1024, 1024}, {1025, 1088},
		{5000, 5120}, {70000, 71680}, {1<<20 + 1, 1081344},
	} {
		if got := PadLen(tc.l); got != tc.want {
			t.Errorf("PadLen(%d) = %d, want %d", tc.l, got, tc.want)
		}
	}
}

// Every bucket is at least L, at most 12% above it, stable (a padded
// length is its own bucket) and monotonic.
func TestPadLenProperties(t *testing.T) {
	prev := 0
	for l := 0; l < 1<<17; l++ {
		p := PadLen(l)
		if p < l || p < MinPadded {
			t.Fatalf("PadLen(%d) = %d", l, p)
		}
		if l > MinPadded && float64(p-l) > 0.12*float64(l) {
			t.Fatalf("PadLen(%d) = %d: overhead above 12%%", l, p)
		}
		if PadLen(p) != p {
			t.Fatalf("PadLen(PadLen(%d)) = %d, not %d", l, PadLen(p), p)
		}
		if p < prev {
			t.Fatalf("PadLen(%d) = %d < PadLen(%d) = %d", l, p, l-1, prev)
		}
		prev = p
	}
}

func TestPadAndPadded(t *testing.T) {
	for _, n := range []int{0, 10, 256, 257, 3000} {
		pt := bytes.Repeat([]byte("x"), n)
		p := Pad(pt)
		if len(p) != PadLen(n) || !bytes.HasPrefix(p, pt) || strings.Trim(string(p[n:]), " ") != "" {
			t.Fatalf("Pad(%d bytes): %d bytes", n, len(p))
		}
		if !Padded(p) {
			t.Fatalf("Padded(Pad(%d bytes)) = false", n)
		}
		if n != PadLen(n) && Padded(pt) {
			t.Fatalf("Padded(%d unpadded bytes) = true", n)
		}
	}
	// Padded JSON is still the same JSON.
	doc := jsonv.Canonical(map[string]any{"a": "b"})
	v, err := jsonv.Parse(Pad(doc))
	if err != nil || !jsonv.Equal(v, map[string]any{"a": "b"}) {
		t.Fatalf("padded JSON: %v %v", v, err)
	}
}

// Padded seals are never compressed, log ranges included, and open to the
// padded plaintext; the padding check sees compression and short
// plaintexts.
func TestSealPadded(t *testing.T) {
	k := key(7)
	kid := Kid("matches", 1)
	large := bytes.Repeat([]byte(`{"a":"bbbbbbbb"},`), 200) // compresses well
	for _, pl := range []PL{ResourcePL("matches", "derby", "1aaaa", KindDoc), RangePL("matches", "", "1bbbb")} {
		jwe, err := SealPadded(k, kid, pl, large)
		if err != nil {
			t.Fatal(err)
		}
		h, pt, err := Open(jwe, k)
		if err != nil {
			t.Fatal(err)
		}
		if h.Zip != "" || len(pt) != PadLen(len(large)) || !IsPadded(h, pt) || !bytes.Equal(bytes.TrimRight(pt, " "), large) {
			t.Fatalf("padded seal: zip %q, %d bytes", h.Zip, len(pt))
		}
	}
	// Unpadded and compressed: not padded.
	jwe, _ := Seal(k, kid, ResourcePL("matches", "derby", "1aaaa", KindDoc), large)
	h, pt, _ := Open(jwe, k)
	if h.Zip != ZipDeflate || IsPadded(h, pt) {
		t.Fatalf("compressed seal counted as padded")
	}
	// Short, unpadded.
	jwe, _ = Seal(k, kid, ResourcePL("matches", "derby", "1aaaa", KindDoc), []byte(`{}`))
	h, pt, _ = Open(jwe, k)
	if IsPadded(h, pt) {
		t.Fatalf("short seal counted as padded")
	}

	// Patch sets and snapshots.
	patches := []any{map[string]any{"op": "add", "path": "/a", "value": "b"}}
	for _, pad := range []bool{false, true} {
		body, err := SealPatchSetPad(k, kid, "matches", "derby", "", patches, pad)
		if err != nil {
			t.Fatal(err)
		}
		v, padded, err := OpenPatchSetPadded(body, k, kid, "matches", "derby", "")
		if err != nil || padded != pad || !jsonv.Equal(v, jsonv.FromGo(patches)) {
			t.Fatalf("pad %v: %v padded %v err %v", pad, v, padded, err)
		}
		snap, err := SealSnapshotPad(k, kid, "matches", "derby", "1aaaa", map[string]any{"a": "b"}, pad)
		if err != nil {
			t.Fatal(err)
		}
		if d, err := OpenSnapshot(snap, k, kid, "matches", "derby", "1aaaa"); err != nil || !jsonv.Equal(d, map[string]any{"a": "b"}) {
			t.Fatalf("snapshot %v %v", d, err)
		}
	}
}
