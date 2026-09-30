package seal

import (
	"bytes"
	"math/bits"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Padding (§E.2.2, optional per namespace with "encryption": { "pad": true }).
//
// The plaintext is the UTF-8 JSON that would otherwise be sealed, followed
// by ASCII spaces up to PadLen of its length. Trailing whitespace is valid
// JSON, so readers need nothing new. Padded payloads are never compressed:
// a compression ratio leaks the content that padding is meant to hide (and
// padding before compressing would be squeezed out again). Each JWE is
// padded as a whole: a log range too, not its entries separately.

// MinPadded is the smallest padded length (§E.2.2).
const MinPadded = 256

// PadLen returns the padded length of an l-byte plaintext:
// max(MinPadded, padmé(l)), where with E = ⌊log₂ l⌋ and S = ⌊log₂ E⌋ + 1,
// padmé rounds l up to a multiple of 2^(E−S). The overhead is at most
// 12%, and a length reveals only about log₂ log₂ l bits.
func PadLen(l int) int {
	if l <= MinPadded {
		return MinPadded
	}
	e := bits.Len(uint(l)) - 1 // ⌊log₂ l⌋
	s := bits.Len(uint(e))     // ⌊log₂ E⌋ + 1
	mask := 1<<(e-s) - 1
	return (l + mask) &^ mask
}

// Pad returns plaintext followed by ASCII spaces up to PadLen(len).
func Pad(plaintext []byte) []byte {
	n := PadLen(len(plaintext))
	out := make([]byte, n)
	copy(out, plaintext)
	for i := len(plaintext); i < n; i++ {
		out[i] = ' '
	}
	return out
}

// Padded reports whether plaintext is padded to its bucket: its length is
// PadLen of its length without trailing spaces. (Canonical JSON never ends
// in a space, so the trailing spaces are exactly the padding.)
func Padded(plaintext []byte) bool {
	return len(plaintext) == PadLen(len(bytes.TrimRight(plaintext, " ")))
}

// IsPadded reports whether a JWE opened as (h, plaintext) is padded as
// §E.2.2 requires: no zip header, and plaintext padded to its bucket.
func IsPadded(h *Header, plaintext []byte) bool {
	return h.Zip == "" && Padded(plaintext)
}

// SealPadded is Seal with padding: plaintext is padded to its bucket and
// never compressed.
func SealPadded(key []byte, kid string, pl PL, plaintext []byte) (string, error) {
	return seal(key, kid, pl, Pad(plaintext), false)
}

// SealMaybePadded is SealPadded if pad is set, Seal otherwise.
func SealMaybePadded(key []byte, kid string, pl PL, plaintext []byte, pad bool) (string, error) {
	if pad {
		return SealPadded(key, kid, pl, plaintext)
	}
	return Seal(key, kid, pl, plaintext)
}

// SealPatchSetPad is SealPatchSet, padding the plaintext patches if pad is
// set (a namespace with "pad", §E.3.1).
func SealPatchSetPad(key []byte, kid, ns, name, parent string, patches any, pad bool) ([]byte, error) {
	jwe, err := SealMaybePadded(key, kid, PatchSetPL(ns, name, parent), jsonv.Canonical(patches), pad)
	if err != nil {
		return nil, err
	}
	return jsonv.Canonical([]any{map[string]any{"op": OpSealed, "value": jwe}}), nil
}

// SealSnapshotPad is SealSnapshot, padding the document if pad is set.
func SealSnapshotPad(key []byte, kid, ns, name, id string, doc any, pad bool) (string, error) {
	return SealMaybePadded(key, kid, SnapshotPL(ns, name, id), jsonv.Canonical(doc), pad)
}
