package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Sealed blobs (§E.2.2, §E.3.1). A JWE would grow a large blob by a third
// in base64, so blobs use a binary form:
//
//	"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(plaintext) ‖ tag
//	plaintext = size ‖ bytes ‖ padding
//
// len is the length of header as a 4-byte big-endian integer, and header is
// canonical JSON. iv is 12 random bytes and the tag 16. The additional data
// is everything before iv, so the header is integrity-protected like a
// JWE's protected header. size is the length of bytes as an 8-byte
// big-endian integer, so the ciphertext commits to the true length, and
// padding is zero bytes, present only with pad, up to PadLen of the whole
// plaintext.
//
// At E2 the server seals a blob once per epoch with the header
// {enc, kid "{ns}#{e}", pl {ns, name, blob}} under the resource's K_r; at
// E3 a client seals each blob under a fresh key of its own with the header
// {enc} only, and the key travels in the sealed reference.

// BlobContentType is the media type of a sealed blob (§E.2.2).
const BlobContentType = "application/vnd.patchlog.sealed-blob"

// blobMagic starts every sealed blob.
const blobMagic = "PLB1"

// maxBlobHeader bounds a sealed blob's header.
const maxBlobHeader = 64 << 10

// BlobPL binds an E2 sealed blob: { ns, name, blob }.
func BlobPL(ns, name, bid string) PL {
	return PL{"ns": ns, "name": name, "blob": bid}
}

// BlobHeader is a sealed blob's header: Kid and PL are empty at E3.
type BlobHeader struct {
	Enc string
	Kid string
	PL  PL
	// Raw is the header as transmitted (canonical JSON when well-formed).
	Raw []byte
}

// SealBlob seals data in the binary form under key. With kid set the header
// is the E2 one, {enc, kid, pl}; with kid "" (and pl nil) it is E3's {enc}.
// With pad, the plaintext is padded with zero bytes to its bucket.
func SealBlob(key []byte, kid string, pl PL, data []byte, pad bool) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	hdr := map[string]any{"enc": EncA256GCM}
	if kid != "" || pl != nil {
		if kid == "" || pl == nil {
			return nil, fmt.Errorf("seal: an E2 sealed blob needs kid and pl")
		}
		hdr["kid"], hdr["pl"] = kid, map[string]any(pl)
	}
	h := jsonv.Canonical(jsonv.FromGo(hdr))
	n := 8 + len(data)
	if pad {
		n = PadLen(n)
	}
	plain := make([]byte, n) // the padding is the zero bytes past the data
	binary.BigEndian.PutUint64(plain, uint64(len(data)))
	copy(plain[8:], data)
	out := make([]byte, 0, 8+len(h)+aead.NonceSize()+n+aead.Overhead())
	out = append(out, blobMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(h)))
	out = append(out, h...)
	aad := out[:len(out):len(out)]
	iv := make([]byte, aead.NonceSize())
	rand.Read(iv)
	out = append(out, iv...)
	return aead.Seal(out, iv, plain, aad), nil
}

// ParseBlobHeader decodes a sealed blob's header without decrypting it. The
// result is unauthenticated until OpenBlob succeeds.
func ParseBlobHeader(sealed []byte) (*BlobHeader, error) {
	h, _, err := splitBlob(sealed)
	return h, err
}

func splitBlob(sealed []byte) (*BlobHeader, int, error) {
	if len(sealed) < 8 || string(sealed[:4]) != blobMagic {
		return nil, 0, fmt.Errorf("%w: not a sealed blob", ErrFormat)
	}
	l := binary.BigEndian.Uint32(sealed[4:8])
	if l > maxBlobHeader || int(l) > len(sealed)-8 {
		return nil, 0, fmt.Errorf("%w: sealed blob header length", ErrFormat)
	}
	raw := sealed[8 : 8+int(l)]
	v, err := jsonv.Parse(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: sealed blob header: %v", ErrFormat, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, 0, fmt.Errorf("%w: sealed blob header is not an object", ErrFormat)
	}
	h := &BlobHeader{Raw: append([]byte(nil), raw...)}
	h.Enc, _ = m["enc"].(string)
	if h.Enc != EncA256GCM {
		return nil, 0, fmt.Errorf("%w: unsupported enc", ErrFormat)
	}
	for k := range m {
		switch k {
		case "enc", "kid", "pl":
		default:
			return nil, 0, fmt.Errorf("%w: sealed blob header member %q", ErrFormat, k)
		}
	}
	if x, has := m["kid"]; has {
		if h.Kid, _ = x.(string); h.Kid == "" {
			return nil, 0, fmt.Errorf("%w: sealed blob kid", ErrFormat)
		}
	}
	if x, has := m["pl"]; has {
		pl, ok := x.(map[string]any)
		if !ok {
			return nil, 0, fmt.Errorf("%w: sealed blob pl", ErrFormat)
		}
		h.PL = PL(pl)
	}
	if (h.Kid == "") != (h.PL == nil) {
		return nil, 0, fmt.Errorf("%w: a sealed blob has both kid and pl or neither", ErrFormat)
	}
	return h, 8 + int(l), nil
}

// OpenBlob decrypts a sealed blob under key and returns its header and
// bytes. It checks the length prefix and that any padding is all zeros;
// callers check the header (Expect, or that an E3 header has no kid).
func OpenBlob(sealed, key []byte) (*BlobHeader, []byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	h, off, err := splitBlob(sealed)
	if err != nil {
		return nil, nil, err
	}
	rest := sealed[off:]
	if len(rest) < aead.NonceSize()+aead.Overhead() {
		return nil, nil, fmt.Errorf("%w: sealed blob too short", ErrFormat)
	}
	iv, ct := rest[:aead.NonceSize()], rest[aead.NonceSize():]
	plain, err := aead.Open(nil, iv, ct, sealed[:off])
	if err != nil {
		return nil, nil, ErrDecrypt
	}
	if len(plain) < 8 {
		return nil, nil, fmt.Errorf("%w: sealed blob plaintext too short", ErrFormat)
	}
	size := binary.BigEndian.Uint64(plain)
	if size > uint64(len(plain)-8) {
		return nil, nil, fmt.Errorf("%w: sealed blob size exceeds its plaintext", ErrFormat)
	}
	data, padding := plain[8:8+size], plain[8+size:]
	if len(padding) > 0 && !bytes.Equal(padding, make([]byte, len(padding))) {
		return nil, nil, fmt.Errorf("%w: sealed blob padding isn't zeros", ErrFormat)
	}
	return h, data, nil
}

// Expect reports ErrMismatch unless the header's kid and pl are exactly
// wantKid and wantPL.
func (h *BlobHeader) Expect(wantKid string, wantPL PL) error {
	if h.Kid != wantKid || !jsonv.Equal(map[string]any(h.PL), jsonv.FromGo(map[string]any(wantPL))) {
		return ErrMismatch
	}
	return nil
}
