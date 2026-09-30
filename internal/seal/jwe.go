// Package seal is the shared cryptography of Addendum E (encryption):
//
//   - E2/E3 sealed representation: JWE compact serialization (RFC 7516) with
//     alg "dir", enc "A256GCM" and the `pl` binding claims (§E.2.2).
//   - Key schedule: epoch keys K_e, kids "{ns}#{e}" and per-resource keys
//     K_r = HKDF-SHA256(K_e, "patchlog-e2", ns ‖ 0x0A ‖ name) (§E.2.1).
//   - Key wrapping to recipients' X25519 keys with HPKE (RFC 9180) and the
//     E3 keyring resource (§E.2.3, §E.3.2).
//   - E3 sealed patch sets and prune snapshots (§E.3.1, §8.6).
//   - E1 storage encryption: row AEAD and a chunked streaming file format.
//   - `$nonce` helpers (§C.7, §E.2.5).
//
// Only the Go standard library is used.
package seal

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// KeySize is the size of every symmetric key in this package (AES-256).
const KeySize = 32

// ContentType is the media type of a sealed response (§E.2.2).
const ContentType = "application/jose"

const (
	// AlgDir and EncA256GCM are the only JWE algorithms used (§E.2.2).
	AlgDir     = "dir"
	EncA256GCM = "A256GCM"
	// ZipDeflate marks raw DEFLATE (RFC 1951) compressed plaintext
	// (RFC 7516 §4.1.3).
	ZipDeflate = "DEF"

	// CompressThreshold is the plaintext size from which Seal tries
	// compression. Compression is kept only if it actually shrinks.
	CompressThreshold = 1024

	// DefaultMaxPlaintext bounds decompressed output in Open and
	// OpenExpect (zip-bomb guard). Use OpenLimit for another bound.
	DefaultMaxPlaintext = 64 << 20
)

var (
	// ErrFormat reports malformed input (not a well-formed JWE, row, file…).
	ErrFormat = errors.New("seal: malformed input")
	// ErrDecrypt reports an authentication failure: wrong key, or tampered
	// header, IV, ciphertext, tag or AAD.
	ErrDecrypt = errors.New("seal: decryption failed")
	// ErrMismatch reports a JWE that decrypted but is bound to another kid
	// or pl than expected (replay under another resource/revision/epoch).
	ErrMismatch = errors.New("seal: kid or pl mismatch")
	// ErrTooLarge reports plaintext above the configured maximum.
	ErrTooLarge = errors.New("seal: plaintext too large")
	// ErrKeySize reports a key that is not KeySize bytes.
	ErrKeySize = errors.New("seal: key must be 32 bytes")
)

var b64 = base64.RawURLEncoding.Strict()

// PL is the `pl` claim set of a protected header, as a jsonv model value.
// Use the constructors below so that shapes stay exactly as specified.
type PL map[string]any

// Kinds of resource/namespace documents in PL.
const (
	KindRev       = "rev"
	KindTombstone = "tombstone"
	KindDoc       = "doc"
	KindLog       = "log"
	KindConfig    = "config"
	KindSnapshot  = "snapshot"
)

// ResourcePL binds a resource revision/document/log entry:
// { ns, name, id, kind } with kind "rev" | "tombstone" | "doc" | "log".
func ResourcePL(ns, name, id, kind string) PL {
	return PL{"ns": ns, "name": name, "id": id, "kind": kind}
}

// NamespaceDocPL binds a namespace document: { ns, id, kind: "config" }.
func NamespaceDocPL(ns, id string) PL {
	return PL{"ns": ns, "id": id, "kind": KindConfig}
}

// RangePL binds a namespace log range: { ns, range: [since, id] }.
// Ranges are sealed as one JWE and never compressed.
func RangePL(ns, since, id string) PL {
	return PL{"ns": ns, "range": []any{since, id}}
}

// PatchSetPL binds an E3 sealed patch set: { ns, name, parent }, parent ""
// for genesis (§E.3.1).
func PatchSetPL(ns, name, parent string) PL {
	return PL{"ns": ns, "name": name, "parent": parent}
}

// SnapshotPL binds an E3 prune snapshot: { ns, name, id, kind: "snapshot" }
// (§8.6).
func SnapshotPL(ns, name, id string) PL {
	return PL{"ns": ns, "name": name, "id": id, "kind": KindSnapshot}
}

// Header is a parsed JWE protected header.
type Header struct {
	Alg string
	Enc string
	Kid string
	Zip string // "" or "DEF"
	PL  PL
	// Raw is the decoded protected header (UTF-8 JSON) as transmitted.
	Raw []byte
}

// Seal encrypts plaintext under key as a JWE compact serialization with
// protected header canonical({alg:"dir", enc:"A256GCM", kid, pl, zip?}).
// Plaintext of at least CompressThreshold bytes is DEFLATE-compressed when
// that shrinks it, except for namespace log ranges (pl with "range"), which
// are never compressed (§E.2.2).
func Seal(key []byte, kid string, pl PL, plaintext []byte) (string, error) {
	_, isRange := pl["range"]
	return seal(key, kid, pl, plaintext, !isRange)
}

// SealUncompressed is Seal without compression, for callers that must not
// compress (e.g. content mixing several authors).
func SealUncompressed(key []byte, kid string, pl PL, plaintext []byte) (string, error) {
	return seal(key, kid, pl, plaintext, false)
}

func seal(key []byte, kid string, pl PL, plaintext []byte, mayCompress bool) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if kid == "" || pl == nil {
		return "", fmt.Errorf("seal: kid and pl are required")
	}
	hdr := map[string]any{"alg": AlgDir, "enc": EncA256GCM, "kid": kid, "pl": map[string]any(pl)}
	body := plaintext
	if mayCompress && len(plaintext) >= CompressThreshold {
		if z := deflate(plaintext); len(z) < len(plaintext) {
			body = z
			hdr["zip"] = ZipDeflate
		}
	}
	protected := b64.EncodeToString(jsonv.Canonical(hdr))
	iv := make([]byte, aead.NonceSize())
	rand.Read(iv)
	sealed := aead.Seal(nil, iv, body, []byte(protected))
	ct, tag := sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():]
	var sb strings.Builder
	sb.WriteString(protected)
	sb.WriteString("..") // empty JWE Encrypted Key for "dir"
	sb.WriteString(b64.EncodeToString(iv))
	sb.WriteByte('.')
	sb.WriteString(b64.EncodeToString(ct))
	sb.WriteByte('.')
	sb.WriteString(b64.EncodeToString(tag))
	return sb.String(), nil
}

// ParseHeader decodes and validates the protected header of a compact JWE
// without decrypting it. The result is unauthenticated until Open succeeds.
func ParseHeader(jwe string) (*Header, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, ErrFormat
	}
	return parseHeader(parts[0])
}

func parseHeader(seg string) (*Header, error) {
	raw, err := b64.DecodeString(seg)
	if err != nil {
		return nil, ErrFormat
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrFormat, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: header is not an object", ErrFormat)
	}
	h := &Header{Raw: raw}
	h.Alg, _ = m["alg"].(string)
	h.Enc, _ = m["enc"].(string)
	h.Kid, _ = m["kid"].(string)
	if h.Alg != AlgDir || h.Enc != EncA256GCM {
		return nil, fmt.Errorf("%w: unsupported alg/enc", ErrFormat)
	}
	if h.Kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrFormat)
	}
	if _, ok := m["crit"]; ok {
		return nil, fmt.Errorf("%w: unsupported crit", ErrFormat)
	}
	if z, ok := m["zip"]; ok {
		if z != ZipDeflate {
			return nil, fmt.Errorf("%w: unsupported zip", ErrFormat)
		}
		h.Zip = ZipDeflate
	}
	pl, ok := m["pl"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: missing pl", ErrFormat)
	}
	h.PL = PL(pl)
	return h, nil
}

// Open decrypts a compact JWE with DefaultMaxPlaintext as the bound. It
// returns the authenticated header so callers can check kid and pl; prefer
// OpenExpect, which does that.
func Open(jwe string, key []byte) (*Header, []byte, error) {
	return OpenLimit(jwe, key, DefaultMaxPlaintext)
}

// OpenLimit is Open with an explicit bound on the (decompressed) plaintext.
func OpenLimit(jwe string, key []byte, maxPlaintext int) (*Header, []byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 || parts[1] != "" {
		return nil, nil, ErrFormat
	}
	h, err := parseHeader(parts[0])
	if err != nil {
		return nil, nil, err
	}
	iv, err1 := b64.DecodeString(parts[2])
	ct, err2 := b64.DecodeString(parts[3])
	tag, err3 := b64.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != aead.NonceSize() || len(tag) != aead.Overhead() {
		return nil, nil, ErrFormat
	}
	if h.Zip == "" && len(ct) > maxPlaintext {
		return nil, nil, ErrTooLarge
	}
	// AAD = ASCII(BASE64URL(UTF8(protected header))), RFC 7516 §5.1 step 14.
	body, err := aead.Open(nil, iv, append(ct, tag...), []byte(parts[0]))
	if err != nil {
		return nil, nil, ErrDecrypt
	}
	if h.Zip == ZipDeflate {
		body, err = inflate(body, maxPlaintext)
		if err != nil {
			return nil, nil, err
		}
	}
	return h, body, nil
}

// OpenExpect decrypts jwe and fails with ErrMismatch unless its kid equals
// wantKid and its pl equals wantPL exactly (same members, same values).
func OpenExpect(jwe string, key []byte, wantKid string, wantPL PL) ([]byte, error) {
	h, pt, err := Open(jwe, key)
	if err != nil {
		return nil, err
	}
	if err := h.Expect(wantKid, wantPL); err != nil {
		return nil, err
	}
	return pt, nil
}

// Expect reports ErrMismatch unless the header's kid and pl are exactly
// wantKid and wantPL.
func (h *Header) Expect(wantKid string, wantPL PL) error {
	if h.Kid != wantKid || !jsonv.Equal(map[string]any(h.PL), jsonv.FromGo(map[string]any(wantPL))) {
		return ErrMismatch
	}
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deflate(p []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(p)
	w.Close()
	return buf.Bytes()
}

// inflate decompresses raw DEFLATE, failing with ErrTooLarge as soon as the
// output would exceed max bytes.
func inflate(z []byte, max int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(z))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", ErrFormat, err)
	}
	if len(out) > max {
		return nil, ErrTooLarge
	}
	return out, nil
}
