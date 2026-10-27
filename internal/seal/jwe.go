// Package seal is the shared cryptography of Addendum E (encryption):
//
//   - E2/E3 sealed representation: JWE compact serialization (RFC 7516) with
//     alg "dir", enc "A256GCM" and the `pl` binding claims (§E.2.2).
//   - Key schedule: epoch keys K_e, kids "{ns}#{e}" and per-resource keys
//     K_r = HKDF-SHA256(K_e, "patchlog-e2", ns ‖ 0x0A ‖ name) (§E.2.1).
//   - Key wrapping to recipients' X25519 keys with HPKE (RFC 9180), in base
//     mode, and in auth mode for the E3 keyring resource (§E.2.3, §E.3.2).
//   - E3 sealed patch sets and prune snapshots (§E.3.1, §8.6).
//   - E1 storage encryption: row AEAD and a chunked streaming file format.
//   - Sealed bundles (§G.5.1.1), line by line to X25519 recipients: bundle
//     tools' and the pruning archives of encrypted namespaces (§8.6).
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
	// (RFC 7516 §4.1.3). Seal never sets it (§E.2.2); Open still inflates
	// it in bytes sealed before v0.65, which are served forever.
	ZipDeflate = "DEF"

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

// Kinds in PL (§E.2.2).
const (
	KindRev       = "rev"
	KindTombstone = "tombstone"
	KindDoc       = "doc"
	KindLog       = "log"
	// KindPurge and KindPrune are the kinds of a resource stream's purge
	// and prune events (ResourceEventPL).
	KindPurge = "purge"
	KindPrune = "prune"
	// KindConfig and KindSnapshot are legacy: bytes sealed before v0.63
	// bind a namespace document with kind "config" (now "doc") and an E3
	// prune snapshot with kind "snapshot" (now no kind). Expect accepts
	// them for those payloads (legacyPL); nothing seals them any more.
	KindConfig   = "config"
	KindSnapshot = "snapshot"
)

// ResourcePL binds a resource revision/document/log entry:
// { ns, name, id, kind } with kind "rev" | "tombstone" | "doc" | "log".
func ResourcePL(ns, name, id, kind string) PL {
	return PL{"ns": ns, "name": name, "id": id, "kind": kind}
}

// ResourceEventPL binds a resource stream's purge or prune event, sealed
// under the resource's K_r of the current epoch (§E.2.2, §7.3):
// { ns, name, kind }, kind the event type, KindPurge or KindPrune. The
// event has no id, so neither has its pl.
func ResourceEventPL(ns, name, kind string) PL {
	return PL{"ns": ns, "name": name, "kind": kind}
}

// NamespaceDocPL binds the namespace document at ns_id id:
// { ns, id, kind: "doc" } (§E.2.2).
func NamespaceDocPL(ns, id string) PL {
	return PL{"ns": ns, "id": id, "kind": KindDoc}
}

// RangePL binds a namespace log range: { ns, range: [since, id] }.
// Ranges are sealed as one JWE and never compressed.
func RangePL(ns, since, id string) PL {
	return PL{"ns": ns, "range": []any{since, id}}
}

// GrantPL binds a grant served by GET /ns/{ns}/grants/{gid} (§C.3.1,
// §E.2.2): { ns, grant: gid }.
func GrantPL(ns, gid string) PL {
	return PL{"ns": ns, "grant": gid}
}

// PatchSetPL binds an E3 sealed patch set: { ns, name, parent }, parent ""
// for genesis (§E.3.1).
func PatchSetPL(ns, name, parent string) PL {
	return PL{"ns": ns, "name": name, "parent": parent}
}

// SnapshotPL binds an E3 prune snapshot to the revision whose document it
// is: { ns, name, id }, with no kind (§E.3.1, §8.6).
func SnapshotPL(ns, name, id string) PL {
	return PL{"ns": ns, "name": name, "id": id}
}

// Header is a parsed JWE protected header.
type Header struct {
	Alg string
	Enc string
	Kid string
	Zip string // "" or, in legacy bytes only, "DEF"
	PL  PL
	// Raw is the decoded protected header (UTF-8 JSON) as transmitted.
	Raw []byte
}

// Seal encrypts plaintext under key as a JWE compact serialization with
// protected header canonical({alg:"dir", enc:"A256GCM", kid, pl}). Sealed
// payloads are never compressed and carry no zip header, whatever pl binds
// (§E.2.2): a document holds content from several authors (CRIME/BREACH).
func Seal(key []byte, kid string, pl PL, plaintext []byte) (string, error) {
	return seal(key, kid, pl, plaintext, nil)
}

// SealUncompressed is Seal, which no longer compresses (§E.2.2).
//
// Deprecated: use Seal.
func SealUncompressed(key []byte, kid string, pl PL, plaintext []byte) (string, error) {
	return seal(key, kid, pl, plaintext, nil)
}

// SealWithIV is Seal with the 12-byte iv in place of a random one, for
// test vectors (Addendum I). Never use it for content: an IV used twice
// under one key breaks AES-GCM.
func SealWithIV(key []byte, kid string, pl PL, plaintext, iv []byte) (string, error) {
	if len(iv) != 12 {
		return "", fmt.Errorf("seal: an IV has 12 bytes")
	}
	return seal(key, kid, pl, plaintext, iv)
}

// seal seals plaintext as Seal does, under iv, or a fresh random IV when
// iv is nil.
func seal(key []byte, kid string, pl PL, plaintext, iv []byte) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if kid == "" || pl == nil {
		return "", fmt.Errorf("seal: kid and pl are required")
	}
	hdr := map[string]any{"alg": AlgDir, "enc": EncA256GCM, "kid": kid, "pl": map[string]any(pl)}
	protected := b64.EncodeToString(jsonv.Canonical(hdr))
	if iv == nil {
		iv = make([]byte, aead.NonceSize())
		rand.Read(iv)
	}
	sealed := aead.Seal(nil, iv, plaintext, []byte(protected))
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

// Expect reports ErrMismatch unless the header's kid is wantKid and its pl
// is exactly wantPL, or the legacy pl of the same payload (legacyPL): bytes
// sealed before v0.63 are stored once and served forever (§E.2.2), so
// readers accept both forms.
func (h *Header) Expect(wantKid string, wantPL PL) error {
	if h.Kid != wantKid {
		return ErrMismatch
	}
	if plEqual(h.PL, wantPL) {
		return nil
	}
	if legacy := legacyPL(wantPL); legacy != nil && plEqual(h.PL, legacy) {
		return nil
	}
	return ErrMismatch
}

func plEqual(got, want PL) bool {
	return jsonv.Equal(map[string]any(got), jsonv.FromGo(map[string]any(want)))
}

// legacyPL returns the pl that bytes sealed before v0.63 carry for the
// payload want binds, or nil where it was the same:
//
//   - a namespace document, { ns, id, kind: "doc" }, was bound to
//     { ns, id, kind: "config" };
//   - an E3 prune snapshot, { ns, name, id }, to { ns, name, id,
//     kind: "snapshot" }.
//
// No other payload had those pls, so accepting them opens nothing else.
func legacyPL(want PL) PL {
	_, ns := want["ns"]
	_, id := want["id"]
	_, name := want["name"]
	kind, hasKind := want["kind"]
	switch {
	case len(want) == 3 && ns && id && kind == KindDoc:
		return PL{"ns": want["ns"], "id": want["id"], "kind": KindConfig}
	case len(want) == 3 && ns && id && name && !hasKind:
		return PL{"ns": want["ns"], "name": want["name"], "id": want["id"], "kind": KindSnapshot}
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

// inflate decompresses raw DEFLATE, failing with ErrTooLarge as soon as the
// output would exceed max bytes. Only bytes sealed before v0.65 are
// compressed (ZipDeflate).
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
