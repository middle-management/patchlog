package bundle

// Sealed bundles (§G.5.1.1): a bundle encrypted line by line to one or more
// X25519 recipients, so it can be written and read as a stream.
//
//	{"id":"<128 bits, b64url>","recipients":[{"kid","suite","wrapped"}],"sealedBundle":1}
//	<JWE compact of bundle line 0 (the header)>
//	<JWE compact of bundle line 1>
//	…
//
//   - The envelope line is canonical JSON. The content key K_b (256 random
//     bits) is wrapped for each recipient with HPKE base mode, suite
//     seal.Suite (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM),
//     info "patchlog-bundle-v1" ‖ 0x0A ‖ id; wrapped is base64url(enc ‖ ct).
//     A recipient's kid is its RFC 7638 JWK thumbprint (Thumbprint).
//   - Each following line is a JWE compact under K_b with the protected
//     header canonical({"alg":"dir","enc":"A256GCM","pl":{"bundle":id,
//     "line":n}}), plus "last":true on the final line only; no kid (there is
//     one key) and no compression. The plaintext of line n is bundle line n
//     as canonical JSON (§3.1), without its newline.
//   - A reader rejects the whole sealed bundle if a line fails to decrypt,
//     its header has other members, pl.bundle isn't id, the line numbers
//     aren't 0, 1, 2… in order, or no line says last or a line follows it.
//     The decrypted lines are then an ordinary bundle, checked by Reader;
//     its digest (source.bundle) is the plaintext bundle's.
//
// Key files are JWKs: a recipient is {"kty":"OKP","crv":"X25519","x"}, an
// identity (private key) the same with "d" (RFC 8037).

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// SealedMediaType is the media type of a sealed bundle (§G.5.1.1).
const SealedMediaType = "application/vnd.patchlog.sealed-bundle+jsonl"

// bundleWrapInfo prefixes the HPKE info of a sealed bundle's content key.
const bundleWrapInfo = "patchlog-bundle-v1\n"

// maxSealedLine bounds one line of a sealed bundle (and its envelope).
const maxSealedLine = 256 << 20

var b64 = base64.RawURLEncoding.Strict()

// ErrNotRecipient reports a sealed bundle that has no content key for the
// identity given (or none was given).
var ErrNotRecipient = errors.New("bundle: the sealed bundle is not addressed to this identity")

// --- keys ---------------------------------------------------------------

// Thumbprint is the RFC 7638 thumbprint of an X25519 public key: base64url
// of the SHA-256 of canonical({crv, kty, x}).
func Thumbprint(pub *ecdh.PublicKey) string {
	s := sha256.Sum256(jsonv.Canonical(seal.RecipientJWK(pub)))
	return b64.EncodeToString(s[:])
}

// IdentityJWK is the private JWK of an X25519 key: {kty, crv, x, d}.
func IdentityJWK(priv *ecdh.PrivateKey) map[string]any {
	m := seal.RecipientJWK(priv.PublicKey())
	m["d"] = b64.EncodeToString(priv.Bytes())
	return m
}

func parseJWK(b []byte) (map[string]any, error) {
	v, err := jsonv.Parse(bytes.TrimSpace(b))
	if err != nil {
		return nil, fmt.Errorf("bundle: key: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok || m["kty"] != "OKP" || m["crv"] != "X25519" {
		return nil, errors.New(`bundle: key: want an X25519 JWK {"kty":"OKP","crv":"X25519",…}`)
	}
	return m, nil
}

// ParseIdentity parses a private X25519 JWK (with "d"). If it has "x", it
// must match "d".
func ParseIdentity(b []byte) (*ecdh.PrivateKey, error) {
	m, err := parseJWK(b)
	if err != nil {
		return nil, err
	}
	ds, _ := m["d"].(string)
	d, err := b64.DecodeString(ds)
	if err != nil || len(d) != 32 {
		return nil, errors.New("bundle: identity: the JWK needs d, a base64url X25519 private key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("bundle: identity: %v", err)
	}
	if x, ok := m["x"]; ok && x != seal.RecipientJWK(priv.PublicKey())["x"] {
		return nil, errors.New("bundle: identity: x doesn't match d")
	}
	return priv, nil
}

// ParseRecipient parses a recipient's X25519 JWK; a private JWK stands for
// its public key.
func ParseRecipient(b []byte) (*ecdh.PublicKey, error) {
	m, err := parseJWK(b)
	if err != nil {
		return nil, err
	}
	if _, ok := m["d"]; ok {
		priv, err := ParseIdentity(b)
		if err != nil {
			return nil, err
		}
		return priv.PublicKey(), nil
	}
	return seal.ParseRecipientJWK(m)
}

// LoadIdentity reads a private JWK file.
func LoadIdentity(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseIdentity(b)
}

// LoadRecipient reads a recipient JWK: inline JSON if s starts with "{",
// a file path otherwise.
func LoadRecipient(s string) (*ecdh.PublicKey, error) {
	b := []byte(s)
	if !strings.HasPrefix(strings.TrimSpace(s), "{") {
		var err error
		if b, err = os.ReadFile(s); err != nil {
			return nil, err
		}
	}
	return ParseRecipient(b)
}

// --- writing --------------------------------------------------------------

var hpkeKDF, hpkeAEAD = hpke.HKDFSHA256(), hpke.AES256GCM()

func newAEAD(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// SealedWriter seals a bundle written to it (the bytes a Writer produces,
// or any bundle file) line by line (§G.5.1.1). Each line is sealed once the
// next one starts, so the last can be marked; Close seals it. Close must be
// called; it doesn't close the underlying writer.
type SealedWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	id      string
	buf     []byte // the incomplete line
	pending []byte // the last complete line, canonical, not yet sealed
	has     bool
	n       int
	err     error
	closed  bool
}

// NewSealedWriter writes the envelope line for recipients to w.
func NewSealedWriter(w io.Writer, recipients []*ecdh.PublicKey) (*SealedWriter, error) {
	if len(recipients) == 0 {
		return nil, errors.New("bundle: a sealed bundle needs at least one recipient")
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	id := b64.EncodeToString(idb)
	key := seal.NewKey()
	info := []byte(bundleWrapInfo + id)
	var rs []any
	for _, r := range recipients {
		pk, err := hpke.NewDHKEMPublicKey(r)
		if err != nil {
			return nil, err
		}
		wrapped, err := hpke.Seal(pk, hpkeKDF, hpkeAEAD, info, key)
		if err != nil {
			return nil, err
		}
		rs = append(rs, map[string]any{"kid": Thumbprint(r), "suite": seal.Suite, "wrapped": b64.EncodeToString(wrapped)})
	}
	env := jsonv.Canonical(map[string]any{"sealedBundle": 1.0, "id": id, "recipients": rs})
	if _, err := w.Write(append(env, '\n')); err != nil {
		return nil, err
	}
	return &SealedWriter{w: w, aead: newAEAD(key), id: id}, nil
}

// Write takes bundle bytes.
func (s *SealedWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("bundle: write after Close")
	}
	if s.err != nil {
		return 0, s.err
	}
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.buf = append(s.buf, p...)
			break
		}
		line := append(s.buf, p[:i]...)
		s.buf, p = nil, p[i+1:]
		if s.err = s.line(line); s.err != nil {
			return 0, s.err
		}
	}
	return n, nil
}

func (s *SealedWriter) line(b []byte) error {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	v, err := jsonv.Parse(b)
	if err != nil {
		return &Error{Line: s.n + 1, Msg: "not I-JSON: " + err.Error()}
	}
	if s.has {
		if err := s.emit(s.pending, false); err != nil {
			return err
		}
	}
	s.pending, s.has = jsonv.Canonical(v), true
	return nil
}

func (s *SealedWriter) emit(pt []byte, last bool) error {
	hdr := map[string]any{"alg": seal.AlgDir, "enc": seal.EncA256GCM, "pl": map[string]any{"bundle": s.id, "line": float64(s.n)}}
	if last {
		hdr["last"] = true
	}
	protected := b64.EncodeToString(jsonv.Canonical(hdr))
	iv := make([]byte, s.aead.NonceSize())
	rand.Read(iv)
	ct := s.aead.Seal(nil, iv, pt, []byte(protected))
	tag := ct[len(ct)-s.aead.Overhead():]
	ct = ct[:len(ct)-s.aead.Overhead()]
	var sb strings.Builder
	sb.WriteString(protected)
	sb.WriteString("..")
	sb.WriteString(b64.EncodeToString(iv))
	sb.WriteByte('.')
	sb.WriteString(b64.EncodeToString(ct))
	sb.WriteByte('.')
	sb.WriteString(b64.EncodeToString(tag))
	sb.WriteByte('\n')
	s.n++
	_, err := io.WriteString(s.w, sb.String())
	return err
}

// Close seals the last line, marked last.
func (s *SealedWriter) Close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.err != nil {
		return s.err
	}
	if len(bytes.TrimSpace(s.buf)) > 0 {
		if s.err = s.line(s.buf); s.err != nil {
			return s.err
		}
	}
	if !s.has {
		s.err = &Error{Line: 1, Msg: "empty bundle"}
		return s.err
	}
	s.err = s.emit(s.pending, true)
	return s.err
}

// --- reading ------------------------------------------------------------

// sealedEnvelope is a parsed envelope line.
type sealedEnvelope struct {
	id         string
	recipients map[string][]byte // kid → wrapped
}

// parseEnvelope parses a sealed bundle's envelope line; ok is false if the
// line isn't one (a plain bundle).
func parseEnvelope(line []byte) (env *sealedEnvelope, ok bool, err error) {
	v, perr := jsonv.Parse(line)
	m, isObj := v.(map[string]any)
	if perr != nil || !isObj {
		return nil, false, nil
	}
	if _, has := m["sealedBundle"]; !has {
		return nil, false, nil
	}
	fail := func(msg string) (*sealedEnvelope, bool, error) {
		return nil, true, &Error{Line: 1, Msg: "sealed bundle envelope: " + msg}
	}
	for k := range m {
		if k != "sealedBundle" && k != "id" && k != "recipients" {
			return fail(fmt.Sprintf("unknown member %q", k))
		}
	}
	if m["sealedBundle"] != 1.0 {
		return fail(fmt.Sprintf("unsupported version %v", m["sealedBundle"]))
	}
	id, _ := m["id"].(string)
	if b, err := b64.DecodeString(id); err != nil || len(b) != 16 {
		return fail("id must be 128 bits, base64url")
	}
	arr, _ := m["recipients"].([]any)
	if len(arr) == 0 {
		return fail("no recipients")
	}
	env = &sealedEnvelope{id: id, recipients: map[string][]byte{}}
	for _, x := range arr {
		r, _ := x.(map[string]any)
		kid, _ := r["kid"].(string)
		ws, _ := r["wrapped"].(string)
		w, err := b64.DecodeString(ws)
		if kid == "" || err != nil || len(w) == 0 || r["suite"] != seal.Suite || len(r) != 3 {
			return fail("malformed recipient")
		}
		env.recipients[kid] = w
	}
	return env, true, nil
}

// sealedReader decrypts a sealed bundle's lines into a plain bundle.
type sealedReader struct {
	br   *bufio.Reader
	aead cipher.AEAD
	id   string
	n    int // the next line number
	last bool
	out  []byte
	err  error
}

func (r *sealedReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.err = r.next()
	}
	k := copy(p, r.out)
	r.out = r.out[k:]
	return k, nil
}

// next decrypts the next line; io.EOF once the last line was read and
// nothing follows it.
func (r *sealedReader) next() error {
	b, rerr := readLine(r.br)
	if rerr == io.EOF {
		if !r.last {
			return &Error{Line: r.n + 2, Msg: "sealed bundle: no line says last (truncated?)"}
		}
		return io.EOF
	}
	if rerr != nil {
		return rerr
	}
	line := r.n + 2 // file line: the envelope is line 1
	fail := func(msg string) error { return &Error{Line: line, Msg: "sealed bundle: " + msg} }
	if r.last {
		return fail("a line follows the last one")
	}
	parts := strings.Split(string(b), ".")
	if len(parts) != 5 || parts[1] != "" {
		return fail("not a JWE compact with alg dir")
	}
	raw, err1 := b64.DecodeString(parts[0])
	iv, err2 := b64.DecodeString(parts[2])
	ct, err3 := b64.DecodeString(parts[3])
	tag, err4 := b64.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(iv) != r.aead.NonceSize() || len(tag) != r.aead.Overhead() {
		return fail("malformed JWE")
	}
	pt, err := r.aead.Open(nil, iv, append(ct, tag...), []byte(parts[0]))
	if err != nil {
		return fail("the line fails to decrypt")
	}
	hv, err := jsonv.Parse(raw)
	h, _ := hv.(map[string]any)
	if err != nil || h == nil || h["alg"] != seal.AlgDir || h["enc"] != seal.EncA256GCM {
		return fail("the protected header must be alg dir, enc A256GCM")
	}
	for k := range h {
		if k != "alg" && k != "enc" && k != "pl" && k != "last" {
			return fail(fmt.Sprintf("unsupported header member %q", k))
		}
	}
	pl, _ := h["pl"].(map[string]any)
	if pl == nil || len(pl) != 2 {
		return fail("pl must be {bundle, line}")
	}
	if pl["bundle"] != r.id {
		return fail("pl.bundle isn't this bundle's id (spliced?)")
	}
	if n, ok := pl["line"].(float64); !ok || n != float64(r.n) {
		return fail(fmt.Sprintf("line %v out of order, want %d", pl["line"], r.n))
	}
	if l, has := h["last"]; has {
		if l != true {
			return fail("last must be true if present")
		}
		r.last = true
	}
	r.n++
	r.out = append(pt, '\n')
	return nil
}

func readLine(br *bufio.Reader) ([]byte, error) {
	for {
		var line []byte
		for {
			chunk, isPrefix, err := br.ReadLine()
			if err != nil {
				if err == io.EOF && len(line) > 0 {
					break
				}
				return nil, err
			}
			line = append(line, chunk...)
			if len(line) > maxSealedLine {
				return nil, &Error{Msg: "sealed bundle: a line is too long"}
			}
			if !isPrefix {
				break
			}
		}
		if len(bytes.TrimSpace(line)) > 0 {
			return line, nil
		}
	}
}

// OpenSealed decrypts a sealed bundle with identity and returns the plain
// bundle it holds, checked line by line as it is read (§G.5.1.1).
func OpenSealed(r io.Reader, identity *ecdh.PrivateKey) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	first, err := readLine(br)
	if err != nil {
		if err == io.EOF {
			return nil, &Error{Line: 1, Msg: "empty bundle"}
		}
		return nil, err
	}
	env, ok, err := parseEnvelope(first)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &Error{Line: 1, Msg: "not a sealed bundle"}
	}
	return env.open(br, identity)
}

func (env *sealedEnvelope) open(br *bufio.Reader, identity *ecdh.PrivateKey) (io.Reader, error) {
	if identity == nil {
		return nil, fmt.Errorf("%w: it is sealed (§G.5.1.1); give the recipient's private key", ErrNotRecipient)
	}
	w, ok := env.recipients[Thumbprint(identity.PublicKey())]
	if !ok {
		return nil, fmt.Errorf("%w (%s)", ErrNotRecipient, Thumbprint(identity.PublicKey()))
	}
	sk, err := hpke.NewDHKEMPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	key, err := hpke.Open(sk, hpkeKDF, hpkeAEAD, []byte(bundleWrapInfo+env.id), w)
	if err != nil || len(key) != seal.KeySize {
		return nil, &Error{Line: 1, Msg: "sealed bundle: the content key fails to unwrap"}
	}
	return &sealedReader{br: br, aead: newAEAD(key), id: env.id}, nil
}

// Unseal returns r's plain bundle: r itself for a plain bundle, the
// decrypted lines for a sealed one (sealed reports which). A sealed bundle
// needs identity.
func Unseal(r io.Reader, identity *ecdh.PrivateKey) (plain io.Reader, sealed bool, err error) {
	br := bufio.NewReaderSize(r, 1<<16)
	// The first line decides; a plain bundle is passed through as is.
	first, err := br.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	env, ok, err := parseEnvelope(bytes.TrimSpace(first))
	if err != nil {
		return nil, true, err
	}
	if !ok {
		return io.MultiReader(bytes.NewReader(first), br), false, nil
	}
	pr, err := env.open(br, identity)
	return pr, true, err
}

// UnsealOpener wraps open so that sealed bundles are decrypted with
// identity; plain bundles pass through.
func UnsealOpener(open Opener, identity *ecdh.PrivateKey) Opener {
	return func() (io.ReadCloser, error) {
		rc, err := open()
		if err != nil {
			return nil, err
		}
		pr, _, err := Unseal(rc, identity)
		if err != nil {
			rc.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{pr, rc}, nil
	}
}
