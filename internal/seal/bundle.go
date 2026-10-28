package seal

// Sealed bundles (§G.5.1.1): a bundle encrypted line by line to one or more
// X25519 recipients, so it can be written and read as a stream. Bundle
// tools (internal/bundle) and pruning archives of encrypted namespaces
// (§8.6, internal/core) both use it.
//
//	{"id":"<128 bits, b64url>","recipients":[{"kid","suite","wrapped"}],"sealedBundle":1}
//	<JWE compact of bundle line 0 (the header)>
//	<JWE compact of bundle line 1>
//	…
//
//   - The envelope line is canonical JSON. The content key K_b (256 random
//     bits) is wrapped for each recipient with HPKE base mode, suite Suite
//     (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM), info
//     "patchlog-bundle-v1" ‖ 0x0A ‖ id; wrapped is base64url(enc ‖ ct). A
//     recipient's kid is its RFC 7638 JWK thumbprint (Thumbprint).
//   - Each following line is a JWE compact under K_b with the protected
//     header canonical({"alg":"dir","enc":"A256GCM","pl":{"bundle":id,
//     "line":n}}), with "last":true in pl on the final line only; no kid
//     (there is one key) and no compression. The plaintext of line n is
//     bundle line n as canonical JSON (§3.1), without its newline, and with
//     BundleWriter.Pad followed by spaces up to its §E.2.2 bucket.
//   - A reader rejects the whole sealed bundle if it isn't framed strictly
//     (v0.74): the envelope not canonical JSON, a line not followed by
//     exactly one 0x0A (a 0x0D, a blank line, or a last line without its
//     0x0A), or a protected header that isn't canonical JSON. It rejects
//     it too if a line fails to decrypt, its header, pl included, has
//     other members (so last beside pl, as written before v0.73, is
//     refused), pl.bundle isn't id, the line numbers aren't 0, 1, 2… in
//     order, or no line says last or a line follows it. Trailing spaces
//     (padding, which canonical JSON never ends in) are removed from each
//     line's plaintext.
//     What it yields is the plain bundle, which the caller checks as a
//     bundle (§G.4.1); its digest (source.bundle) is the plain bundle's.
//
// This package knows lines only as canonical JSON: the writer seals no
// other line, and the reader yields the decrypted lines as they are.

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// BundleMediaType is the media type of a sealed bundle (§G.5.1.1).
const BundleMediaType = "application/vnd.patchlog.sealed-bundle+jsonl"

// bundleWrapInfo prefixes the HPKE info of a sealed bundle's content key.
const bundleWrapInfo = "patchlog-bundle-v1\n"

// MaxBundleLine is the longest line of a sealed bundle, without its line
// end, that OpenBundle and BundleEnvelope.Open read and that BundleWriter
// writes unless told otherwise (OpenBundleMax, BundleEnvelope.OpenMax,
// BundleWriter.MaxLine). §G.5.1.1 sets no bound: this one keeps what a
// reader holds of one line in memory bounded when the bundle comes from
// elsewhere. The blob line of an attachment over about 144 MiB (128 MiB
// padded) is longer sealed; pruning archives (§8.6), which the server
// writes and reads back itself, are written and read without a bound, as
// plain bundles are.
const MaxBundleLine = 256 << 20

// lineBound is the bound a MaxLine-style argument stands for: 0 is
// MaxBundleLine, a negative value is none (-1).
func lineBound(max int) int {
	if max == 0 {
		return MaxBundleLine
	}
	if max < 0 {
		return -1
	}
	return max
}

// ErrNotRecipient reports a sealed bundle that has no content key for the
// identity given (or none was given).
var ErrNotRecipient = errors.New("seal: the sealed bundle is not addressed to this identity")

// BundleError reports a sealed bundle that fails a check of §G.5.1.1, or a
// line BundleWriter won't seal. Line is the 1-based line of the file (the
// envelope is line 1) or, from the writer, of the plain bundle; 0 if
// unknown.
type BundleError struct {
	Line int
	Msg  string
}

func (e *BundleError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("seal: line %d: %s", e.Line, e.Msg)
	}
	return "seal: " + e.Msg
}

// --- writing --------------------------------------------------------------

// BundleWriter seals a bundle written to it line by line (§G.5.1.1). Each
// line is sealed once the next one starts, so the last can be marked;
// Close seals it. Close must be called; it doesn't close the underlying
// writer. It takes only canonical JSON lines, each followed by one 0x0A
// (§G.4.1), so it never seals a bundle a bundle reader would reject for
// its lines.
type BundleWriter struct {
	// Pad pads each line's plaintext to its §E.2.2 bucket with spaces,
	// which readers remove (§G.5.1.1); set it before the first Write.
	Pad bool
	// MaxLine is the longest sealed line, without its 0x0A, the writer
	// writes: 0 is MaxBundleLine, the bound OpenBundle reads with, and a
	// negative value is no bound. A line whose sealed form would be longer
	// is refused (*BundleError naming the plain bundle's line) before any
	// of it is written, so the writer never writes a bundle that a reader
	// with the same bound refuses. Set it before the first Write.
	MaxLine int

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

// NewBundleWriter writes the envelope line for recipients to w.
func NewBundleWriter(w io.Writer, recipients []*ecdh.PublicKey) (*BundleWriter, error) {
	if len(recipients) == 0 {
		return nil, errors.New("seal: a sealed bundle needs at least one recipient")
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	id := b64.EncodeToString(idb)
	key := NewKey()
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
		rs = append(rs, map[string]any{"kid": Thumbprint(r), "suite": Suite, "wrapped": b64.EncodeToString(wrapped)})
	}
	env := jsonv.Canonical(map[string]any{"sealedBundle": 1.0, "id": id, "recipients": rs})
	if _, err := w.Write(append(env, '\n')); err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &BundleWriter{w: w, aead: aead, id: id}, nil
}

// Write takes bundle bytes.
func (s *BundleWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("seal: write after Close")
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

// line takes one bundle line, without its 0x0A.
func (s *BundleWriter) line(b []byte) error {
	no := s.n + 1
	if s.has {
		no++
	}
	if len(b) == 0 {
		return &BundleError{Line: no, Msg: "a blank line; every line is canonical JSON (§G.4.1)"}
	}
	v, err := jsonv.Parse(b)
	if err != nil {
		return &BundleError{Line: no, Msg: "not I-JSON: " + err.Error()}
	}
	if !bytes.Equal(jsonv.Canonical(v), b) {
		return &BundleError{Line: no, Msg: "not canonical JSON (§3.1); every line is written in its canonical form (§G.4.1)"}
	}
	if s.has {
		if err := s.emit(s.pending, false); err != nil {
			return err
		}
	}
	s.pending, s.has = append([]byte(nil), b...), true
	return nil
}

func (s *BundleWriter) emit(pt []byte, last bool) error {
	pl := map[string]any{"bundle": s.id, "line": float64(s.n)}
	if last {
		pl["last"] = true
	}
	if s.Pad {
		pt = Pad(pt)
	}
	hdr := map[string]any{"alg": AlgDir, "enc": EncA256GCM, "pl": pl}
	protected := b64.EncodeToString(jsonv.Canonical(hdr))
	// The sealed line: protected ".." iv "." ciphertext "." tag, the
	// ciphertext as long as the plaintext.
	size := len(protected) + 2 + b64.EncodedLen(s.aead.NonceSize()) + 1 + b64.EncodedLen(len(pt)) + 1 + b64.EncodedLen(s.aead.Overhead())
	if max := lineBound(s.MaxLine); max >= 0 && size > max {
		return &BundleError{Line: s.n + 1, Msg: fmt.Sprintf("sealed, the line would be %d bytes, more than the %d a reader takes (§G.5.1.1)", size, max)}
	}
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
func (s *BundleWriter) Close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.err != nil {
		return s.err
	}
	if len(s.buf) > 0 {
		no := s.n + 1
		if s.has {
			no++
		}
		s.err = &BundleError{Line: no, Msg: "the last line doesn't end in 0x0A (truncated?); every line is followed by one (§G.4.1)"}
		return s.err
	}
	if !s.has {
		s.err = &BundleError{Line: 1, Msg: "empty bundle"}
		return s.err
	}
	s.err = s.emit(s.pending, true)
	return s.err
}

// --- reading ------------------------------------------------------------

// BundleEnvelope is a sealed bundle's parsed envelope line.
type BundleEnvelope struct {
	ID         string
	Recipients map[string][]byte // kid (thumbprint) → wrapped
}

// ParseBundleEnvelope parses a sealed bundle's envelope line, without its
// 0x0A; ok is false if the line isn't one (a plain bundle's header, say).
// The envelope must be canonical JSON (§G.5.1.1, §3.1).
func ParseBundleEnvelope(line []byte) (env *BundleEnvelope, ok bool, err error) {
	v, perr := jsonv.Parse(line)
	m, isObj := v.(map[string]any)
	if perr != nil || !isObj {
		return nil, false, nil
	}
	if _, has := m["sealedBundle"]; !has {
		return nil, false, nil
	}
	fail := func(msg string) (*BundleEnvelope, bool, error) {
		return nil, true, &BundleError{Line: 1, Msg: "sealed bundle envelope: " + msg}
	}
	if !bytes.Equal(jsonv.Canonical(v), line) {
		return fail("not canonical JSON (§3.1), or not followed by exactly one 0x0A (§G.5.1.1)")
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
	env = &BundleEnvelope{ID: id, Recipients: map[string][]byte{}}
	for _, x := range arr {
		r, _ := x.(map[string]any)
		kid, _ := r["kid"].(string)
		ws, _ := r["wrapped"].(string)
		w, err := b64.DecodeString(ws)
		if kid == "" || err != nil || len(w) == 0 || r["suite"] != Suite || len(r) != 3 {
			return fail("malformed recipient")
		}
		env.Recipients[kid] = w
	}
	return env, true, nil
}

// Open unwraps the content key with identity and returns the plain bundle
// whose sealed lines follow the envelope in br, decrypted and checked line
// by line as they are read (§G.5.1.1). A line longer than MaxBundleLine is
// refused.
func (env *BundleEnvelope) Open(br *bufio.Reader, identity *ecdh.PrivateKey) (io.Reader, error) {
	return env.OpenMax(br, identity, 0)
}

// OpenMax is Open reading lines of up to maxLine bytes: 0 is
// MaxBundleLine, a negative value is no bound.
func (env *BundleEnvelope) OpenMax(br *bufio.Reader, identity *ecdh.PrivateKey, maxLine int) (io.Reader, error) {
	if identity == nil {
		return nil, fmt.Errorf("%w: it is sealed (§G.5.1.1); give the recipient's private key", ErrNotRecipient)
	}
	w, ok := env.Recipients[Thumbprint(identity.PublicKey())]
	if !ok {
		return nil, fmt.Errorf("%w (%s)", ErrNotRecipient, Thumbprint(identity.PublicKey()))
	}
	sk, err := hpke.NewDHKEMPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	key, err := hpke.Open(sk, hpkeKDF, hpkeAEAD, []byte(bundleWrapInfo+env.ID), w)
	if err != nil || len(key) != KeySize {
		return nil, &BundleError{Line: 1, Msg: "sealed bundle: the content key fails to unwrap"}
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &bundleReader{br: br, aead: aead, id: env.ID, max: lineBound(maxLine)}, nil
}

// OpenBundle decrypts a sealed bundle with identity and returns the plain
// bundle it holds, checked line by line as it is read (§G.5.1.1). A line
// longer than MaxBundleLine is refused.
func OpenBundle(r io.Reader, identity *ecdh.PrivateKey) (io.Reader, error) {
	return OpenBundleMax(r, identity, 0)
}

// OpenBundleMax is OpenBundle reading lines, the envelope included, of up
// to maxLine bytes: 0 is MaxBundleLine, a negative value is no bound.
func OpenBundleMax(r io.Reader, identity *ecdh.PrivateKey, maxLine int) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	first, err := readBundleLine(br, lineBound(maxLine))
	if err != nil {
		var be *BundleError
		if err == io.EOF {
			return nil, &BundleError{Line: 1, Msg: "empty bundle"}
		} else if errors.As(err, &be) {
			be.Line = 1
		}
		return nil, err
	}
	env, ok, err := ParseBundleEnvelope(first)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &BundleError{Line: 1, Msg: "not a sealed bundle"}
	}
	return env.OpenMax(br, identity, maxLine)
}

// bundleReader decrypts a sealed bundle's lines into a plain bundle.
type bundleReader struct {
	br   *bufio.Reader
	aead cipher.AEAD
	id   string
	max  int // the longest line read, -1 for no bound
	n    int // the next line number
	last bool
	out  []byte
	err  error
}

func (r *bundleReader) Read(p []byte) (int, error) {
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
func (r *bundleReader) next() error {
	b, rerr := readBundleLine(r.br, r.max)
	if rerr == io.EOF {
		if !r.last {
			return &BundleError{Line: r.n + 2, Msg: "sealed bundle: no line says last (truncated?)"}
		}
		return io.EOF
	}
	line := r.n + 2 // file line: the envelope is line 1
	if rerr != nil {
		var be *BundleError
		if errors.As(rerr, &be) && be.Line == 0 {
			be.Line = line
		}
		return rerr
	}
	fail := func(msg string) error { return &BundleError{Line: line, Msg: "sealed bundle: " + msg} }
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
	if err != nil || h == nil || h["alg"] != AlgDir || h["enc"] != EncA256GCM {
		return fail("the protected header must be alg dir, enc A256GCM")
	}
	if !bytes.Equal(jsonv.Canonical(hv), raw) {
		return fail("the protected header is not canonical JSON (§3.1)")
	}
	// Only alg, enc and pl: last beside pl, as written before v0.73, is
	// another member (§G.5.1.1, v0.74).
	for k := range h {
		if k != "alg" && k != "enc" && k != "pl" {
			return fail(fmt.Sprintf("unsupported header member %q", k))
		}
	}
	pl, _ := h["pl"].(map[string]any)
	if pl == nil {
		return fail("pl must be {bundle, line, last?}")
	}
	for k := range pl {
		if k != "bundle" && k != "line" && k != "last" {
			return fail("pl must be {bundle, line, last?}")
		}
	}
	if pl["bundle"] != r.id {
		return fail("pl.bundle isn't this bundle's id (spliced?)")
	}
	if n, ok := pl["line"].(float64); !ok || n != float64(r.n) {
		return fail(fmt.Sprintf("line %v out of order, want %d", pl["line"], r.n))
	}
	if l, has := pl["last"]; has {
		if l != true {
			return fail("pl.last must be true if present")
		}
		r.last = true
	}
	// Padding (§E.2.2) is removed before the checks and the digest: the
	// spaces after the JSON, which a canonical line never ends in. What is
	// left is one bundle line, which the bundle reader checks (§G.4.1).
	pt = bytes.TrimRight(pt, " ")
	if bytes.IndexByte(pt, '\n') >= 0 {
		return fail("a line's plaintext holds a 0x0A; each sealed line is one bundle line")
	}
	r.n++
	r.out = append(pt, '\n')
	return nil
}

// readBundleLine reads the next line of a sealed bundle, without its
// 0x0A; io.EOF when nothing is left. A sealed bundle is framed strictly
// (§G.5.1.1): each line is followed by exactly one 0x0A, so a blank line,
// a 0x0D (a CRLF line end) or a last line without its 0x0A is refused. A
// line longer than max bytes is refused, unless max is -1.
func readBundleLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		n := len(line)
		if err == nil {
			n--
		}
		if max >= 0 && n > max {
			return nil, &BundleError{Msg: fmt.Sprintf("sealed bundle: a line is too long (more than %d bytes)", max)}
		}
		switch {
		case err == nil:
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF && len(line) == 0:
			return nil, io.EOF
		case err == io.EOF:
			return nil, &BundleError{Msg: "sealed bundle: the last line doesn't end in 0x0A (truncated?); every line is followed by one (§G.5.1.1)"}
		default:
			return nil, err
		}
		break
	}
	line = line[:len(line)-1]
	if len(line) == 0 {
		return nil, &BundleError{Msg: "sealed bundle: a blank line; every line is followed by exactly one 0x0A (§G.5.1.1)"}
	}
	if bytes.IndexByte(line, '\r') >= 0 {
		return nil, &BundleError{Msg: "sealed bundle: a 0x0D in a line (a CRLF line end?); every line is followed by exactly one 0x0A (§G.5.1.1)"}
	}
	return line, nil
}
