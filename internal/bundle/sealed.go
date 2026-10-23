package bundle

// Sealed bundles (§G.5.1.1): a bundle encrypted line by line to one or more
// X25519 recipients, so it can be written and read as a stream. The format,
// its writer and its reader are internal/seal's (seal.BundleWriter,
// seal.OpenBundle), shared with the pruning archives of encrypted
// namespaces (§8.6); this file wraps them for bundle tools, reporting what
// fails a check as an *Error, and holds the key files.
//
//   - The writer seals only canonical lines, each followed by one 0x0A
//     (§G.4.1): it never seals a bundle a Reader would reject for its lines.
//   - The decrypted lines are an ordinary bundle, checked by Reader as
//     strictly as a plain one (§G.4.1); its digest (source.bundle) is the
//     plaintext bundle's (§G.5.1.1).
//
// Key files are JWKs: a recipient is {"kty":"OKP","crv":"X25519","x"}, an
// identity (private key) the same with "d" (RFC 8037).

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
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
const SealedMediaType = seal.BundleMediaType

var b64 = base64.RawURLEncoding.Strict()

// ErrNotRecipient reports a sealed bundle that has no content key for the
// identity given (or none was given).
var ErrNotRecipient = seal.ErrNotRecipient

// sealedErr reports a sealed bundle's failed check (a *seal.BundleError)
// as the *Error of the bundle it holds.
func sealedErr(err error) error {
	var se *seal.BundleError
	if errors.As(err, &se) {
		return &Error{Line: se.Line, Msg: se.Msg}
	}
	return err
}

// --- keys ---------------------------------------------------------------

// Thumbprint is the RFC 7638 thumbprint of an X25519 public key: base64url
// of the SHA-256 of canonical({crv, kty, x}) (seal.Thumbprint).
func Thumbprint(pub *ecdh.PublicKey) string { return seal.Thumbprint(pub) }

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

// SealedWriter seals a bundle written to it (the bytes a Writer produces,
// or any bundle file) line by line (§G.5.1.1), through seal.BundleWriter.
// Each line is sealed once the next one starts, so the last can be marked;
// Close seals it. Close must be called; it doesn't close the underlying
// writer. Like a Reader it takes only canonical lines, each followed by one
// 0x0A (§G.4.1).
type SealedWriter struct {
	// Pad pads each line's plaintext to its §E.2.2 bucket with spaces,
	// which readers remove (§G.5.1.1); set it before the first Write.
	Pad bool

	w *seal.BundleWriter
}

// NewSealedWriter writes the envelope line for recipients to w.
func NewSealedWriter(w io.Writer, recipients []*ecdh.PublicKey) (*SealedWriter, error) {
	if len(recipients) == 0 {
		return nil, errors.New("bundle: a sealed bundle needs at least one recipient")
	}
	sw, err := seal.NewBundleWriter(w, recipients)
	if err != nil {
		return nil, err
	}
	return &SealedWriter{w: sw}, nil
}

// Write takes bundle bytes.
func (s *SealedWriter) Write(p []byte) (int, error) {
	s.w.Pad = s.Pad
	n, err := s.w.Write(p)
	return n, sealedErr(err)
}

// Close seals the last line, marked last.
func (s *SealedWriter) Close() error {
	s.w.Pad = s.Pad
	return sealedErr(s.w.Close())
}

// --- reading ------------------------------------------------------------

// sealedReader reports the failed checks of seal's reader as *Error.
type sealedReader struct{ r io.Reader }

func (r sealedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF {
		err = sealedErr(err)
	}
	return n, err
}

// OpenSealed decrypts a sealed bundle with identity and returns the plain
// bundle it holds, checked line by line as it is read (§G.5.1.1).
func OpenSealed(r io.Reader, identity *ecdh.PrivateKey) (io.Reader, error) {
	pr, err := seal.OpenBundle(r, identity)
	if err != nil {
		return nil, sealedErr(err)
	}
	return sealedReader{pr}, nil
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
	env, ok, err := seal.ParseBundleEnvelope(bytes.TrimSpace(first))
	if err != nil {
		return nil, true, sealedErr(err)
	}
	if !ok {
		return io.MultiReader(bytes.NewReader(first), br), false, nil
	}
	pr, err := env.Open(br, identity)
	if err != nil {
		return nil, true, sealedErr(err)
	}
	return sealedReader{pr}, true, nil
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
