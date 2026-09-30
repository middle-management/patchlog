// Package edge decides how private responses are cached at the edge (§9).
//
// Private content may be cached at the edge only behind an edge that
// verifies grants. Such an edge proves it verified a request by sending a
// shared secret in a header (DefaultHeader). An origin configured with the
// secret (a Verifier) serves private reads only to requests that carry it,
// and gives those responses edge lifetimes. Without a Verifier (no CDN, or
// one that doesn't verify grants) private responses are marked
// CDN-Cache-Control: no-store and Surrogate-Control: no-store, so no shared
// cache stores them.
package edge

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// DefaultHeader is the request header a verifying edge carries the secret in.
const DefaultHeader = "X-Edge-Verified"

// Code and Message are the 403 an origin with a Verifier answers to a
// private read that didn't come through the edge.
const (
	Code    = "edge_required"
	Message = "private reads are served only through the verifying edge"
)

// Verifier checks that a request came through the verifying edge. A nil
// *Verifier means there is none.
type Verifier struct {
	sum    [32]byte
	header string
}

// New returns a Verifier for secret in header (DefaultHeader if empty).
func New(secret []byte, header string) (*Verifier, error) {
	if len(secret) == 0 {
		return nil, errors.New("empty edge secret")
	}
	if header == "" {
		header = DefaultHeader
	}
	return &Verifier{sum: sha256.Sum256(secret), header: http.CanonicalHeaderKey(header)}, nil
}

// Load reads the secret from a file (surrounding whitespace, such as a
// trailing newline, is ignored) and returns its Verifier.
func Load(file, header string) (*Verifier, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	v, err := New([]byte(strings.TrimSpace(string(b))), header)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return v, nil
}

// Header is the request header the secret is expected in.
func (v *Verifier) Header() string { return v.header }

// Verified reports whether r carries the secret. The comparison is of
// SHA-256 digests in constant time, so neither the secret's bytes nor its
// length leak through timing.
func (v *Verifier) Verified(r *http.Request) bool {
	if v == nil {
		return false
	}
	got := r.Header.Get(v.header)
	if got == "" {
		return false
	}
	sum := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(sum[:], v.sum[:]) == 1
}

// Allow reports whether a response may be served to r: public (and sealed)
// responses always, private ones without a Verifier (the origin checked the
// grant itself) or when r came through the edge.
func (v *Verifier) Allow(r *http.Request, public bool) bool {
	return public || v == nil || v.Verified(r)
}

// Private sets the edge directives of a private response: lifetime (a
// Cache-Control value such as "max-age=0, s-maxage=1") as CDN-Cache-Control
// behind a verifying edge, and no-store for every shared cache otherwise.
// It is only called for responses Allow admitted.
func (v *Verifier) Private(h http.Header, lifetime string) {
	if v == nil {
		h.Set("CDN-Cache-Control", "no-store")
		h.Set("Surrogate-Control", "no-store")
		return
	}
	h.Set("CDN-Cache-Control", lifetime)
}
