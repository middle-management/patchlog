// Package edge decides how private responses are cached at the edge (§9).
//
// Private content may be cached at the edge only behind an edge that
// verifies edge grants (§C.5). Such an edge says what it verified in two
// headers it adds and strips from incoming requests: a secret it shares
// with the origin (DefaultHeader) and the prefix of the edge grant it
// checked (DefaultPrefixHeader). An origin configured with the secret (a
// Verifier) gives edge lifetimes only to a private read the edge verified
// itself: each header is one line without a comma, the secret matches,
// the prefix covers the URL, and the request carries no other credential.
// Every other private response, and every one without a Verifier (no
// CDN, or one that doesn't verify grants), is marked CDN-Cache-Control:
// no-store and Surrogate-Control: no-store, so no shared cache stores it.
// Private reads are served either way: the origin verifies the grant or
// the cookie itself, and the headers decide only lifetimes, never access.
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

// DefaultHeader is the request header a verifying edge carries the secret
// in, and DefaultPrefixHeader the one it carries the prefix of the edge
// grant it checked in (§9, §C.5).
const (
	DefaultHeader       = "X-Edge-Verified"
	DefaultPrefixHeader = "X-Edge-Prefix"
)

// Verifier recognises reads the verifying edge verified. A nil *Verifier
// means there is none.
type Verifier struct {
	sum          [32]byte
	header       string
	prefixHeader string
	cookieKey    []byte // edge-grant cookies (KeyFromSecret)
}

// New returns a Verifier for secret in header and the verified prefix in
// prefixHeader (DefaultHeader and DefaultPrefixHeader if empty).
func New(secret []byte, header, prefixHeader string) (*Verifier, error) {
	if len(secret) == 0 {
		return nil, errors.New("empty edge secret")
	}
	if strings.Contains(string(secret), ",") {
		// The edge sends it as one header line without a comma (§9).
		return nil, errors.New("the edge secret can't contain a comma")
	}
	if header == "" {
		header = DefaultHeader
	}
	if prefixHeader == "" {
		prefixHeader = DefaultPrefixHeader
	}
	header, prefixHeader = http.CanonicalHeaderKey(header), http.CanonicalHeaderKey(prefixHeader)
	if header == prefixHeader {
		return nil, errors.New("the edge's secret and prefix headers must differ")
	}
	return &Verifier{sum: sha256.Sum256(secret), header: header, prefixHeader: prefixHeader, cookieKey: KeyFromSecret(secret)}, nil
}

// Load reads the secret from a file (surrounding whitespace, such as a
// trailing newline, is ignored) and returns its Verifier.
func Load(file, header, prefixHeader string) (*Verifier, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	v, err := New([]byte(strings.TrimSpace(string(b))), header, prefixHeader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return v, nil
}

// Header is the request header the secret is expected in.
func (v *Verifier) Header() string { return v.header }

// PrefixHeader is the request header the verified prefix is expected in.
func (v *Verifier) PrefixHeader() string { return v.prefixHeader }

// Verified reports whether r carries the secret, as exactly one header
// line without a comma (§9). The comparison is of SHA-256 digests in
// constant time, so neither the secret's bytes nor its length leak
// through timing.
func (v *Verifier) Verified(r *http.Request) bool {
	if v == nil {
		return false
	}
	got, ok := oneLine(r.Header, v.header)
	if !ok || got == "" {
		return false
	}
	sum := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(sum[:], v.sum[:]) == 1
}

// oneLine is the value of header k when h has exactly one line of it,
// without a comma (§9, §C.5): two lines, or a list in one, count as
// none, since proxies may join or split them.
func oneLine(h http.Header, k string) (string, bool) {
	vs := h.Values(k)
	if len(vs) != 1 || strings.Contains(vs[0], ",") {
		return "", false
	}
	return vs[0], true
}

// VerifiedRead reports whether the edge verified r itself, so that a
// private response to it may have edge lifetimes (§9): r carries the
// secret and the prefix, each as exactly one header line without a comma,
// the prefix covers r's path, and r carries no other credential, neither
// Authorization nor Source-Authorization (the reference defines no
// signed-URL parameters). A read the edge only relayed, one with a grant
// the origin verifies itself and one fetched around the edge get no
// lifetimes. It decides lifetimes only: the origin authorises the read
// from its cookie or grant all the same.
func (v *Verifier) VerifiedRead(r *http.Request) bool {
	if !v.Verified(r) {
		return false
	}
	p, ok := oneLine(r.Header, v.prefixHeader)
	if !ok || !Covers(p, r.URL.EscapedPath()) {
		return false
	}
	return len(r.Header.Values("Authorization")) == 0 && len(r.Header.Values("Source-Authorization")) == 0
}

// Private sets the edge directives of a private response to r: lifetime
// (a Cache-Control value such as "max-age=0, s-maxage=1") as
// CDN-Cache-Control for a read the verifying edge verified (VerifiedRead),
// and no-store for every shared cache otherwise, with or without a
// Verifier (§9).
func (v *Verifier) Private(h http.Header, r *http.Request, lifetime string) {
	if !v.VerifiedRead(r) {
		NoStore(h)
		return
	}
	h.Set("CDN-Cache-Control", lifetime)
}

// NoStore sets the edge directives of a private response no shared cache
// may store (§9): every private response but a read the verifying edge
// verified, such as a read with a grant in Authorization, which belongs to
// one credential, or a schemaReads read opened by a referrer (§6.1), which
// depends on the referrer.
func NoStore(h http.Header) {
	h.Set("CDN-Cache-Control", "no-store")
	h.Set("Surrogate-Control", "no-store")
}
