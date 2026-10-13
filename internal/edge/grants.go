package edge

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Edge grants as cookies (§C.5 "Issuing them").
//
// POST /edge-grants exchanges verified grants with read for edge grants,
// one per namespace each names, fixed to path prefixes: /r/{ns}/{name}, one
// per name, for a grant whose read rules fix /resource, else /r/{ns} and
// /ns/{ns}. Each prefix is a cookie whose Path is the prefix, so a browser
// sends it only there, named per prefix so the cookies of several
// namespaces and documents coexist. The format is the spec's default (§C.5 "Format"), so an edge
// can be written once:
//
//	name:  CookiePrefix + hex(sha256(p)[:8])
//	value: base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))
//
// unpadded, where c is the canonical JSON (§3.1) of { "exp", "kid", "p" }:
// Unix seconds, the key's name and the prefix. The origin's key vouches
// only for the core prefixes (ParsePrefix); a service's key, with
// Cookies.Vouches set, only for prefixes under a root of its own, never
// under /r/ or /ns/, such as a catalog service's /{catalog}/g/{gs}
// (§B.11.5). So a cookie one mints never covers the other's URLs, even
// under the other's key. A verifying edge holding the
// key checks a request as Check does; without one the origin checks it
// itself. The key is the deployment's: given on its own, or derived from
// the edge secret (KeyFromSecret), so the edge and the origin share it.

// CookiePrefix starts the name of every edge-grant cookie. The __Secure-
// prefix makes browsers refuse it without Secure.
const CookiePrefix = "__Secure-pl-eg-"

// DefaultKid names the origin's edge-grant key unless the deployment names
// it otherwise.
const DefaultKid = "origin"

// MaxGrantTTL is the longest an edge grant lives: its lifetime is the
// revocation latency (§C.5, 5–15 minutes).
const MaxGrantTTL = 15 * time.Minute

// Claims are what an edge grant says (§C.5 "Format"): GET and HEAD under
// Prefix are authorised until Exp (Unix seconds), vouched for by the key
// named Kid. They carry no subject and no grant id.
type Claims struct {
	Kid    string
	Prefix string
	Exp    int64
}

// Cookies issues and verifies edge-grant cookies under one key.
type Cookies struct {
	kid string
	key []byte
	// SameSite is the cookies' SameSite attribute: None when pages on
	// other origins call with credentials (§C.5), else Lax.
	SameSite http.SameSite
	// TTL caps an edge grant's lifetime (MaxGrantTTL if zero).
	TTL time.Duration
	// Vouches, if set, reports whether the key vouches for a prefix: a
	// service's key, for prefixes under a root of its own (§C.5
	// "Format"). A prefix under /r/ or /ns/ is never one of them,
	// whatever Vouches says. Unset, the key is the origin's, which
	// vouches only for the core prefixes (ParsePrefix).
	Vouches func(prefix string) bool
}

// NewCookies returns a Cookies with key, named kid (DefaultKid if empty),
// or with a random key if key is empty: edge grants then verify only in
// this process.
func NewCookies(kid string, key []byte) *Cookies {
	if kid == "" {
		kid = DefaultKid
	}
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
	}
	return &Cookies{kid: kid, key: append([]byte(nil), key...), SameSite: http.SameSiteLaxMode}
}

// Kid names the key the cookies are issued and verified under.
func (c *Cookies) Kid() string { return c.kid }

// KeyFromSecret derives the edge-grant key from the edge secret, so a
// verifying edge configured with the secret can verify the cookies.
func KeyFromSecret(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("patchlog edge grants v1"))
	return m.Sum(nil)
}

// CookieKey is the edge-grant key derived from v's secret (KeyFromSecret),
// nil without a Verifier.
func (v *Verifier) CookieKey() []byte {
	if v == nil {
		return nil
	}
	return append([]byte(nil), v.cookieKey...)
}

// VouchesFor reports whether c's key vouches for a prefix (§C.5
// "Format"): a core prefix for the origin's key, one Vouches allows, and
// not under /r/ or /ns/, for a service's.
func (c *Cookies) VouchesFor(p string) bool {
	if c.Vouches == nil {
		_, _, ok := ParsePrefix(p)
		return ok
	}
	return !Covers("/r", p) && !Covers("/ns", p) && c.Vouches(p)
}

// MaxTTL is the longest an edge grant c issues lives: the TTL, at most
// MaxGrantTTL.
func (c *Cookies) MaxTTL() time.Duration {
	if c.TTL <= 0 || c.TTL > MaxGrantTTL {
		return MaxGrantTTL
	}
	return c.TTL
}

// Lifetime is how long an edge grant issued at now for a grant expiring at
// exp (zero: no exp) lives: at most the TTL, never past exp.
func (c *Cookies) Lifetime(now, exp time.Time) time.Time {
	out := now.Add(c.MaxTTL())
	if !exp.IsZero() && exp.Before(out) {
		out = exp
	}
	return out.Truncate(time.Second)
}

// Name is the cookie name for a prefix: per prefix, so cookies for several
// namespaces and documents coexist.
func Name(prefix string) string {
	sum := sha256.Sum256([]byte(prefix))
	return CookiePrefix + hex.EncodeToString(sum[:8])
}

// Issue returns the Set-Cookie of an edge grant issued at now, under c's
// key and kid (cl.Kid is ignored).
func (c *Cookies) Issue(cl Claims, now time.Time) *http.Cookie {
	p := base64.RawURLEncoding.EncodeToString(jsonv.Canonical(map[string]any{
		"exp": float64(cl.Exp), "kid": c.kid, "p": cl.Prefix,
	}))
	return &http.Cookie{
		Name:     Name(cl.Prefix),
		Value:    p + "." + base64.RawURLEncoding.EncodeToString(c.mac(p)),
		Path:     cl.Prefix,
		Expires:  time.Unix(cl.Exp, 0).UTC(),
		MaxAge:   int(time.Unix(cl.Exp, 0).Sub(now).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: c.SameSite,
	}
}

// mac is HMAC-SHA256 under c's key of a value's first part.
func (c *Cookies) mac(p string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(p))
	return m.Sum(nil)
}

var errBadCookie = errors.New("edge grant: malformed or badly signed")

// parse splits a cookie value into its claims, not yet verified, the text
// the MAC is over and the MAC. The claims are exactly kid and p, strings,
// and exp, an integer, as canonical JSON (§3.1); both parts are unpadded
// base64url.
func parse(value string) (*Claims, string, []byte, error) {
	p, macText, ok := strings.Cut(value, ".")
	if !ok {
		return nil, "", nil, errBadCookie
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(macText)
	if err != nil {
		return nil, "", nil, errBadCookie
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(p)
	if err != nil {
		return nil, "", nil, errBadCookie
	}
	v, err := jsonv.Parse(body)
	if err != nil || !bytes.Equal(jsonv.Canonical(v), body) {
		return nil, "", nil, errBadCookie
	}
	m, _ := v.(map[string]any)
	kid, kidOK := m["kid"].(string)
	prefix, pOK := m["p"].(string)
	exp, expOK := m["exp"].(float64)
	if len(m) != 3 || !kidOK || !pOK || !expOK || exp != math.Trunc(exp) || math.Abs(exp) > jsonv.MaxSafeInteger {
		return nil, "", nil, errBadCookie
	}
	return &Claims{Kid: kid, Prefix: prefix, Exp: int64(exp)}, p, mac, nil
}

// verify checks parsed claims at now: c's kid, which vouches only for its
// own prefixes (VouchesFor), and a valid MAC, compared in constant time
// (check 4 of §C.5); exp in the future (check 5).
func (c *Cookies) verify(cl *Claims, p string, mac []byte, now time.Time) error {
	if !c.VouchesFor(cl.Prefix) || cl.Kid != c.kid {
		return errBadCookie
	}
	if !hmac.Equal(mac, c.mac(p)) {
		return errBadCookie
	}
	if now.Unix() >= cl.Exp {
		return errors.New("edge grant: expired")
	}
	return nil
}

// Verify checks a cookie value at now (§C.5 "Format"): its claims, its kid
// and prefix, its MAC and its expiry.
func (c *Cookies) Verify(value string, now time.Time) (*Claims, error) {
	cl, p, mac, err := parse(value)
	if err != nil {
		return nil, err
	}
	if err := c.verify(cl, p, mac, now); err != nil {
		return nil, err
	}
	return cl, nil
}

var (
	nsNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)   // §3.6, as core.ValidNSName
	resNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`) // §3.6, as core.ValidResourceName
)

// ParsePrefix parses a core prefix, the only ones the origin's key vouches
// for (§C.5): /r/{ns}/{name}, /r/{ns} or /ns/{ns}, with names valid under
// §3.6. resource is "" for a namespace-wide prefix.
func ParsePrefix(p string) (ns, resource string, ok bool) {
	s := strings.Split(p, "/")
	switch {
	case len(s) == 3 && s[0] == "" && (s[1] == "r" || s[1] == "ns") && nsNameRe.MatchString(s[2]):
		return s[2], "", true
	case len(s) == 4 && s[0] == "" && s[1] == "r" && nsNameRe.MatchString(s[2]) && resNameRe.MatchString(s[3]):
		return s[2], s[3], true
	}
	return "", "", false
}

// Covers reports whether a request path lies under prefix: the prefix
// itself or below it, segment by segment (as a cookie's Path matches,
// RFC 6265 §5.1.4), so /r/demo covers neither /r/demo-x/… nor /r/demox.
// An empty prefix covers nothing.
func Covers(prefix, path string) bool {
	return prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/"))
}

// CanonicalPath reports whether an escaped path has no empty, "." or ".."
// segment and no percent-escape, check 2 of §C.5 (400 otherwise): the
// cache keys the raw URL, and core names never need one (§3.6). "/" fails
// it, having an empty segment; no prefix covers it anyway. An edge
// embedding Check answers 400 for a request whose path fails it, which
// Check alone reports only as no covering cookie.
func CanonicalPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "%") {
		return false
	}
	for _, seg := range strings.Split(path[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Check makes the checks an edge MUST make on every request, cache hits
// included, before serving it or forwarding it as verified (§C.5 "What
// an edge MUST check"), in order:
//
//  1. the method is GET or HEAD;
//  2. the path has no empty, "." or ".." segment and no percent-escape;
//  3. a cookie whose name is derived from its own p (others are ignored);
//  4. c's kid, which vouches for p (VouchesFor), and a valid MAC;
//  5. exp is in the future;
//  6. p covers the path segment by segment.
//
// One covering cookie is enough: Check returns its p. A deployment may
// embed it in an edge, which then forwards a passing request with the
// secret and p in its verification headers (§9). Check answers a request
// failing check 2 as one without a covering cookie: the edge answers it
// 400 by testing CanonicalPath first.
func (c *Cookies) Check(r *http.Request, now time.Time) (p string, ok bool) {
	cl := c.check(r, now)
	if cl == nil {
		return "", false
	}
	return cl.Prefix, true
}

func (c *Cookies) check(r *http.Request, now time.Time) *Claims {
	if c == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return nil
	}
	path := r.URL.EscapedPath()
	if !CanonicalPath(path) {
		return nil
	}
	for _, ck := range r.Cookies() {
		if !strings.HasPrefix(ck.Name, CookiePrefix) {
			continue
		}
		cl, p, mac, err := parse(ck.Value)
		if err != nil || ck.Name != Name(cl.Prefix) {
			continue
		}
		if c.verify(cl, p, mac, now) != nil || !Covers(cl.Prefix, path) {
			continue
		}
		return cl
	}
	return nil
}

// FromRequest returns the claims of the first edge-grant cookie of r that
// passes Check at now, or nil.
func (c *Cookies) FromRequest(r *http.Request, now time.Time) *Claims {
	return c.check(r, now)
}
