package edge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Edge grants as cookies (§C.5 "Issuing them").
//
// POST /edge-grants exchanges a verified grant with read for one edge grant
// per namespace it names, each fixed to a path prefix: /r/{ns}/{name} for a
// grant whose read rules fix /resource, else /r/{ns} and /ns/{ns}. Each is
// a cookie whose Path is the prefix, so a browser sends it only there,
// named per prefix so the cookies of several namespaces and documents
// coexist. The format is this deployment's:
//
//	base64url(JSON claims) "." base64url(HMAC-SHA256(key, first part))
//
// with claims { "v": 1, "p": prefix, "ns", "r"?: resource, "sub", "exp":
// Unix seconds }. A verifying edge holding the key checks it as the origin
// does (Cookies.Verify); without one the origin verifies it itself. The
// key is the deployment's: derived from the edge secret (KeyFromSecret),
// so the edge and the origin share it, or given on its own.

// CookiePrefix starts the name of every edge-grant cookie. The __Secure-
// prefix makes browsers refuse it without Secure.
const CookiePrefix = "__Secure-pl-eg-"

// MaxGrantTTL is the longest an edge grant lives: its lifetime is the
// revocation latency (§C.5, 5–15 minutes).
const MaxGrantTTL = 15 * time.Minute

// Claims are what an edge grant says: GET and HEAD under Prefix are
// authorised for Sub until Exp, in namespace NS, fixed to Resource if set.
type Claims struct {
	V        int    `json:"v"`
	Prefix   string `json:"p"`
	NS       string `json:"ns"`
	Resource string `json:"r,omitempty"`
	Sub      string `json:"sub"`
	Exp      int64  `json:"exp"`
}

// Cookies issues and verifies edge-grant cookies under one key.
type Cookies struct {
	key []byte
	// SameSite is the cookies' SameSite attribute: None when pages on
	// other origins call with credentials (§C.5), else Lax.
	SameSite http.SameSite
	// TTL caps an edge grant's lifetime (MaxGrantTTL if zero).
	TTL time.Duration
}

// NewCookies returns a Cookies with key, or with a random one if key is
// empty: edge grants then verify only in this process.
func NewCookies(key []byte) *Cookies {
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
	}
	return &Cookies{key: append([]byte(nil), key...), SameSite: http.SameSiteLaxMode}
}

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

// Lifetime is how long an edge grant issued at now for a grant expiring at
// exp (zero: no exp) lives: at most the TTL, never past exp.
func (c *Cookies) Lifetime(now, exp time.Time) time.Time {
	ttl := c.TTL
	if ttl <= 0 || ttl > MaxGrantTTL {
		ttl = MaxGrantTTL
	}
	out := now.Add(ttl)
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

// Issue returns the Set-Cookie of an edge grant issued at now.
func (c *Cookies) Issue(cl Claims, now time.Time) *http.Cookie {
	cl.V = 1
	body, _ := json.Marshal(cl)
	p := base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(p))
	return &http.Cookie{
		Name:     Name(cl.Prefix),
		Value:    p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)),
		Path:     cl.Prefix,
		Expires:  time.Unix(cl.Exp, 0).UTC(),
		MaxAge:   int(time.Unix(cl.Exp, 0).Sub(now).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: c.SameSite,
	}
}

var errBadCookie = errors.New("edge grant: malformed or badly signed")

// Verify checks a cookie value's signature and expiry at now.
func (c *Cookies) Verify(value string, now time.Time) (*Claims, error) {
	p, sigText, ok := strings.Cut(value, ".")
	if !ok {
		return nil, errBadCookie
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigText)
	if err != nil {
		return nil, errBadCookie
	}
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(p))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, errBadCookie
	}
	body, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, errBadCookie
	}
	var cl Claims
	if err := json.Unmarshal(body, &cl); err != nil || cl.V != 1 || cl.Prefix == "" || cl.NS == "" {
		return nil, errBadCookie
	}
	if now.Unix() >= cl.Exp {
		return nil, errors.New("edge grant: expired")
	}
	return &cl, nil
}

// Covers reports whether a request path lies under prefix: the prefix
// itself or below it, segment by segment (as a cookie's Path matches,
// RFC 6265 §5.1.4).
func Covers(prefix, path string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// FromRequest returns the claims of the first edge-grant cookie of r that
// verifies at now and covers r's path, or nil.
func (c *Cookies) FromRequest(r *http.Request, now time.Time) *Claims {
	if c == nil {
		return nil
	}
	path := r.URL.EscapedPath()
	for _, ck := range r.Cookies() {
		if !strings.HasPrefix(ck.Name, CookiePrefix) {
			continue
		}
		cl, err := c.Verify(ck.Value, now)
		if err != nil || ck.Name != Name(cl.Prefix) || !Covers(cl.Prefix, path) {
			continue
		}
		return cl
	}
	return nil
}
