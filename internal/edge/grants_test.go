package edge

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEdgeGrantCookies(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c := NewCookies([]byte("0123456789abcdef0123456789abcdef"))
	exp := c.Lifetime(now, time.Time{})
	if !exp.Equal(now.Add(MaxGrantTTL)) {
		t.Fatalf("lifetime %v", exp)
	}
	if got := c.Lifetime(now, now.Add(time.Minute)); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("lifetime past the grant's exp: %v", got)
	}
	ck := c.Issue(Claims{Prefix: "/r/ns/doc", NS: "ns", Resource: "doc", Sub: "user:li", Exp: exp.Unix()}, now)
	if ck.Path != "/r/ns/doc" || !ck.Secure || !ck.HttpOnly || !strings.HasPrefix(ck.Name, CookiePrefix) || ck.MaxAge != int(MaxGrantTTL.Seconds()) {
		t.Fatalf("cookie %+v", ck)
	}
	if Name("/r/ns") == Name("/ns/ns") {
		t.Fatal("names collide")
	}
	cl, err := c.Verify(ck.Value, now)
	if err != nil || cl.NS != "ns" || cl.Resource != "doc" || cl.Sub != "user:li" {
		t.Fatalf("verify %v %v", cl, err)
	}
	if _, err := c.Verify(ck.Value, exp); err == nil {
		t.Fatal("expired cookie verified")
	}
	if _, err := NewCookies([]byte("another key, another deployment")).Verify(ck.Value, now); err == nil {
		t.Fatal("verified under another key")
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{{"/r/ns/doc", true}, {"/r/ns/doc/rev/x", true}, {"/r/ns/doc2", false}, {"/r/ns", false}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		if got := c.FromRequest(r, now) != nil; got != tc.ok {
			t.Fatalf("%s: %v", tc.path, got)
		}
	}
	// A namespace prefix covers the namespace URL itself and what lies
	// below, segment by segment (§C.5).
	for _, tc := range []struct {
		path string
		ok   bool
	}{{"/ns/ns", true}, {"/ns/ns/log", true}, {"/ns/ns/rev/x/heads", true}, {"/ns/ns2", false}, {"/ns", false}} {
		if Covers("/ns/ns", tc.path) != tc.ok {
			t.Fatalf("/ns/ns covers %s: %v", tc.path, !tc.ok)
		}
	}
	// SameSite is the deployment's: None with credentialed origins.
	c.SameSite = http.SameSiteNoneMode
	if ck := c.Issue(Claims{Prefix: "/ns/ns", NS: "ns", Sub: "user:li", Exp: exp.Unix()}, now); ck.SameSite != http.SameSiteNoneMode || ck.Path != "/ns/ns" {
		t.Fatalf("cookie %+v", ck)
	}
	// A read an edge forwards undecided is no-store for shared caches,
	// with or without a Verifier.
	h := http.Header{}
	NoStore(h)
	if h.Get("CDN-Cache-Control") != "no-store" || h.Get("Surrogate-Control") != "no-store" {
		t.Fatalf("no-store %v", h)
	}
	// The key derived from an edge secret is the Verifier's.
	v, _ := New([]byte("s3cret"), "")
	if string(v.CookieKey()) != string(KeyFromSecret([]byte("s3cret"))) || (*Verifier)(nil).CookieKey() != nil {
		t.Fatal("cookie key")
	}
}

// The README's example edge grant, which an edge implemented elsewhere
// can check itself against: the key derived from an edge secret, the
// cookie's name and value, and a verifier's answer to it.
func TestCookieVector(t *testing.T) {
	key := KeyFromSecret([]byte("example edge secret"))
	if got := hex.EncodeToString(key); got != "3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708" {
		t.Fatalf("derived key %s", got)
	}
	const (
		name  = "__Secure-pl-eg-4390e78526d94754"
		value = "eyJ2IjoxLCJwIjoiL3IvZGVtby9kZXJieSIsIm5zIjoiZGVtbyIsInIiOiJkZXJieSIsInN1YiI6InVzZXI6bGkiLCJleHAiOjE3OTAwMDA5MDB9._U1WpIxTk-e-oRCQqufab2XM3CXgRG2eiR78olNgx6Q"
	)
	c := NewCookies(key)
	ck := c.Issue(Claims{Prefix: "/r/demo/derby", NS: "demo", Resource: "derby", Sub: "user:li", Exp: 1790000900}, time.Unix(1790000000, 0))
	if ck.Name != name || ck.Value != value || ck.Path != "/r/demo/derby" {
		t.Fatalf("cookie %s=%s; Path=%s", ck.Name, ck.Value, ck.Path)
	}
	p, _, _ := strings.Cut(value, ".")
	if claims, _ := base64.RawURLEncoding.DecodeString(p); string(claims) != `{"v":1,"p":"/r/demo/derby","ns":"demo","r":"derby","sub":"user:li","exp":1790000900}` {
		t.Fatalf("claims %s", claims)
	}
	if _, err := c.Verify(value, time.Unix(1790000899, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(value, time.Unix(1790000900, 0)); err == nil {
		t.Fatal("verified at exp")
	}
}
