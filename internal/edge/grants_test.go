package edge

import (
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
