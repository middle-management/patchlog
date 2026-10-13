package edge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestEdgeGrantCookies(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c := NewCookies("", testKey)
	if c.Kid() != DefaultKid {
		t.Fatalf("kid %q", c.Kid())
	}
	exp := c.Lifetime(now, time.Time{})
	if !exp.Equal(now.Add(MaxGrantTTL)) {
		t.Fatalf("lifetime %v", exp)
	}
	if got := c.Lifetime(now, now.Add(time.Minute)); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("lifetime past the grant's exp: %v", got)
	}
	ck := c.Issue(Claims{Prefix: "/r/ns/doc", Exp: exp.Unix()}, now)
	if ck.Path != "/r/ns/doc" || !ck.Secure || !ck.HttpOnly || !strings.HasPrefix(ck.Name, CookiePrefix) || ck.MaxAge != int(MaxGrantTTL.Seconds()) {
		t.Fatalf("cookie %+v", ck)
	}
	if Name("/r/ns") == Name("/ns/ns") {
		t.Fatal("names collide")
	}
	cl, err := c.Verify(ck.Value, now)
	if err != nil || *cl != (Claims{Kid: "origin", Prefix: "/r/ns/doc", Exp: exp.Unix()}) {
		t.Fatalf("verify %v %v", cl, err)
	}
	if _, err := c.Verify(ck.Value, exp); err == nil {
		t.Fatal("expired cookie verified")
	}
	if _, err := NewCookies("", []byte("another key, another deployment")).Verify(ck.Value, now); err == nil {
		t.Fatal("verified under another key")
	}
	if _, err := NewCookies("other", testKey).Verify(ck.Value, now); err == nil {
		t.Fatal("verified under another kid")
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
	// below, segment by segment (§C.5); an empty one covers nothing.
	for _, tc := range []struct {
		prefix, path string
		ok           bool
	}{
		{"/ns/ns", "/ns/ns", true}, {"/ns/ns", "/ns/ns/log", true}, {"/ns/ns", "/ns/ns/rev/x/heads", true},
		{"/ns/ns", "/ns/ns2", false}, {"/ns/ns", "/ns", false}, {"/r/demo", "/r/demo-x/a", false}, {"/r/demo", "/r/demox", false},
		{"", "/r/demo", false}, {"", "", false},
	} {
		if Covers(tc.prefix, tc.path) != tc.ok {
			t.Fatalf("%q covers %q: %v", tc.prefix, tc.path, !tc.ok)
		}
	}
	// SameSite is the deployment's: None with credentialed origins.
	c.SameSite = http.SameSiteNoneMode
	if ck := c.Issue(Claims{Prefix: "/ns/ns", Exp: exp.Unix()}, now); ck.SameSite != http.SameSiteNoneMode || ck.Path != "/ns/ns" {
		t.Fatalf("cookie %+v", ck)
	}
	// The key derived from an edge secret is the Verifier's.
	v, _ := New([]byte("s3cret"), "", "")
	if string(v.CookieKey()) != string(KeyFromSecret([]byte("s3cret"))) || (*Verifier)(nil).CookieKey() != nil {
		t.Fatal("cookie key")
	}
}

// The README's example edge grant in the default format (§C.5 "Format"),
// which an edge implemented elsewhere can check itself against: the key
// derived from an edge secret, the cookie's name and value, and a
// verifier's answer to it.
func TestCookieVector(t *testing.T) {
	key := KeyFromSecret([]byte("example edge secret"))
	if got := hex.EncodeToString(key); got != "3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708" {
		t.Fatalf("derived key %s", got)
	}
	const (
		name  = "__Secure-pl-eg-4390e78526d94754"
		value = "eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw"
	)
	c := NewCookies("origin", key)
	ck := c.Issue(Claims{Prefix: "/r/demo/derby", Exp: 1790000900}, time.Unix(1790000000, 0))
	if ck.Name != name || ck.Value != value || ck.Path != "/r/demo/derby" {
		t.Fatalf("cookie %s=%s; Path=%s", ck.Name, ck.Value, ck.Path)
	}
	p, _, _ := strings.Cut(value, ".")
	if claims, _ := base64.RawURLEncoding.DecodeString(p); string(claims) != `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}` {
		t.Fatalf("claims %s", claims)
	}
	if _, err := c.Verify(value, time.Unix(1790000899, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(value, time.Unix(1790000900, 0)); err == nil {
		t.Fatal("verified at exp")
	}
	r := httptest.NewRequest("GET", "/r/demo/derby/rev/x", nil)
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	if p, ok := c.Check(r, time.Unix(1790000899, 0)); !ok || p != "/r/demo/derby" {
		t.Fatalf("check %q %v", p, ok)
	}
}

// sign returns the value of an edge grant with claims c, as written, under
// key: what a minter that isn't Issue might send.
func sign(key []byte, c string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(c))
	m := hmac.New(sha256.New, key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Verify accepts exactly the default format under its own kid, for the
// core prefixes only (§C.5 "Format").
func TestVerifyRefuses(t *testing.T) {
	now := time.Unix(1790000000, 0)
	c := NewCookies("origin", testKey)
	good := sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}`)
	if _, err := c.Verify(good, now); err != nil {
		t.Fatal(err)
	}
	pad := func(s string) string {
		for len(s)%4 != 0 {
			s += "="
		}
		return s
	}
	p, mac, _ := strings.Cut(good, ".")
	for name, v := range map[string]string{
		"wrong kid":          sign(testKey, `{"exp":1790000900,"kid":"tree","p":"/r/demo/derby"}`),
		"numeric kid":        sign(testKey, `{"exp":1790000900,"kid":1,"p":"/r/demo/derby"}`),
		"extra member":       sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby","sub":"user:li"}`),
		"v0.49 claims":       sign(testKey, `{"v":1,"p":"/r/demo/derby","ns":"demo","r":"derby","sub":"user:li","exp":1790000900}`),
		"missing exp":        sign(testKey, `{"kid":"origin","p":"/r/demo/derby"}`),
		"fractional exp":     sign(testKey, `{"exp":1790000900.5,"kid":"origin","p":"/r/demo/derby"}`),
		"string exp":         sign(testKey, `{"exp":"1790000900","kid":"origin","p":"/r/demo/derby"}`),
		"huge exp":           sign(testKey, `{"exp":1e+21,"kid":"origin","p":"/r/demo/derby"}`),
		"not canonical":      sign(testKey, `{"kid":"origin","exp":1790000900,"p":"/r/demo/derby"}`),
		"not an object":      sign(testKey, `["origin","/r/demo/derby",1790000900]`),
		"service prefix":     sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/tree/x"}`),
		"invalid name":       sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/r/Demo"}`),
		"below a resource":   sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby/rev"}`),
		"ns with a resource": sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/ns/demo/derby"}`),
		"trailing slash":     sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/r/demo/"}`),
		"bad MAC":            sign([]byte("another key"), `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}`),
		"padded claims":      pad(p) + "." + mac,
		"padded MAC":         p + "." + pad(mac),
		"no MAC":             p,
		"two dots":           good + ".x",
		"expired":            sign(testKey, `{"exp":1790000000,"kid":"origin","p":"/r/demo/derby"}`),
	} {
		if _, err := c.Verify(v, now); err == nil {
			t.Errorf("%s: verified %s", name, v)
		}
	}
}

// Check makes the six checks of §C.5 "What an edge MUST check", each of
// which refuses a request on its own.
func TestCheck(t *testing.T) {
	now := time.Unix(1790000000, 0)
	c := NewCookies("origin", testKey)
	issue := func(p string, exp int64) *http.Cookie { return c.Issue(Claims{Prefix: p, Exp: exp}, now) }
	derby := issue("/r/demo/derby", 1790000900)
	demo := issue("/r/demo", 1790000900)
	other := NewCookies("origin", []byte("another key")).Issue(Claims{Prefix: "/r/demo/derby", Exp: 1790000900}, now)
	otherKid := NewCookies("tree", testKey).Issue(Claims{Prefix: "/r/demo/derby", Exp: 1790000900}, now)
	renamed := *derby
	renamed.Name = Name("/r/demo")
	service := &http.Cookie{Name: Name("/tree/x"), Value: sign(testKey, `{"exp":1790000900,"kid":"origin","p":"/tree/x"}`)}
	for _, tc := range []struct {
		name, method, path string
		cookies            []*http.Cookie
		want               string // the p that passes, "" for none
	}{
		{"pass", "GET", "/r/demo/derby", []*http.Cookie{derby}, "/r/demo/derby"},
		{"HEAD", "HEAD", "/r/demo/derby/rev/x", []*http.Cookie{derby}, "/r/demo/derby"},
		// 1. GET or HEAD only.
		{"POST", "POST", "/r/demo/derby", []*http.Cookie{derby}, ""},
		{"PATCH", "PATCH", "/r/demo/derby", []*http.Cookie{derby}, ""},
		// 2. No empty, "." or ".." segment, no percent-escape.
		{"dot-dot", "GET", "/r/demo/derby/../other", []*http.Cookie{derby}, ""},
		{"dot", "GET", "/r/demo/derby/./log", []*http.Cookie{derby}, ""},
		{"empty", "GET", "/r/demo//derby", []*http.Cookie{demo}, ""},
		{"trailing slash", "GET", "/r/demo/derby/", []*http.Cookie{derby}, ""},
		{"escape", "GET", "/r/demo/%64erby", []*http.Cookie{demo}, ""},
		// 3. A cookie named for its own p; others are ignored.
		{"renamed", "GET", "/r/demo/derby", []*http.Cookie{&renamed}, ""},
		{"not ours", "GET", "/r/demo/derby", []*http.Cookie{{Name: "session", Value: derby.Value}}, ""},
		// 4. A kid held, vouching for p, and a valid MAC.
		{"other kid", "GET", "/r/demo/derby", []*http.Cookie{otherKid}, ""},
		{"non-core p", "GET", "/tree/x", []*http.Cookie{service}, ""},
		{"bad MAC", "GET", "/r/demo/derby", []*http.Cookie{other}, ""},
		// 5. exp in the future.
		{"expired", "GET", "/r/demo/derby", []*http.Cookie{issue("/r/demo/derby", 1790000000)}, ""},
		// 6. p covers the path segment by segment.
		{"sibling", "GET", "/r/demo/derby2", []*http.Cookie{derby}, ""},
		{"above", "GET", "/r/demo", []*http.Cookie{derby}, ""},
		{"prefix-x", "GET", "/r/demo-x/a", []*http.Cookie{demo}, ""},
		{"prefix glued", "GET", "/r/demox", []*http.Cookie{demo}, ""},
		// One covering cookie is enough, wherever it is.
		{"second covers", "GET", "/r/demo/derby", []*http.Cookie{issue("/r/demo/x", 1790000900), &renamed, demo}, "/r/demo"},
		{"none", "GET", "/r/demo/derby", nil, ""},
	} {
		r := httptest.NewRequest(tc.method, "http://origin.example"+tc.path, nil)
		for _, ck := range tc.cookies {
			r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
		p, ok := c.Check(r, now)
		if ok != (tc.want != "") || p != tc.want {
			t.Errorf("%s: %q %v, want %q", tc.name, p, ok, tc.want)
		}
		if got := c.FromRequest(r, now); (got != nil) != ok {
			t.Errorf("%s: FromRequest %v", tc.name, got)
		}
	}
	if _, ok := (*Cookies)(nil).Check(httptest.NewRequest("GET", "/r/demo", nil), now); ok {
		t.Error("nil Cookies checked a request")
	}
}

// ParsePrefix accepts the core prefixes with names valid under §3.6, as
// core judges them.
func TestParsePrefix(t *testing.T) {
	for _, tc := range []struct {
		p, ns, res string
		ok         bool
	}{
		{"/r/demo/derby", "demo", "derby", true},
		{"/r/demo", "demo", "", true},
		{"/ns/demo", "demo", "", true},
		{"/r/demo/a.b_c-1", "demo", "a.b_c-1", true},
		{"/ns/demo/derby", "", "", false},
		{"/r/demo/derby/rev", "", "", false},
		{"/r/Demo", "", "", false},
		{"/r/de.mo", "", "", false},
		{"/r/demo/", "", "", false},
		{"/r//derby", "", "", false},
		{"r/demo", "", "", false},
		{"/x/demo", "", "", false},
		{"/r", "", "", false},
		{"/", "", "", false},
		{"", "", "", false},
		{"/r/" + strings.Repeat("a", 65), "", "", false},
		{"/r/demo/" + strings.Repeat("a", 129), "", "", false},
	} {
		ns, res, ok := ParsePrefix(tc.p)
		if ns != tc.ns || res != tc.res || ok != tc.ok {
			t.Errorf("%q: %q %q %v", tc.p, ns, res, ok)
		}
	}
	// The name rules are core's.
	for _, n := range []string{"a", "demo", "a-b_c", "a.b", "-a", "_a", ".a", "A", "a b", "", strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("a", 128), strings.Repeat("a", 129)} {
		if nsNameRe.MatchString(n) != core.ValidNSName(n) || resNameRe.MatchString(n) != core.ValidResourceName(n) {
			t.Errorf("name %q judged otherwise than by core", n)
		}
	}
}
