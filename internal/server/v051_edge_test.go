package server

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
)

// withExchangeRate sets the deployment's exchangeRate (§6.6, §C.5).
func withExchangeRate(r core.Rate) envOpt {
	return func(o *core.Options) {
		if o.Maximums == (core.Limits{}) {
			o.Maximums = o.Limits
			if o.Maximums == (core.Limits{}) {
				o.Maximums = core.DefaultLimits()
			}
		}
		o.Maximums.ExchangeRate = r
	}
}

// edgeNames are n resource names, prefix000 on.
func edgeNames(prefix string, n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%03d", prefix, i)
	}
	return out
}

// v0.52 §6.6: exchangeRate defaults to 10/s, burst 100, also for options
// from before it, and only the deployment sets it.
func TestV051ExchangeRateDefault(t *testing.T) {
	t.Parallel()
	want := core.Rate{Rate: 10, Burst: 100}
	if got := core.DefaultLimits().ExchangeRate; got != want {
		t.Errorf("default %v", got)
	}
	if got := newEnv(t).e.Limits().ExchangeRate; got != want {
		t.Errorf("deployment %v", got)
	}
	// Limits set without it, as before v0.52.
	old := newEnv(t, func(o *core.Options) {
		l := core.DefaultLimits()
		l.ExchangeRate = core.Rate{}
		o.Limits, o.Maximums = l, l
	})
	if got := old.e.Limits().ExchangeRate; got != want {
		t.Errorf("options from before exchangeRate: %v", got)
	}
	if got := newEnv(t, withExchangeRate(core.Rate{Rate: 1, Burst: 5})).e.Limits().ExchangeRate; got != (core.Rate{Rate: 1, Burst: 5}) {
		t.Errorf("set: %v", got)
	}
	e := newEnv(t)
	r := e.do(req{method: "PATCH", path: "/ns/x", ifNoneMatch: "*", author: "admin",
		body: addRoot(map[string]any{"limits": map[string]any{"exchangeRate": map[string]any{"rate": 1, "burst": 2}}})})
	if r.Code != 422 || !strings.Contains(string(r.Body), "deployment") {
		t.Errorf("a namespace setting exchangeRate: %d %s", r.Code, r.Body)
	}
}

// v0.51 §9, §C.5: X-Edge-Verified and X-Edge-Prefix each count only as
// exactly one header line without a comma; otherwise the read is served
// all the same, with no edge lifetimes.
func TestV051EdgeHeadersOneLine(t *testing.T) {
	t.Parallel()
	e := newEdgeEnv(t)
	e.mkNS("priv", map[string]any{"read": "grant"})
	id := e.create("priv", "a", map[string]any{"x": 1.0})
	path := "/r/priv/a/rev/" + id
	get := func(secrets, prefixes []string) *resp {
		t.Helper()
		hr, err := http.NewRequest("GET", e.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			hr.Header.Add(edge.DefaultHeader, s)
		}
		for _, p := range prefixes {
			hr.Header.Add(edge.DefaultPrefixHeader, p)
		}
		res, err := http.DefaultClient.Do(hr)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return &resp{Code: res.StatusCode, H: res.Header, Body: b}
	}
	one := []string{edgeSecret}
	r := get(one, []string{"/r/priv/a"})
	if expect(t, r, 200); r.H.Get("CDN-Cache-Control") != "max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("verified: %v", r.H)
	}
	for _, c := range []struct {
		name              string
		secrets, prefixes []string
	}{
		{"the secret twice", []string{edgeSecret, edgeSecret}, []string{"/r/priv/a"}},
		{"the secret and another", []string{edgeSecret, "x"}, []string{"/r/priv/a"}},
		{"secrets in one line", []string{edgeSecret + ", " + edgeSecret}, []string{"/r/priv/a"}},
		{"the secret and a comma", []string{edgeSecret + ","}, []string{"/r/priv/a"}},
		{"the prefix twice", one, []string{"/r/priv/a", "/r/priv/a"}},
		{"two prefixes", one, []string{"/r/priv", "/r/priv/a"}},
		{"prefixes in one line", one, []string{"/r/priv,/r/priv/a"}},
		{"the prefix and a comma", one, []string{"/r/priv/a,"}},
	} {
		r := get(c.secrets, c.prefixes)
		expect(t, r, 200)
		expectNoStore(t, c.name, r)
	}
}

// v0.51 §C.5 "Format": the origin accepts several edge-grant keys at once
// and mints with the newest, so a key is rotated without making clients
// exchange again; a cookie's claims are exactly kid, p and exp,
// canonical byte for byte.
func TestV051EdgeGrantKeyRotation(t *testing.T) {
	t.Parallel()
	k1, k2 := []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210fedcba9876543210")
	ck := edge.NewCookies("k1", k1)
	if err := ck.AddKey("k2", k2); err != nil {
		t.Fatal(err)
	}
	var priv ed25519.PrivateKey
	e := newEnvWith(t, []Option{WithEdgeGrants(ck)}, withAuth(&priv))
	e.opPriv = priv
	k := newKey("k")
	e.mkNS("sec", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.create("sec", "a", map[string]any{"v": 1.0}, e.grant(k, "user:root", []string{"sec"}, allVerbs))

	// Minted with the newest key.
	r := e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(k, "user:bob", []string{"sec"}, []string{"read"})})
	expect(t, r, 200)
	nc := edgeCookies(t, r)["/r/sec"]
	if nc == nil {
		t.Fatalf("cookies %v", r.H.Values("Set-Cookie"))
	}
	p, _, _ := strings.Cut(nc.Value, ".")
	if claims, _ := base64.RawURLEncoding.DecodeString(p); !strings.Contains(string(claims), `"kid":"k2"`) {
		t.Fatalf("claims %s", claims)
	}
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(nc)}), 302)
	// A cookie minted before the rotation, under the old key alone, still
	// reads.
	exp := e.clock.Now().Add(edge.MaxGrantTTL).Unix()
	old := edge.NewCookies("k1", k1).Issue(edge.Claims{Prefix: "/r/sec", Exp: exp}, e.clock.Now())
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(old)}), 302)
	// A key the origin doesn't hold, or a kid under another's key, doesn't.
	for name, c := range map[string]*http.Cookie{
		"unknown kid": edge.NewCookies("k0", k1).Issue(edge.Claims{Prefix: "/r/sec", Exp: exp}, e.clock.Now()),
		"wrong key":   edge.NewCookies("k1", k2).Issue(edge.Claims{Prefix: "/r/sec", Exp: exp}, e.clock.Now()),
	} {
		if r := e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(c)}); r.Code != 401 {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// Claims other than exactly kid, p and exp, or not canonical byte for
	// byte, are ignored, even under a key the origin holds.
	sign := func(claims string) *http.Cookie {
		p := base64.RawURLEncoding.EncodeToString([]byte(claims))
		m := hmac.New(sha256.New, k2)
		m.Write([]byte(p))
		return &http.Cookie{Name: edge.Name("/r/sec"), Value: p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))}
	}
	good := fmt.Sprintf(`{"exp":%d,"kid":"k2","p":"/r/sec"}`, exp)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(sign(good))}), 302)
	for name, claims := range map[string]string{
		"extra member":  fmt.Sprintf(`{"exp":%d,"kid":"k2","p":"/r/sec","sub":"user:bob"}`, exp),
		"not canonical": fmt.Sprintf(`{"kid":"k2","exp":%d,"p":"/r/sec"}`, exp),
		"whitespace":    fmt.Sprintf(`{"exp": %d,"kid":"k2","p":"/r/sec"}`, exp),
		"no kid":        fmt.Sprintf(`{"exp":%d,"p":"/r/sec"}`, exp),
	} {
		if r := e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(sign(claims))}); r.Code != 401 {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
}

// v0.51 §C.5: while authentication is disabled, issuance is 404
// not_offered before the body is read, whatever it is.
func TestV051EdgeGrantsNotOfferedFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, c := range []struct {
		name string
		q    req
	}{
		{"no body", req{}},
		{"a grant", req{bearer: "x"}},
		{"grants", req{body: map[string]any{"grants": []any{"x"}}}},
		{"text/plain", req{raw: `{"grants":["x"]}`, ct: "text/plain"}},
		{"malformed", req{raw: `{"grants": [`}},
		{"too large", req{raw: `{"grants": ["` + strings.Repeat("A", 600<<10) + `"]}`}},
		{"body and Authorization", req{body: map[string]any{"grants": []any{"x"}}, bearer: "x"}},
	} {
		c.q.method, c.q.path = "POST", "/edge-grants"
		r := e.do(c.q)
		if r.Code != 404 || r.Str("code") != "not_offered" || r.H.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v %s", c.name, r.Code, r.H, r.Body)
		}
		expectNoCookies(t, c.name, r)
	}
}

// v0.51 §7: a path with an empty segment, a "." or ".." segment, or any
// percent-escape is 400 bad_input at the origin, whatever the method or
// credential, except "/" itself.
func TestV051NonCanonicalPaths(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	r := e.do(req{method: "POST", path: "/edge-grants", bearer: reader})
	expect(t, r, 200)
	cookie := cookieHdr(edgeCookies(t, r)["/r/sec"])
	for _, c := range []struct{ method, path string }{
		{"POST", "/edge-grants/"},
		{"POST", "//edge-grants"},
		{"DELETE", "/edge-grants/?prefix=/r/sec"},
		{"PATCH", "/r/sec/%61"},
		{"PATCH", "/r/sec/a/"},
		{"DELETE", "/r/sec/./a"},
		{"POST", "/ns/sec/batch/"},
		{"GET", "/ns/sec/../sec"},
		{"GET", "/r/sec//a"},
		{"GET", "/r/sec/a%2Flog"},
	} {
		for _, q := range []req{{bearer: f.adminG}, {hdr: cookie}, {}} {
			q.method, q.path = c.method, c.path
			if r := e.do(q); r.Code != 400 || r.Str("code") != "bad_input" {
				t.Errorf("%s %s: %d %s", c.method, c.path, r.Code, r.Body)
			}
		}
	}
	expect(t, e.do(req{method: "GET", path: "/"}), 200)
}

// An exchange over the cap stays cheap (§C.5): the cap no longer comes
// before the rules are tested, so fifty grants fixing /resource to as
// many names as 8 KiB holds test their rules once per namespace, not once
// per name, which grows with the square of the names (about a second
// here, against a tenth).
func TestV051EdgeGrantsOverCapCheaply(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	names := edgeNames("n", 800)
	gs := make([]string, 50)
	for i := range gs {
		gs[i] = e.grant(f.issuer, fmt.Sprintf("user:x%d", i), []string{"sec"}, []string{"read"},
			map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}})
	}
	if len(gs[0]) > 8<<10 {
		t.Fatalf("grant of %d bytes", len(gs[0]))
	}
	start := time.Now()
	r := e.issueGrants(gs...)
	if took := time.Since(start); r.Code != 400 || took > 5*time.Second {
		t.Fatalf("%d in %v", r.Code, took)
	}
	expectNoCookies(t, "over the cap", r)
}
