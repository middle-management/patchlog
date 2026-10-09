package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/middle-management/patchlog/internal/edge"
)

// v0.48 §C.5 "Withdrawing them": DELETE /edge-grants?prefix=… answers 204,
// no-store, with an expired Set-Cookie of the same name and attributes for
// each prefix named, and needs no grant.
func TestEdgeGrantsWithdraw(t *testing.T) {
	t.Parallel()
	ck := edge.NewCookies(nil)
	ck.SameSite = http.SameSiteNoneMode // as with credentialed origins
	var priv ed25519.PrivateKey
	e := newEnvWith(t, []Option{WithEdgeGrants(ck)}, withAuth(&priv))
	e.opPriv = priv
	k := newKey("k")
	e.mkNS("sec", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.create("sec", "a", map[string]any{"v": 1.0}, e.grant(k, "user:root", []string{"sec"}, allVerbs))
	issue := func(extra ...map[string]any) map[string]*http.Cookie {
		r := e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(k, "user:bob", []string{"sec"}, []string{"read"}, extra...)})
		expect(t, r, 200)
		return edgeCookies(t, r)
	}
	issued := issue()
	for p, c := range issue(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}) {
		issued[p] = c
	}
	if len(issued) != 3 {
		t.Fatalf("issued %v", issued)
	}
	withdraw := func(query string) *resp {
		return e.do(req{method: "DELETE", path: "/edge-grants" + query})
	}

	// No grant; one expired cookie per prefix named, with the issued one's
	// name and attributes.
	r := withdraw("?prefix=/r/sec&prefix=/r/sec/a")
	expect(t, r, 204)
	if r.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", r.H.Get("Cache-Control"))
	}
	gone := (&http.Response{Header: r.H}).Cookies()
	if len(gone) != 2 {
		t.Fatalf("Set-Cookie %v", r.H.Values("Set-Cookie"))
	}
	for _, c := range gone {
		was := issued[c.Path]
		if was == nil || c.Path == "/ns/sec" || c.Name != was.Name || c.Secure != was.Secure || c.HttpOnly != was.HttpOnly || c.SameSite != was.SameSite ||
			c.Value != "" || c.MaxAge >= 0 || !c.Expires.Before(t0) {
			t.Fatalf("withdrawn %+v, issued %+v", c, was)
		}
	}
	// A browser drops exactly those, and keeps /ns/sec's.
	jar, _ := cookiejar.New(nil)
	origin := &url.URL{Scheme: "https", Host: "cms.example", Path: "/"}
	jar.SetCookies(origin, []*http.Cookie{issued["/r/sec"], issued["/r/sec/a"], issued["/ns/sec"]})
	jar.SetCookies(origin, gone)
	for path, want := range map[string]int{"/r/sec/a": 0, "/r/sec/b": 0, "/ns/sec": 1} {
		if got := jar.Cookies(origin.ResolveReference(&url.URL{Path: path})); len(got) != want {
			t.Fatalf("%s: %d cookies left, want %d", path, len(got), want)
		}
	}

	// A prefix named twice is withdrawn once.
	r = withdraw("?prefix=/ns/sec&prefix=/ns/sec")
	expect(t, r, 204)
	if cs := (&http.Response{Header: r.H}).Cookies(); len(cs) != 1 || cs[0].Name != issued["/ns/sec"].Name || cs[0].Path != "/ns/sec" {
		t.Fatalf("Set-Cookie %v", r.H.Values("Set-Cookie"))
	}

	// Strict query parameters (§7): prefix alone, at least once, each of
	// a shape issuance returns.
	for _, q := range []string{"", "?prefix=", "?prefix=/r/sec&x=1", "?prefix=/r/sec/a/rev", "?prefix=/ns/sec/log", "?prefix=/r/", "?prefix=/r/sec/",
		"?prefix=r/sec", "?prefix=/x/sec", "?prefix=/r/Sec", "?prefix=/ns/sec/a", "?prefix=/r/sec&prefix=/edge-grants", "?prefix=%zz"} {
		r := withdraw(q)
		expectCode(t, r, 400, "bad_input")
		if r.H.Get("Set-Cookie") != "" || r.H.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %v", q, r.H)
		}
	}
	// Only DELETE, besides issuance's POST.
	for _, m := range []string{"GET", "HEAD", "PUT", "PATCH"} {
		expect(t, e.do(req{method: m, path: "/edge-grants?prefix=/r/sec"}), 405)
	}
}
