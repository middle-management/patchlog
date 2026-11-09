package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/ids"
)

// §2.1 Edge prefix, §B.11.9 Edge grants, §C.5.4: /ns/{ns}/g/{gs} is a core
// prefix, withdrawn like the others, with gs an id ("all" is a service's
// and isn't one); its cookie authorises nothing outside its path, and
// reaches the engine with GS set.
func TestV075EdgePrefixG(t *testing.T) {
	t.Parallel()
	ck := edge.NewCookies("", nil)
	var priv ed25519.PrivateKey
	e := newEnvWith(t, []Option{WithEdgeGrants(ck)}, withAuth(&priv))
	e.opPriv = priv
	k := newKey("k")
	head := e.mkNS("demo", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	gs := ids.Of([]byte("a subject set")).String()
	prefix := "/ns/demo/g/" + gs

	r := e.do(req{method: "DELETE", path: "/edge-grants?prefix=" + prefix})
	expect(t, r, 204)
	gone := (&http.Response{Header: r.H}).Cookies()
	if len(gone) != 1 || gone[0].Path != prefix || gone[0].Name != edge.Name(prefix) || gone[0].MaxAge >= 0 {
		t.Fatalf("Set-Cookie %v", r.H.Values("Set-Cookie"))
	}
	for _, p := range []string{"/ns/demo/g/all", "/ns/demo/g/xyz", "/ns/demo/g/" + gs + "/at", "/ns/demo/g/", "/ns/Demo/g/" + gs} {
		expectCode(t, e.do(req{method: "DELETE", path: "/edge-grants?prefix=" + p}), 400, "bad_input")
	}
	if p, ok := edge.ParseCorePrefix(prefix); !ok || p != (edge.Prefix{NS: "demo", GS: gs}) {
		t.Fatalf("ParseCorePrefix = %+v, %v", p, ok)
	}
	if _, _, ok := edge.ParsePrefix(prefix); ok {
		t.Fatal("ParsePrefix takes the g form")
	}

	// A hand-minted origin cookie for the g prefix doesn't cover the
	// namespace's own URLs.
	c := ck.Issue(edge.Claims{Prefix: prefix, Exp: t0.Add(5 * 60e9).Unix()}, t0)
	r = e.do(req{method: "GET", path: "/ns/demo/rev/" + head + "/heads", hdr: cookieHdr(c)})
	if r.Code != 401 && r.Code != 403 {
		t.Fatalf("heads under a g cookie: %d %s", r.Code, r.Body)
	}

	// Under its path, the request carries the edge grant with GS set.
	s := New(e.e, WithEdgeGrants(ck))
	hr := httptest.NewRequest("GET", "https://cms.example"+prefix+"/heads", nil)
	hr.AddCookie(c)
	eg, _ := s.edgeCred(hr).Context().Value(edgeGrantKey{}).(*core.EdgeGrant)
	if eg == nil || eg.NS != "demo" || eg.GS != gs || eg.Resource != "" || eg.Prefix != prefix {
		t.Fatalf("edge grant %+v", eg)
	}
	if got := eg.Prefixes(); len(got) != 1 || got[0] != prefix {
		t.Fatalf("Prefixes %v", got)
	}
	// The engine refuses it at the namespace's unfiltered URLs (§B.11.9:
	// only the filtered entry points admit it).
	if _, err := e.e.NamespaceHeads(t.Context(), "demo", head, "", core.Credentials{Edge: eg}); !v075IsStatus(err, 403) {
		t.Fatalf("NamespaceHeads under a GS edge grant: %v", err)
	}
}

func v075IsStatus(err error, status int) bool {
	ce, ok := err.(*core.Error)
	return ok && ce.Status == status
}
