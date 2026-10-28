package tree_test

import (
	"net/http"
	"testing"
)

// v0.74 integration (§C.5.3, changelog Grants: "an empty Authorization
// counts as present, and cookies count only without it"): the catalog
// service's own edge cookies admit a listing read only when the request
// carries no Authorization header field at all; with an empty one, the
// cookie is ignored and the read is judged as a grant's, so it is 401.
func TestV074EmptyAuthorizationIgnoresCookie(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start(withEdgeGrants)
	bob := p.scoped("user:bob", "root", "season")
	prefix, cookie := p.exchange(bob)
	at := prefix + "/at/" + p.x.s.At() + "/children?of=root"
	if r := p.do("GET", at, "", "", cookie); r.status != 200 {
		t.Fatalf("the cookie alone: %d %v", r.status, r.body)
	}
	for _, v := range []string{"", " "} {
		req := must(http.NewRequest("GET", p.x.http.URL+at, nil))
		req.Header["Authorization"] = []string{v}
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		res := must(noRedirect.Do(req))
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Errorf("the cookie with Authorization %q: %d", v, res.StatusCode)
		}
	}
}
