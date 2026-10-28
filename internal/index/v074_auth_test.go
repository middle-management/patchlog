package index_test

import (
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/svcedge"
)

// v0.74 integration (§C.5.3, changelog Grants: "an empty Authorization
// counts as present, and cookies count only without it"): the index's own
// edge cookies admit a read only when the request carries no
// Authorization header field at all; with an empty one, the cookie is
// ignored and the read is judged as a grant's, so it is 401.
func TestV074EmptyAuthorizationIgnoresCookie(t *testing.T) {
	t.Parallel()
	w := p37Setup(t, svcedge.DefaultExchangeRate)
	x := w.x
	amy := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pa", "pb"}, []string{"read"})
	prefixes, cookies := w.exchange(t, x, amy)
	r, at := p37Follow(t, x, prefixes["pa"]+"?limit=5", cookies, "")
	if r.status != 200 {
		t.Fatalf("the cookie alone: %d %v", r.status, r.body)
	}
	for _, v := range []string{"", " "} {
		req := must(http.NewRequest("GET", x.http.URL+at, nil))
		req.Header["Authorization"] = []string{v}
		for _, c := range cookies {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		res := must(noFollow.Do(req))
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Errorf("the cookie with Authorization %q: %d", v, res.StatusCode)
		}
	}
}
