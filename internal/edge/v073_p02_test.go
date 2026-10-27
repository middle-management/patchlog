package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Check 1 of §C.5.3: the method is GET or HEAD and the request carries no
// Authorization; a cookie counts only on a request without one, so an
// edge built on Check gives a request with a grant no claims.
func TestV073CheckRefusesAuthorization(t *testing.T) {
	now := time.Unix(1790000000, 0)
	c := NewCookies("origin", testKey)
	ck := c.Issue(Claims{Prefix: "/r/demo/derby", Exp: 1790000900}, now)
	req := func(auth ...string) *http.Request {
		r := httptest.NewRequest("GET", "http://origin.example/r/demo/derby", nil)
		r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		for _, a := range auth {
			r.Header.Add("Authorization", a)
		}
		return r
	}
	if p, ok := c.Check(req(), now); !ok || p != "/r/demo/derby" {
		t.Fatalf("without Authorization: %q %v", p, ok)
	}
	for _, auth := range []string{"Bearer x", ""} {
		r := req(auth)
		if _, ok := c.Check(r, now); ok || c.FromRequest(r, now) != nil {
			t.Fatalf("Authorization %q: the cookie counted", auth)
		}
	}
}
