package edge

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A withdrawal has the issued cookie's name and attributes, empty and
// expired (§C.5 "Withdrawing them").
func TestWithdraw(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	c := NewCookies(nil)
	c.SameSite = http.SameSiteNoneMode
	for _, p := range []string{"/r/ns/doc", "/r/ns", "/ns/ns"} {
		was := c.Issue(Claims{Prefix: p, NS: "ns", Sub: "user:li", Exp: now.Add(MaxGrantTTL).Unix()}, now)
		got := c.Withdraw(p)
		if got.Name != was.Name || got.Path != was.Path || got.Domain != was.Domain || got.Secure != was.Secure ||
			got.HttpOnly != was.HttpOnly || got.SameSite != was.SameSite || got.Value != "" || !got.Expires.Before(now) {
			t.Fatalf("%s: withdrawn %+v, issued %+v", p, got, was)
		}
		if s := got.String(); !strings.Contains(s, "; Max-Age=0") || !strings.Contains(s, "; Expires=Thu, 01 Jan 1970 00:00:00 GMT") {
			t.Fatalf("%s: %s", p, s)
		}
	}
}
