package edge

import (
	"net/http"
	"time"
)

// Withdraw returns the Set-Cookie that removes prefix's edge grant from a
// browser (§C.5 "Withdrawing them"): Issue's name and attributes, empty
// and expired, so the browser drops the cookie it holds under them.
func (c *Cookies) Withdraw(prefix string) *http.Cookie {
	ck := c.Issue(Claims{Prefix: prefix}, time.Unix(0, 0))
	ck.Value, ck.Expires, ck.MaxAge = "", time.Unix(0, 0).UTC(), -1
	return ck
}
