package svcedge

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestV082NonBearerAuthorization (SVC-17i; SPEC §C.8: any Authorization
// that isn't a Bearer grant is a malformed grant, never a request without
// one): Bearer gives no token for a scheme other than Bearer, or for
// Bearer with nothing after it, so the caller answers 401 as for no
// usable grant; an exchange with a body refuses any Authorization beside
// it, whatever its scheme (§C.5.3).
func TestV082NonBearerAuthorization(t *testing.T) {
	for _, h := range []string{"Basic eDp5", "Digest x", "Bearer", "Bearer ", "bearertoken", "Token abc"} {
		r := httptest.NewRequest("POST", "/edge-grants", nil)
		r.Header.Set("Authorization", h)
		if got := Bearer(r); got != "" {
			t.Errorf("Authorization %q: token %q, want none", h, got)
		}
		grants, refusal := Bearers(r, DefaultGrantSize)
		if refusal != nil || len(grants) != 0 {
			t.Errorf("Authorization %q without a body: %v %v, want no grant (the caller's 401)", h, grants, refusal)
		}
		r = httptest.NewRequest("POST", "/edge-grants", strings.NewReader(`{"grants":["abc"]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", h)
		if _, refusal := Bearers(r, DefaultGrantSize); refusal == nil || refusal.Status != 400 {
			t.Errorf("Authorization %q beside a body: %+v, want 400", h, refusal)
		}
	}
	r := httptest.NewRequest("POST", "/edge-grants", nil)
	r.Header.Set("Authorization", "bEaReR  abc ")
	if got := Bearer(r); got != "abc" {
		t.Errorf("a Bearer grant, its scheme in any case: %q", got)
	}
}
