package svcedge

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// GRANTS-5/SERVICES-15 (§C.5.2, §C.5.3, §B.11.5, v0.74): a services'
// exchange counts an empty Authorization as present, so a body with one
// is 400 bad_input, before the 415 of a body that isn't application/json.
func TestV074BearersEmptyAuthorization(t *testing.T) {
	t.Parallel()
	for _, ct := range []string{"application/json", "text/plain"} {
		r := httptest.NewRequest("POST", "/edge-grants", strings.NewReader(`{"grants":["abc"]}`))
		r.Header.Set("Content-Type", ct)
		r.Header["Authorization"] = []string{""}
		bs, e := Bearers(r, DefaultGrantSize)
		if e == nil || e.Status != 400 || e.Body["code"] != "bad_input" {
			t.Errorf("%s with an empty Authorization: %v %+v, want 400 bad_input", ct, bs, e)
		}
	}
}
