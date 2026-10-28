package server

import "testing"

// GRANTS-5 (§C.5.2, §C.5.3, v0.74): an empty Authorization counts as
// present. A body with one is 400 bad_input, before the 415, and cookies
// count only on a read without it.
func TestV074EmptyAuthorizationIsPresent(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	empty := map[string]string{"Authorization": ""}

	r := e.do(req{method: "POST", path: "/edge-grants", body: map[string]any{"grants": []any{reader}}, hdr: empty})
	if r.Code != 400 || r.Str("code") != "bad_input" {
		t.Fatalf("body with an empty Authorization: want 400 bad_input, got %d %s", r.Code, r.Body)
	}
	expectNoCookies(t, "empty Authorization", r)
	// Before the 415 of a body that isn't application/json.
	r = e.do(req{method: "POST", path: "/edge-grants", raw: `{"grants":["` + reader + `"]}`, ct: "text/plain", hdr: empty})
	if r.Code != 400 || r.Str("code") != "bad_input" {
		t.Fatalf("text/plain body with an empty Authorization: want 400 bad_input, got %d %s", r.Code, r.Body)
	}

	// The cookies issued without it admit a read, not one carrying an
	// empty Authorization.
	r = e.issueGrants(reader)
	expect(t, r, 200)
	rc := edgeCookies(t, r)["/r/sec"]
	if rc == nil {
		t.Fatalf("cookies %v", r.H.Values("Set-Cookie"))
	}
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(rc)}), 302)
	h := cookieHdr(rc)
	h["Authorization"] = ""
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: h}), 401)
}
