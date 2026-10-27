package server

import (
	"strings"
	"testing"
)

// W1X: a branch's malformed name is the request's own shape (§3.6, §6.2):
// 400 before authentication and before an unknown base's 404, as a
// malformed at is. A batch body's shapes come once the grant is verified,
// because the body is read up to the verified principal's batchSize
// (§6.2, §7.5): an undecodable bearer is 401 there first.
func TestW1XBranchNameShapeFirst(t *testing.T) {
	e := newAuthEnv(t)
	admin := newKey("admin")
	e.mkNS("main", map[string]any{"keys": []any{admin.entry("*")}})
	ag := e.grant(admin, "user:admin", []string{"main"}, allVerbs)
	a1 := e.create("main", "a", map[string]any{"v": 1.0}, ag)
	big := "biscuit:" + strings.Repeat("A", 20000) // over grantSize when decoded
	for _, bearer := range []string{"", "garbage", big, ag} {
		for _, base := range []string{"main", "nosuch"} {
			for _, name := range []string{"B!", "", "a/b"} {
				r := e.do(req{method: "POST", path: "/ns/" + base + "/branches", ifNoneMatch: "*", body: map[string]any{"name": name}, bearer: bearer})
				if r.Code != 400 || !strings.Contains(string(r.Body), "bad_input") {
					t.Errorf("bearer %.10q, base %s, name %q: %d %s, want 400 bad_input", bearer, base, name, r.Code, r.Body)
				}
			}
		}
	}
	// A batch body's shape after the grant (§7.5).
	r := e.do(req{method: "POST", path: "/ns/main/batch", bearer: "garbage", body: map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a1, "ifNoneMatch": "*", "steps": []any{ops(op("add", "/x", 1.0))}}}}})
	if r.Code != 401 {
		t.Errorf("batch body shape, garbage bearer: %d %s, want 401 (the body is read by the principal's batchSize)", r.Code, r.Body)
	}
	r = e.do(req{method: "POST", path: "/ns/main/batch", bearer: ag, body: map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a1, "ifNoneMatch": "*", "steps": []any{ops(op("add", "/x", 1.0))}}}}})
	if r.Code != 400 {
		t.Errorf("batch body shape, valid grant: %d %s, want 400", r.Code, r.Body)
	}
}
