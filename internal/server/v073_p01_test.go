package server

import (
	"strings"
	"testing"
)

// expectShape checks a request-shape refusal (§6.2): 400 bad_input,
// never cached.
func expectShape(t *testing.T, name string, r *resp) {
	t.Helper()
	if r.Code != 400 || r.Str("code") != "bad_input" {
		t.Errorf("%s: %d %s, want 400 bad_input", name, r.Code, r.Body)
		return
	}
	if cc := r.H.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control %q, want no-store", name, cc)
	}
}

// §3.1 (CIS-1): a request body other than a blob upload's with a Unicode
// noncharacter, raw or escaped (a surrogate pair included), is 400.
func TestV073NoncharacterBodies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	id := e.create("m", "a", map[string]any{"n": 1})
	for _, nc := range []string{"\uFDD0", "\uFFFE", "\U0010FFFF", `\uFDEF`, `\ud83f\udffe`} {
		patch := `[{"op":"add","path":"/s","value":"x` + nc + `"}]`
		create := `[{"op":"add","path":"","value":{"s":"` + nc + `"}}]`
		for _, c := range []struct {
			name string
			q    req
		}{
			{"resource PATCH", req{method: "PATCH", path: "/r/m/b", ifNoneMatch: "*", raw: create}},
			{"key", req{method: "PATCH", path: "/r/m/a", ifMatch: id, raw: `[{"op":"add","path":"/` + nc + `","value":1}]`}},
			{"config PATCH", req{method: "PATCH", path: "/ns/m", ifMatch: e.configID("m"), raw: `[{"op":"add","path":"/x-s","value":"` + nc + `"}]`}},
			{"namespace creation", req{method: "PATCH", path: "/ns/n2", ifNoneMatch: "*", raw: `[{"op":"add","path":"","value":{"x-s":"` + nc + `"}}]`}},
			{"batch", req{method: "POST", path: "/ns/m/batch", raw: `{"items":[{"resource":"a","ifMatch":"` + id + `","steps":[` + patch + `]}]}`}},
			{"branch", req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", raw: `{"name":"m-b","patches":[{"op":"add","path":"/x-s","value":"` + nc + `"}]}`}},
			{"remote registration", req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", raw: `{"remote":{"origin":"https://other.example","ns":"` + nc + `"},"at":"` + id + `"}`}},
			{"prune", req{method: "POST", path: "/r/m/a/prune", raw: `{"horizon":"` + id + `","snapshot":"` + nc + `"}`}},
			{"keys", req{method: "POST", path: "/ns/m/keys", raw: `{"resources":["` + nc + `"]}`}},
		} {
			c.q.author = "alice"
			expectShape(t, c.name+" "+nc, e.do(c.q))
		}
	}
	if e.head("m", "a") != id {
		t.Error("a refused body changed the resource")
	}
	// Blob uploads are bytes, not JSON (§3.1).
	e.upload("m", "a", "application/json", []byte(`{"s":"`+"\uFDD0\U0001FFFE"+`"}`))
	// Edge-grant exchanges too (§C.5.2).
	f := newAuthFixture(t, nil)
	r := f.do(req{method: "POST", path: "/edge-grants", raw: `{"grants":["` + strings.Repeat("A", 8) + `\ufdd0"]}`})
	expectShape(t, "edge-grants", r)
}
