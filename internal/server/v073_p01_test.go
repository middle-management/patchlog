package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// sendRaw sends a request built by hand, for headers req can't express
// (repeated ones).
func sendRaw(t *testing.T, hr *http.Request) *resp {
	t.Helper()
	r, err := client.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return &resp{Code: r.StatusCode, H: r.Header, Body: b}
}

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

// §C.3.1 (GR-37): a Signature header or step signature whose <sig> isn't
// exactly 86 base64url characters, without padding, is 400 before step 1,
// whatever its alg or kid; one of the right form by an unlisted kid is
// stored unverified.
func TestV073SignatureShape(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	g := e.grant(f.issuer, "user:alice", []string{"sec"}, []string{"read", "create", "append", "delete"})
	gen := addRoot(map[string]any{"t": "x"})
	good := strings.Repeat("A", 86)
	for _, s := range []string{
		"Ed25519:k1:abcd",                              // valid base64url, too short
		"Ed25519:k1:" + strings.Repeat("A", 87),        // too long
		"Ed25519:k1:" + strings.Repeat("A", 84) + "==", // padded
		"Ed25519:k1:" + strings.Repeat("A", 85) + "+",  // not base64url
		"other:k:" + strings.Repeat("A", 22),           // another alg
		"",                                             // empty
	} {
		q := req{method: "PATCH", path: "/r/sec/a", ifNoneMatch: "*", body: gen, bearer: g, hdr: map[string]string{"Signature": s}}
		expectShape(t, "PATCH "+s, e.do(q))
		// Before authentication, and before the unknown namespace's 401.
		q.bearer = ""
		expectShape(t, "PATCH unauthenticated "+s, e.do(q))
		q.path = "/r/nowhere/a"
		expectShape(t, "PATCH unknown namespace "+s, e.do(q))
		q = req{method: "DELETE", path: "/r/sec/a", ifMatch: hashID(t, "", nil), hdr: map[string]string{"Signature": s}}
		expectShape(t, "DELETE "+s, e.do(q))
		if s == "" {
			continue
		}
		step := map[string]any{"patches": gen, "signature": s}
		r := e.batchReq("sec", map[string]any{"items": []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{step}}}}, g)
		expectShape(t, "batch step "+s, r)
		if _, has := r.Obj()["items"]; has {
			t.Errorf("batch step %s: refused per item: %s", s, r.Body)
		}
	}
	// Repeated: not one signature.
	hr, _ := http.NewRequest("PATCH", e.srv.URL+"/r/sec/a", strings.NewReader(string(canonical(gen))))
	hr.Header.Set("Content-Type", "application/json-patch+json")
	hr.Header.Set("If-None-Match", "*")
	hr.Header.Set("Authorization", "Bearer "+g)
	hr.Header.Add("Signature", "Ed25519:k1:"+good)
	hr.Header.Add("Signature", "Ed25519:k1:"+good)
	expectShape(t, "repeated Signature", sendRaw(t, hr))
	// An unlisted kid: stored unverified.
	q := req{method: "PATCH", path: "/r/sec/a", ifNoneMatch: "*", body: gen, bearer: g, hdr: map[string]string{"Signature": "Ed25519:k1:" + good}}
	expect(t, e.do(q), 201)
	if le := e.lastLog("sec", "a", e.head("sec", "a", g), g); le["signature"] != "Ed25519:k1:"+good {
		t.Fatalf("signature not stored: %v", le)
	}
}
