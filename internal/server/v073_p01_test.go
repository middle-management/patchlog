package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
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

// §7.2, §12.1 (GB-19, GB-20, GB-21): every JSON body other than a JSON
// Patch is application/json; media types are compared ignoring case, a
// charset naming UTF-8 the only parameter; every 415 is unsupported_type.
func TestV073MediaTypes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	id := e.create("m", "a", map[string]any{"n": 1})
	unsupported := func(name string, r *resp) {
		t.Helper()
		if r.Code != 415 || r.Str("code") != "unsupported_type" {
			t.Errorf("%s: %d %s, want 415 unsupported_type", name, r.Code, r.Body)
		}
	}
	// JSON bodies other than a JSON Patch, sent as anything else.
	batch := map[string]any{"items": []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}
	for _, ct := range []string{"text/plain", "application/json; charset=latin1", "application/json; foo=bar", "application/json-patch+json", " "} {
		for _, c := range []struct {
			name string
			q    req
		}{
			{"batch", req{method: "POST", path: "/ns/m/batch", body: batch}},
			{"branch", req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"name": "m-b"}}},
			{"remote registration", req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"remote": map[string]any{"origin": "https://other.example", "ns": "x"}, "at": id}}},
			{"prune", req{method: "POST", path: "/r/m/a/prune", body: map[string]any{"horizon": id}}},
			{"keys", req{method: "POST", path: "/ns/m/keys", body: map[string]any{}}},
		} {
			c.q.ct, c.q.author = ct, "alice"
			unsupported(c.name+" "+ct, e.do(c.q))
		}
	}
	// /keys without a body keeps its no-body form (here: not sealed).
	expectCode(t, e.do(req{method: "POST", path: "/ns/m/keys", author: "alice"}), 404, "not_offered")
	// JSON Patch bodies.
	for _, ct := range []string{"application/json", "application/json-patch+json; charset=latin1", "application/json-patch+json; foo=bar", "text/plain"} {
		unsupported("resource PATCH "+ct, e.do(req{method: "PATCH", path: "/r/m/a", ifMatch: id, ct: ct, body: ops(op("add", "/x", 1)), author: "alice"}))
		unsupported("config PATCH "+ct, e.do(req{method: "PATCH", path: "/ns/m", ifMatch: e.configID("m"), ct: ct, body: ops(op("add", "/x-a", 1)), author: "alice"}))
	}
	// Case and a UTF-8 charset don't matter.
	r := e.do(req{method: "PATCH", path: "/r/m/a", ifMatch: id, ct: "Application/JSON-Patch+JSON; Charset=UTF-8", body: ops(op("add", "/x", 1)), author: "alice"})
	expect(t, r, 201)
	expect(t, e.do(req{method: "PATCH", path: "/ns/m", ifMatch: e.configID("m"), ct: `application/json-patch+json;charset="utf-8"`, body: ops(op("add", "/x-a", 1)), author: "alice"}), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/m/batch", ct: "APPLICATION/json; charset=Utf-8", body: batch, author: "alice"}), 201)
	expect(t, e.do(req{method: "POST", path: "/r/m/a/prune", ct: "application/json;charset=utf-8", body: map[string]any{"horizon": id}, author: "alice"}), 200)
	// Edge-grant exchanges (§C.5.2).
	f := newAuthFixture(t, nil)
	reader := f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	for _, ct := range []string{"application/json; charset=latin1", "application/json; x=y", "text/plain"} {
		unsupported("edge-grants "+ct, f.do(req{method: "POST", path: "/edge-grants", ct: ct, body: map[string]any{"grants": []any{reader}}}))
	}
	expect(t, f.do(req{method: "POST", path: "/edge-grants", ct: "Application/Json; charset=UTF-8", body: map[string]any{"grants": []any{reader}}}), 200)
	// An E3 upload that isn't a sealed blob (§7.8, §E.3.1).
	k := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	k.mkNS("e", e2eDoc(map[string]any{}))
	r, _ = k.putBlob("e", "a", "image/png", "", []byte("plain"))
	unsupported("E3 upload", r)
}

// §7, §3.2 (CIS-4): an id not in text form in a URL, in since or in an
// event stream's Last-Event-ID is 400 bad_input, not cached, before
// authentication, the read check and an unknown namespace's 404; a
// well-formed unknown id stays 404, short. A gesture listing's after
// stays 404 (§7.4).
func TestV073MalformedIDs(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	k := newKey("pub")
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	w := e.grant(k, "user:w", []string{"pub"}, []string{"read", "create", "append"})
	id := e.create("pub", "a", map[string]any{"n": 1}, w)
	nsID := e.nsHead("pub")
	good := hashID(t, "", []byte("nowhere"))
	for _, bad := range []string{"nope", strings.ToUpper(good), good[:32], good + "a", "2" + good[1:], good[:32] + "1"} {
		for _, ns := range []string{"pub", "sec", "nowhere"} {
			paths := []string{
				"/r/" + ns + "/a/rev/" + bad, "/r/" + ns + "/a/rev/" + bad + "/log", "/r/" + ns + "/a/rev/" + bad + "/raw",
				"/ns/" + ns + "/rev/" + bad, "/ns/" + ns + "/rev/" + bad + "/log", "/ns/" + ns + "/rev/" + bad + "/heads",
				"/ns/" + ns + "/grants/" + bad,
				"/r/" + ns + "/a/blob/" + bad, "/r/" + ns + "/a/blob/" + bad + "/e/1",
				"/r/" + ns + "/a/rev/" + id + "/log?since=" + bad, "/r/" + ns + "/a/log?since=" + bad,
				"/r/" + ns + "/a/log?since=" + bad + "&live=long-poll", "/r/" + ns + "/a/events?since=" + bad,
				"/ns/" + ns + "/rev/" + nsID + "/log?since=" + bad, "/ns/" + ns + "/log?since=" + bad,
				"/ns/" + ns + "/log?live=long-poll&since=" + bad, "/ns/" + ns + "/events?since=" + bad,
			}
			for _, p := range paths {
				r := e.get(p)
				expectShape(t, p, r)
				if strings.Contains(p, "/blob/") && (r.H.Get("X-Content-Type-Options") != "nosniff" || r.H.Get("Content-Security-Policy") != "sandbox") {
					t.Errorf("%s: blob headers %v", p, r.H)
				}
			}
			for _, p := range []string{"/r/" + ns + "/a/events", "/ns/" + ns + "/events"} {
				expectShape(t, p+" Last-Event-ID", e.do(req{method: "GET", path: p, hdr: map[string]string{"Last-Event-ID": bad}}))
			}
			r := e.do(req{method: "PUT", path: "/r/" + ns + "/a/blob/" + bad, raw: "x", ct: "text/plain"})
			expectShape(t, "PUT blob "+bad, r)
		}
	}
	// Well-formed but unknown: 404, short.
	for _, p := range []string{"/r/pub/a/rev/" + good, "/ns/pub/rev/" + good, "/r/pub/a/rev/" + id + "/log?since=" + good} {
		r := e.get(p)
		expectCode(t, r, 404, "not_found")
		if cc := r.H.Get("Cache-Control"); cc != ccShort {
			t.Errorf("%s: Cache-Control %q", p, cc)
		}
	}
	// An empty since is genesis; an empty Last-Event-ID is none.
	expect(t, e.get("/r/pub/a/rev/"+id+"/log?since="), 200)
	// A gesture listing's after is a cursor: an unknown one is 404.
	d := newEnv(t)
	d.mkNS("m", map[string]any{"read": "public"})
	expectCode(t, d.get("/ns/m/gestures/"+strings.Repeat("a", 26)+"?after=nope"), 404, "not_found")
}

// §7.3 (RH-31): a present, non-empty Last-Event-ID wins over since, on
// resource and namespace streams.
func TestV073LastEventIDWins(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	r1 := e.create("docs", "a", map[string]any{"n": 1})
	n1 := e.nsHead("docs")
	r2 := e.appendRev("docs", "a", r1, ops(op("replace", "/n", 2)))
	n2 := e.nsHead("docs")
	r3 := e.appendRev("docs", "a", r2, ops(op("replace", "/n", 3)))
	n3 := e.nsHead("docs")
	ch, _, _ := e.openSSE("/r/docs/a/events?since="+r1, map[string]string{"Last-Event-ID": r2})
	if ev := next(t, ch); ev.id != r3 {
		t.Fatalf("resource stream from Last-Event-ID: %v, want %s", ev, r3)
	}
	ch, _, _ = e.openSSE("/ns/docs/events?since="+n1, map[string]string{"Last-Event-ID": n2})
	if ev := next(t, ch); ev.id != n3 {
		t.Fatalf("namespace stream from Last-Event-ID: %v, want %s", ev, n3)
	}
	// An empty Last-Event-ID leaves since.
	ch, _, _ = e.openSSE("/r/docs/a/events?since="+r1, map[string]string{"Last-Event-ID": ""})
	if ev := next(t, ch); ev.id != r2 {
		t.Fatalf("resource stream from since: %v, want %s", ev, r2)
	}
	// A Last-Event-ID not in the log is judged, not since.
	other := hashID(t, "", []byte("other"))
	expectCode(t, e.do(req{method: "GET", path: "/r/docs/a/events?since=" + r1, hdr: map[string]string{"Last-Event-ID": other}}), 404, "not_found")
	expectCode(t, e.do(req{method: "GET", path: "/ns/docs/events?since=" + n1, hdr: map[string]string{"Last-Event-ID": other}}), 404, "not_found")
}

// §7, §7.2, §7.5 (CIS-5, GB-23): a write's precondition is one strong
// entity tag around a text id or If-None-Match: *; If-Match: *, a weak tag,
// a list, a sealed "{id}.{e}", a non-id, an empty value, both headers, and
// in a batch both item preconditions or a malformed ifMatch, are the
// request's own 400 before step 1, never a per-item report. So are a
// malformed branch or registration at and prune horizon or keep; a
// well-formed id that isn't in the chain stays 422.
func TestV073PreconditionShapes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	id := e.create("m", "a", map[string]any{"n": 1})
	cfg := e.configID("m")
	patch := ops(op("add", "/x", 1))
	bad := []string{"*", `W/"` + id + `"`, `"` + id + `", "` + id + `"`, `"` + id + `.3"`, `"zzz"`, `"` + strings.ToUpper(id) + `"`, id, `""`}
	for _, im := range bad {
		h := map[string]string{"If-Match": im}
		expectShape(t, "PATCH If-Match "+im, e.do(req{method: "PATCH", path: "/r/m/a", body: patch, hdr: h, author: "alice"}))
		expectShape(t, "DELETE If-Match "+im, e.do(req{method: "DELETE", path: "/r/m/a", hdr: h, author: "alice"}))
		expectShape(t, "config If-Match "+im, e.do(req{method: "PATCH", path: "/ns/m", body: ops(op("add", "/x-a", 1)), hdr: h, author: "alice"}))
		expectShape(t, "purge If-Match "+im, e.do(req{method: "POST", path: "/r/m/a/purge", hdr: h, author: "alice"}))
		expectShape(t, "prune If-Match "+im, e.do(req{method: "POST", path: "/r/m/a/prune", body: map[string]any{"horizon": id}, hdr: h, author: "alice"}))
	}
	for _, inm := range []string{`"` + id + `"`, "**", `W/"` + id + `"`} {
		expectShape(t, "If-None-Match "+inm, e.do(req{method: "PATCH", path: "/r/m/b", body: addRoot(map[string]any{}), hdr: map[string]string{"If-None-Match": inm}, author: "alice"}))
	}
	both := map[string]string{"If-Match": `"` + id + `"`, "If-None-Match": "*"}
	expectShape(t, "PATCH both", e.do(req{method: "PATCH", path: "/r/m/a", body: patch, hdr: both, author: "alice"}))
	expectShape(t, "prune both", e.do(req{method: "POST", path: "/r/m/a/prune", body: map[string]any{"horizon": id}, hdr: both, author: "alice"}))
	if e.head("m", "a") != id {
		t.Fatal("a refused write moved the head")
	}
	// A config write's malformed If-Match was ignored (412); now 400, and a
	// well-formed stale one is still 412.
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/m", ifMatch: id, body: ops(op("add", "/x-a", 1)), author: "alice"}), 412, "stale")
	expect(t, e.do(req{method: "PATCH", path: "/ns/m", ifMatch: cfg, body: ops(op("add", "/x-a", 1)), author: "alice"}), 201)

	// Batches: two item preconditions, or a malformed ifMatch, are the
	// batch's own 400, without items.
	item := func(m map[string]any) map[string]any {
		m["resource"], m["steps"] = "a", []any{patch}
		return m
	}
	cfgChange := func(ifMatch any) map[string]any {
		return map[string]any{"config": map[string]any{"ifMatch": ifMatch, "patches": ops(op("add", "/x-b", 1))}}
	}
	for name, body := range map[string]map[string]any{
		"both":                 {"items": []any{item(map[string]any{"ifMatch": id, "ifNoneMatch": "*"})}},
		"uppercase":            {"items": []any{item(map[string]any{"ifMatch": strings.ToUpper(id)})}},
		"sealed ETag":          {"items": []any{item(map[string]any{"ifMatch": id + ".1"})}},
		"empty":                {"items": []any{item(map[string]any{"ifMatch": ""})}},
		"quoted":               {"items": []any{item(map[string]any{"ifMatch": `"` + id + `"`})}},
		"config ifMatch":       cfgChange("zzz"),
		"config ifMatch not a": cfgChange(1.0),
	} {
		r := e.batchReq("m", body, "alice")
		expectShape(t, "batch "+name, r)
		if _, has := r.Obj()["items"]; has {
			t.Errorf("batch %s: reported per item: %s", name, r.Body)
		}
	}
	// Under a grant without the verbs, the shape error still wins.
	f := newAuthFixture(t, nil)
	ro := f.grant(f.issuer, "user:ro", []string{"sec"}, []string{"read"})
	r := f.batchReq("sec", map[string]any{"items": []any{item(map[string]any{"ifMatch": id, "ifNoneMatch": "*"})}}, ro)
	expectShape(t, "batch both, unauthorised", r)
	// Before authentication for single writes.
	expectShape(t, "PATCH weak, no grant", f.do(req{method: "PATCH", path: "/r/sec/a", body: patch, hdr: map[string]string{"If-Match": `W/"` + id + `"`}}))
	expectShape(t, "PATCH *, no grant", f.do(req{method: "PATCH", path: "/r/nowhere/a", body: patch, hdr: map[string]string{"If-Match": "*"}}))
	// And before a frozen namespace's 409.
	e.mkNS("fz", map[string]any{"read": "public", "frozen": true})
	expectShape(t, "PATCH sealed ETag, frozen", e.do(req{method: "PATCH", path: "/r/fz/a", body: patch, hdr: map[string]string{"If-Match": `"` + id + `.3"`}, author: "alice"}))

	// Branch creation and remote registration: at.
	for _, at := range []any{"zzz", strings.ToUpper(id), "", 5.0} {
		expectShape(t, "branch at", e.do(req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"name": "m-b", "at": at}, author: "alice"}))
		expectShape(t, "registration at", e.do(req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"remote": map[string]any{"origin": "https://other.example", "ns": "x"}, "at": at}, author: "alice"}))
	}
	expectCode(t, e.do(req{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"name": "m-b", "at": id}, author: "alice"}), 422, "invalid")
	// Prune: horizon and keep.
	for _, body := range []map[string]any{
		{"horizon": "zzz"}, {"horizon": strings.ToUpper(id)}, {"horizon": id, "keep": []any{"zzz"}}, {"horizon": id, "keep": []any{id, ""}},
	} {
		expectShape(t, "prune body", e.do(req{method: "POST", path: "/r/m/a/prune", body: body, author: "alice"}))
	}
	expectCode(t, e.do(req{method: "POST", path: "/r/m/a/prune", body: map[string]any{"horizon": hashID(t, "", []byte("x"))}, author: "alice"}), 422, "invalid")
}

// §7.5, §12.1 (GB-6): DELETE with If-None-Match: * is a precondition DELETE
// doesn't take, the core's answer after authorisation (428 once the gate
// says so), no longer a request-shape 400; it deletes nothing.
func TestV073DeleteIfNoneMatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	id := e.create("m", "a", map[string]any{"n": 1})
	for _, name := range []string{"a", "missing"} {
		r := e.do(req{method: "DELETE", path: "/r/m/" + name, ifNoneMatch: "*", author: "alice"})
		if r.Code == 400 || r.Code < 400 {
			t.Errorf("DELETE %s with If-None-Match: %d %s", name, r.Code, r.Body)
		}
	}
	if e.head("m", "a") != id {
		t.Fatal("DELETE with If-None-Match deleted")
	}
	// Under a grant without delete it is refused at step 1 (§6.2).
	f := newAuthFixture(t, nil)
	ro := f.grant(f.issuer, "user:ro", []string{"sec"}, []string{"read", "create"})
	expectCode(t, f.do(req{method: "DELETE", path: "/r/sec/a", ifNoneMatch: "*", bearer: ro}), 403, "forbidden")
}

// §7.2, §8.6, §7.8 (GB-14, GB-58, BBD-26): the request facts the core
// judges: a prune's keep: [] told from no keep, and whether a prune or an
// upload sent a precondition; an upload's Blob-Nonce as sent, empty or
// repeated included. Two preconditions, or a malformed one, stay 400:
// before step 1 for a prune, at check 4 for an upload (after 409 frozen).
func TestV073RequestFacts(t *testing.T) {
	t.Parallel()
	id := hashID(t, "", []byte("x"))
	prune := func(body string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest("POST", "/r/m/a/prune", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	for _, c := range []struct {
		body             string
		hdr              map[string]string
		keepSent, precnd bool
		keep             int
	}{
		{`{"horizon":"` + id + `"}`, nil, false, false, 0},
		{`{"horizon":"` + id + `","keep":[]}`, nil, true, false, 0},
		{`{"horizon":"` + id + `","keep":["` + id + `"]}`, nil, true, false, 1},
		{`{"horizon":"` + id + `"}`, map[string]string{"If-Match": `"` + id + `"`}, false, true, 0},
		{`{"horizon":"` + id + `"}`, map[string]string{"If-None-Match": "*"}, false, true, 0},
	} {
		pr, err := pruneRequest(prune(c.body, c.hdr))
		if err != nil || pr.KeepSent != c.keepSent || pr.Precondition != c.precnd || len(pr.Keep) != c.keep || pr.Horizon != id {
			t.Errorf("%s %v: %+v %v", c.body, c.hdr, pr, err)
		}
	}
	if _, err := pruneRequest(prune(`{"horizon":"`+id+`"}`, map[string]string{"If-Match": `"` + id + `"`, "If-None-Match": "*"})); err == nil {
		t.Error("prune with both preconditions parsed")
	}

	upload := func(hdr http.Header) *http.Request {
		r := httptest.NewRequest("PUT", "/r/m/a/blob/"+id, strings.NewReader("x"))
		r.Header = hdr
		return r
	}
	nonce := strings.Repeat("a", 26)
	for _, c := range []struct {
		hdr       http.Header
		nonceSent bool
		nonce     string
		precnd    bool
		shape     bool
	}{
		{http.Header{}, false, "", false, false},
		{http.Header{"Blob-Nonce": {nonce}}, true, nonce, false, false},
		{http.Header{"Blob-Nonce": {""}}, true, "", false, false},
		{http.Header{"Blob-Nonce": {nonce, nonce}}, true, nonce + "," + nonce, false, false},
		{http.Header{"If-None-Match": {"*"}}, false, "", true, false},
		{http.Header{"If-Match": {`"` + id + `"`}}, false, "", true, false},
		{http.Header{"If-Match": {`"` + id + `"`}, "If-None-Match": {"*"}}, false, "", false, true},
		{http.Header{"If-Match": {"*"}}, false, "", false, true},
	} {
		up := blobUpload(upload(c.hdr))
		if up.NonceSent != c.nonceSent || up.Nonce != c.nonce || up.Precondition != c.precnd || (up.ShapeErr != "") != c.shape {
			t.Errorf("%v: %+v", c.hdr, up)
		}
	}

	// Over HTTP: the upload's header errors come at check 4.
	e := newEnv(t, withBlobTuning)
	e.mkNS("m", map[string]any{"read": "public"})
	e.mkNS("fz", map[string]any{"read": "public", "frozen": true})
	data := []byte("bytes")
	bid := blobID("text/plain", "", data)
	both := map[string]string{"If-Match": `"` + id + `"`, "If-None-Match": "*"}
	expectShape(t, "upload both", e.do(req{method: "PUT", path: blobPath("m", "a", bid), raw: string(data), ct: "text/plain", hdr: both, author: "alice"}))
	expectCode(t, e.do(req{method: "PUT", path: blobPath("fz", "a", bid), raw: string(data), ct: "text/plain", hdr: both, author: "alice"}), 409, "frozen")
	hr, _ := http.NewRequest("PUT", e.srv.URL+blobPath("m", "a", blobID("text/plain", nonce, data)), strings.NewReader(string(data)))
	hr.Header.Set("Content-Type", "text/plain")
	hr.Header.Set("X-Author", "alice")
	hr.Header.Add("Blob-Nonce", nonce)
	hr.Header.Add("Blob-Nonce", nonce)
	expectShape(t, "repeated Blob-Nonce", sendRaw(t, hr))
}

// §3.5, §7.5 (CIS-8): a batch source of any shape but { origin?, ns, at,
// bundle?, ids? }, with text ids, ids naming the batch's resources and a
// canonical origin, is the batch's own 400, recorded nowhere.
func TestV073BatchSourceShape(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	e.mkNS("rel", map[string]any{"read": "public"})
	at := e.nsHead("rel")
	id := hashID(t, "", []byte("x"))
	items := []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}
	before := e.nsHead("m")
	for _, src := range []any{
		"rel", nil, []any{}, map[string]any{},
		map[string]any{"ns": "rel"},
		map[string]any{"at": at},
		map[string]any{"ns": "Rel!", "at": at},
		map[string]any{"ns": "rel", "at": "zzz"},
		map[string]any{"ns": "rel", "at": at, "x": 1},
		map[string]any{"ns": "rel", "at": at, "bundle": 5},
		map[string]any{"ns": "rel", "at": at, "bundle": "zzz"},
		map[string]any{"ns": "rel", "at": at, "ids": []any{}},
		map[string]any{"ns": "rel", "at": at, "ids": map[string]any{"zzz": id}},
		map[string]any{"ns": "rel", "at": at, "ids": map[string]any{"a": "notanid"}},
		map[string]any{"ns": "rel", "at": at, "ids": map[string]any{"a": 1}},
		map[string]any{"ns": "rel", "at": at, "origin": 1},
		map[string]any{"ns": "rel", "at": at, "origin": "https://Other.example"},
		map[string]any{"ns": "rel", "at": at, "origin": "HTTPS://other.example"},
		map[string]any{"ns": "rel", "at": at, "origin": "https://other.example/"},
		map[string]any{"ns": "rel", "at": at, "origin": "https://other.example:443"},
		map[string]any{"ns": "rel", "at": at, "origin": "https://other.example:0444"},
		map[string]any{"ns": "rel", "at": at, "origin": "https://other.example:"},
		map[string]any{"ns": "rel", "at": at, "origin": "http://other.example:80"},
		map[string]any{"ns": "rel", "at": at, "origin": "https://u@other.example"},
		map[string]any{"ns": "rel", "at": at, "origin": "ftp://other.example"},
		map[string]any{"ns": "rel", "at": at, "origin": "other.example"},
	} {
		r := e.batchReq("m", map[string]any{"items": items, "source": src}, "alice")
		expectShape(t, string(canonical(src)), r)
	}
	if e.nsHead("m") != before {
		t.Fatal("a refused source was recorded")
	}
	// Well-formed: another deployment's source is recorded unchecked.
	src := map[string]any{"origin": "https://other.example:8443", "ns": "rel", "at": id, "bundle": id, "ids": map[string]any{"a": id}}
	r := e.batchReq("m", map[string]any{"items": items, "source": src}, "alice")
	expect(t, r, 201)
	lg := e.get("/ns/m/rev/" + r.Str("ns_id") + "/log").Arr()
	if got := lg[len(lg)-1].(map[string]any)["source"]; string(canonical(got)) != string(canonical(src)) {
		t.Fatalf("source %v", got)
	}
}

// §7.5 (GB-27): a batch's Gesture and Undoes headers are its defaults; one
// given both as a header and in the body is 400.
func TestV073BatchGestureHeaders(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	g, u := strings.Repeat("g", 26), strings.Repeat("u", 26)
	items := []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}
	r := e.do(req{method: "POST", path: "/ns/m/batch", body: map[string]any{"items": items}, author: "alice", hdr: map[string]string{"Gesture": g, "Undoes": u}})
	expect(t, r, 201)
	id := r.Obj()["items"].([]any)[0].(map[string]any)["ids"].([]any)[0].(string)
	if le := e.lastLog("m", "a", id, ""); le["gesture"] != g || le["undoes"] != u {
		t.Fatalf("entry %v", le)
	}
	// A step's own value still overrides the header's.
	own := strings.Repeat("s", 26)
	items2 := []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{map[string]any{"patches": addRoot(map[string]any{}), "gesture": own}}}}
	r = e.do(req{method: "POST", path: "/ns/m/batch", body: map[string]any{"items": items2}, author: "alice", hdr: map[string]string{"Gesture": g}})
	expect(t, r, 201)
	if le := e.lastLog("m", "b", e.head("m", "b"), ""); le["gesture"] != own {
		t.Fatalf("entry %v", le)
	}
	for _, k := range []string{"gesture", "undoes"} {
		h := map[string]string{"Gesture": g}
		if k == "undoes" {
			h = map[string]string{"Undoes": u}
		}
		expectShape(t, "both ways "+k, e.do(req{method: "POST", path: "/ns/m/batch", body: map[string]any{"items": items, k: g}, author: "alice", hdr: h}))
	}
	expectShape(t, "malformed Gesture", e.do(req{method: "POST", path: "/ns/m/batch", body: map[string]any{"items": items}, author: "alice", hdr: map[string]string{"Gesture": "nope"}}))
}

// §C.3.1 (GR-38): a Signature header on any write other than a resource
// PATCH or DELETE is 400, before any 401; an upload's is a header shape
// error of check 4 (§7.8), after authorisation and 409 frozen.
func TestV073SignatureHeaderElsewhere(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	hdr := map[string]string{"Signature": "Ed25519:k1:" + strings.Repeat("A", 86)}
	id := hashID(t, "", []byte("x"))
	for _, q := range []req{
		{method: "PATCH", path: "/ns/sec", ifMatch: id, body: ops(op("add", "/x-a", 1))},
		{method: "PATCH", path: "/ns/new", ifNoneMatch: "*", body: addRoot(map[string]any{})},
		{method: "POST", path: "/ns/sec/batch", body: map[string]any{"items": []any{}}},
		{method: "POST", path: "/r/sec/a/purge", ifMatch: id},
		{method: "POST", path: "/ns/sec/purge", ifMatch: id},
		{method: "POST", path: "/r/sec/a/prune", body: map[string]any{"horizon": id}},
		{method: "POST", path: "/ns/sec/branches", ifNoneMatch: "*", body: map[string]any{"name": "sec-b"}},
		{method: "POST", path: "/ns/sec/branches", ifNoneMatch: "*", body: map[string]any{"remote": map[string]any{"origin": "https://other.example", "ns": "x"}, "at": id}},
	} {
		q.hdr = hdr
		expectShape(t, q.method+" "+q.path, e.do(q))
		q.bearer = f.adminG
		expectShape(t, q.method+" "+q.path+" with a grant", e.do(q))
	}
	// Uploads and copies: at check 4.
	data := []byte("bytes")
	bid := blobID("text/plain", "", data)
	up := req{method: "PUT", path: blobPath("sec", "a", bid), raw: string(data), ct: "text/plain", hdr: hdr}
	expectCode(t, e.do(up), 401, "unauthenticated")
	up.bearer = f.issuerG
	expectShape(t, "upload", e.do(up))
	cp := req{method: "PUT", path: blobPath("sec", "a", bid), bearer: f.issuerG, hdr: map[string]string{"Signature": hdr["Signature"], "Blob-From": blobPath("sec", "b", bid)}}
	expectShape(t, "copy", e.do(cp))
	k := newKey("fz")
	e.mkNS("fz", map[string]any{"read": "public", "frozen": true, "keys": []any{k.entry("*")}})
	up = req{method: "PUT", path: blobPath("fz", "a", bid), raw: string(data), ct: "text/plain", hdr: hdr, bearer: e.grant(k, "user:w", []string{"fz"}, []string{"create"})}
	expectCode(t, e.do(up), 409, "frozen")
}

// §7.2 (GB-57): while authentication is disabled, a write without X-Author
// is 400; reads are unaffected. An upload's is a header shape error of
// check 4 (§7.8).
func TestV073XAuthorRequired(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("m", map[string]any{"read": "public"})
	id := e.create("m", "a", map[string]any{"n": 1})
	cfg, at := e.configID("m"), e.nsHead("m")
	data := []byte("bytes")
	bid := blobID("text/plain", "", data)
	for _, author := range []string{"", " "} {
		for _, q := range []req{
			{method: "PATCH", path: "/r/m/a", ifMatch: id, body: ops(op("add", "/x", 1))},
			{method: "PATCH", path: "/r/m/b", ifNoneMatch: "*", body: addRoot(map[string]any{})},
			{method: "DELETE", path: "/r/m/a", ifMatch: id},
			{method: "PATCH", path: "/ns/m", ifMatch: cfg, body: ops(op("add", "/x-a", 1))},
			{method: "PATCH", path: "/ns/n2", ifNoneMatch: "*", body: addRoot(map[string]any{})},
			{method: "POST", path: "/ns/m/batch", body: map[string]any{"items": []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}},
			{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"name": "m-b"}},
			{method: "POST", path: "/ns/m/branches", ifNoneMatch: "*", body: map[string]any{"remote": map[string]any{"origin": "https://other.example", "ns": "x"}, "at": at}},
			{method: "POST", path: "/r/m/a/purge", ifMatch: id},
			{method: "POST", path: "/ns/m/purge", ifMatch: at},
			{method: "POST", path: "/r/m/a/prune", body: map[string]any{"horizon": id}},
			{method: "PUT", path: blobPath("m", "a", bid), raw: string(data), ct: "text/plain"},
		} {
			if author != "" {
				q.hdr = map[string]string{"X-Author": author}
			}
			expectShape(t, q.method+" "+q.path+" author "+author, e.do(q))
		}
	}
	if e.head("m", "a") != id {
		t.Fatal("a write without X-Author changed the resource")
	}
	// Reads, POST /keys among them, need none.
	expect(t, e.get("/r/m/a"), 302)
	expect(t, e.get("/r/m/a/rev/"+id), 200)
	expectCode(t, e.do(req{method: "POST", path: "/ns/m/keys"}), 404, "not_offered")
	// With an author, the same write goes through.
	expect(t, e.do(req{method: "PATCH", path: "/r/m/a", ifMatch: id, body: ops(op("add", "/x", 1)), author: "alice"}), 201)
	// With authentication on, X-Author isn't needed.
	f := newAuthFixture(t, nil)
	expect(t, f.do(req{method: "PATCH", path: "/r/sec/a", ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: f.issuerG}), 201)
}

// §7.7 (RH-40): live is absent or long-poll, an empty value included
// otherwise 400; cursor is a decimal number, so cursor= and +5 are 400;
// both before authorisation.
func TestV073LiveQuery(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	k := newKey("pub")
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	e.create("pub", "a", map[string]any{"n": 1}, e.grant(k, "user:w", []string{"pub"}, []string{"create"}))
	for _, ns := range []string{"pub", "sec", "nowhere"} {
		for _, base := range []string{"/r/" + ns + "/a/log", "/ns/" + ns + "/log"} {
			for _, q := range []string{"live=", "live=sse", "live=Long-Poll", "live=long-poll&cursor=", "live=long-poll&cursor=%2B5",
				"live=long-poll&cursor=+5", "live=long-poll&cursor=-1", "live=long-poll&cursor=1.0", "live=long-poll&cursor=x",
				"live=long-poll&cursor=99999999999999999999", "cursor=", "cursor=x"} {
				expectShape(t, base+"?"+q, e.get(base+"?"+q))
			}
		}
	}
	// Without live: the 302; with it and a decimal cursor: an answer.
	expect(t, e.get("/r/pub/a/log"), 302)
	expect(t, e.get("/ns/pub/log?cursor=0"), 302)
	expect(t, e.get("/r/pub/a/log?live=long-poll&cursor=007"), 200)
	expect(t, e.get("/ns/pub/log?live=long-poll"), 200)
}

// §6.6 (GB-47): a config write's, a namespace creation's and a branch's
// body is cut off as a resource PATCH's is, naming documentSize with the
// deployment's maximum.
func TestV073PatchBodiesNameDocumentSize(t *testing.T) {
	t.Parallel()
	l := core.DefaultLimits()
	l.DocumentSize, l.PatchSetSize = 64<<10, 16<<10
	e := newEnv(t, func(o *core.Options) { o.Limits, o.Maximums = l, l })
	e.mkNS("b", map[string]any{})
	bound := 4 * (64 << 10)
	pad := strings.Repeat("x", 300<<10)
	expectLimit(t, e.write("PATCH", "b", "r", "", addRoot(map[string]any{"a": pad})), 413, "documentSize", int64(bound+1), 64<<10)
	expectLimit(t, e.patchNS("b", ops(op("add", "/x-a", pad)), ""), 413, "documentSize", int64(bound+1), 64<<10)
	expectLimit(t, e.do(req{method: "PATCH", path: "/ns/c", ifNoneMatch: "*", body: addRoot(map[string]any{"x-a": pad}), author: "admin"}), 413, "documentSize", int64(bound+1), 64<<10)
	expectLimit(t, e.branch("b", map[string]any{"name": "b1", "patches": ops(op("add", "/x-a", pad))}, "alice"), 413, "documentSize", int64(bound+1), 64<<10)
}
