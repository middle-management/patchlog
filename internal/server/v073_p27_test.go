package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Spec v0.73, package P27: blob uploads and copies, epoch blob URLs
// (§7.1, §7.8, §12.1).

// putBlobHdr is a blob PUT with headers added as given, repeats included
// (Header.Add), which the tests' req can't send.
func (e *tenv) putBlobHdr(path, ct, body string, hdr [][2]string) *resp {
	e.t.Helper()
	hr, err := http.NewRequest("PUT", e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if ct != "" {
		hr.Header.Set("Content-Type", ct)
	}
	hr.Header.Set("X-Author", "alice")
	for _, h := range hdr {
		hr.Header.Add(h[0], h[1])
	}
	r, err := client.Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return &resp{Code: r.StatusCode, H: r.Header, Body: b}
}

// expectBlobHeaders checks what every response to a blob URL carries
// (§7.8 Reading).
func expectBlobHeaders(t *testing.T, r *resp, what string) {
	t.Helper()
	if r.H.Get("X-Content-Type-Options") != "nosniff" || r.H.Get("Content-Security-Policy") != "sandbox" {
		t.Errorf("%s (%d): nosniff %q, CSP %q; want nosniff and sandbox", what, r.Code, r.H.Get("X-Content-Type-Options"), r.H.Get("Content-Security-Policy"))
	}
}

// BBD-19: uploads and copies answer at a blob URL, so their responses,
// errors included, carry nosniff and the sandbox too (§7.8 Reading).
func TestV073BlobPutHeaders(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("h", map[string]any{"read": "public"})
	data := []byte("headers")
	r, bid := e.putBlob("h", "a", "text/plain", "", data)
	expect(t, r, 201)
	expectBlobHeaders(t, r, "201 upload")
	expectBlobHeaders(t, e.putBlobAs("h", "a", bid, "nonsense", "", data), "400 media type")
	expectBlobHeaders(t, e.putBlobAs("h", "a", bid, "text/html", "", data), "422 blob_mismatch")
	// A request-shape error in the URL, answered before routing.
	r = e.do(req{method: "PUT", path: "/r/h/a/blob/1abc", raw: "x", hasRaw: true, ct: "text/plain", author: "alice"})
	expect(t, r, 400)
	expectBlobHeaders(t, r, "400 malformed bid")
	e.create("h", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	r = e.copyBlob("h", "c", bid, blobPath("h", "a", bid), "")
	expect(t, r, 201)
	expectBlobHeaders(t, r, "201 copy")
	r = e.copyBlob("h", "c", bid, blobPath("h", "nothing", bid), "")
	expect(t, r, 404)
	expectBlobHeaders(t, r, "404 copy")
}

// GB-58 (BBD-25): an upload or copy takes no precondition; one sent is
// 428 precondition_required at check 4, after authorisation, purges and
// a frozen namespace, and for a copy after its source checks (§7.2, §7.8,
// §12.1).
func TestV073BlobPutPrecondition(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("p", map[string]any{"read": "public"})
	data := []byte("precondition")
	bid := blobID("text/plain", "", data)
	path := blobPath("p", "a", bid)
	for _, h := range [][2]string{{"If-None-Match", "*"}, {"If-Match", `"` + bid + `"`}} {
		expectCode(t, e.putBlobHdr(path, "text/plain", string(data), [][2]string{h}), 428, "precondition_required")
	}
	// Request-shape errors of check 4 come first: both preconditions, a
	// media type that doesn't parse.
	expectCode(t, e.putBlobHdr(path, "text/plain", string(data), [][2]string{{"If-None-Match", "*"}, {"If-Match", `"` + bid + `"`}}), 400, "bad_input")
	expectCode(t, e.putBlobHdr(path, "nonsense", string(data), [][2]string{{"If-None-Match", "*"}}), 400, "bad_input")
	// Nothing was stored.
	if s := e.blobStats(); s.Pending != 0 {
		t.Fatalf("stats %+v: a refused upload stored a pending entry", s)
	}

	// A copy: the source checks, then 428.
	expect(t, e.putBlobAs("p", "a", bid, "text/plain", "", data), 201)
	e.create("p", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	from := [2]string{"Blob-From", path}
	expectCode(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{from, {"If-None-Match", "*"}}), 428, "precondition_required")
	expectCode(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{{"Blob-From", blobPath("p", "none", bid)}, {"If-None-Match", "*"}}), 404, "not_found")
	other := blobID("text/plain", "", []byte("other"))
	expectCode(t, e.putBlobHdr(blobPath("p", "c", other), "", "", [][2]string{from, {"If-None-Match", "*"}}), 422, "blob")
	// Without one it copies.
	expect(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{from}), 201)

	// A purged resource (410) and a frozen namespace (409) come first.
	h := e.create("p", "gone", map[string]any{"n": 1})
	expect(t, e.do(req{method: "POST", path: "/r/p/gone/purge", ifMatch: h, author: "admin"}), 204)
	expectCode(t, e.putBlobHdr(blobPath("p", "gone", bid), "text/plain", string(data), [][2]string{{"If-None-Match", "*"}}), 410, "gone")
	expect(t, e.patchNS("p", ops(op("add", "/frozen", true)), ""), 201)
	expectCode(t, e.putBlobHdr(path, "text/plain", string(data), [][2]string{{"If-None-Match", "*"}}), 409, "frozen")
	expectCode(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{from, {"If-Match", `"` + bid + `"`}}), 409, "frozen")
}

// GB-58: authorisation comes before the 428 (§7.8 check 1).
func TestV073BlobPutPreconditionAfterAuth(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	data := []byte("auth first")
	bid := blobID("text/plain", "", data)
	readOnly := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"})
	q := req{method: "PUT", path: blobPath("sec", "a", bid), raw: string(data), hasRaw: true, ct: "text/plain", ifNoneMatch: "*"}
	expectCode(t, e.do(q), 401, "unauthenticated")
	q.bearer = readOnly
	expectCode(t, e.do(q), 403, "forbidden")
	q.bearer = f.issuerG
	expectCode(t, e.do(q), 428, "precondition_required")
}

// BBD-26: a Blob-Nonce that is present but empty, or repeated, is 400
// bad_input at check 4: a blob without a nonce sends no Blob-Nonce (§7.8).
func TestV073BlobNonceShape(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("n", map[string]any{"read": "public"})
	data := []byte("nonce shape")
	bid := blobID("text/plain", "", data)
	path := blobPath("n", "a", bid)
	expectCode(t, e.putBlobHdr(path, "text/plain", string(data), [][2]string{{"Blob-Nonce", ""}}), 400, "bad_input")
	nonce := strings.Repeat("a", 26)
	nbid := blobID("text/plain", nonce, data)
	expectCode(t, e.putBlobHdr(blobPath("n", "a", nbid), "text/plain", string(data), [][2]string{{"Blob-Nonce", nonce}, {"Blob-Nonce", nonce}}), 400, "bad_input")
	// After the frozen check (check 3), as check 4 is.
	expect(t, e.putBlobHdr(path, "text/plain", string(data), nil), 201)
	expect(t, e.putBlobHdr(blobPath("n", "a", nbid), "text/plain", string(data), [][2]string{{"Blob-Nonce", nonce}}), 201)
	expect(t, e.patchNS("n", ops(op("add", "/frozen", true)), ""), 201)
	expectCode(t, e.putBlobHdr(path, "text/plain", string(data), [][2]string{{"Blob-Nonce", ""}}), 409, "frozen")
}

// BBD-22: a copy is checked as an upload of the source's type, nonce and
// size, whatever Content-Type and Blob-Nonce it carries (§7.8 Copying).
func TestV073BlobCopyIgnoresTypeAndNonce(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("c", map[string]any{"read": "public"})
	data := []byte("copied as is")
	bid := e.upload("c", "a", "text/plain", data)
	e.create("c", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	r := e.putBlobHdr(blobPath("c", "b", bid), "nonsense", "", [][2]string{{"Blob-From", blobPath("c", "a", bid)}, {"Blob-Nonce", "short"}})
	expect(t, r, 201)
	expect(t, e.write("PATCH", "c", "b", "", addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), 201)
}

// BBD-24: an upload's body is bytes, never checked as I-JSON, whatever its
// Content-Type (§3.1, §7.8).
func TestV073BlobBodyNotIJSON(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("j", map[string]any{"read": "public"})
	for i, body := range []string{`{"a":1,"a":2}`, "{\"s\":\"\\ud800\"}", "not json at all"} {
		name := "r" + strconv.Itoa(i)
		r, bid := e.putBlob("j", name, "application/json", "", []byte(body))
		expect(t, r, 201)
		e.create("j", name, map[string]any{"b": ref(bid, "application/json", len(body), "")})
		got := e.get(blobPath("j", name, bid))
		expect(t, got, 200)
		if string(got.Body) != body {
			t.Fatalf("served %q, want %q", got.Body, body)
		}
	}
}

// RH-48 (BBD-33): …/blob/{bid}/e/{e} outside sealed namespaces is 404
// not_offered, after the resource's read check, cached as short (§7.1,
// §9).
func TestV073EpochBlobURLNotOffered(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	data := []byte("plain namespace")
	k := newKey("pk")
	e.mkNS("open", map[string]any{"read": "public", "keys": []any{k.entry("read", "create", "append")}})
	w := e.grant(k, "user:w", []string{"open"}, []string{"read", "create", "append"})
	obid := e.upload("open", "a", "text/plain", data, w)
	e.create("open", "a", map[string]any{"b": ref(obid, "text/plain", len(data), "")}, w)
	for _, p := range []string{blobPath("open", "a", obid) + "/e/1", blobPath("open", "a", obid) + "/e/x", blobPath("open", "nothing", obid) + "/e/1"} {
		r := e.get(p)
		expectCode(t, r, 404, "not_offered")
		if cc := r.H.Get("Cache-Control"); cc != ccShort {
			t.Errorf("%s: Cache-Control %q, want %q", p, cc, ccShort)
		}
		expectBlobHeaders(t, r, p)
	}
	// A private namespace: the read check first.
	sbid := e.upload("sec", "a", "text/plain", data, f.issuerG)
	e.create("sec", "a", map[string]any{"b": ref(sbid, "text/plain", len(data), "")}, f.issuerG)
	expectCode(t, e.get(blobPath("sec", "a", sbid)+"/e/1"), 401, "unauthenticated")
	onlyB := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	expectCode(t, e.get(blobPath("sec", "a", sbid)+"/e/1", onlyB), 404, "not_found")
	r := e.get(blobPath("sec", "a", sbid)+"/e/1", f.issuerG)
	expectCode(t, r, 404, "not_offered")
	if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
		t.Errorf("private namespace: Cache-Control %q", cc)
	}
}
