package server

import (
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
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
// a frozen namespace, and for a copy before its bid and source checks
// (§7.2, §7.8, §12.1).
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

	// A copy: 428 before the bid and source checks (v0.74, §7.8 Copying).
	expect(t, e.putBlobAs("p", "a", bid, "text/plain", "", data), 201)
	e.create("p", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	from := [2]string{"Blob-From", path}
	expectCode(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{from, {"If-None-Match", "*"}}), 428, "precondition_required")
	expectCode(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{{"Blob-From", blobPath("p", "none", bid)}, {"If-None-Match", "*"}}), 428, "precondition_required")
	expectCode(t, e.putBlobHdr(blobPath("p", "c", bid), "", "", [][2]string{{"Blob-From", blobPath("p", "none", bid)}}), 404, "not_found")
	other := blobID("text/plain", "", []byte("other"))
	expectCode(t, e.putBlobHdr(blobPath("p", "c", other), "", "", [][2]string{from, {"If-None-Match", "*"}}), 428, "precondition_required")
	expectCode(t, e.putBlobHdr(blobPath("p", "c", other), "", "", [][2]string{from}), 422, "blob")
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
// §9); a purged resource's is 410 first, as its other URLs (§8.3).
func TestV073EpochBlobURLNotOffered(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	data := []byte("plain namespace")
	k := newKey("pk")
	e.mkNS("open", map[string]any{"read": "public", "keys": []any{k.entry("read", "create", "append", "purge")}})
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

	// A purged resource: 410 before not_offered, once the caller passes
	// the read check (§8.3), as its blob URL and document URL answer.
	purger := e.grant(k, "user:p", []string{"open"}, []string{"read", "purge"})
	pbid := e.upload("open", "p", "text/plain", data, w)
	ph := e.create("open", "p", map[string]any{"b": ref(pbid, "text/plain", len(data), "")}, w)
	expect(t, e.do(req{method: "POST", path: "/r/open/p/purge", ifMatch: ph, bearer: purger}), 204)
	for _, p := range []string{blobPath("open", "p", pbid), blobPath("open", "p", pbid) + "/e/1", "/r/open/p"} {
		expect(t, e.get(p), 410)
	}
	spbid := e.upload("sec", "p", "text/plain", data, f.issuerG)
	sh := e.create("sec", "p", map[string]any{"b": ref(spbid, "text/plain", len(data), "")}, f.issuerG)
	expect(t, e.do(req{method: "POST", path: "/r/sec/p/purge", ifMatch: sh, bearer: f.adminG}), 204)
	expectCode(t, e.get(blobPath("sec", "p", spbid)+"/e/1"), 401, "unauthenticated")
	expectCode(t, e.get(blobPath("sec", "p", spbid)+"/e/1", onlyB), 404, "not_found")
	expect(t, e.get(blobPath("sec", "p", spbid)+"/e/1", f.issuerG), 410)
}

// protectionEnv is an authenticated deployment with sealed namespaces, and
// a key k every namespace it makes lists as a "*" key, so one grant may
// name several (§C.4).
type protectionEnv struct {
	*tenv
	k    keyPair
	long map[string]any
	// star may write, read and change the configuration of every
	// namespace made; nbf0 is a block member from before the first epoch.
	star string
	nbf0 map[string]any
	all  []string
}

func newProtectionEnv(t *testing.T, nss map[string]map[string]any) *protectionEnv {
	e := newSealedAuthEnv(t, withBlobTuning)
	p := &protectionEnv{tenv: e, k: newKey("k"), long: map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339)}}
	for _, ns := range sortedNames(nss) {
		doc := nss[ns]
		doc["keys"] = []any{p.k.entry("*")}
		e.mkNS(ns, doc)
		p.all = append(p.all, ns)
	}
	p.star = e.grant(p.k, "user:admin", p.all, []string{"create", "append", "read", "config"}, p.long)
	p.nbf0 = map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339), "nbf": t0.Add(-time.Hour).Format(time.RFC3339)}
	return p
}

func sortedNames(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// blobIn uploads data to ns/name and writes a document referencing it,
// with a fresh $nonce, under the star grant.
func (p *protectionEnv) blobIn(ns, name string, data []byte) string {
	p.t.Helper()
	bid := p.upload(ns, name, "text/plain", data, p.star)
	p.wr(ns, name, "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), p.star)
	return bid
}

// rotate starts the next epoch of sealed namespace ns an hour later.
func (p *protectionEnv) rotate(ns string, epoch float64) {
	p.t.Helper()
	p.clock.Advance(time.Hour)
	expect(p.t, p.patchNS(ns, ops(op("add", "/encryption/epoch", epoch)), p.star), 201)
}

// CIS-28 (BBD-28, ENC-31): as a source a sealed namespace ranks sealed
// (= private) whatever its read; as a target, one whose read is public
// ranks public. A copy into another namespace that ranks lower is 404;
// ranks don't apply within one namespace (§2.1 Protection, §7.8 Copying;
// security scenarios Protection 2, 3 and 4).
func TestV073CopyRanks(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{
		"priv":  {"read": "grant"},
		"priv2": {"read": "grant"},
		"pub":   {"read": "public"},
		"spub":  sealedDoc(map[string]any{"read": "public"}),
		"spriv": sealedDoc(map[string]any{"read": "grant"}),
	})
	data := []byte("ranked bytes")
	bid := p.blobIn("priv", "a", data)
	from := blobPath("priv", "a", bid)
	// Scenario 2: private source, sealed target with read public.
	expectCode(t, p.copyBlob("spub", "a", bid, from, "", p.star), 404, "not_found")
	// Equal ranks and upward work: private = sealed.
	expect(t, p.copyBlob("priv2", "a", bid, from, "", p.star), 201)
	expect(t, p.copyBlob("spriv", "a", bid, from, "", p.star), 201)
	// Public into sealed public: equal ranks.
	pbid := p.blobIn("pub", "a", []byte("public bytes"))
	expect(t, p.copyBlob("spub", "a", pbid, blobPath("pub", "a", pbid), "", p.star), 201)

	// Scenario 3: a sealed source with read public ranks sealed: not into a
	// plain public namespace, nor another sealed public one; into a sealed
	// private one it may.
	sbid := p.blobIn("spub", "s", []byte("sealed public bytes"))
	sfrom := blobPath("spub", "s", sbid)
	expectCode(t, p.copyBlob("pub", "s", sbid, sfrom, "", p.star), 404, "not_found")
	expect(t, p.copyBlob("spriv", "s", sbid, sfrom, "", p.star), 201)
	expect(t, p.copyBlob("priv", "s", sbid, sfrom, "", p.star), 201)
	// Scenario 4: within the sealed public namespace, ranks don't apply.
	expect(t, p.copyBlob("spub", "t", sbid, sfrom, "", p.star), 201)
}

// BBD-29: a copy from a sealed source, public or not, within one namespace
// too, takes only a blob that opens under an epoch it is served under
// there, with keys §E.2.3 gives the request's own grant or one in
// Source-Authorization; otherwise 404 (§2.1 Protection, §7.8 Copying;
// security scenarios Protection 4, 21 and 23).
func TestV073CopySealedKeyWindow(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{
		"priv":  {"read": "grant"},
		"spub":  sealedDoc(map[string]any{"read": "public"}),
		"spriv": sealedDoc(map[string]any{"read": "grant"}),
	})
	bid := p.blobIn("spub", "a", []byte("public sealed bytes"))
	from := blobPath("spub", "a", bid)
	// Scenario 21: a writer elsewhere with no grant for the public sealed
	// source gets no keys: 404, though anyone may read it.
	w := p.grant(p.k, "user:w", []string{"priv"}, []string{"read", "create", "append"}, p.long)
	expectCode(t, p.copyBlob("priv", "x", bid, from, "", w), 404, "not_found")
	// One whose grant also names the source with read gets K_e.
	wr := p.grant(p.k, "user:w", []string{"priv", "spub"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.copyBlob("priv", "x", bid, from, "", wr), 201)
	// Or with Source-Authorization.
	src := p.grant(p.k, "user:w", []string{"spub"}, []string{"read"}, p.long)
	expect(t, p.copyBlob("priv", "y", bid, from, src, w), 201)
	// Scenario 4: within the sealed public namespace, a writer without
	// read gets no keys.
	wo := p.grant(p.k, "user:w", []string{"spub"}, []string{"create", "append"}, p.long)
	expectCode(t, p.copyBlob("spub", "b", bid, from, "", wo), 404, "not_found")
	expect(t, p.copyBlob("spub", "b", bid, from, "", wr), 201)
	// A grant whose rules fix /resource gets K_r of the names it fixes.
	fixA := p.grant(p.k, "user:w", []string{"spub", "priv"}, []string{"read", "create", "append"}, p.long, map[string]any{"rules": []any{map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": []any{"a", "z"}}}}})
	expect(t, p.copyBlob("priv", "z", bid, from, "", fixA), 201)

	// Scenario 23: a sealed private source whose blob is served under
	// epoch 1 only; once the epoch is 2, a grant without nbf gets the
	// current epoch's keys alone, and the copy is 404. One whose nbf
	// reaches back to epoch 1 gets that epoch's too.
	gbid := p.blobIn("spriv", "a", []byte("sealed private bytes"))
	gfrom := blobPath("spriv", "a", gbid)
	reader := p.grant(p.k, "user:r", []string{"spriv", "priv"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.copyBlob("priv", "g1", gbid, gfrom, "", reader), 201)
	p.rotate("spriv", 2)
	reader = p.grant(p.k, "user:r", []string{"spriv", "priv"}, []string{"read", "create", "append"}, p.long)
	expectCode(t, p.copyBlob("priv", "g2", gbid, gfrom, "", reader), 404, "not_found")
	early := p.grant(p.k, "user:r", []string{"spriv", "priv"}, []string{"read", "create", "append"}, p.nbf0)
	expect(t, p.copyBlob("priv", "g2", gbid, gfrom, "", early), 201)
	// A revision written now references it too: served under epoch 2 as
	// well, so the grant without nbf opens it.
	h := p.head("spriv", "a", p.star)
	p.wr("spriv", "a", h, withNonce(ops(op("add", "/again", true))), p.star)
	expect(t, p.copyBlob("priv", "g3", gbid, gfrom, "", reader), 201)
}

// BBD-30: a batch's local source from a sealed source.ns makes available
// only the blobs the caller's keys open under a served epoch; the others
// are 422 blob (§2.1 Protection, §7.8 Availability; security scenario
// Protection 22).
func TestV073SourceSealedKeyWindow(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{
		"priv": {"read": "grant"},
		"spub": sealedDoc(map[string]any{"read": "public"}),
	})
	data := []byte("source bytes")
	bid := p.blobIn("spub", "a", data)
	at := p.nsHead("spub", p.star)
	batch := func(bearer, srcGrant string) *resp {
		item := map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})}}
		q := req{method: "POST", path: "/ns/priv/batch", bearer: bearer, body: map[string]any{"items": []any{item}, "source": map[string]any{"ns": "spub", "at": at}}}
		if srcGrant != "" {
			q.hdr = map[string]string{"Source-Authorization": "Bearer " + srcGrant}
		}
		return p.do(q)
	}
	// Anyone reads the public source unrestricted, so source.at is
	// checked; without keys, its blob isn't made available.
	w := p.grant(p.k, "user:w", []string{"priv"}, []string{"read", "create", "append"}, p.long)
	r := batch(w, "")
	expectCode(t, r, 422, "batch")
	if !strings.Contains(r.String(), `"blob"`) {
		t.Fatalf("want an item refused with blob: %s", r.Body)
	}
	// With keys, from Source-Authorization or the grant itself.
	expect(t, batch(w, p.grant(p.k, "user:w", []string{"spub"}, []string{"read"}, p.long)), 201)
}

// CIS-23: resolving a schema from a sealed namespace, public or not, takes
// keys §E.2.3 gives for the epoch the revision is served under, to the
// request's grant or one in Source-Authorization, in the namespace written
// too; without them it is 422 schema_unavailable (§6.1 Read permission;
// security scenario Protection 36).
func TestV073SchemaSealedKeyWindow(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{
		"docs":    {"read": "grant"},
		"schemas": sealedDoc(map[string]any{"read": "public"}),
	})
	x := p.wr("schemas", "match", "", withNonce(addRoot(map[string]any{"$schema": dialect, "type": "object", "required": []any{"n"}})), p.star)
	path := "/r/schemas/match/rev/" + x
	doc := map[string]any{"$schema": path, "n": 1.0}
	// No grant for schemas: no keys, though it is public.
	w := p.grant(p.k, "user:w", []string{"docs"}, []string{"read", "create", "append"}, p.long)
	r := p.write("PATCH", "docs", "d", "", addRoot(doc), w)
	expectCode(t, r, 422, "schema_unavailable")
	if r.Str("path") != path && r.Str("ref") != path {
		t.Fatalf("names %s: %s", path, r.Body)
	}
	// With keys for X's epoch: resolves, and validates.
	wk := p.grant(p.k, "user:w", []string{"docs", "schemas"}, []string{"read", "create", "append"}, p.long)
	expectCode(t, p.write("PATCH", "docs", "bad", "", addRoot(map[string]any{"$schema": path}), wk), 422, "invalid")
	expect(t, p.write("PATCH", "docs", "d", "", addRoot(doc), wk), 201)
	// Once the epoch moved on, a grant whose window starts after X's epoch
	// gets no key for it: in the namespace written too.
	p.rotate("schemas", 2)
	wk = p.grant(p.k, "user:w", []string{"docs", "schemas"}, []string{"read", "create", "append"}, p.long)
	expectCode(t, p.write("PATCH", "docs", "e", "", addRoot(doc), wk), 422, "schema_unavailable")
	expectCode(t, p.write("PATCH", "schemas", "e", "", withNonce(addRoot(doc)), wk), 422, "schema_unavailable")
	early := p.grant(p.k, "user:w", []string{"docs", "schemas"}, []string{"read", "create", "append"}, p.nbf0)
	expect(t, p.write("PATCH", "docs", "e", "", addRoot(doc), early), 201)
	expect(t, p.write("PATCH", "schemas", "e", "", withNonce(addRoot(doc)), early), 201)
	// Source-Authorization serves as well.
	q := req{method: "PATCH", path: "/r/docs/f", ifNoneMatch: "*", body: addRoot(doc), bearer: w,
		hdr: map[string]string{"Source-Authorization": "Bearer " + p.grant(p.k, "user:w", []string{"schemas"}, []string{"read"}, p.nbf0)}}
	expect(t, p.do(q), 201)
}

// CIS-20: 422 schema_unavailable names the revision path that didn't
// resolve as path; ref carries it too, for one release (§6.1, §12.1).
func TestV073SchemaUnavailablePath(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("n", map[string]any{"read": "public"})
	unknown := "/r/n/s/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	r := e.write("PATCH", "n", "d", "", addRoot(map[string]any{"$schema": unknown}))
	expectCode(t, r, 422, "schema_unavailable")
	if r.Str("path") != unknown || r.Str("ref") != unknown {
		t.Fatalf("path %q, ref %q; want %s: %s", r.Str("path"), r.Str("ref"), unknown, r.Body)
	}
	// In a schema's $ref closure: the revision that didn't resolve, not
	// the dialect.
	r = e.write("PATCH", "n", "s2", "", addRoot(map[string]any{"$schema": dialect, "$ref": unknown}))
	expectCode(t, r, 422, "schema_unavailable")
	if r.Str("path") != unknown {
		t.Fatalf("closure: path %q: %s", r.Str("path"), r.Body)
	}
	// A batch item carries it too.
	item := map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"$schema": unknown})}}
	r = e.do(req{method: "POST", path: "/ns/n/batch", author: "alice", body: map[string]any{"items": []any{item}}})
	expectCode(t, r, 422, "batch")
	items, _ := r.Obj()["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["path"] != unknown {
		t.Fatalf("batch item: %s", r.Body)
	}
}

// CIS-22: a $schema or $ref path naming a branch is 422 schema_ref only for
// a writer who can read the revision there; for any other, or for a
// revision the branch doesn't hold, it is schema_unavailable, as for a
// namespace that doesn't exist (§6.1 Never into a branch).
func TestV073SchemaBranchPathUnreadable(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k := newKey("k")
	e.mkNS("main", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.mkNS("docs", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	star := e.grant(k, "user:admin", []string{"main", "main-b", "docs"}, allVerbs)
	expect(t, e.branch("main", map[string]any{"name": "main-b"}, star), 201)
	x := e.create("main-b", "s", map[string]any{"$schema": dialect, "type": "object"}, star)
	path := "/r/main-b/s/rev/" + x
	unknown := "/r/main-b/s/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nowhere := "/r/nothing/s/rev/" + x

	w := e.grant(k, "user:w", []string{"docs"}, []string{"read", "create", "append"})
	r := e.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": path}), w)
	expectCode(t, r, 422, "schema_unavailable")
	if r.Str("path") != path {
		t.Fatalf("path %q: %s", r.Str("path"), r.Body)
	}
	// The same answer as for a namespace that doesn't exist.
	r2 := e.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": nowhere}), w)
	expectCode(t, r2, 422, "schema_unavailable")
	// In a schema's $ref too.
	expectCode(t, e.write("PATCH", "docs", "s", "", addRoot(map[string]any{"$schema": dialect, "$ref": path}), w), 422, "schema_unavailable")
	// A grant reading the branch, but not that resource, can't read it.
	only := e.grant(k, "user:w", []string{"docs", "main-b"}, []string{"read", "create", "append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "d"}}})
	expectCode(t, e.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": path}), only), 422, "schema_unavailable")

	// A writer who reads it there learns it is a branch: schema_ref.
	wr := e.grant(k, "user:w", []string{"docs", "main-b"}, []string{"read", "create", "append"})
	expectCode(t, e.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": path}), wr), 422, "schema_ref")
	expectCode(t, e.write("PATCH", "docs", "s", "", addRoot(map[string]any{"$schema": dialect, "$ref": path}), wr), 422, "schema_ref")
	// In a write to the branch itself, with the write's own grant.
	expectCode(t, e.write("PATCH", "main-b", "d", "", addRoot(map[string]any{"$schema": path}), wr), 422, "schema_ref")
	// A revision the branch doesn't hold doesn't resolve.
	expectCode(t, e.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": unknown}), wr), 422, "schema_unavailable")
}

// CIS-27: schemaReads.for is never matched against a branch. A write to a
// branch qualifies only through the namespace at the root of its local
// bases, and referrers count only in listed namespaces that aren't
// branches (§6.1 Schemas follow their documents, §2.1 Referrer).
func TestV073SchemaReadsNeverBranches(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, pk := newKey("sk"), newKey("pk")
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{sk.entry("*"), pk.entry("read")},
		"schemaReads": map[string]any{"for": []any{"content*", "rel"}}})
	e.mkNS("plain", map[string]any{"read": "grant", "keys": []any{pk.entry("*")}})
	e.mkNS("content", map[string]any{"read": "grant", "keys": []any{pk.entry("*")}})
	sg := e.grant(sk, "user:admin", []string{"schemas"}, allVerbs)
	s := e.create("schemas", "s", map[string]any{"$schema": dialect, "type": "object"}, sg)
	sRef := "/r/schemas/s/rev/" + s
	pg := e.grant(pk, "user:admin", []string{"plain", "content-x", "rel", "content", "content-y"}, allVerbs)
	for _, b := range [][2]string{{"plain", "content-x"}, {"plain", "rel"}, {"content", "content-y"}} {
		expect(t, e.branch(b[0], map[string]any{"name": b[1]}, pg), 201)
	}
	w := e.grant(pk, "user:w", []string{"plain", "content-x", "rel", "content", "content-y"}, []string{"read", "create", "append"})
	// Branches of an unlisted base whose names match the list, by prefix
	// or exactly, don't resolve it without read on schemas.
	for _, ns := range []string{"content-x", "rel", "plain"} {
		expectCode(t, e.write("PATCH", ns, "d", "", addRoot(map[string]any{"$schema": sRef}), w), 422, "schema_unavailable")
	}
	// A listed namespace and its branch do.
	expect(t, e.write("PATCH", "content", "d", "", addRoot(map[string]any{"$schema": sRef}), w), 201)
	expect(t, e.write("PATCH", "content-y", "e", "", addRoot(map[string]any{"$schema": sRef}), w), 201)

	// Referrers: a document of content-x pinning the revision, written by
	// one who may read schemas, doesn't open it to content-x's readers;
	// content's does.
	sr := e.grant(pk, "user:w", []string{"schemas"}, []string{"read"})
	expect(t, e.do(req{method: "PATCH", path: "/r/content-x/pin", ifNoneMatch: "*", body: addRoot(map[string]any{"$schema": sRef}), bearer: w,
		hdr: map[string]string{"Source-Authorization": "Bearer " + sr}}), 201)
	xr := e.grant(pk, "user:xr", []string{"content-x"}, []string{"read"})
	expectCode(t, e.get(sRef, xr), 403, "forbidden")
	cr := e.grant(pk, "user:cr", []string{"content"}, []string{"read"})
	expect(t, e.get(sRef, cr), 200)
	// content-y reads content's documents through; its own count for
	// nothing, but the grant also names content.
	yr := e.grant(pk, "user:yr", []string{"content-y"}, []string{"read"})
	expectCode(t, e.get(sRef, yr), 403, "forbidden")
}
