package playground

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

var update = flag.Bool("update", false, "regenerate static/selftest.json (with node on PATH, also its fromJS part)")

func TestHandler(t *testing.T) {
	h := Handler()
	for path, want := range map[string]string{
		"/playground/":              "text/html",
		"/playground/app.js":        "javascript",
		"/playground/seal.js":       "javascript",
		"/playground/app.css":       "text/css",
		"/playground/selftest.json": "application/json",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), want) || rec.Body.Len() == 0 {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		// connect-src stays same-origin; img-src adds blob: for blob previews (§7.8).
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self'") || !strings.Contains(csp, "img-src 'self' data: blob:;") {
			t.Errorf("%s: CSP %q", path, csp)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/playground/" {
		t.Errorf("redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, p := range []string{"/playground/nope", "/playground/tree/", "/playground/tree/cat/roots", "/playground/index/", "/playground/index/demo"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

// TestPage checks that the page stays dependency-free and wires every tab.
func TestPage(t *testing.T) {
	html, err := assets.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="([^"]*)"`).FindAllSubmatch(html, -1) {
		u := string(m[1])
		if !strings.HasPrefix(u, "data:") && (strings.Contains(u, "//") || strings.HasPrefix(u, "/")) {
			t.Errorf("non-relative asset %q", u)
		}
	}
	js, _ := assets.ReadFile("static/app.js")
	for _, tab := range regexp.MustCompile(`data-tab="([a-z]+)"`).FindAllSubmatch(html, -1) {
		if !bytes.Contains(html, []byte(`id="tab-`+string(tab[1])+`"`)) {
			t.Errorf("tab %s has no panel", tab[1])
		}
	}
	for _, want := range []string{`data-tab="cat"`, `data-tab="sr"`, `data-tab="keys"`, `<script src="seal.js"></script>`} {
		if !bytes.Contains(html, []byte(want)) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	// Every element the script looks up by id exists.
	for _, m := range regexp.MustCompile(`\$\('([A-Za-z0-9]+)'\)`).FindAllSubmatch(js, -1) {
		if !bytes.Contains(html, []byte(`id="`+string(m[1])+`"`)) {
			t.Errorf("app.js uses #%s, which index.html lacks", m[1])
		}
	}
	for _, f := range []string{"static/app.js", "static/seal.js"} {
		b, _ := assets.ReadFile(f)
		if bytes.Contains(b, []byte("eval(")) || bytes.Contains(b, []byte("new Function")) || regexp.MustCompile(`(fetch|import|src)\(?\s*['"]https?:`).Match(b) {
			t.Errorf("%s: dynamic code or an external fetch", f)
		}
	}
}

// ---- crypto fixture shared with seal.js ----

type fixture struct {
	Note      string `json:"note"`
	Recipient struct {
		D   string `json:"d"`
		X   string `json:"x"`
		RID string `json:"rid"`
	} `json:"recipient"`
	EpochKey        string          `json:"epochKey"`
	Wrapped         fxWrapped       `json:"wrapped"`
	WrappedResource fxWrapped       `json:"wrappedResource"`
	ResourceKey     fxResourceKey   `json:"resourceKey"`
	JWE             fxJWE           `json:"jwe"`
	JWEZip          fxJWE           `json:"jweZip"`
	JWEPadded       fxJWE           `json:"jwePadded"`
	PadLen          [][2]int        `json:"padLen"`
	Keyring         json.RawMessage `json:"keyring"`
	PatchSet        fxPatchSet      `json:"patchSet"`
	BlobIDs         []fxBlobID      `json:"blobIDs"`
	BlobE3          fxBlob          `json:"blobE3"`
	BlobE3Padded    fxBlob          `json:"blobE3Padded"`
	BlobE2          fxBlob          `json:"blobE2"`
	PatchSetBlobs   fxPatchSet      `json:"patchSetBlobs"`
	FromJS          *fromJS         `json:"fromJS,omitempty"`
}

type fxWrapped struct {
	Kid      string `json:"kid"`
	Resource string `json:"resource,omitempty"`
	Wrapped  string `json:"wrapped"`
	Key      string `json:"key,omitempty"` // fromJS: the key that was wrapped
}

type fxResourceKey struct {
	NS   string `json:"ns"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type fxJWE struct {
	Key       string         `json:"key"`
	Kid       string         `json:"kid"`
	PL        map[string]any `json:"pl"`
	Plaintext string         `json:"plaintext"`
	JWE       string         `json:"jwe"`
}

type fxPatchSet struct {
	NS        string          `json:"ns"`
	Name      string          `json:"name"`
	Parent    string          `json:"parent"`
	Patches   json.RawMessage `json:"patches"`
	PatchSet  json.RawMessage `json:"patchSet"`
	ID        string          `json:"id"`
	Tombstone string          `json:"tombstone,omitempty"`
	Blobs     []string        `json:"blobs,omitempty"` // the declared blob list of the sealed op
}

// fxBlobID is a blob id vector (§3.7).
type fxBlobID struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
	ID    string `json:"id"`
}

// fxBlob is a sealed blob (§E.2.2, §E.3.1). Key is the key it is sealed
// under (K_r at E2, the reference's key at E3); Kid and PL are the E2 header.
type fxBlob struct {
	Key    string         `json:"key"`
	Kid    string         `json:"kid,omitempty"`
	PL     map[string]any `json:"pl,omitempty"`
	Data   string         `json:"data"`
	Sealed string         `json:"sealed"`
	Ref    map[string]any `json:"ref,omitempty"`
}

// fromJS holds outputs of seal.js (run under node) that Go must open.
type fromJS struct {
	Wrapped  fxWrapped       `json:"wrapped"`
	JWE      fxJWE           `json:"jwe"`
	PatchSet fxPatchSet      `json:"patchSet"`
	Padded   fxPatchSet      `json:"patchSetPadded"`
	Blobs    fxPatchSet      `json:"patchSetBlobs"`
	BlobE3   fxBlob          `json:"blobE3"`
	BlobE3Pd fxBlob          `json:"blobE3Padded"`
	BlobE2   fxBlob          `json:"blobE2"`
	Keyring  json.RawMessage `json:"keyring"`
}

const fixturePath = "static/selftest.json"

var b64 = base64.RawURLEncoding

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

func generateFixture(t *testing.T) *fixture {
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{Note: "Known-answer vectors for seal.js, made with internal/seal by `go test ./internal/playground -update`; the playground's self-test and TestSealJSWithNode check seal.js against them, and TestSelfTestFixture checks the fromJS part with internal/seal."}
	f.Recipient.D, f.Recipient.X, f.Recipient.RID = b64.EncodeToString(priv.Bytes()), jwk["x"].(string), seal.RecipientID(priv.PublicKey())
	ke := seal.NewKey()
	f.EpochKey = b64.EncodeToString(ke)
	kid := seal.Kid("fx", 3)
	w, err := seal.WrapKey(priv.PublicKey(), kid, "", ke)
	if err != nil {
		t.Fatal(err)
	}
	f.Wrapped = fxWrapped{Kid: kid, Wrapped: b64.EncodeToString(w.Wrapped)}
	kr, _ := seal.ResourceKey(ke, "fx", "derby")
	f.ResourceKey = fxResourceKey{NS: "fx", Name: "derby", Key: b64.EncodeToString(kr)}
	wr, err := seal.WrapKey(priv.PublicKey(), kid, "derby", kr)
	if err != nil {
		t.Fatal(err)
	}
	f.WrappedResource = fxWrapped{Kid: kid, Resource: "derby", Wrapped: b64.EncodeToString(wr.Wrapped)}
	id1 := ids.Revision(nil, []byte(`[]`)).String()
	pl := seal.ResourcePL("fx", "derby", id1, seal.KindDoc)
	pt := `{"title":"Stockholm derby","ünïcode":"✓"}`
	j, err := seal.Seal(kr, kid, pl, []byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	f.JWE = fxJWE{Key: f.ResourceKey.Key, Kid: kid, PL: pl, Plaintext: pt, JWE: j}
	big := `{"text":"` + strings.Repeat("patch log ", 300) + `"}`
	jz, err := seal.Seal(ke, kid, seal.NamespaceDocPL("fx", id1), []byte(big))
	if err != nil || !strings.Contains(string(mustHeader(t, jz).Raw), `"zip":"DEF"`) {
		t.Fatalf("zip JWE: %v", err)
	}
	f.JWEZip = fxJWE{Key: f.EpochKey, Kid: kid, PL: seal.NamespaceDocPL("fx", id1), Plaintext: big, JWE: jz}
	jp, err := seal.SealPadded(ke, kid, seal.RangePL("fx", "", id1), []byte(big))
	if err != nil {
		t.Fatal(err)
	}
	f.JWEPadded = fxJWE{Key: f.EpochKey, Kid: kid, PL: seal.RangePL("fx", "", id1), Plaintext: big, JWE: jp}
	for _, n := range []int{0, 1, 255, 256, 257, 300, 511, 512, 513, 1000, 1025, 4097, 70000, 1 << 20} {
		f.PadLen = append(f.PadLen, [2]int{n, seal.PadLen(n)})
	}
	ring, err := seal.BuildKeyring("fx", 3, ke, []*ecdh.PublicKey{priv.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	f.Keyring, _ = ring.MarshalJSON()
	patches := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"title": "sealed"}}, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}
	ps, err := seal.SealPatchSet(ke, kid, "fx", "derby", "", jsonv.FromGo(patches))
	if err != nil {
		t.Fatal(err)
	}
	rid := ids.Revision(nil, ps)
	f.PatchSet = fxPatchSet{NS: "fx", Name: "derby", Parent: "", Patches: jsonv.Canonical(jsonv.FromGo(patches)), PatchSet: ps, ID: rid.String(), Tombstone: ids.Tombstone(rid).String()}
	// Blobs: ids, an E3 blob (plain and padded), an E2 blob, and a sealed op declaring blobs.
	blobData := []byte("\x89PNG\r\n\x1a\n blob bytes \x00\x01\xff")
	for _, v := range []struct{ typ, nonce string }{{"image/png", ""}, {"text/plain", seal.NewNonce()}, {"application/octet-stream", ""}} {
		f.BlobIDs = append(f.BlobIDs, fxBlobID{Type: v.typ, Nonce: v.nonce, Data: b64.EncodeToString(blobData), ID: ids.Blob(v.typ, v.nonce, blobData).String()})
	}
	for _, v := range []struct {
		dst *fxBlob
		pad bool
	}{{&f.BlobE3, false}, {&f.BlobE3Padded, true}} {
		sealed, ref, err := client.EncryptBlob("image/png", blobData, v.pad)
		if err != nil {
			t.Fatal(err)
		}
		*v.dst = fxBlob{Key: ref["sealed"].(map[string]any)["key"].(string), Data: b64.EncodeToString(blobData), Sealed: b64.EncodeToString(sealed), Ref: ref}
	}
	bid := ids.Blob("image/png", seal.NewNonce(), blobData).String()
	sb, err := seal.SealBlob(kr, kid, seal.BlobPL("fx", "derby", bid), blobData, false)
	if err != nil {
		t.Fatal(err)
	}
	f.BlobE2 = fxBlob{Key: f.ResourceKey.Key, Kid: kid, PL: seal.BlobPL("fx", "derby", bid), Data: b64.EncodeToString(blobData), Sealed: b64.EncodeToString(sb)}
	bpatches := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"pic": f.BlobE3.Ref}}}
	bps, err := seal.SealPatchSet(ke, kid, "fx", "derby", "", jsonv.FromGo(bpatches))
	if err != nil {
		t.Fatal(err)
	}
	if bps, err = seal.WithBlobs(bps, []string{f.BlobE3.Ref["$blob"].(string)}); err != nil {
		t.Fatal(err)
	}
	f.PatchSetBlobs = fxPatchSet{NS: "fx", Name: "derby", Patches: jsonv.Canonical(jsonv.FromGo(bpatches)), PatchSet: bps, ID: ids.Revision(nil, bps).String(), Blobs: []string{f.BlobE3.Ref["$blob"].(string)}}
	return f
}

func mustHeader(t *testing.T, jwe string) *seal.Header {
	t.Helper()
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func readFixture(t *testing.T) *fixture {
	t.Helper()
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func writeFixture(t *testing.T, f *fixture) {
	t.Helper()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func recipientOf(t *testing.T, f *fixture) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(unb64(t, f.Recipient.D))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestSelfTestFixture checks static/selftest.json with internal/seal: the
// Go-made vectors are consistent, and everything seal.js produced (fromJS)
// opens in Go.
func TestSelfTestFixture(t *testing.T) {
	if *update {
		f := generateFixture(t)
		writeFixture(t, f)
		if node, err := exec.LookPath("node"); err == nil {
			out := runNode(t, node)
			f.FromJS = &out.FromJS
			writeFixture(t, f)
		} else {
			t.Log("node not found: fromJS was not regenerated")
		}
	}
	f := readFixture(t)
	priv := recipientOf(t, f)
	if b64.EncodeToString(priv.PublicKey().Bytes()) != f.Recipient.X || seal.RecipientID(priv.PublicKey()) != f.Recipient.RID {
		t.Fatal("recipient")
	}
	ke := unb64(t, f.EpochKey)
	k, err := seal.UnwrapKey(priv, seal.WrappedKey{Kid: f.Wrapped.Kid, Wrapped: unb64(t, f.Wrapped.Wrapped)})
	if err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("unwrap: %v", err)
	}
	kr, _ := seal.ResourceKey(ke, f.ResourceKey.NS, f.ResourceKey.Name)
	if b64.EncodeToString(kr) != f.ResourceKey.Key {
		t.Fatal("resource key")
	}
	if pt, err := seal.OpenExpect(f.JWE.JWE, unb64(t, f.JWE.Key), f.JWE.Kid, seal.PL(f.JWE.PL)); err != nil || string(pt) != f.JWE.Plaintext {
		t.Fatalf("jwe: %v", err)
	}
	if pt, err := seal.OpenExpect(f.JWEZip.JWE, unb64(t, f.JWEZip.Key), f.JWEZip.Kid, seal.PL(f.JWEZip.PL)); err != nil || string(pt) != f.JWEZip.Plaintext {
		t.Fatalf("zip jwe: %v", err)
	}
	if h, pt, err := seal.Open(f.JWEPadded.JWE, unb64(t, f.JWEPadded.Key)); err != nil || !seal.IsPadded(h, pt) || strings.TrimRight(string(pt), " ") != f.JWEPadded.Plaintext {
		t.Fatalf("padded jwe: %v", err)
	}
	for _, p := range f.PadLen {
		if seal.PadLen(p[0]) != p[1] {
			t.Fatalf("PadLen(%d) = %d, fixture %d", p[0], seal.PadLen(p[0]), p[1])
		}
	}
	ring, err := seal.ParseKeyring([]byte(f.Keyring))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := ring.EpochKey(priv, ring.Current); err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("keyring: %v", err)
	}
	checkPatchSet(t, f.PatchSet, ke)
	checkPatchSet(t, f.PatchSetBlobs, ke)
	for _, b := range f.BlobIDs {
		if got := ids.Blob(b.Type, b.Nonce, unb64(t, b.Data)).String(); got != b.ID {
			t.Fatalf("blob id %s %q = %s, fixture %s", b.Type, b.Nonce, got, b.ID)
		}
	}
	checkBlob(t, f.BlobE3)
	checkBlob(t, f.BlobE3Padded)
	checkBlob(t, f.BlobE2)

	if f.FromJS == nil {
		t.Fatal("the fixture has no fromJS part; regenerate with node on PATH: go test ./internal/playground -run TestSelfTestFixture -update")
	}
	checkFromJS(t, f, priv, f.FromJS)
}

// checkBlob opens a sealed blob in Go and checks its header and bytes. At
// E3 (no kid) it also checks the blob against its reference.
func checkBlob(t *testing.T, b fxBlob) {
	t.Helper()
	sealed := unb64(t, b.Sealed)
	h, data, err := seal.OpenBlob(sealed, unb64(t, b.Key))
	if err != nil || !bytes.Equal(data, unb64(t, b.Data)) {
		t.Fatalf("open blob: %v", err)
	}
	if b.Kid == "" {
		if h.Kid != "" || h.PL != nil || string(h.Raw) != `{"enc":"A256GCM"}` {
			t.Fatalf("e3 blob header %s", h.Raw)
		}
	} else if err := h.Expect(b.Kid, seal.PL(b.PL)); err != nil {
		t.Fatalf("e2 blob header %s: %v", h.Raw, err)
	}
	if b.Ref != nil {
		if _, err := client.DecryptBlob(b.Ref, sealed); err != nil {
			t.Fatalf("DecryptBlob: %v", err)
		}
	}
}

func checkPatchSet(t *testing.T, p fxPatchSet, ke []byte) {
	t.Helper()
	if _, declared, ok := seal.SealedOp([]byte(p.PatchSet)); !ok || strings.Join(declared, ",") != strings.Join(p.Blobs, ",") {
		t.Fatalf("declared blobs %v, want %v", declared, p.Blobs)
	}
	var parent *ids.ID
	if p.Parent != "" {
		pid, err := ids.Parse(p.Parent)
		if err != nil {
			t.Fatal(err)
		}
		parent = &pid
	}
	if got := ids.Revision(parent, jsonv.Canonical(mustParse(t, p.PatchSet))).String(); got != p.ID {
		t.Fatalf("patch set id %s, want %s", got, p.ID)
	}
	h := mustHeader(t, mustSealedJWE(t, p.PatchSet))
	got, err := seal.OpenPatchSet([]byte(p.PatchSet), ke, h.Kid, p.NS, p.Name, p.Parent)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonv.Equal(got, mustParse(t, p.Patches)) {
		t.Fatalf("patches %v", got)
	}
}

func mustParse(t *testing.T, b []byte) any {
	t.Helper()
	v, err := jsonv.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustSealedJWE(t *testing.T, ps []byte) string {
	t.Helper()
	j, ok := seal.SealedJWE(ps)
	if !ok {
		t.Fatalf("not a sealed patch set: %s", ps)
	}
	return j
}

func checkFromJS(t *testing.T, f *fixture, priv *ecdh.PrivateKey, js *fromJS) {
	t.Helper()
	k, err := seal.UnwrapKey(priv, seal.WrappedKey{Kid: js.Wrapped.Kid, Resource: js.Wrapped.Resource, Wrapped: unb64(t, js.Wrapped.Wrapped)})
	if err != nil || b64.EncodeToString(k) != js.Wrapped.Key {
		t.Fatalf("JS-wrapped key: %v", err)
	}
	if pt, err := seal.OpenExpect(js.JWE.JWE, unb64(t, js.JWE.Key), js.JWE.Kid, seal.PL(js.JWE.PL)); err != nil || string(pt) != js.JWE.Plaintext {
		t.Fatalf("JS JWE: %v %q", err, pt)
	}
	checkPatchSet(t, js.PatchSet, unb64(t, f.EpochKey))
	checkPatchSet(t, js.Padded, unb64(t, f.EpochKey))
	checkPatchSet(t, js.Blobs, unb64(t, f.EpochKey))
	checkBlob(t, js.BlobE3)
	checkBlob(t, js.BlobE3Pd)
	checkBlob(t, js.BlobE2)
	h := mustHeader(t, mustSealedJWE(t, js.Padded.PatchSet))
	if _, padded, err := seal.OpenPatchSetPadded([]byte(js.Padded.PatchSet), unb64(t, f.EpochKey), h.Kid, js.Padded.NS, js.Padded.Name, js.Padded.Parent); err != nil || !padded {
		t.Fatalf("JS padded patch set: padded %v, %v", padded, err)
	}
	ring, err := seal.ParseKeyring([]byte(js.Keyring))
	if err != nil {
		t.Fatalf("JS keyring: %v", err)
	}
	if k, err := ring.EpochKey(priv, ring.Current); err != nil || !bytes.Equal(k, unb64(t, f.EpochKey)) {
		t.Fatalf("JS keyring epoch key: %v", err)
	}
}

// nodeHarness runs seal.js's self-test against the fixture and prints
// fresh seal.js outputs for Go to open.
const nodeHarness = `
const fs = require('fs');
require(process.argv[2]);
const S = globalThis.PLSeal;
const fx = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
(async () => {
  const selfTest = await S.selfTest(fx);
  const ke = S.unb64u(fx.epochKey);
  const key = S.randomBytes(32);
  const wrapped = await S.wrapKey(fx.recipient.x, 'fx#7', 'derby', key);
  const jweKey = S.randomBytes(32);
  const pl = { ns: 'fx', name: 'derby', id: fx.patchSet.id, kind: 'doc' };
  const plaintext = JSON.stringify({ title: 'sealed by seal.js', 'ünïcode': '✓' });
  const jwe = await S.sealJWE(jweKey, 'fx#7', pl, plaintext);
  const patches = [{ op: 'replace', path: '/title', value: 'from JS ✓' }, { op: 'add', path: '/$nonce', value: S.newNonce() }];
  const ps = await S.sealPatchSet(ke, 'fx#3', 'fx', 'derby', fx.patchSet.id, patches);
  const pps = await S.sealPatchSet(ke, 'fx#3', 'fx', 'derby', '', patches, true);
  const blobData = S.unb64u(fx.blobE3.data);
  const e3 = await S.encryptBlob('image/png', blobData, false);
  const e3p = await S.encryptBlob('image/png', blobData, true);
  const e2pl = { ns: 'fx', name: 'derby', blob: await S.blobID('image/png', 'abcdefghijklmnopqrstuvwxyz', blobData) };
  const e2 = await S.sealBlob(S.unb64u(fx.resourceKey.key), 'fx#3', e2pl, blobData, false);
  const asBlob = (x) => ({ key: x.ref.sealed.key, data: S.b64u(blobData), sealed: S.b64u(x.sealed), ref: x.ref });
  const bpatches = [{ op: 'add', path: '', value: { pic: e3.ref } }];
  const bps = await S.sealPatchSet(ke, 'fx#3', 'fx', 'derby', '', bpatches, false, S.blobIDs({ pic: e3.ref }));
  const kr = S.buildKeyring('fx', 3);
  await S.keyringAdd(kr, fx.recipient.x, 3, ke);
  process.stdout.write(JSON.stringify({ selfTest, fromJS: {
    wrapped: { kid: 'fx#7', resource: 'derby', wrapped: S.b64u(wrapped), key: S.b64u(key) },
    jwe: { key: S.b64u(jweKey), kid: 'fx#7', pl, plaintext, jwe },
    patchSet: { ns: 'fx', name: 'derby', parent: fx.patchSet.id, patches, patchSet: ps, id: await S.revisionID(fx.patchSet.id, ps) },
    patchSetPadded: { ns: 'fx', name: 'derby', parent: '', patches, patchSet: pps, id: await S.revisionID('', pps) },
    patchSetBlobs: { ns: 'fx', name: 'derby', parent: '', patches: bpatches, patchSet: bps, id: await S.revisionID('', bps), blobs: S.blobIDs({ pic: e3.ref }) },
    blobE3: asBlob(e3), blobE3Padded: asBlob(e3p),
    blobE2: { key: fx.resourceKey.key, kid: 'fx#3', pl: e2pl, data: S.b64u(blobData), sealed: S.b64u(e2) },
    keyring: kr } }));
})().catch((e) => { console.error(e); process.exit(1); });
`

type nodeOut struct {
	SelfTest []struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	} `json:"selfTest"`
	FromJS fromJS `json:"fromJS"`
}

func runNode(t *testing.T, node string) *nodeOut {
	t.Helper()
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(nodeHarness), 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	fx, _ := filepath.Abs(fixturePath)
	cmd := exec.Command(node, h, sealJS, fx)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var out nodeOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output: %v\n%s", err, b)
	}
	return &out
}

// TestSealJSWithNode runs seal.js under node, when it is installed: its
// self-test must pass against the Go-made fixture, and what it seals must
// open in Go. There is no build step; node is only a test runner here.
func TestSealJSWithNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	f := readFixture(t)
	out := runNode(t, node)
	if len(out.SelfTest) < 10 {
		t.Fatalf("self-test ran %d checks", len(out.SelfTest))
	}
	for _, c := range out.SelfTest {
		if !c.OK {
			t.Errorf("seal.js self-test %q: %s", c.Name, c.Detail)
		}
	}
	checkFromJS(t, f, recipientOf(t, f), &out.FromJS)
}
