package playground

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// legacyZipJWE seals plaintext as JWEs were sealed before v0.65 when they
// were compressed: raw DEFLATE under the protected header canonical({alg,
// enc, kid, pl, zip: "DEF"}) (RFC 7516 §5.1). Seal never compresses now
// (§E.2.2), but readers still open such stored bytes.
func legacyZipJWE(key []byte, kid string, pl seal.PL, plaintext []byte) (string, error) {
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	w.Write(plaintext)
	w.Close()
	hdr := map[string]any{"alg": seal.AlgDir, "enc": seal.EncA256GCM, "kid": kid, "pl": map[string]any(pl), "zip": seal.ZipDeflate}
	protected := b64.EncodeToString(jsonv.Canonical(hdr))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	out := gcm.Seal(nil, iv, z.Bytes(), []byte(protected))
	ct, tag := out[:len(out)-gcm.Overhead()], out[len(out)-gcm.Overhead():]
	return protected + ".." + b64.EncodeToString(iv) + "." + b64.EncodeToString(ct) + "." + b64.EncodeToString(tag), nil
}

// nsDocHarness runs app.js's nsHeadDoc (with nsDocPL, openSealed and
// decrypted) for each case of the input, with the browser stubbed: api()
// answers GET /ns/{ns} with the case's sealed namespace document, and
// contentKey() with the key.
const nsDocHarness = `
const fs = require('fs');
const [sealJS, inJSON] = process.argv.slice(2);
require(sealJS);
const Z = globalThis.PLSeal;
const input = JSON.parse(fs.readFileSync(inJSON, 'utf8'));
let c = null;
function renderEntry() {}
async function contentKey() { return Z.unb64u(input.key); }
async function api() {
  return { status: 200, jose: true, text: c.jwe, entry: {}, etag: () => c.head, hdr: () => '', finalPath: '/ns/' + c.ns + '/rev/' + c.head };
}
FUNCTIONS
(async () => {
  const out = [];
  for (c of input.cases) {
    const d = await nsHeadDoc(c.ns);
    out.push({ doc: d.doc, sealed: d.sealed });
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// ENC-1: a sealed namespace document is bound to pl {ns, id, kind: "doc"}
// (§E.2.2), and bytes sealed before v0.63 to kind "config". The catalog
// tab reads namespace documents through nsHeadDoc, which opens both, like
// refreshNS (both take nsDocPL), and nothing else.
func TestNSHeadDocPLWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"nsDocPL", "openSealed", "decrypted", "nsHeadDoc"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	key := seal.NewKey()
	doc := []byte(`{"catalog":{"trust":["content"]}}`)
	type nsCase struct {
		NS   string `json:"ns"`
		Head string `json:"head"`
		JWE  string `json:"jwe"`
	}
	sealed := func(ns, head string, pl seal.PL) nsCase {
		jwe, err := seal.Seal(key, ns+"#1", pl, doc)
		if err != nil {
			t.Fatal(err)
		}
		return nsCase{ns, head, jwe}
	}
	cases := []nsCase{
		sealed("cat", "1abc", seal.NamespaceDocPL("cat", "1abc")),                            // v0.63: kind "doc"
		sealed("cat", "1abc", seal.PL{"ns": "cat", "id": "1abc", "kind": seal.KindConfig}),   // stored before v0.63
		sealed("cat", "1abc", seal.PL{"ns": "cat", "id": "1abc", "kind": seal.KindSnapshot}), // another payload's kind
		sealed("cat", "1abc", seal.NamespaceDocPL("cat", "1abd")),                            // another revision
	}
	want := []bool{true, true, false, false}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(nsDocHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"key": b64.EncodeToString(key), "cases": cases})
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	out, err := exec.Command(node, h, sealJS, inPath).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got []struct {
		Doc    map[string]any `json:"doc"`
		Sealed bool           `json:"sealed"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("node output %s: %v", out, err)
	}
	for i, g := range got {
		if !g.Sealed {
			t.Errorf("case %d: not taken as sealed", i)
		}
		if opened := g.Doc != nil; opened != want[i] {
			t.Errorf("case %d: opened %v, want %v", i, opened, want[i])
		} else if opened && g.Doc["catalog"] == nil {
			t.Errorf("case %d: doc %v", i, g.Doc)
		}
	}
}

// Namespace documents are opened against nsDocPL, never a pl literal of
// the kind "config" that only bytes sealed before v0.63 carry.
func TestNSDocPLUsed(t *testing.T) {
	t.Parallel()
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`kind: *'config'`).FindAll(js, -1); len(m) != 0 {
		t.Fatalf("app.js wants pl kind \"config\" outside nsDocPL: %q", m)
	}
}
