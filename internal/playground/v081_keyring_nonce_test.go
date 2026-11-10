package playground

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// §E.3.2, §C.7 (v0.76, v0.81): the playground's keyring writes (krAdd,
// krRotate, run under node with api stubbed) carry a fresh $nonce in
// place of the one read with the keyring, as client.E2E does: one stored
// before v0.76 may have another form, which servers refuse, so copying it
// made every keyring write of such a namespace 422. A keyring read
// without a $nonce is written without one.
func TestV081PlaygroundKeyringWriteNonce(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	src := `require(process.argv[1]);
const Z = globalThis.PLSeal;
const PJ = 'application/json-patch+json';
const quoteId = (id) => '"' + id + '"';
let ID, other, stored, written;
const S = { ns: 'e', nsLevel: 'e2e', nsDoc: { encryption: { level: 'e2e', epoch: 1 } }, config: 'c1' };
const $ = () => ({ checked: false });
const document = { querySelectorAll: () => [] };
const confirm = () => true;
const toasts = [];
const toast = (m) => toasts.push(m);
function renderKeyring() {}
function rememberKey() {}
function holdEpoch() {}
async function refreshNS() {}
const nsInfoCache = new Map();
function readerX() { return other.x; }
async function epochKey() { return new Uint8Array(32).fill(7); }
async function api(method, path, o) {
  if (method === 'GET' && path === '/r/e/keyring') return { status: 200, json: JSON.parse(JSON.stringify(stored)), hdr: () => '1head', etag: () => '1head' };
  if (method === 'PATCH' && path === '/r/e/keyring') { written = o.body[0].value; return { ok: true, status: 200 }; }
  if (method === 'POST' && path === '/ns/e/batch') { written = o.body.items[0].steps[0][0].value; return { ok: true, status: 200 }; }
  throw new Error('unexpected ' + method + ' ' + path);
}
` + jsFunction(t, js, "loadKeyring") + "\n" + jsFunction(t, js, "krLegacyRefused") + "\n" + jsFunction(t, js, "krAdd") + "\n" + jsFunction(t, js, "krRotate") + `
const KR = { ns: '', doc: null, legacy: null, head: '', status: 0 };
(async () => {
  ID = await Z.generateIdentity();
  other = await Z.generateIdentity();
  const out = [];
  for (const nonce of ['pre-v0.76 nonce', Z.newNonce(), null]) {
    for (const op of [krAdd, krRotate]) {
      const kr = Z.buildKeyringV2();
      await Z.keyringV2Add(kr, ID, ID.x, Z.kid('e', 1), new Uint8Array(32).fill(7));
      if (nonce !== null) kr.$nonce = nonce;
      stored = kr; written = undefined;
      await op();
      if (!written) throw new Error(op.name + ' wrote nothing: ' + toasts.join('; '));
      out.push({ op: op.name, stored: nonce, written: '$nonce' in written ? written.$nonce : null, keys: written.keys.length });
    }
  }
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });`
	out, err := exec.Command(node, "-e", src, sealJS).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var got []struct {
		Op      string
		Stored  *string
		Written *string
		Keys    int
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 6 {
		t.Fatalf("node output %s: %v", out, err)
	}
	fresh := func(s string) bool {
		if len(s) != 26 {
			return false
		}
		return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz234567") == ""
	}
	for _, g := range got {
		switch {
		case g.Keys != 2:
			t.Errorf("%s: %d entries written", g.Op, g.Keys)
		case g.Stored == nil && g.Written != nil:
			t.Errorf("%s: a keyring without $nonce written with %q", g.Op, *g.Written)
		case g.Stored != nil && (g.Written == nil || !fresh(*g.Written) || *g.Written == *g.Stored):
			w := "none"
			if g.Written != nil {
				w = *g.Written
			}
			t.Errorf("%s: stored $nonce %q written as %q, want a fresh one", g.Op, *g.Stored, w)
		}
	}
}
