package playground

import (
	"crypto/hpke"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// relayHarness runs app.js's fetchKeyFor (with takeKeys, keyringKey and
// nsInfo) for an e2e namespace with the browser stubbed: api() answers
// POST /ns/{ns}/keys with the case's relayed entry and GET
// /r/{ns}/keyring with the keyring.
const relayHarness = `
const fs = require('fs');
const [sealJS, inJSON] = process.argv.slice(2);
require(sealJS);
const Z = globalThis.PLSeal;
const input = JSON.parse(fs.readFileSync(inJSON, 'utf8'));
let KEYS;
const nsInfoCache = new Map();
let ID = input.identity;
let relayed = '';
function renderKeysHeld() {}
const $ = () => ({ value: 'bearer' });
async function api(method, path) {
  if (method === 'GET' && path === '/ns/' + input.ns) return { status: 200, json: { encryption: { level: 'e2e' } } };
  if (method === 'POST' && path === '/ns/' + input.ns + '/keys') return { ok: true, status: 200, json: { keys: [{ kid: input.kid, wrapped: relayed }] } };
  if (method === 'GET' && path === '/r/' + input.ns + '/keyring') return { status: 200, json: input.keyring };
  return { status: 404 };
}
FUNCTIONS
(async () => {
  const out = [];
  for (const c of input.cases) {
    KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
    relayed = c;
    let r = {};
    try {
      await fetchKeyFor(input.kid, '');
      r = { key: Z.b64u(KEYS.epoch.get(input.kid)), from: KEYS.from.get(input.kid + '\n') };
    } catch (e) { r = { err: e.message }; }
    out.push(r);
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// W1X: keyrings stored before v0.63 wrap their keys under the info of
// that time, and /keys relays their entries as stored (§E.2.3, §E.3.2).
// The playground opens them under either info, from the relay and from
// the keyring, and a relayed entry it can't open leaves the keyring.
func TestW1XRelayedLegacyKeyringEntriesWithNode(t *testing.T) {
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
	for _, f := range []string{"keyFrom", "holdEpoch", "holdRes", "nsInfo", "takeKeys", "keyringKey", "fetchKeyFor"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	const ns = "e"
	kid := seal.Kid(ns, 1)
	key := seal.NewKey()
	pk, err := hpke.NewDHKEMPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-keys-v1\n"+kid), key)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := seal.BuildKeyring(ns, 1, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	rid := seal.RecipientID(priv.PublicKey())
	kr.Recipients[rid] = priv.PublicKey()
	kr.Epochs[1][rid] = legacy
	broken := append([]byte(nil), legacy...)
	broken[len(broken)-1] ^= 1
	in, _ := json.Marshal(map[string]any{
		"identity": map[string]string{"d": b64.EncodeToString(priv.Bytes()), "x": b64.EncodeToString(priv.PublicKey().Bytes())},
		"ns":       ns, "kid": kid, "keyring": kr.Value(),
		"cases": []string{b64.EncodeToString(legacy), b64.EncodeToString(broken)},
	})
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(relayHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	out, err := exec.Command(node, h, sealJS, inPath).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got []struct{ Key, From, Err string }
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 2 {
		t.Fatalf("node output %s: %v", out, err)
	}
	want := []string{"POST /keys (HPKE-wrapped)", "keyring (HPKE-wrapped)"}
	for i, g := range got {
		if g.Err != "" || g.Key != b64.EncodeToString(key) || g.From != want[i] {
			t.Errorf("case %d: %+v, want the key from %s", i, g, want[i])
		}
	}
}
