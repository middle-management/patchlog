package playground

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// keyringHarness runs seal.js's keyring document functions and app.js's
// takeKeys against Go's (internal/seal) with node.
const keyringHarness = `
const fs = require('fs');
const [sealJS, inJSON] = process.argv.slice(2);
require(sealJS);
const Z = globalThis.PLSeal;
const input = JSON.parse(fs.readFileSync(inJSON, 'utf8'));
let KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
let ID = input.reader;
const mem = {};
const store = { get(k, d) { return k in mem ? mem[k] : d; }, set(k, v) { mem[k] = v; } };
function renderKeysHeld() {}
FUNCTIONS
(async () => {
  const out = {};
  out.thumbprint = await Z.thumbprint(input.reader.x);
  const kr = Z.parseKeyringV2(input.keyring);
  try { await Z.keyringV2EpochKey(kr, input.reader, input.kid, []); out.unknownSender = 'opened'; } catch (e) { out.unknownSender = e.message; }
  out.goEntry = Z.b64u(await Z.keyringV2EpochKey(kr, input.reader, input.kid, [input.admin.x]));
  const mine = Z.buildKeyringV2();
  await Z.keyringV2Add(mine, input.admin, input.reader.x, input.kid, Z.unb64u(input.key));
  await Z.keyringV2Add(mine, input.admin, input.admin.x, input.kid, Z.unb64u(input.key));
  await Z.keyringV2Add(mine, input.admin, input.reader.x, input.kid, Z.unb64u(input.key));
  out.jsKeyring = mine;
  try { Z.parseKeyringV2({ keys: [Object.assign({ suite: 'x' }, mine.keys[0])] }); out.extraMember = 'parsed'; } catch (e) { out.extraMember = e.message; }
  // takeKeys: a relayed entry opens only from a known sender; a K_r is held by its name.
  out.taken0 = await takeKeys(input.relayed);
  rememberKey(input.admin.x);
  out.taken1 = await takeKeys(input.relayed);
  out.epochKey = KEYS.epoch.has(input.kid) ? Z.b64u(KEYS.epoch.get(input.kid)) : '';
  out.resKey = KEYS.res.has(input.kid + '\nderby') ? Z.b64u(KEYS.res.get(input.kid + '\nderby')) : '';
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// P18, ENC-9 and ENC-11 (§E.2.3, §E.3.2): the playground names keys by
// their RFC 7638 thumbprint, opens a keyring document's entries in HPKE
// auth mode only from a sender it knows, writes entries Go opens, and
// takes /keys entries with from and name.
func TestV073PlaygroundKeyringDocumentWithNode(t *testing.T) {
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
	for _, f := range []string{"knownKeys", "rememberKey", "keyFrom", "holdEpoch", "holdRes", "takeKeys"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	_, reader, _ := seal.GenerateRecipient()
	_, admin, _ := seal.GenerateRecipient()
	const kid = "e#1"
	key := seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, key, []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	kRes, _ := seal.ResourceKey(key, "e", "derby")
	wRes, _ := seal.WrapKey(reader.PublicKey(), kid, "derby", kRes)
	ident := func(p *ecdh.PrivateKey) map[string]string {
		return map[string]string{"d": b64.EncodeToString(p.Bytes()), "x": b64.EncodeToString(p.PublicKey().Bytes())}
	}
	in, _ := json.Marshal(map[string]any{
		"reader": ident(reader), "admin": ident(admin), "kid": kid, "key": b64.EncodeToString(key),
		"keyring": kr.Value(),
		"relayed": []any{kr.Entries[0].Relayed().Value(), wRes.Value()},
	})
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(keyringHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
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
	var got struct {
		Thumbprint, UnknownSender, GoEntry, ExtraMember, EpochKey, ResKey string
		JSKeyring                                                         json.RawMessage
		Taken0, Taken1                                                    int
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("node output %s: %v", out, err)
	}
	if got.Thumbprint != seal.Thumbprint(reader.PublicKey()) {
		t.Errorf("thumbprint %s, want %s", got.Thumbprint, seal.Thumbprint(reader.PublicKey()))
	}
	if !strings.Contains(got.UnknownSender, "doesn't know") {
		t.Errorf("an entry from an unknown sender: %s", got.UnknownSender)
	}
	if got.GoEntry != b64.EncodeToString(key) {
		t.Error("the Go-wrapped entry didn't open to the key")
	}
	if !strings.Contains(got.ExtraMember, "exactly kid, to, from and wrapped") {
		t.Errorf("an entry with another member: %s", got.ExtraMember)
	}
	mine, err := seal.ParseKeyringV2([]byte(got.JSKeyring))
	if err != nil || len(mine.Entries) != 2 {
		t.Fatalf("the playground's keyring: %v %s", err, got.JSKeyring)
	}
	k, err := mine.EpochKey(reader, kid, []*ecdh.PublicKey{admin.PublicKey()})
	if err != nil || !bytes.Equal(k, key) {
		t.Fatalf("Go opening the playground's entry: %v", err)
	}
	if e, _ := mine.Entry(kid, seal.Thumbprint(reader.PublicKey())); e.From != seal.Thumbprint(admin.PublicKey()) {
		t.Fatalf("from %s", e.From)
	}
	// Before the admin's key is known only the K_r opens; after, both.
	if got.Taken0 != 1 || got.Taken1 != 2 || got.EpochKey != b64.EncodeToString(key) || got.ResKey != b64.EncodeToString(kRes) {
		t.Fatalf("takeKeys: %d then %d, epoch key %q, K_r %q", got.Taken0, got.Taken1, got.EpochKey, got.ResKey)
	}
}
