package playground

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// keysHarness runs app.js's takeKeys, keyringKey and fetchKeyFor (with
// nsInfo) with the browser stubbed: each take is one /keys answer for a
// namespace at a level; for each ring api() answers GET /r/{ns}/keyring
// with input.keyrings[ring]; each fetch reads a key with GET /ns/{ns}
// answering 403 (a grant that can't read the namespace document, §C.5)
// and POST /ns/{ns}/keys answering the case's answer.
const keysHarness = `
const fs = require('fs');
const [sealJS, inJSON] = process.argv.slice(2);
require(sealJS);
const Z = globalThis.PLSeal;
const input = JSON.parse(fs.readFileSync(inJSON, 'utf8'));
let KEYS;
let ID = input.identity;
const mem = { 'pl.knownKeys': input.known };
const store = { get(k, d) { return k in mem ? mem[k] : d; }, set(k, v) { mem[k] = v; } };
function renderKeysHeld() {}
const $ = () => ({ value: 'bearer' });
let nsInfoCache;
let ring = '', answer = null;
async function api(method, path) {
  if (method === 'GET' && path === '/r/' + input.ns + '/keyring' && ring) return { status: 200, json: input.keyrings[ring] };
  if (method === 'GET' && /^\/ns\/[^/]+$/.test(path)) return { status: 403, json: { code: 'forbidden' } };
  if (method === 'POST' && /^\/ns\/[^/]+\/keys$/.test(path) && answer) return { ok: true, status: 200, json: answer };
  return { status: 404 };
}
FUNCTIONS
(async () => {
  const out = { takes: [], rings: [], fetches: [] };
  const held = () => [...KEYS.epoch.keys()].map((k) => k + '=' + Z.b64u(KEYS.epoch.get(k)))
    .concat([...KEYS.res.keys()].map((k) => k.replace('\n', '/') + '=' + Z.b64u(KEYS.res.get(k))));
  for (const c of input.takes) {
    KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
    let n = -1, err = '';
    try { n = await takeKeys([c.entry], c.level); } catch (e) { err = e.message; }
    out.takes.push({ name: c.name, n, held: held(), err });
  }
  for (const r of input.rings) {
    KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
    ring = r;
    let err = '';
    try { await keyringKey(input.ns, 1); } catch (e) { err = e.message; }
    out.rings.push({ name: r, n: KEYS.epoch.size, held: held(), err });
  }
  ring = '';
  for (const c of input.fetches) {
    KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
    nsInfoCache = new Map();
    answer = c.answer;
    let err = '';
    try { await fetchKeyFor(c.kid, c.resource || ''); } catch (e) { err = e.message; }
    out.fetches.push({ name: c.name, n: KEYS.epoch.size + KEYS.res.size, held: held(), err });
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// E2E-10, KEYS-6 (§E.2.3, §E.3.2; v0.78 Legacy): the playground takes
// /keys entries and keyring keys as internal/client does.
//   - At E3 (client.E2E findKey) only a relayed keyring entry naming its
//     sender in from, opened in auth mode with a sender it knows: a raw
//     key, an entry wrapped without from (base mode, either info), one
//     from an unknown sender and a per-resource one are skipped.
//   - At E2 (client.Keys) raw keys and keys wrapped in base mode under the
//     info of v0.63, never under the info of keyrings stored before v0.63,
//     and no relayed keyring entry.
//   - The keyring opens only in the §E.3.2 form, from a known sender; one
//     in the format before v0.63 opens nothing (client.E2E keyring).
//   - A grant that can't read the namespace document takes keys by the
//     level the /keys answer names, and none where nothing names one.
func TestV081PlaygroundKeysAsClientWithNode(t *testing.T) {
	t.Parallel()
	node := needNode(t)
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"knownKeys", "keyFrom", "holdEpoch", "holdRes", "takeKeys", "keyringKey", "nsInfo", "fetchKeyFor"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	_, reader, _ := seal.GenerateRecipient()
	_, admin, _ := seal.GenerateRecipient()
	_, stranger, _ := seal.GenerateRecipient()
	const e3, e2 = "e", "s"
	key := seal.NewKey()
	kid := seal.Kid(e3, 1)
	readers := []*ecdh.PublicKey{reader.PublicKey()}
	ring, err := seal.BuildKeyringV2(admin, e3, 1, key, readers)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := seal.BuildKeyringV2(stranger, e3, 1, key, readers)
	if err != nil {
		t.Fatal(err)
	}
	relayed := ring.Entries[0].Relayed().Value()
	base, _ := seal.WrapKey(reader.PublicKey(), kid, "", key)
	// A K_r relayed with from, as no server sends at E3.
	kRes, _ := seal.ResourceKey(key, e3, "derby")
	resAuth, err := seal.WrapKeyAuth(admin, reader.PublicKey(), kid, "derby", kRes)
	if err != nil {
		t.Fatal(err)
	}
	resAuth.From = seal.Thumbprint(admin.PublicKey())
	pk, err := hpke.NewDHKEMPublicKey(reader.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	legacyInfo := func(kid string) map[string]any {
		w, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-keys-v1\n"+kid), key)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"kid": kid, "wrapped": b64.EncodeToString(w)}
	}
	sKid := seal.Kid(e2, 1)
	sBase, _ := seal.WrapKey(reader.PublicKey(), sKid, "", key)
	sRes, _ := seal.ResourceKey(key, e2, "derby")
	sResW, _ := seal.WrapKey(reader.PublicKey(), sKid, "derby", sRes)
	legacy, err := seal.BuildKeyring(e3, 1, key, readers)
	if err != nil {
		t.Fatal(err)
	}
	ident := func(p *ecdh.PrivateKey) map[string]string {
		return map[string]string{"d": b64.EncodeToString(p.Bytes()), "x": b64.EncodeToString(p.PublicKey().Bytes())}
	}
	raw := func(kid string) map[string]any { return map[string]any{"kid": kid, "key": b64.EncodeToString(key)} }
	type take struct {
		Name  string `json:"name"`
		Level string `json:"level"`
		Entry any    `json:"entry"`
		want  string // the key held, "" for none
	}
	kb := b64.EncodeToString(key)
	takes := []take{
		{"e3 relayed from a known sender", "e2e", relayed, kid + "=" + kb},
		{"e3 relayed from an unknown sender", "e2e", foreign.Entries[0].Relayed().Value(), ""},
		{"e3 raw key", "e2e", raw(kid), ""},
		{"e3 wrapped without from", "e2e", base.Value(), ""},
		{"e3 wrapped without from, info before v0.63", "e2e", legacyInfo(kid), ""},
		{"e3 per-resource key with from", "e2e", resAuth.Value(), ""},
		{"e2 raw key", "sealed", raw(sKid), sKid + "=" + kb},
		{"e2 wrapped", "sealed", sBase.Value(), sKid + "=" + kb},
		{"e2 wrapped K_r", "sealed", sResW.Value(), sKid + "/derby=" + b64.EncodeToString(sRes)},
		{"e2 wrapped, info before v0.63", "sealed", legacyInfo(sKid), ""},
		{"e2 relayed keyring entry", "sealed", relayed, ""},
	}
	// A grant that can't read the namespace document learns the level
	// from the /keys answer (§E.2.3), and takes nothing where neither
	// names one.
	type fetch struct {
		Name     string         `json:"name"`
		Kid      string         `json:"kid"`
		Resource string         `json:"resource,omitempty"`
		Answer   map[string]any `json:"answer"`
		want     string
	}
	fetches := []fetch{
		{"e3 relayed, level from /keys", kid, "", map[string]any{"level": "e2e", "epoch": 1, "keys": []any{relayed}}, kid + "=" + kb},
		{"e3 raw key, level from /keys", kid, "", map[string]any{"level": "e2e", "epoch": 1, "keys": []any{raw(kid)}}, ""},
		{"e2 K_r, level from /keys", sKid, "derby", map[string]any{"level": "sealed", "epoch": 1, "keys": []any{sResW.Value()}}, sKid + "/derby=" + b64.EncodeToString(sRes)},
		{"no level anywhere", sKid, "", map[string]any{"keys": []any{raw(sKid)}}, ""},
	}
	in, _ := json.Marshal(map[string]any{
		"identity": ident(reader),
		"known":    []string{b64.EncodeToString(admin.PublicKey().Bytes())},
		"takes":    takes,
		"ns":       e3,
		"keyrings": map[string]any{"v2": ring.Value(), "old": legacy.Value(), "foreign": foreign.Value()},
		"rings":    []string{"v2", "old", "foreign"},
		"fetches":  fetches,
	})
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(keysHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	b, err := exec.Command(node, h, sealJS, inPath).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, b)
	}
	type result struct {
		Name string
		N    int
		Held []string
		Err  string
	}
	var got struct{ Takes, Rings, Fetches []result }
	if err := json.Unmarshal(b, &got); err != nil || len(got.Takes) != len(takes) || len(got.Rings) != 3 || len(got.Fetches) != len(fetches) {
		t.Fatalf("node output %s: %v", b, err)
	}
	for i, c := range takes {
		g := got.Takes[i]
		want := 0
		if c.want != "" {
			want = 1
		}
		if g.Err != "" || g.N != want || want == 1 && (len(g.Held) != 1 || g.Held[0] != c.want) || want == 0 && len(g.Held) != 0 {
			t.Errorf("%s: %+v, want %q", c.Name, g, c.want)
		}
	}
	// The §E.3.2 keyring opens from a known sender only; one in the
	// format before v0.63 opens nothing, even for a reader it wraps for.
	if g := got.Rings[0]; g.Err != "" || len(g.Held) != 1 || g.Held[0] != kid+"="+kb {
		t.Errorf("keyring: %+v", g)
	}
	if g := got.Rings[1]; g.N != 0 || !strings.Contains(g.Err, "not in the §E.3.2 form") {
		t.Errorf("keyring before v0.63: %+v", g)
	}
	if g := got.Rings[2]; g.N != 0 || !strings.Contains(g.Err, "doesn't know") {
		t.Errorf("keyring from an unknown sender: %+v", g)
	}
	for i, c := range fetches {
		g := got.Fetches[i]
		if c.want != "" && (g.Err != "" || len(g.Held) != 1 || g.Held[0] != c.want) || c.want == "" && (g.N != 0 || g.Err == "") {
			t.Errorf("%s: %+v, want %q", c.Name, g, c.want)
		}
	}
}
