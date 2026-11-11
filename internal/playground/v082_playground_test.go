package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82Prelude is what the v0.82 harnesses share: seal.js, the input, and
// the names app.js's functions expect around them. api answers from
// routes, a map the scenario fills: path -> { status, json?, text?, jose?,
// finalPath?, headers? } or a function of the path giving one.
const v82Prelude = `
const fs = require('fs');
PRELOAD
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
const ID_RE = /^1[a-z2-7]{32}$/;
const short = (id) => id || '';
const routes = {};
const asked = [];
async function api(method, path, o) {
  asked.push(method + ' ' + path);
  let a = routes[path];
  if (typeof a === 'function') a = a(path, o);
  a = a || { status: 404, json: { code: 'not_found' } };
  const hd = a.headers || {};
  return { status: a.status, ok: a.status >= 200 && a.status < 300, json: a.json === undefined ? null : a.json, text: a.text !== undefined ? a.text : JSON.stringify(a.json === undefined ? null : a.json),
    jose: !!a.jose, finalPath: a.finalPath || path, entry: {}, hdr: (k) => hd[k] || '', etag: () => '' };
}
const nsInfoCache = new Map();
FUNCTIONS
(async () => {
  const out = {};
SCENARIO
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// runV82 runs scenario under node over app.js's functions fns and
// seal.js, after preload, and decodes what it wrote into out.
func runV82(t *testing.T, fns []string, preload, scenario string, input, out any) {
	t.Helper()
	node := needNode(t)
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var src []string
	for _, f := range fns {
		src = append(src, jsFunction(t, js, f))
	}
	h := strings.NewReplacer("PRELOAD", preload, "FUNCTIONS", strings.Join(src, "\n"), "SCENARIO", scenario).Replace(v82Prelude)
	dir := t.TempDir()
	hp := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(hp, []byte(h), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(input)
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	cmd := exec.Command(node, hp, sealJS, inPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
}

// E2E-7 (§7.1 End-to-end namespaces, Levels, HTTP-68; scenario 70), in
// the playground: app.js's nsInfo and readDoc keep the highest level
// learnt. A page set to expect e2e, or one that learnt e2e before,
// refuses a plaintext 200 of a resource other than the keyring whatever
// the namespace document or /keys now claims; a 404 teaches nothing;
// /keys naming a lower level throws before any key is taken. Without the
// setting a first contact is believed.
func TestV082PlaygroundLevelsWithNode(t *testing.T) {
	t.Parallel()
	const id = "1nyv2d2ibcop4nnp4k5niguadz7lvyjad"
	var out map[string]struct {
		Level, Lowered string
		Doc            any
		Read           any
		ReadErr        string
		Keyring        any
		Held           string
		Err            string
	}
	runV82(t, []string{"nsInfo", "revTarget", "notOffered", "readDoc", "undoKeysLevel", "tombHead"}, "", `
  const plain = (ns) => { routes['/r/' + ns + '/d/rev/' + input.id] = { status: 200, json: { title: 'forged' } }; routes['/r/' + ns + '/keyring/rev/' + input.id] = { status: 200, json: { keys: [] } }; };
  const read = async (key, ns) => {
    nsInfoCache.clear();
    const info = await nsInfo(ns);
    const d = await readDoc(ns, 'd', input.id, await api('GET', '/r/' + ns + '/d/rev/' + input.id));
    const k = await readDoc(ns, 'keyring', input.id, await api('GET', '/r/' + ns + '/keyring/rev/' + input.id));
    out[key] = { level: info.level, lowered: info.lowered || '', doc: info.doc, read: d.doc, readErr: d.foldErr || '', keyring: k.doc, held: Z.heldLevel(ns) };
  };
  // Configured: the setting, then a server claiming each lower level.
  Z.expectLevel('c', 'e2e'); plain('c');
  routes['/ns/c'] = { status: 200, json: { read: 'public' } };
  await read('configured, no encryption', 'c');
  routes['/ns/c'] = { status: 200, json: { encryption: { level: 'at-rest' } } };
  await read('configured, at-rest', 'c');
  routes['/ns/c'] = { status: 200, jose: true, text: 'eyJ.x.y.z.w', json: null };
  await read('configured, sealed', 'c');
  routes['/ns/c'] = { status: 200, json: { encryption: { level: 'zz' } } };
  await read('configured, unknown level', 'c');
  routes['/ns/c'] = { status: 404, json: { code: 'not_found' } };
  await read('configured, 404', 'c');
  routes['/ns/c'] = { status: 200, json: { encryption: { level: 'e2e', epoch: 2 } } };
  await read('configured, e2e', 'c');
  // Learnt from the document, then lowered.
  plain('l');
  routes['/ns/l'] = { status: 200, json: { encryption: { level: 'e2e', epoch: 1 } } };
  await read('learnt', 'l');
  routes['/ns/l'] = { status: 200, json: { read: 'public' } };
  await read('learnt, then no encryption', 'l');
  routes['/ns/l'] = { status: 403, json: { code: 'forbidden' } };
  await read('learnt, then 403', 'l');
  // Learnt from /keys, for a grant that can't read the document.
  plain('k');
  routes['/ns/k'] = { status: 403, json: { code: 'forbidden' } };
  out['keys names e2e'] = { level: Z.keysLevel('k', '', { level: 'e2e', keys: [] }) };
  await read('learnt from /keys', 'k');
  try { Z.keysLevel('k', '', { level: 'sealed', keys: [] }); out['keys lowered'] = { err: '' }; } catch (e) { out['keys lowered'] = { err: e.message }; }
  try { Z.keysLevel('k', 'e2e', { level: 'sealed', keys: [] }); out['keys lowered beside the document'] = { err: '' }; } catch (e) { out['keys lowered beside the document'] = { err: e.message }; }
  out['keys without a level'] = { level: Z.keysLevel('k', '', { keys: [] }), held: Z.heldLevel('k') };
  routes['/ns/k/keys'] = { status: 404, json: { code: 'not_offered' } };
  out['undo, /keys not offered'] = { level: await undoKeysLevel('k') };
  routes['/ns/k/keys'] = { status: 200, json: { level: 'sealed', keys: [] } };
  try { out['undo, /keys lowered'] = { level: await undoKeysLevel('k'), err: '' }; } catch (e) { out['undo, /keys lowered'] = { err: e.message }; }
  routes['/ns/u/keys'] = { status: 404, json: { code: 'not_offered' } };
  out['undo, nothing held'] = { level: await undoKeysLevel('u') };
  // First contact without the setting: believed.
  plain('f');
  routes['/ns/f'] = { status: 200, json: { read: 'public' } };
  await read('first contact', 'f');
  // The order, and forgetting.
  Z.learnLevel('o', 'at-rest'); Z.learnLevel('o', 'sealed');
  out['order'] = { level: Z.learnLevel('o', 'at-rest').level, lowered: Z.learnLevel('o', '').lowered, held: Z.heldLevel('o') };
  Z.forgetLevel('o');
  out['forgotten'] = { held: Z.heldLevel('o'), level: Z.learnLevel('o', '').level };
  // A tombstone's own /rev 410 isn't a tombstoned head (E2E-3).
  const t410 = { status: 410, json: { code: 'gone', tombstone: input.id, last: input.id } };
  out['tombHead'] = { level: [tombHead(Object.assign({ finalPath: '/r/c/d' }, t410)), tombHead(Object.assign({ finalPath: '/r/c/d/rev/' + input.id }, t410)), tombHead({ status: 410, json: { code: 'gone' }, finalPath: '/r/c/d' })].join(',') };
`, map[string]any{"id": id}, &out)

	refused := func(key, level string) {
		t.Helper()
		g := out[key]
		if g.Level != level || g.Held != level || g.Read != nil || !strings.Contains(g.ReadErr, "never serves an e2e document in the clear") || g.Keyring == nil {
			t.Errorf("%s: %+v", key, g)
		}
	}
	for _, key := range []string{"configured, no encryption", "configured, at-rest", "configured, sealed", "configured, unknown level", "learnt, then no encryption"} {
		refused(key, "e2e")
		if g := out[key]; !strings.Contains(g.Lowered, "never lowered") || g.Doc != nil {
			t.Errorf("%s: the lower claim wasn't refused: %+v", key, g)
		}
	}
	for _, key := range []string{"configured, 404", "configured, e2e", "learnt", "learnt, then 403", "learnt from /keys"} {
		refused(key, "e2e")
		if g := out[key]; g.Lowered != "" {
			t.Errorf("%s: %+v", key, g)
		}
	}
	if g := out["first contact"]; g.Level != "" || g.Held != "" || g.Read == nil || g.ReadErr != "" {
		t.Errorf("first contact without the setting: %+v", g)
	}
	if out["keys names e2e"].Level != "e2e" || !strings.Contains(out["keys lowered"].Err, "never lowered") || !strings.Contains(out["keys lowered beside the document"].Err, "never lowered") {
		t.Errorf("/keys: %+v %+v %+v", out["keys names e2e"], out["keys lowered"], out["keys lowered beside the document"])
	}
	if g := out["keys without a level"]; g.Level != "e2e" || g.Held != "e2e" {
		t.Errorf("/keys without a level: %+v", g)
	}
	if out["undo, /keys not offered"].Level != "e2e" || !strings.Contains(out["undo, /keys lowered"].Err, "never lowered") || out["undo, nothing held"].Level != "" {
		t.Errorf("undo's /keys level: %+v %+v %+v", out["undo, /keys not offered"], out["undo, /keys lowered"], out["undo, nothing held"])
	}
	if g := out["order"]; g.Level != "sealed" || g.Held != "sealed" || g.Lowered == "" {
		t.Errorf("order: %+v", g)
	}
	if g := out["forgotten"]; g.Held != "" || g.Level != "" {
		t.Errorf("forgotten: %+v", g)
	}
	if out["tombHead"].Level != "true,false,false" {
		t.Errorf("tombHead: %s", out["tombHead"].Level)
	}
}

// E2E-7: the levels are kept in localStorage, by origin and namespace,
// so a later page holds what an earlier one learnt.
func TestV082PlaygroundLevelsStoredWithNode(t *testing.T) {
	t.Parallel()
	var out struct {
		Seeded, Other, After string
		Stored               map[string]string
	}
	runV82(t, nil, `
const mem = new Map([['pl.levels', JSON.stringify({ 'https://o.example seeded': 'e2e', 'https://other.example other': 'e2e', 'https://o.example odd': 'what' })]]);
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => { mem.set(k, String(v)); } };
globalThis.location = { origin: 'https://o.example' };
`, `
  out.seeded = Z.heldLevel('seeded') + ',' + Z.heldLevel('odd');
  out.other = Z.heldLevel('other');
  Z.learnLevel('n', 'sealed'); Z.learnLevel('n', 'e2e'); Z.learnLevel('n', 'sealed'); Z.expectLevel('m', 'sealed'); Z.learnLevel('p', '');
  out.after = Z.learnLevel('seeded', 'sealed').lowered ? 'refused' : 'believed';
  out.stored = JSON.parse(localStorage.getItem('pl.levels'));
`, map[string]any{}, &out)
	// A stored value that is no level is held as e2e, never as none.
	if out.Seeded != "e2e,e2e" || out.Other != "" || out.After != "refused" {
		t.Errorf("held from the store: %+v", out)
	}
	if out.Stored["https://o.example n"] != "e2e" || out.Stored["https://o.example m"] != "sealed" || out.Stored["https://o.example seeded"] != "e2e" {
		t.Errorf("stored: %v", out.Stored)
	}
	if _, has := out.Stored["https://o.example p"]; has {
		t.Errorf("no level was stored as one: %v", out.Stored)
	}
}

// E2E-11 (§E.2.1 Message bound, E3): the playground counts the sealings
// under a resource's K_r, the log's own sealed ops and those it makes,
// per (ns, name, kid), and seals none past the bound (here lowered to 4).
// A refused write's sealing counts; the same ciphertext read back from
// the log counts once; a base's ops read through and another epoch's
// don't count toward this key; a grant that can't read the log counts its
// own and says so; a log that fails otherwise seals nothing.
func TestV082PlaygroundSealCountWithNode(t *testing.T) {
	t.Parallel()
	ke := seal.NewKey()
	var out struct {
		Bound                     float64
		First, AfterTwo, AfterLog float64
		Third, OtherKid           string
		Reread                    float64
		Partial                   bool
		PartialCount              float64
		PartialErr, Broken        string
		BrokenAsked               []string
		Fresh                     float64
	}
	runV82(t, []string{"logPages", "pageEndErr", "jweID", "readLogRange", "countSealings", "sealCounted"}, "", `
  const key = await Z.resourceKey(Z.unb64u(input.ke), 'e', 'd');
  out.bound = new Z.SealCounter().bound;
  const mk = async (ns, kid, parent, n) => { const patches = await Z.sealPatchSet(key, kid, ns, 'd', parent, [{ op: 'add', path: '/n', value: n }], false, []); return { id: await Z.revisionID(parent, patches), parent, kind: 'rev', patches }; };
  // The log: a base's op read through (pl.ns base), two of e's own under e#1, one under e#2.
  const b = await mk('base', 'base#1', '', 0), e1 = await mk('e', 'e#1', b.id, 1), e2 = await mk('e', 'e#1', e1.id, 2), e3 = await mk('e', 'e#2', e2.id, 3);
  let log = [b, e1, e2, e3];
  routes['/r/e/d/log'] = () => ({ status: 200, json: log, finalPath: '/r/e/d/rev/' + log[log.length - 1].id + '/log' });
  const seals = new Z.SealCounter(4);
  out.first = (await countSealings(seals, 'e', 'd'), seals.count('e', 'd', 'e#1'));
  // Two sealings here: one accepted later, one refused by the server. Both count.
  const w1 = await sealCounted(seals, key, 'e#1', 'e', 'd', e3.id, [{ op: 'add', path: '/n', value: 4 }], false, []);
  await sealCounted(seals, key, 'e#1', 'e', 'd', e3.id, [{ op: 'add', path: '/n', value: 5 }], false, []);
  out.afterTwo = seals.count('e', 'd', 'e#1');
  try { await sealCounted(seals, key, 'e#1', 'e', 'd', e3.id, [{ op: 'add', path: '/n', value: 6 }], false, []); out.third = 'sealed'; } catch (err) { out.third = err.message; }
  // The new epoch's K_r has its own count.
  try { await sealCounted(seals, key, 'e#2', 'e', 'd', e3.id, [{ op: 'add', path: '/n', value: 6 }], false, []); out.otherKid = 'sealed'; } catch (err) { out.otherKid = err.message; }
  // The accepted write read back from the log is the same sealing, once.
  log = log.concat([{ id: await Z.revisionID(e3.id, w1), parent: e3.id, kind: 'rev', patches: w1 }]);
  seals.noteLog('e', 'd', log, false);
  out.afterLog = seals.count('e', 'd', 'e#1');
  seals.noteLog('e', 'd', log, false);
  out.reread = seals.count('e', 'd', 'e#1');
  // A grant that can't read the log: its own sealings count, partial.
  routes['/r/e/x/log'] = { status: 403, json: { code: 'forbidden' } };
  const p = new Z.SealCounter(2);
  await sealCounted(p, key, 'e#1', 'e', 'x', '', [{ op: 'add', path: '', value: {} }], false, []);
  await sealCounted(p, key, 'e#1', 'e', 'x', '', [{ op: 'add', path: '', value: {} }], false, []);
  out.partial = p.partial('e', 'x'); out.partialCount = p.count('e', 'x', 'e#1');
  try { await sealCounted(p, key, 'e#1', 'e', 'x', '', [{ op: 'add', path: '', value: {} }], false, []); out.partialErr = 'sealed'; } catch (err) { out.partialErr = err.message; }
  // A log that can't be read for another reason: nothing is sealed.
  routes['/r/e/y/log'] = { status: 500, json: { code: 'internal' } };
  const q = new Z.SealCounter(2);
  try { await sealCounted(q, key, 'e#1', 'e', 'y', '', [{ op: 'add', path: '', value: {} }], false, []); out.broken = 'sealed'; } catch (err) { out.broken = err.message; }
  // A resource that doesn't exist yet has nothing to count.
  const f = new Z.SealCounter(2);
  await sealCounted(f, key, 'e#1', 'e', 'new', '', [{ op: 'add', path: '', value: {} }], false, []);
  out.fresh = f.count('e', 'new', 'e#1');
`, map[string]any{"ke": b64u.EncodeToString(ke)}, &out)
	if out.Bound != 1<<32 {
		t.Errorf("the default bound is %v, want 2^32", out.Bound)
	}
	if out.First != 2 || out.AfterTwo != 4 {
		t.Errorf("counted %v from the log, %v after two sealings; want 2 and 4", out.First, out.AfterTwo)
	}
	if !strings.Contains(out.Third, "the bound is 4") || !strings.Contains(out.Third, "§E.2.1") {
		t.Errorf("a fifth sealing under a bound of 4: %q", out.Third)
	}
	if out.OtherKid != "sealed" {
		t.Errorf("a sealing under the next epoch's key: %q", out.OtherKid)
	}
	if out.AfterLog != 4 || out.Reread != 4 {
		t.Errorf("after the log shows the accepted write: %v, again %v; want 4", out.AfterLog, out.Reread)
	}
	if !out.Partial || out.PartialCount != 2 || !strings.Contains(out.PartialErr, "at least") {
		t.Errorf("a log the grant can't read: partial %v, count %v, then %q", out.Partial, out.PartialCount, out.PartialErr)
	}
	if !strings.Contains(out.Broken, "can't be counted") {
		t.Errorf("a log answering 500: %q", out.Broken)
	}
	if out.Fresh != 1 {
		t.Errorf("a new resource's first sealing: %v", out.Fresh)
	}
}

// SVC-11c (SERVICES §B.5): the playground reads ancestors and where
// answers in v0.82's shape, paths as arrays of node names with the nodes
// map, tooDeep and truncated as booleans, and in the shape before it,
// path elements as objects and tooDeep a count. A cut, a missing paths
// and anything that doesn't decode are a cut, never a complete answer.
func TestV082PlaygroundWherePathsWithNode(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"v0.82":             `{"at":"1x","of":"matches.derby","paths":[["root","season-2026","matches.derby"],["archive","matches.derby"]],"nodes":{"root":{"href":"/r/cat/root","title":"Root"},"season-2026":{"href":"/r/cat/season-2026","sealed":"x"},"matches.derby":{"href":"/r/cat/matches.derby","title":"Derby"},"archive":{"href":"/r/cat/archive"}}}`,
		"v0.82 tooDeep":     `{"paths":[["a","b"]],"nodes":{},"tooDeep":true}`,
		"v0.82 truncated":   `{"paths":[["a","b"]],"nodes":{},"truncated":true}`,
		"before":            `{"paths":[[{"href":"/r/cat/root","name":"root","title":"Root"},{"href":"/r/cat/x","name":"x"}]]}`,
		"before, tooDeep":   `{"paths":[[{"href":"/r/cat/root","name":"root"}]],"tooDeep":2}`,
		"before, zero deep": `{"paths":[[{"href":"/r/cat/root","name":"root"}]],"tooDeep":0}`,
		"no paths":          `{"at":"1x"}`,
		"paths not arrays":  `{"paths":{"a":1}}`,
		"a bad element":     `{"paths":[["a",7],["b"]]}`,
		"a bad path":        `{"paths":["a",["b"]]}`,
		"tooDeep a string":  `{"paths":[["a"]],"tooDeep":"yes"}`,
		"not an object":     `[]`,
		"null":              `null`,
		"empty, complete":   `{"paths":[]}`,
		"proto name":        `{"paths":[["__proto__","constructor"]],"nodes":{}}`,
	}
	var out map[string]struct {
		Paths [][]struct{ Name, Href, Title string }
		Cut   bool
		Why   string
	}
	runV82(t, []string{"wherePaths"}, "", `
  for (const [k, v] of Object.entries(input.cases)) out[k] = wherePaths(JSON.parse(v));
`, map[string]any{"cases": cases}, &out)
	g := out["v0.82"]
	if g.Cut || len(g.Paths) != 2 || len(g.Paths[0]) != 3 || g.Paths[0][0].Title != "Root" || g.Paths[0][0].Href != "/r/cat/root" ||
		g.Paths[0][1].Name != "season-2026" || g.Paths[0][1].Title != "" || g.Paths[0][2].Title != "Derby" || g.Paths[1][0].Name != "archive" {
		t.Errorf("v0.82: %+v", g)
	}
	g = out["before"]
	if g.Cut || len(g.Paths) != 1 || g.Paths[0][0].Title != "Root" || g.Paths[0][1].Name != "x" || g.Paths[0][1].Href != "/r/cat/x" {
		t.Errorf("before v0.82: %+v", g)
	}
	for key, paths := range map[string]int{"v0.82 tooDeep": 1, "v0.82 truncated": 1, "before, tooDeep": 1, "no paths": 0, "paths not arrays": 0, "a bad element": 1, "a bad path": 1, "tooDeep a string": 1, "not an object": 0, "null": 0} {
		if g := out[key]; !g.Cut || g.Why == "" || len(g.Paths) != paths {
			t.Errorf("%s: %+v, want a cut with %d paths", key, g, paths)
		}
	}
	for key, paths := range map[string]int{"before, zero deep": 1, "empty, complete": 0, "proto name": 1} {
		if g := out[key]; g.Cut || len(g.Paths) != paths {
			t.Errorf("%s: %+v, want %d paths and no cut", key, g, paths)
		}
	}
	if g := out["proto name"]; g.Paths[0][0].Name != "__proto__" || g.Paths[0][0].Href != "" || g.Paths[0][0].Title != "" {
		t.Errorf("a node named __proto__: %+v", g)
	}
}

// SVC-11c (SERVICES §E.2.6 Values of another resource): a reader
// compares a nested value's pl.ns and pl.name with the resource the entry
// draws it from, where the entry names it: a placement's item, or, for
// born, the entry's own resource. A value sealed for another resource,
// with a valid tag under that resource's key, is refused; an entry that
// names no item is read as before.
func TestV082PlaygroundNestedValueResourceWithNode(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children/docs"
	ke := map[string][]byte{"cat": seal.NewKey(), "matches": seal.NewKey()}
	keys := map[string]string{}
	val := func(ns, name, plain string) map[string]any {
		kr, err := seal.ResourceKey(ke[ns], ns, name)
		if err != nil {
			t.Fatal(err)
		}
		keys[ns+"/"+name] = b64u.EncodeToString(kr)
		vr, _ := seal.ViewKey(kr, view)
		j, err := seal.Seal(vr, seal.Kid(ns, 1), seal.PL{"ns": ns, "name": name, "view": view}, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"sealed": j}
	}
	own := func(name string) string { return val("cat", name, `{"title":"T `+name+`"}`)["sealed"].(string) }
	body := map[string]any{"children": []any{
		// A placement: file from its item, born from itself.
		map[string]any{"name": "matches.derby", "kind": "item", "item": "/r/matches/derby", "sealed": own("matches.derby"),
			"file": val("matches", "derby", `{"file":"derby.md"}`), "born": val("cat", "matches.derby", `{"born":"1x"}`)},
		// file sealed for another resource of the item's namespace, and
		// for the same name in another namespace.
		map[string]any{"name": "matches.derby", "kind": "item", "item": "/r/matches/derby", "sealed": own("matches.derby"),
			"file": val("matches", "final", `{"file":"final.md"}`), "born": val("cat", "other", `{"born":"1y"}`)},
		map[string]any{"name": "matches.derby", "kind": "item", "item": "/r/matches/derby", "sealed": own("matches.derby"),
			"file": val("cat", "derby", `{"file":"cat-derby.md"}`), "born": val("matches", "matches.derby", `{"born":"1z"}`)},
		// A clear placement entry (a public catalog over a sealed item).
		map[string]any{"name": "matches.derby", "kind": "item", "item": "/r/matches/derby", "title": "Derby",
			"file": val("matches", "final", `{"file":"final.md"}`)},
		// A folder: born is its own; no item is named, so another member
		// isn't compared.
		map[string]any{"name": "docs", "kind": "folder", "sealed": own("docs"), "born": val("cat", "elsewhere", `{"born":"1w"}`), "extra": val("matches", "final", `{"extra":1}`)},
	}}
	var out struct {
		Children []struct {
			Title string `json:"title"`
			Err   string `json:"_sealedErr"`
			File  struct {
				File string `json:"file"`
				Err  string `json:"_sealedErr"`
			} `json:"file"`
			Born struct {
				Born string `json:"born"`
				Err  string `json:"_sealedErr"`
			} `json:"born"`
			Extra struct {
				Extra float64 `json:"extra"`
				Err   string  `json:"_sealedErr"`
			} `json:"extra"`
		} `json:"children"`
	}
	runV82(t, []string{"openSealed", "openSealedEntries"}, "", `
  globalThis.contentKey = async (kid, resource) => { const k = input.keys[Z.parseKid(kid).ns + '/' + resource]; if (!k) throw new Error('no key for ' + kid + ' / ' + resource); return Z.unb64u(k); };
  const body = input.body;
  await openSealedEntries(body, input.view);
  out.children = body.children;
`, map[string]any{"view": view, "keys": keys, "body": body}, &out)
	if len(out.Children) != 5 {
		t.Fatalf("%d entries", len(out.Children))
	}
	c := out.Children[0]
	if c.Title != "T matches.derby" || c.Err != "" || c.File.File != "derby.md" || c.File.Err != "" || c.Born.Born != "1x" || c.Born.Err != "" {
		t.Errorf("a placement's values from its item and itself: %+v", c)
	}
	for i := 1; i <= 2; i++ {
		c = out.Children[i]
		if c.Title != "T matches.derby" || c.File.File != "" || !strings.Contains(c.File.Err, "isn't the resource its entry draws it from") ||
			c.Born.Born != "" || !strings.Contains(c.Born.Err, "isn't the resource its entry draws it from") {
			t.Errorf("entry %d, values sealed for another resource: %+v", i, c)
		}
	}
	if c = out.Children[3]; c.File.File != "" || !strings.Contains(c.File.Err, "isn't the resource its entry draws it from") {
		t.Errorf("a clear entry's value sealed for another resource: %+v", c)
	}
	c = out.Children[4]
	if c.Title != "T docs" || c.Born.Born != "" || !strings.Contains(c.Born.Err, "isn't the resource") || c.Extra.Extra != 1 || c.Extra.Err != "" {
		t.Errorf("a folder's values: %+v", c)
	}
}

// E2E-11 against a live server: countSealings reads GET /r/{ns}/{name}/log,
// which redirects to the head's range (the tombstone's for a tombstoned
// head) and is 404 for a resource that doesn't exist and 410 for a purged
// one, and counts the sealed ops the log really shows.
func TestV082PlaygroundSealCountLiveWithNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"))
	if _, err := c.CreateNamespace(ctx, "e", map[string]any{"read": "public", "encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := seal.GenerateRecipient()
	x := c.E2E(priv)
	if _, err := x.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	x = x.WithoutValidation()
	write := func(name, parent string, n float64) string {
		t.Helper()
		var w *client.WriteResult
		var err error
		if parent == "" {
			w, err = x.CreateSealed(ctx, "e", name, client.GenesisPatches(map[string]any{"n": n}))
		} else {
			w, err = x.AppendSealed(ctx, "e", name, parent, []any{map[string]any{"op": "replace", "path": "/n", "value": n}})
		}
		if err != nil {
			t.Fatal(err)
		}
		return w.ID
	}
	d := write("d", write("d", write("d", "", 1), 2), 3)
	_ = d
	tomb := write("t", "", 1)
	if _, err := c.Delete(ctx, "e", "t", tomb); err != nil {
		t.Fatal(err)
	}
	gone := write("p", "", 1)
	if _, err := c.Purge(ctx, "e", "p", gone, false); err != nil {
		t.Fatal(err)
	}
	var out map[string]struct {
		Count   float64
		Partial bool
		Err     string
	}
	runV82(t, []string{"logPages", "pageEndErr", "jweID", "readLogRange", "countSealings"}, "", `
  api = async (method, path) => {
    const res = await fetch(input.base + path, { method });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (_) { /* not JSON */ }
    const u = new URL(res.url);
    return { status: res.status, ok: res.ok, json, text, finalPath: u.pathname + u.search, entry: {}, jose: false, hdr: (k) => res.headers.get(k), etag: () => '' };
  };
  for (const name of ['d', 't', 'p', 'none']) {
    const seals = new Z.SealCounter();
    try { await countSealings(seals, 'e', name); out[name] = { count: seals.count('e', name, 'e#1'), partial: seals.partial('e', name), err: seals.counted('e', name) ? '' : 'not counted' }; }
    catch (e) { out[name] = { err: e.message }; }
  }
`, map[string]any{"base": s.URL}, &out)
	for name, want := range map[string]float64{"d": 3, "t": 1, "p": 0, "none": 0} {
		if g := out[name]; g.Err != "" || g.Partial || g.Count != want {
			t.Errorf("%s: %+v, want %v sealings counted in full", name, g, want)
		}
	}
}
