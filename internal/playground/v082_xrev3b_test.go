package playground

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// SERVICES §E.2.6 Per-entry sealing, Values of another resource: a value
// nested in an entry ({ "sealed" } alone: born in place, file) that
// stands for the entry's own was compared with the entry's namespace only
// where the entry's own sealed value had opened. An entry with no own
// "sealed", or one that didn't open, let any namespace's value of the
// same resource name pass as its own, in a catalog the caller named and
// knows sealed. It is now of the namespace the answer is of (or the one
// the entry's href names), or of a confirmed branch of it; with no
// namespace to compare with it isn't the entry's own. A value that hangs
// on no entry is of the answer's namespace or a branch of it.
func TestV082Xrev3bNestedValueOfAnotherNamespace(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=root"
	s := newXrev2Sealer(t, view)
	born := func(ns, name, id string) string { return s.val(ns, name, `{"born":"`+id+`"}`) }
	body := `{
	 "paths": [["filed"]],
	 "nodes": {"filed": {"href":"/r/cat/filed","born":{"sealed":"` + born("secret", "filed", "1evil") + `"}}},
	 "children": [
	  {"name":"docs","href":"/r/cat/docs","kind":"folder","born":{"sealed":"` + born("secret", "docs", "1evil") + `"}},
	  {"name":"matches.derby","href":"/r/cat/matches.derby","kind":"item","item":"/r/matches/derby","file":{"sealed":"` + s.val("secret", "matches.derby", `{"file":{"size":666}}`) + `"}},
	  {"name":"failed","href":"/r/cat/failed","kind":"folder","sealed":"` + s.val("cat", "docs", `{"title":"x"}`) + `","born":{"sealed":"` + born("secret", "failed", "1evil") + `"}},
	  {"name":"mine","href":"/r/cat/mine","kind":"folder","born":{"sealed":"` + born("cat", "mine", "1mine") + `"}},
	  {"name":"preview","href":"/r/cat/preview","kind":"folder","born":{"sealed":"` + born("cat-r7", "preview", "1branch") + `"}},
	  {"name":"far","href":"/r/cat/far","kind":"folder","born":{"sealed":"` + born("other-r7", "far", "1evil") + `"}},
	  {"name":"matches.final","href":"/r/cat/matches.final","kind":"item","item":"/r/matches/final","file":{"sealed":"` + s.val("matches", "final", `{"file":{"size":3}}`) + `"}},
	  {"name":"docs","href":"/r/cat/docs","kind":"folder","extra":{"sealed":"` + s.val("cat", "../x", `{"extra":1}`) + `"}}
	 ],
	 "loose": [{"sealed":"` + born("secret", "docs", "1evil") + `"}, {"sealed":"` + born("cat", "docs", "1cat") + `"}, {"sealed":"` + born("cat-r7", "docs", "1branch") + `"}],
	 "meta": {"deep": {"sealed":"` + born("secret", "docs", "1evil") + `"}}
	}`
	// The same entries where the caller names no namespace: the href's, and with neither nothing.
	bare := `{"children": [
	  {"name":"docs","href":"/r/cat/docs","kind":"folder","born":{"sealed":"` + born("secret", "docs", "1evil") + `"}},
	  {"name":"mine","href":"/r/cat/mine","kind":"folder","born":{"sealed":"` + born("cat", "mine", "1mine") + `"}},
	  {"name":"mine","kind":"folder","born":{"sealed":"` + born("cat", "mine", "1mine") + `"}}
	 ],
	 "loose": [{"sealed":"` + born("cat", "docs", "1cat") + `"}]
	}`
	// A whole answer whose kid names no namespace, which this harness's contentKey has a key for.
	kw := seal.NewKey()
	s.keys[xrev3bEvil+"/"] = b64u.EncodeToString(kw)
	vw, err := seal.ViewKey(kw, view)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := seal.Seal(vw, xrev3bEvil+"#1", seal.PL{"ns": xrev3bEvil, "view": view}, []byte(`{"children":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	type entry = map[string]any
	var out struct {
		WholeErr string
		Nodes    map[string]entry
		Children []entry
		Loose    []entry
		Meta     map[string]entry
		Bare     struct{ Children, Loose []entry }
		Asked    []string
	}
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  const b = JSON.parse(input.body);
  await openSealedEntries(b, input.view, undefined, undefined, { ns: 'cat', sealed: true });
  out.nodes = b.nodes; out.children = b.children; out.loose = b.loose; out.meta = b.meta;
  out.bare = JSON.parse(input.bare);
  await openSealedEntries(out.bare, input.view);
  out.asked = asked;
  try { await openSealed('', input.whole, '', { ns: input.evil, view: input.view }); out.wholeErr = ''; } catch (e) { out.wholeErr = e.message; }
`, map[string]any{"view": view, "keys": s.keys, "body": body, "bare": bare, "whole": whole, "evil": xrev3bEvil, "head": xrev2Head, "docs": map[string]any{
		"secret":   map[string]any{"read": "public"},
		"cat-r7":   map[string]any{"base": map[string]any{"ns": "cat", "at": xrev2Head}},
		"other-r7": map[string]any{"base": map[string]any{"ns": "other", "at": xrev2Head}},
	}}, &out)
	// A value isn't shown: dropped, or left sealed with its error.
	refused := func(what string, v any, key string) {
		t.Helper()
		m, _ := v.(entry)
		if m == nil {
			return
		}
		if m["_opened"] != nil || m[key] != nil || m["_sealedErr"] == nil {
			t.Errorf("%s: a value sealed for another namespace is shown in catalog cat: %v", what, m)
		}
	}
	opened := func(what string, v any, key string, want any) {
		t.Helper()
		m, _ := v.(entry)
		if m == nil || m["_sealedErr"] != nil || m["_opened"] == nil {
			t.Errorf("%s: not opened: %v", what, v)
			return
		}
		if f, ok := m[key].(entry); ok {
			m = f
			key = "size"
		}
		if m[key] != want {
			t.Errorf("%s: %s is %v, want %v", what, key, m[key], want)
		}
	}
	refused("nodes[filed]", out.Nodes["filed"]["born"], "born")
	if len(out.Children) != 8 || len(out.Loose) != 3 || len(out.Bare.Children) != 3 || len(out.Bare.Loose) != 1 {
		t.Fatalf("children %v, loose %v, bare %v", out.Children, out.Loose, out.Bare)
	}
	refused("child docs (no own sealed)", out.Children[0]["born"], "born")
	refused("child matches.derby (file of its own name, another namespace)", out.Children[1]["file"], "file")
	refused("child failed (own sealed doesn't open)", out.Children[2]["born"], "born")
	opened("child mine (born of the catalog, no own sealed)", out.Children[3]["born"], "born", "1mine")
	opened("child preview (born of a branch of the catalog)", out.Children[4]["born"], "born", "1branch")
	refused("child far (born of another namespace's branch)", out.Children[5]["born"], "born")
	opened("child matches.final (file of its item)", out.Children[6]["file"], "file", float64(3))
	refused("a value whose pl names no resource name", out.Children[7]["extra"], "extra")
	if !strings.Contains(out.WholeErr, "§3.6") {
		t.Errorf("openSealed of a JWE whose kid names no namespace, with a key for it: %q", out.WholeErr)
	}
	refused("a value on no entry, of another namespace", out.Loose[0], "born")
	opened("a value on no entry, of the catalog", out.Loose[1], "born", "1cat")
	opened("a value on no entry, of a branch of the catalog", out.Loose[2], "born", "1branch")
	refused("a value under a member with neither name nor item", out.Meta["deep"], "born")
	refused("no namespace given, the href's: child docs", out.Bare.Children[0]["born"], "born")
	opened("no namespace given, the href's: child mine", out.Bare.Children[1]["born"], "born", "1mine")
	refused("no namespace given and no href", out.Bare.Children[2]["born"], "born")
	if out.Bare.Children[2]["born"] == nil {
		t.Error("an entry of no known namespace lost its born, which should stand sealed with its error")
	}
	refused("a value on no entry in an answer of no known namespace", out.Bare.Loose[0], "born")
}

// xrev3bEvil is in the place of a namespace what a service can put into a
// JWE header's kid: "/ns/" + it is, to a browser, a request elsewhere.
const xrev3bEvil = "a/../../r/victim/planted?"

// xrev3bKeyFns are app.js's own key and namespace document readers, with
// api recorded: nothing between a kid and the requests it leads to is a
// stub.
var xrev3bKeyFns = []string{"openSealed", "decrypted", "nsDocPL", "nsHeadDoc", "branchBase", "openSealedEntries", "contentKey", "fetchKeyFor", "nsInfo", "keyringKey", "keyFrom", "holdRes", "holdEpoch"}

const xrev3bKeyPreload = `const KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
globalThis.ID = { d: 'x', x: 'x' };
globalThis.$ = () => ({ value: 'GRANT' }); globalThis.takeKeys = async () => 0; globalThis.renderEntry = () => {}; globalThis.renderKeysHeld = () => {};`

// The kid of a service's JWE header names a namespace, which the page
// put, unchecked, into GET /ns/{ns} and POST /ns/{ns}/keys, sent with the
// reader's credentials. Read through openSealedEntries, in a catalog the
// caller named and in an answer of no known namespace, such a value now
// leads to no request.
func TestV082Xrev3bNestedValueKidReachesNoRequest(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=root"
	evil := func(name string) string {
		j, err := seal.Seal(seal.NewKey(), xrev3bEvil+"#1", seal.PL{"ns": xrev3bEvil, "name": name, "view": view}, []byte(`{"born":"1x"}`))
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	// A kid of a real namespace on a value whose pl names no resource name.
	odd, err := seal.Seal(seal.NewKey(), "cat#1", seal.PL{"ns": "cat", "name": "../../ns/victim", "view": view}, []byte(`{"born":"1x"}`))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"children": [{"name":"docs","href":"/r/cat/docs","kind":"folder","born":{"sealed":"` + evil("docs") + `"}}]}`
	// With nothing to compare a kid with: an entry's own value, a nested one, and one on no entry.
	bare := `{"children": [
	  {"name":"docs","kind":"folder","sealed":"` + evil("docs") + `"},
	  {"name":"docs","kind":"folder","extra":{"sealed":"` + evil("other") + `"}},
	  {"name":"docs","kind":"folder","extra":{"sealed":"` + odd + `"}},
	  {"sealed":"` + evil("docs") + `"}
	 ]}`
	var out struct {
		Asked, BareAsked []string
		Bare             struct{ Children []map[string]any }
	}
	runV82(t, xrev3bKeyFns, xrev3bKeyPreload, `
  const b = JSON.parse(input.body);
  await openSealedEntries(b, input.view, undefined, undefined, { ns: 'cat', sealed: true });
  out.asked = asked.slice();
  asked.length = 0;
  out.bare = JSON.parse(input.bare);
  await openSealedEntries(out.bare, input.view);
  out.bareAsked = asked.slice();
`, map[string]any{"view": view, "body": body, "bare": bare}, &out)
	for _, a := range append(out.Asked, out.BareAsked...) {
		if strings.Contains(a, "..") || strings.Contains(a, "victim") {
			t.Errorf("the page requested with the reader's credentials: %s", a)
		}
	}
	if len(out.Asked) != 0 || len(out.BareAsked) != 0 {
		t.Errorf("requests for values whose kid or pl names no name: %v, %v", out.Asked, out.BareAsked)
	}
	if len(out.Bare.Children) != 4 {
		t.Fatalf("bare: %v", out.Bare)
	}
	for i, c := range out.Bare.Children {
		v := c
		if x, ok := c["extra"].(map[string]any); ok {
			v = x
		}
		if e, _ := v["_sealedErr"].(string); !strings.Contains(e, "§3.6") || v["_opened"] != nil || v["born"] != nil {
			t.Errorf("bare entry %d: %v", i, v)
		}
	}
}

// Each layer under openSealedEntries refuses what is no name by itself
// (SPEC §3.6: names go into URLs verbatim): contentKey gives no key, held
// or not, and fetchKeyFor, keyringKey, nsInfo, nsHeadDoc, branchBase and
// openSealed (a whole answer's JWE, whose pl a service wrote) ask for
// nothing. A namespace that is one is asked about as before.
func TestV082Xrev3bNamesAreCheckedBeforeRequests(t *testing.T) {
	t.Parallel()
	whole, err := seal.Seal(seal.NewKey(), xrev3bEvil+"#1", seal.PL{"ns": xrev3bEvil, "view": "/v"}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]struct {
		Asked []string
		Err   string
		V     any
	}
	runV82(t, xrev3bKeyFns, xrev3bKeyPreload, `
  const evil = input.evil, kid = evil + '#1', long = 'n'.repeat(65);
  const tryIt = async (name, f) => {
    asked.length = 0;
    let err = '', v = null;
    try { v = await f(); } catch (e) { err = e.message; }
    out[name] = { asked: asked.slice(), err, v: v instanceof Uint8Array ? 'key' : v === undefined ? null : v };
  };
  const k = new Uint8Array(32);
  // Held keys: without its own check contentKey would give or derive one, asking nothing.
  KEYS.epoch.set(kid, k); KEYS.res.set(kid + '\ndocs', k); KEYS.epoch.set('held#1', k);
  await tryIt('contentKey, kid', () => contentKey(kid, 'docs'));
  await tryIt('contentKey, kid, K_n', () => contentKey(kid, ''));
  await tryIt('contentKey, resource', () => contentKey('held#1', '../x'));
  await tryIt('contentKey, long resource', () => contentKey('held#1', 'r'.repeat(129)));
  await tryIt('contentKey, held', () => contentKey('held#1', 'docs'));
  await tryIt('fetchKeyFor, kid', () => fetchKeyFor(kid, 'docs'));
  await tryIt('fetchKeyFor, kid, K_e', () => fetchKeyFor(kid, ''));
  await tryIt('fetchKeyFor, long kid', () => fetchKeyFor(long + '#1', ''));
  await tryIt('fetchKeyFor, resource', () => fetchKeyFor('cat#1', 'a/b'));
  await tryIt('fetchKeyFor, cat', () => fetchKeyFor('cat#1', 'docs'));
  await tryIt('keyringKey', () => keyringKey(evil, 1));
  await tryIt('nsInfo', () => nsInfo(evil));
  await tryIt('nsInfo, array', () => nsInfo(['cat']));
  await tryIt('nsInfo, cat', () => nsInfo('cat2'));
  await tryIt('nsHeadDoc', () => nsHeadDoc(evil));
  await tryIt('nsHeadDoc, cat', () => nsHeadDoc('cat'));
  await tryIt('branchBase', () => branchBase(evil));
  await tryIt('branchBase, long', () => branchBase(long));
  await tryIt('branchBase, cat', () => branchBase('cat3'));
  KEYS.epoch.delete(kid); KEYS.res.clear();
  await tryIt('openSealed', () => openSealed(Z.parseJWE(input.whole).header.pl.ns, input.whole, '', { ns: evil, view: '/v' }));
  await tryIt('openSealed, any namespace', () => openSealed('', input.whole, '', { ns: evil, view: '/v' }));
`, map[string]any{"evil": xrev3bEvil, "whole": whole}, &out)
	for _, name := range []string{"contentKey, kid", "contentKey, kid, K_n", "contentKey, resource", "contentKey, long resource", "fetchKeyFor, kid", "fetchKeyFor, kid, K_e",
		"fetchKeyFor, long kid", "fetchKeyFor, resource", "keyringKey", "openSealed", "openSealed, any namespace"} {
		if o := out[name]; len(o.Asked) != 0 || !strings.Contains(o.Err, "§3.6") || o.V != nil {
			t.Errorf("%s: asked %v, error %q, value %v", name, o.Asked, o.Err, o.V)
		}
	}
	for _, name := range []string{"nsInfo", "nsInfo, array"} {
		o := out[name]
		m, _ := o.V.(map[string]any)
		if len(o.Asked) != 0 || o.Err != "" || m == nil || m["level"] != "" || m["doc"] != nil || m["refused"] == nil {
			t.Errorf("%s: asked %v, error %q, value %v", name, o.Asked, o.Err, o.V)
		}
	}
	if o := out["nsHeadDoc"]; len(o.Asked) != 0 || o.Err != "" || o.V.(map[string]any)["status"] != float64(400) {
		t.Errorf("nsHeadDoc: %+v", o)
	}
	for _, name := range []string{"branchBase", "branchBase, long"} {
		if o := out[name]; len(o.Asked) != 0 || o.Err != "" || o.V != "" {
			t.Errorf("%s: %+v", name, o)
		}
	}
	// What is a name is read as before.
	if o := out["contentKey, held"]; o.V != "key" || o.Err != "" || len(o.Asked) != 0 {
		t.Errorf("contentKey of a held epoch: %+v", o)
	}
	for name, want := range map[string]string{
		"fetchKeyFor, cat": "GET /ns/cat,POST /ns/cat/keys",
		"nsInfo, cat":      "GET /ns/cat2",
		"nsHeadDoc, cat":   "GET /ns/cat",
		"branchBase, cat":  "GET /ns/cat3",
	} {
		if o := out[name]; strings.Join(o.Asked, ",") != want {
			t.Errorf("%s asked %v, want %s", name, o.Asked, want)
		}
	}
}

// branchBase kept only the bases it found: every entry of a listing whose
// kid named a namespace that is no branch cost one credentialed GET of
// that namespace's document. That a namespace is no branch is now kept
// while one answer is read, and asked again for the next (a namespace may
// be created later); a base, which never changes, is kept for the page.
func TestV082Xrev3bBranchBaseAsksOncePerAnswer(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=root"
	s := newXrev2Sealer(t, view)
	var kids []string
	for _, e := range []struct{ name, ns string }{
		{"a", "secret"}, {"b", "secret"}, {"c", "secret"}, {"d", "absent"}, {"e", "absent"}, {"f", "cat-r7"}, {"g", "cat-r7"},
	} {
		kids = append(kids, `{"name":"`+e.name+`","href":"/r/cat/`+e.name+`","kind":"folder","sealed":"`+s.val(e.ns, e.name, `{"title":"T"}`)+`",
		  "born":{"sealed":"`+s.val(e.ns, e.name, `{"born":"1b"}`)+`"}}`)
	}
	body := `{"children": [` + strings.Join(kids, ",") + `], "loose": [{"sealed":"` + s.val("secret", "a", `{"born":"1b"}`) + `"}]}`
	var out struct {
		First, Second, Direct []string
		Children              []map[string]any
	}
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  const read = async () => {
    asked.length = 0;
    const b = JSON.parse(input.body);
    await openSealedEntries(b, input.view, undefined, undefined, { ns: 'cat', sealed: true });
    out.children = b.children;
    return asked.slice();
  };
  out.first = await read();
  out.second = await read();
  // Without the caller's set nothing negative is kept.
  asked.length = 0;
  await branchBase('secret'); await branchBase('secret'); await branchBase('cat-r7');
  out.direct = asked.slice();
`, map[string]any{"view": view, "keys": s.keys, "body": body, "head": xrev2Head, "docs": map[string]any{
		"secret": map[string]any{"read": "public"},
		"cat-r7": map[string]any{"base": map[string]any{"ns": "cat", "at": xrev2Head}},
	}}, &out)
	if got := strings.Join(out.First, ","); got != "GET /ns/secret,GET /ns/absent,GET /ns/cat-r7" {
		t.Errorf("the first answer's requests: %v", out.First)
	}
	if got := strings.Join(out.Second, ","); got != "GET /ns/secret,GET /ns/absent" {
		t.Errorf("the second answer's requests (what is no branch asked again, once; a base kept): %v", out.Second)
	}
	if got := strings.Join(out.Direct, ","); got != "GET /ns/secret,GET /ns/secret" {
		t.Errorf("branchBase with no set: %v", out.Direct)
	}
	if len(out.Children) != 7 {
		t.Fatalf("children: %v", out.Children)
	}
	for i, c := range out.Children {
		if branch := i >= 5; (c["title"] == "T") != branch || (c["_sealedErr"] == nil) != branch {
			t.Errorf("child %d: %v", i, c)
		}
	}
}

// branchBase read a namespace's document through nsHeadDoc, without the
// refusal nsInfo applies (§7.1, Levels): a document in the clear, naming
// a base, for a namespace this browser holds as sealed or e2e made that
// namespace a "branch" of the catalog, and its values the catalog's. A
// document naming a lower level than held now names no base; one naming
// the level held, or a higher one, does, and teaches its level.
func TestV082Xrev3bBranchBaseKeepsTheLevelHeld(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=root"
	s := newXrev2Sealer(t, view)
	base := `"base":{"ns":"cat","at":"` + xrev2Head + `"}`
	clear := func(level string) map[string]any {
		d := map[string]any{"base": map[string]any{"ns": "cat", "at": xrev2Head}}
		if level != "" {
			d["encryption"] = map[string]any{"level": level, "epoch": 1}
		}
		return d
	}
	docs := map[string]any{
		"held-sealed-clear":   clear(""),
		"held-sealed-atrest":  clear("at-rest"),
		"held-sealed-unknown": clear("zz"),
		"held-sealed-sealed":  s.nsDoc("held-sealed-sealed", `{`+base+`,"encryption":{"level":"sealed","epoch":1}}`),
		"held-sealed-e2e":     clear("e2e"),
		"held-e2e-clear":      clear(""),
		"held-e2e-sealed":     s.nsDoc("held-e2e-sealed", `{`+base+`,"encryption":{"level":"sealed","epoch":1}}`),
		"held-e2e-e2e":        clear("e2e"),
		"held-none-clear":     clear(""),
		"held-none-atrest":    clear("at-rest"),
	}
	var kids []string
	for _, ns := range []string{"held-sealed-clear", "held-sealed-sealed", "held-e2e-clear", "held-e2e-e2e"} {
		kids = append(kids, `{"name":"docs","href":"/r/cat/docs","kind":"folder","sealed":"`+s.val(ns, "docs", `{"title":"T"}`)+`"}`)
	}
	var out struct {
		Base, Held map[string]string
		Children   []map[string]any
	}
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  for (const ns of Object.keys(input.docs)) { const l = ns.split('-')[1]; if (l !== 'none') Z.expectLevel(ns, l); }
  const b = JSON.parse(input.body);
  await openSealedEntries(b, input.view, undefined, undefined, { ns: 'cat', sealed: true });
  out.children = b.children;
  out.base = {}; out.held = {};
  for (const ns of Object.keys(input.docs)) { out.base[ns] = await branchBase(ns); out.held[ns] = Z.heldLevel(ns); }
`, map[string]any{"view": view, "keys": s.keys, "body": `{"children": [` + strings.Join(kids, ",") + `]}`, "head": xrev2Head, "docs": docs}, &out)
	for ns, want := range map[string][2]string{
		"held-sealed-clear":   {"", "sealed"},
		"held-sealed-atrest":  {"", "sealed"},
		"held-sealed-unknown": {"", "sealed"},
		"held-sealed-sealed":  {"cat", "sealed"},
		"held-sealed-e2e":     {"cat", "e2e"},
		"held-e2e-clear":      {"", "e2e"},
		"held-e2e-sealed":     {"", "e2e"},
		"held-e2e-e2e":        {"cat", "e2e"},
		"held-none-clear":     {"cat", ""},
		"held-none-atrest":    {"cat", "at-rest"},
	} {
		if out.Base[ns] != want[0] || out.Held[ns] != want[1] {
			t.Errorf("%s: base %q, level held %q; want %q, %q", ns, out.Base[ns], out.Held[ns], want[0], want[1])
		}
	}
	if len(out.Children) != 4 {
		t.Fatalf("children: %v", out.Children)
	}
	for i, branch := range []bool{false, true, false, true} {
		c := out.Children[i]
		if (c["title"] == "T") != branch || (c["_sealedErr"] == nil) != branch {
			t.Errorf("child %d, a value of a namespace whose document %s: %v", i, map[bool]string{true: "names cat as its base at the level held", false: "is in the clear below the level held"}[branch], c)
		}
	}
}
