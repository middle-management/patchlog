package playground

import (
	"strings"
	"testing"
)

// v0.86 §7.1 End-to-end namespaces ("It holds for a branch at least the
// level it holds for any base in the branch's base chain (Levels)";
// HTTP-68; Encryption levels scenario 94), in the playground (seal.js's
// levels, app.js's nsInfo and readDoc): with sealed held for n from the
// setting, a z document naming n as its base and claiming at-rest, or
// nothing, is refused, and so is a plaintext 200 of a document of z, read
// through or its own; the chain is kept, so z stays held when its
// document is unreadable later. A holder of sealed refuses a plaintext
// 200 in n itself too, the resource named keyring included. The chain is
// followed through every base whose document was read; an unrelated one
// is not in it. Until v0.86 a level was held per
// namespace only, and only a holder of e2e refused a document in the
// clear.
func TestV086PlaygroundBranchLevelWithNode(t *testing.T) {
	t.Parallel()
	const id = "1nyv2d2ibcop4nnp4k5niguadz7lvyjad"
	var out map[string]struct {
		Level, Lowered string
		Doc            any
		Read           any
		ReadErr        string
		Keyring        any
		Held           string
		Stored         map[string][]string
	}
	runV82(t, []string{"nsInfo", "revTarget", "notOffered", "readDoc"}, `
const mem = new Map();
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => { mem.set(k, String(v)); } };
globalThis.location = { origin: 'https://o.example' };
`, `
  const plain = (ns) => { routes['/r/' + ns + '/d/rev/' + input.id] = { status: 200, json: { title: 'in the clear' } }; routes['/r/' + ns + '/keyring/rev/' + input.id] = { status: 200, json: { keys: [] } }; };
  const read = async (key, ns) => {
    nsInfoCache.clear();
    const info = await nsInfo(ns);
    const d = await readDoc(ns, 'd', input.id, await api('GET', '/r/' + ns + '/d/rev/' + input.id));
    const k = await readDoc(ns, 'keyring', input.id, await api('GET', '/r/' + ns + '/keyring/rev/' + input.id));
    out[key] = { level: info.level, lowered: info.lowered || '', doc: info.doc, read: d.doc, readErr: d.foldErr || '', keyring: k.doc, held: Z.heldLevel(ns) };
  };
  const base = (ns) => ({ ns, at: input.id });
  // Scenario 94: sealed held for n by the setting, nothing learnt for z.
  Z.expectLevel('n', 'sealed'); plain('z'); plain('n');
  out['before'] = { held: Z.heldLevel('z') };
  routes['/ns/z'] = { status: 200, json: { base: base('n'), encryption: { level: 'at-rest' } } };
  await read('z claims at-rest', 'z');
  routes['/ns/z'] = { status: 200, json: { base: base('n') } };
  await read('z claims nothing', 'z');
  routes['/ns/z'] = { status: 403, json: { code: 'forbidden' } };
  await read('z unreadable later', 'z');
  routes['/ns/z'] = { status: 200, jose: true, text: 'eyJ.x.y.z.w', json: null };
  await read('z served sealed', 'z');
  routes['/ns/n'] = { status: 404, json: { code: 'not_found' } };
  await read('n itself', 'n');
  // A chain of two: m is e2e by the setting, n2 a branch of m, z2 of n2.
  Z.expectLevel('m', 'e2e'); plain('z2');
  routes['/ns/n2'] = { status: 200, json: { base: base('m'), encryption: { level: 'e2e', epoch: 1 } } };
  routes['/ns/z2'] = { status: 200, json: { base: base('n2'), encryption: { level: 'sealed', epoch: 1 } } };
  await read('z2 before n2 is read', 'z2');
  nsInfoCache.clear(); await nsInfo('n2');
  await read('z2 after n2 is read', 'z2');
  // A base nothing is held for.
  plain('q');
  routes['/ns/q'] = { status: 200, json: { base: base('p') } };
  await read('a branch of another', 'q');
  out['stored'] = { stored: JSON.parse(localStorage.getItem('pl.bases')) };
  // Forgetting z drops its chain: the user's own act.
  Z.forgetLevel('z');
  out['forgotten'] = { held: Z.heldLevel('z'), stored: JSON.parse(localStorage.getItem('pl.bases')) };
`, map[string]any{"id": id}, &out)

	if out["before"].Held != "" {
		t.Errorf("before z's document is read: %+v", out["before"])
	}
	for _, key := range []string{"z claims at-rest", "z claims nothing"} {
		g := out[key]
		if g.Level != "sealed" || g.Held != "sealed" || !strings.Contains(g.Lowered, "a base it is a branch of") || g.Doc != nil {
			t.Errorf("%s: the claim below the base's level wasn't refused: %+v", key, g)
		}
	}
	for _, key := range []string{"z claims at-rest", "z claims nothing", "z unreadable later", "z served sealed", "n itself"} {
		g := out[key]
		if g.Level != "sealed" || g.Held != "sealed" || g.Read != nil || !strings.Contains(g.ReadErr, "holds as sealed") || g.Keyring != nil {
			t.Errorf("%s: a plaintext 200 where sealed is held: %+v", key, g)
		}
	}
	if g := out["z served sealed"]; g.Lowered != "" {
		t.Errorf("a z served sealed is the level held for its base: %+v", g)
	}
	if g := out["z2 before n2 is read"]; g.Level != "sealed" || g.Held != "sealed" || g.Lowered != "" {
		t.Errorf("z2, its base's document unread: %+v", g)
	}
	if g := out["z2 after n2 is read"]; g.Level != "e2e" || g.Held != "e2e" || g.Lowered == "" || g.Read != nil || g.Keyring == nil {
		t.Errorf("z2 under an e2e chain: %+v", g)
	}
	if g := out["a branch of another"]; g.Level != "" || g.Held != "" || g.Read == nil || g.ReadErr != "" {
		t.Errorf("a branch of a namespace nothing is held for: %+v", g)
	}
	st := out["stored"].Stored
	if len(st["https://o.example z"]) != 1 || st["https://o.example z"][0] != "n" {
		t.Errorf("the chain as stored: %v", st)
	}
	if g := out["forgotten"]; g.Held != "" || len(g.Stored["https://o.example z"]) != 0 {
		t.Errorf("forgotten: %+v", g)
	}
}

// v0.86 §E.2.2 ("Where they can't place that parent, the op fails the
// check"), §E.3.1 (a prune's snapshot "is one such op"), §G.4.1: app.js's
// nsChainOK, with the namespace documents and /heads given. z is a
// branch of n, a branch of m; d forked from n at F1 and from m at F2.
//
//   - A snapshot sealed under a base is read through at the fork or
//     before it, never past it: the playground checked no fork for a
//     snapshot until v0.86.
//   - A fork is placed from the base's /heads, else from the branch's own
//     at its first namespace entry; one placed by neither refuses every
//     namespace behind it, while a nearer base is still accepted up to
//     its own fork; and it is asked for again later, not kept as unplaced.
func TestV086PlaygroundChainCheckWithNode(t *testing.T) {
	t.Parallel()
	ids := map[string]string{}
	for i, k := range []string{"A", "B", "F1", "F2", "W", "X", "G"} {
		ids[k] = "1" + strings.Repeat(string(rune('a'+i)), 32)
	}
	var out map[string]bool
	runV82(t, []string{"nsFirstEntry", "revPrecedes", "nsChainOK"}, `
const docs = {};
async function nsInfo(ns) { return { level: 'e2e', doc: docs[ns] || null }; }
`, `
  const I = input.ids;
  docs.z = { base: { ns: 'n', at: I.A } }; docs.n = { base: { ns: 'm', at: I.B } }; docs.m = {};
  const heads = (target) => ({ status: 200, json: { heads: [{ resource: 'c', kind: 'head', target: I.W }, { resource: 'd', kind: 'head', target }, { resource: 'e', kind: 'head', target: I.W }] } });
  const denied = { status: 403, json: { code: 'forbidden' } };
  const at = (seen, since, ids) => ({ name: 'd', seen: new Set(seen || []), since: since || '', ids: new Set(ids || []) });
  routes['/ns/n/rev/' + I.A + '/heads'] = heads(I.F1);
  routes['/ns/m/rev/' + I.B + '/heads'] = heads(I.F2);
  routes['/r/z/d/rev/' + I.F1 + '/log?since=' + I.W] = { status: 200, json: [] };
  // No fork check: membership in the chain.
  out['member n'] = await nsChainOK('z', 'n'); out['member m'] = await nsChainOK('z', 'm'); out['member x'] = await nsChainOK('z', 'x');
  // Every fork placed.
  out['n before its fork'] = await nsChainOK('z', 'n', at());
  out['n past its fork'] = await nsChainOK('z', 'n', at([I.F1]));
  out['m before both'] = await nsChainOK('z', 'm', at());
  out['m past its fork'] = await nsChainOK('z', 'm', at([I.F2]));
  // A snapshot (the range starts after it and holds nothing).
  out['snapshot at the fork'] = await nsChainOK('z', 'n', at([], I.F1));
  out['snapshot before the fork'] = await nsChainOK('z', 'n', at([], I.W));
  out['snapshot past the fork'] = await nsChainOK('z', 'n', at([], I.X));
  // A range that holds the fork is checked as it goes.
  out['range holding the fork'] = await nsChainOK('z', 'n', at([], I.W, [I.F1]));
  out.asked0 = asked.filter((p) => p.includes('/heads')).length === 2;

  // n's fork from m can't be placed: m's /heads and n's own log are closed.
  nsChainOK.forks = new Map();
  routes['/ns/m/rev/' + I.B + '/heads'] = denied;
  out['m, its fork unplaced'] = await nsChainOK('z', 'm', at());
  out['n, the nearer fork placed'] = await nsChainOK('z', 'n', at());
  out['n past its fork, still'] = await nsChainOK('z', 'n', at([I.F1]));
  // Placed from n's own /heads at its first namespace entry.
  routes['/ns/n/log'] = { status: 200, json: [{ id: I.G, prev: '', kind: 'config' }, { id: I.W, prev: I.G, kind: 'head' }] };
  routes['/ns/n/rev/' + I.G + '/heads'] = heads(I.F2);
  out['m, placed from n\'s own /heads'] = await nsChainOK('z', 'm', at());
  out['m past it'] = await nsChainOK('z', 'm', at([I.F2]));
  // A log that doesn't start with a config genesis places nothing.
  nsChainOK.forks = new Map();
  routes['/ns/n/log'] = { status: 200, json: [{ id: I.G, prev: '', kind: 'head' }] };
  out['no config genesis'] = await nsChainOK('z', 'm', at());
  // A base whose /heads this reader may not read: only the branch's own /heads at its first entry.
  nsChainOK.forks = new Map();
  docs.r = { base: { ns: 'q', at: I.A } }; docs.q = {};
  routes['/ns/q/rev/' + I.A + '/heads'] = denied;
  routes['/ns/r/log'] = { status: 200, json: [{ id: I.G, prev: '', kind: 'config' }] };
  routes['/ns/r/rev/' + I.G + '/heads'] = heads(I.F1);
  out['unread base q'] = await nsChainOK('r', 'q', at());
  out['q past the fork'] = await nsChainOK('r', 'q', at([I.F1]));
  out['not in the chain'] = await nsChainOK('r', 'x', at());
  // A partial reader's /heads is a redirect to its filtered listing, which api follows: it places no fork.
  nsChainOK.forks = new Map();
  routes['/ns/r/rev/' + I.G + '/heads'] = Object.assign(heads(I.F1), { finalPath: '/ns/r/view/' + I.W + '/rev/' + I.G + '/heads' });
  out['filtered /heads'] = await nsChainOK('r', 'q', at());
  routes['/ns/r/rev/' + I.G + '/heads'] = heads(I.F1);
  routes['/ns/r/log'] = { status: 200, json: [{ id: I.G, prev: '', kind: 'config' }], finalPath: '/ns/r/view/' + I.W + '/rev/' + I.X + '/log' };
  out['filtered namespace log'] = await nsChainOK('r', 'q', at());
  routes['/ns/r/log'] = { status: 200, json: [{ id: I.G, prev: '', kind: 'config' }], finalPath: '/ns/r/rev/' + I.X + '/log' };
  out['the range at the head'] = await nsChainOK('r', 'q', at());
  // Whether since precedes the fork: an answer of the moment concludes nothing and isn't kept.
  routes['/r/r/d/rev/' + I.F1 + '/log?since=' + I.W] = { status: 503, json: { code: 'behind' } };
  try { await nsChainOK('r', 'q', at([], I.W)); out['503 throws'] = false; } catch (e) { out['503 throws'] = true; }
  routes['/r/r/d/rev/' + I.F1 + '/log?since=' + I.W] = { status: 429, json: { code: 'rate_limited' } };
  try { await nsChainOK('r', 'q', at([], I.W)); out['429 throws'] = false; } catch (e) { out['429 throws'] = true; }
  routes['/r/r/d/rev/' + I.F1 + '/log?since=' + I.W] = { status: 200, json: [] };
  out['after the 503'] = await nsChainOK('r', 'q', at([], I.W));
  routes['/r/r/d/rev/' + I.F1 + '/log?since=' + I.X] = { status: 404, json: { code: 'not_found' } };
  out['a refusal is an answer'] = await nsChainOK('r', 'q', at([], I.X));
  // The base had no such resource: nothing is read through.
  routes['/ns/r/rev/' + I.G + '/heads'] = { status: 200, json: { heads: [{ resource: 'c', kind: 'head', target: I.W }] } };
  nsChainOK.forks = new Map();
  out['the base had none'] = await nsChainOK('r', 'q', at());
`, map[string]any{"ids": ids}, &out)
	for key, want := range map[string]bool{
		"member n": true, "member m": true, "member x": false,
		"n before its fork": true, "n past its fork": false, "m before both": true, "m past its fork": false,
		"snapshot at the fork": true, "snapshot before the fork": true, "snapshot past the fork": false,
		"range holding the fork": true, "asked0": true,
		"m, its fork unplaced": false, "n, the nearer fork placed": true, "n past its fork, still": false,
		"m, placed from n's own /heads": true, "m past it": false, "no config genesis": false,
		"unread base q": true, "q past the fork": false, "not in the chain": false, "the base had none": false,
		"filtered /heads": false, "filtered namespace log": false, "the range at the head": true,
		"503 throws": true, "429 throws": true, "after the 503": true, "a refusal is an answer": false,
	} {
		if got, ok := out[key]; !ok || got != want {
			t.Errorf("%s: %v (present %v), want %v", key, got, ok, want)
		}
	}
}

// v0.86 SERVICES §B.5 Previews ("A reader accepts an entry sealed under a
// namespace other than the catalog's, or a value sealed under one other
// than its item's (§E.2.6), only where the namespace documents it reads
// (§7.4) put the catalog's or item's namespace in the local base chain of
// the one the seal's pl.ns names. Otherwise it shows the entry by name
// only"; Encryption levels scenarios 92 and 93), in the playground's
// openSealedEntries. A catalog entry sealed under a release branch of the
// catalog opens, and so does one sealed under a branch of that branch,
// which until v0.86 the playground followed for an item's value only. One
// sealed under a namespace whose document the reader can't read, or a
// branch of something else shows by name only; so does an
// item's value sealed under such a namespace.
func TestV086PlaygroundPreviewChainWithNode(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=docs"
	s := newXrev2Sealer(t, view)
	local := func(base string) map[string]any {
		return map[string]any{"base": map[string]any{"ns": base, "at": xrev2Head}}
	}
	docs := map[string]any{
		"cat-r": local("cat"), "cat-rr": local("cat-r"), "cat-other": local("elsewhere"),
		"matches-r": local("matches"), "matches-rr": local("matches-r"), "matches-other": local("elsewhere"),
	}
	// Each child: the namespace its own value is sealed under, and the one
	// its item's file value is, named by its content URL.
	cases := []struct{ entryNS, itemNS string }{
		{"cat-r", "matches-r"},           // 0: a release preview
		{"cat-rr", "matches-rr"},         // 1: a stacked one
		{"cat-unread", "matches-unread"}, // 2: documents the reader can't read
		{"cat-other", "matches-other"},   // 3: branches of something else
		{"cat", "matches"},               // 4: no preview
	}
	var kids []any
	for _, c := range cases {
		kids = append(kids, map[string]any{"name": "matches.derby", "href": "/r/cat/matches.derby", "kind": "item", "item": "/r/matches/derby",
			"title":  "a title in the clear",
			"url":    "https://cms.example/r/" + c.itemNS + "/derby/rev/" + xrev2Head,
			"sealed": s.val(c.entryNS, "matches.derby", `{"title":"Derby"}`),
			"file":   map[string]any{"sealed": s.val(c.itemNS, "derby", `{"file":{"name":"derby.md"}}`)}})
	}
	var out struct {
		Children []struct {
			Name  string `json:"name"`
			Title string `json:"title"`
			Err   string `json:"_sealedErr"`
			File  struct {
				File any    `json:"file"`
				Err  string `json:"_sealedErr"`
			} `json:"file"`
		} `json:"children"`
		Asked []string
	}
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  routes['/ns/cat-unread'] = { status: 403, json: { code: 'forbidden' } };
  routes['/ns/matches-unread'] = { status: 403, json: { code: 'forbidden' } };
  const body = input.body;
  await openSealedEntries(body, input.view, undefined, undefined, { ns: 'cat', sealed: true });
  out.children = body.children;
  out.asked = asked;
`, map[string]any{"view": view, "keys": s.keys, "body": map[string]any{"children": kids}, "head": xrev2Head, "docs": docs}, &out)
	if len(out.Children) != len(cases) {
		t.Fatalf("children: %+v", out.Children)
	}
	for i, c := range out.Children {
		opens := i == 0 || i == 1 || i == 4
		if c.Name != "matches.derby" {
			t.Errorf("child %d: the name is gone: %+v", i, c)
		}
		switch {
		case opens && (c.Title != "Derby" || c.Err != ""):
			t.Errorf("child %d (%s): the entry's own value isn't opened: %+v", i, cases[i].entryNS, c)
		case !opens && (c.Title != "" || c.Err == ""):
			t.Errorf("child %d (%s): shown with a title, not by name only: %+v", i, cases[i].entryNS, c)
		}
		switch {
		case opens && (c.File.File == nil || c.File.Err != ""):
			t.Errorf("child %d (%s): the item's value isn't opened: %+v", i, cases[i].itemNS, c.File)
		case !opens && (c.File.File != nil || c.File.Err == ""):
			t.Errorf("child %d (%s): the item's value was opened: %+v", i, cases[i].itemNS, c.File)
		}
	}
	// A base is confirmed by the branch's own document: the catalog's and
	// the item's own are never asked for.
	for _, a := range out.Asked {
		if a == "GET /ns/cat" || a == "GET /ns/matches" {
			t.Errorf("the reader asked %s", a)
		}
	}
}
