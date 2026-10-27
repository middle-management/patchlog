package playground

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// undoPrelude runs app.js's undo procedure (extracted, with api over fetch,
// sending input.bearer if given, and the sealed-content key stubbed with
// the namespace's epoch key, input.key or input.nsKeys[ns]) against a live
// server; the scenarios follow
// it (undoHarness, undoLimitedHarness).
const undoPrelude = `
const fs = require('fs');
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
const ID_RE = /^1[a-z2-7]{32}$/;
const short = (id) => id || '';
const httpFail = (r) => new Error('HTTP ' + r.status + (r.json && r.json.code ? ' ' + r.json.code : ''));
const S = { ns: '', nsLogErr: '' };
const KEY = Z.unb64u(input.key);
const NS_KEYS = Object.fromEntries(Object.entries(input.nsKeys || {}).map(([ns, k]) => [ns, Z.unb64u(k)]));
async function api(method, path, o = {}) {
  const headers = { 'X-Author': input.author };
  if (input.bearer) headers.Authorization = 'Bearer ' + input.bearer;
  let body = o.body;
  if (body !== undefined) { if (typeof body !== 'string') body = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
  const res = await fetch(input.base + path, { method, headers, body, redirect: 'follow' });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { /* not JSON */ }
  const u = new URL(res.url);
  return { status: res.status, ok: res.ok, json, text, finalPath: u.pathname + u.search,
    jose: /^application\/jose\b/i.test(res.headers.get('Content-Type') || ''), hdr: (k) => res.headers.get(k),
    etag() { const v = res.headers.get('ETag'); return v ? v.replace(/^"|"$/g, '') : ''; } };
}
async function contentKey(kid, resource) {
  const ns = Z.parseKid(kid).ns, key = NS_KEYS[ns] || KEY;
  return resource ? Z.resourceKey(key, ns, resource) : key;
}
async function decrypted(r, ns, resource, want) {
  try { const d = await openSealed(ns, r.text.trim(), resource, want); return { value: d.value, kid: d.kid }; }
  catch (err) { return { value: null, error: err.message }; }
}
FUNCTIONS
`

// undoHarness runs the scenarios of TestUndoWithNode.
const undoHarness = undoPrelude + `
(async () => {
  const out = {};
  const g = input.g;
  // A: a gesture over three resources and two saves, with bob's edit in between: undo, then redo.
  const planA = await undoPlan('docs', g, {});
  out.planA = { source: planA.source, author: planA.author, writes: planA.resources.map((r) => r.resource + ':' + r.writes.join(',')) };
  const u = await undoRun('docs', g, {});
  out.undoA = { ok: !!u.ok, gesture: u.gesture, items: u.ok ? u.plan.items.length : 0 };
  out.afterUndo = (await api('GET', '/r/docs/a')).json;
  const latest = await undoLatest('docs', g, 'alice');
  out.latest = latest && latest.gesture;
  const r = await undoRun('docs', latest.gesture, { author: 'alice', scanLog: true });
  out.redoA = { ok: !!r.ok, gesture: r.gesture, source: r.ok ? r.plan.source : '' };
  // B: a later overlapping edit is a conflict.
  const b = await undoRun('docs', input.gd, {});
  out.conflictB = b.conflicts || null;
  // C: pruned.
  const c = await undoRun('docs', input.gp, {});
  out.prunedC = { impossible: c.impossible || '', resource: c.resource || '' };
  // D: a move is moved back.
  const d = await undoPlan('docs', input.gm, {});
  out.moveD = d.items.length ? d.items[0].steps : null;
  out.moveDone = !!(await undoRun('docs', input.gm, {})).ok;
  // E: sealed: no listing, the namespace log is scanned, every set gets a fresh nonce.
  S.ns = 's';
  const e = await undoRun('s', input.gs, { level: 'sealed' });
  out.sealedE = { ok: !!e.ok, source: e.ok ? e.plan.source : '', steps: e.ok ? e.plan.items[0].steps : null, err: e.refused || e.impossible || '' };
  // F: a namespace that came to require nonces after the gesture: the set gets a fresh one, though the document has none.
  S.ns = 'n';
  const f = await undoRun('n', input.gn, { nonce: needsNonce((await api('GET', '/ns/n')).json) });
  out.nonceF = { ok: !!f.ok, steps: f.ok ? f.plan.items[0].steps : null, err: f.refused || f.impossible || '' };
  // G: a grant that can't read the namespace document doesn't know the setting: the set gets one all the same.
  S.ns = 'o';
  const gg = await undoRun('o', input.go, { nonce: needsNonce(null) });
  out.nonceG = { ok: !!gg.ok, steps: gg.ok ? gg.plan.items[0].steps : null, err: gg.refused || gg.impossible || '' };
  // H: there, an array has no member to add: its inverse goes without one.
  const hh = await undoRun('o', input.ga, { nonce: needsNonce(null) });
  out.nonceH = { ok: !!hh.ok, steps: hh.ok ? hh.plan.items[0].steps : null, err: hh.refused || hh.impossible || '' };
  // The stack, rebuilt from the namespace log.
  S.ns = 'docs';
  const st = undoStackFrom(await undoNSLog('docs'), 'alice');
  out.stack = { done: st.done.map((x) => x.gesture + '>' + x.target + ':' + x.chain.length), undone: st.undone.map((x) => x.gesture + '>' + x.target) };
  out.e2e = (await undoRun('docs', g, { level: 'e2e' })).refused || '';
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// §11.2: the playground's undo runs the client procedure in the browser:
// it finds gestures through the listing or the namespace log, writes the
// inverse as one batch with Undoes, redoes by undoing the undo, reports
// conflicts and impossible undos, moves back moves, adds fresh nonces in
// sealed namespaces, and rebuilds the author's stack. app.js's functions
// run under node against a server with a log page size of 3.
func TestUndoWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: newTestKeyStore(t), LogPageSize: 3})
	keys := client.WithKeys(client.NewKeys(nil))
	alice := s.Client(t, client.WithAuthor("alice"), keys)
	bob := s.Client(t, client.WithAuthor("bob"), keys)
	op := func(o, path string, v any) map[string]any { return map[string]any{"op": o, "path": path, "value": v} }
	ops := func(o ...map[string]any) []any {
		out := make([]any, len(o))
		for i, x := range o {
			out[i] = x
		}
		return out
	}
	head := func(c *client.Client, ns, name string) string {
		h, err := c.Head(ctx, ns, name)
		if err != nil {
			t.Fatal(err)
		}
		return h.ID
	}
	check := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(alice.CreateNamespace(ctx, "docs", map[string]any{}))
	check(alice.CreateDoc(ctx, "docs", "a", map[string]any{"t": 1, "o": 1, "items": []any{1, 2}}))
	check(alice.CreateDoc(ctx, "docs", "b", map[string]any{"t": 1}))
	g := client.NewGesture()
	check(alice.Append(ctx, "docs", "a", head(alice, "docs", "a"), ops(op("replace", "/t", 2), op("add", "/items/-", 3)), client.WithGesture(g)))
	check(bob.Append(ctx, "docs", "a", head(bob, "docs", "a"), ops(op("replace", "/o", 2))))
	check(alice.Batch(ctx, "docs", client.BatchRequest{Gesture: g, Items: []client.BatchItem{
		{Resource: "b", IfMatch: head(alice, "docs", "b"), Steps: []client.Step{client.PatchStep(ops(op("replace", "/t", 2)))}},
		{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"new": true}))}},
	}}, false))
	// B: d, edited by alice, then the same path by bob.
	check(alice.CreateDoc(ctx, "docs", "d", map[string]any{"t": 1}))
	gd := client.NewGesture()
	check(alice.Append(ctx, "docs", "d", head(alice, "docs", "d"), ops(op("replace", "/t", 2)), client.WithGesture(gd)))
	check(bob.Append(ctx, "docs", "d", head(bob, "docs", "d"), ops(op("replace", "/t", 3))))
	// C: p, a gesture below a pruning horizon.
	w, err := alice.CreateDoc(ctx, "docs", "p", map[string]any{"n": 0})
	check(w, err)
	gp := client.NewGesture()
	w, err = alice.Append(ctx, "docs", "p", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(gp))
	check(w, err)
	var horizon string
	for i := range 2 {
		w, err = alice.Append(ctx, "docs", "p", w.ID, ops(op("add", "/m", i)))
		check(w, err)
		horizon = w.ID
	}
	// D: m, a move.
	check(alice.CreateDoc(ctx, "docs", "m", map[string]any{"l": []any{"x", "y", "z"}}))
	gm := client.NewGesture()
	check(alice.Append(ctx, "docs", "m", head(alice, "docs", "m"), []any{map[string]any{"op": "move", "from": "/l/0", "path": "/l/-"}}, client.WithGesture(gm)))
	// E: sealed.
	check(alice.CreateNamespace(ctx, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}}))
	nonced := func(p []any) []any { return append(p, op("add", "/$nonce", seal.NewNonce())) }
	w, err = alice.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"t": 1})))
	check(w, err)
	gs := client.NewGesture()
	w, err = alice.Append(ctx, "s", "a", w.ID, nonced(ops(op("replace", "/t", 2))), client.WithGesture(gs))
	check(w, err)
	oldNonce := func() string {
		d, err := alice.Doc(ctx, "s", "a", w.ID)
		if err != nil {
			t.Fatal(err)
		}
		return d.Value.(map[string]any)["$nonce"].(string)
	}()
	// F: a namespace that comes to require nonces after the gesture (§C.7).
	check(alice.CreateNamespace(ctx, "n", map[string]any{}))
	w, err = alice.CreateDoc(ctx, "n", "a", map[string]any{"t": 1})
	check(w, err)
	gn := client.NewGesture()
	check(alice.Append(ctx, "n", "a", w.ID, ops(op("replace", "/t", 2)), client.WithGesture(gn)))
	nh, err := alice.NSHead(ctx, "n")
	check(nh, err)
	check(alice.PatchConfig(ctx, "n", nh.Config, ops(op("add", "/nonce", "required"))))
	// G: one that doesn't require them, whose document the browser couldn't read.
	check(alice.CreateNamespace(ctx, "o", map[string]any{}))
	w, err = alice.CreateDoc(ctx, "o", "a", map[string]any{"t": 1})
	check(w, err)
	gO := client.NewGesture()
	check(alice.Append(ctx, "o", "a", w.ID, ops(op("replace", "/t", 2)), client.WithGesture(gO)))
	w, err = alice.Create(ctx, "o", "arr", client.GenesisPatches([]any{1, 2}))
	check(w, err)
	gA := client.NewGesture()
	check(alice.Append(ctx, "o", "arr", w.ID, ops(op("add", "/-", 3)), client.WithGesture(gA)))
	s.Clock.Advance(10 * time.Minute)
	check(alice.Prune(ctx, "docs", "p", client.PruneRequest{Horizon: horizon}))
	fk, err := alice.FetchKeys(ctx, "s", nil, nil)
	if err != nil || len(fk) != 1 || fk[0].Key == nil {
		t.Fatalf("keys %v %v", fk, err)
	}

	b := runUndoHarness(t, node, undoHarness, map[string]any{"base": s.URL, "author": "alice", "key": base64.RawURLEncoding.EncodeToString(fk[0].Key),
		"g": g, "gd": gd, "gp": gp, "gm": gm, "gs": gs, "gn": gn, "go": gO, "ga": gA})
	var out struct {
		PlanA struct {
			Source, Author string
			Writes         []string
		}
		UndoA struct {
			OK      bool
			Gesture string
			Items   int
		}
		AfterUndo map[string]any
		Latest    string
		RedoA     struct {
			OK              bool
			Gesture, Source string
		}
		ConflictB []struct {
			Resource, Kind, Entry, Author string
			Paths                         []string
		}
		PrunedC  struct{ Impossible, Resource string }
		MoveD    []any
		MoveDone bool
		SealedE  struct {
			OK          bool
			Source, Err string
			Steps       []any
		}
		NonceF, NonceG, NonceH struct {
			OK    bool
			Err   string
			Steps []any
		}
		Stack struct{ Done, Undone []string }
		E2E   string
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	if out.PlanA.Source != "gestures" || out.PlanA.Author != "alice" || strings.Join(out.PlanA.Writes, " ") != "a:/items,/t b:/t c:" {
		t.Errorf("plan A %+v", out.PlanA)
	}
	if !out.UndoA.OK || out.UndoA.Items != 3 || !client.ValidGesture(out.UndoA.Gesture) {
		t.Errorf("undo A %+v", out.UndoA)
	}
	if !jsonv.Equal(jsonv.FromGo(out.AfterUndo), jsonv.FromGo(map[string]any{"t": 1, "o": 2, "items": []any{1, 2}})) {
		t.Errorf("a after the undo: %v", out.AfterUndo)
	}
	if out.Latest != out.UndoA.Gesture || !out.RedoA.OK || out.RedoA.Source != "log" {
		t.Errorf("redo A %q %+v", out.Latest, out.RedoA)
	}
	doc := func(ns, name string) (map[string]any, client.State) {
		h, err := alice.Head(ctx, ns, name)
		if err != nil {
			t.Fatal(err)
		}
		id := h.ID
		if h.State == client.Tombstoned {
			id = h.Last
		}
		d, err := alice.Doc(ctx, ns, name, id)
		if err != nil {
			t.Fatal(err)
		}
		return d.Value.(map[string]any), h.State
	}
	if a, _ := doc("docs", "a"); !jsonv.Equal(a, jsonv.FromGo(map[string]any{"t": 2, "o": 2, "items": []any{1, 2, 3}})) {
		t.Errorf("a after the redo: %v", a)
	}
	if c, st := doc("docs", "c"); st != client.Live || c["new"] != true {
		t.Errorf("c after the redo: %v %v", st, c)
	}
	lg, err := alice.Log(ctx, "docs", "a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if e := lg[len(lg)-1]; e.Gesture != out.RedoA.Gesture || e.Undoes != out.UndoA.Gesture || lg[len(lg)-2].Undoes != g {
		t.Errorf("a's log ends with %+v", e)
	}
	if len(out.ConflictB) != 1 || out.ConflictB[0].Resource != "d" || out.ConflictB[0].Kind != "overlap" || out.ConflictB[0].Author != "bob" || strings.Join(out.ConflictB[0].Paths, ",") != "/t" {
		t.Errorf("conflict B %+v", out.ConflictB)
	}
	if out.PrunedC.Impossible != "pruned" || out.PrunedC.Resource != "p" {
		t.Errorf("pruned C %+v", out.PrunedC)
	}
	if len(out.MoveD) != 1 || !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(out.MoveD))), `[{"from":"/l/2","op":"move","path":"/l/0"}]`) || !out.MoveDone {
		t.Errorf("move D %v %v", out.MoveD, out.MoveDone)
	}
	if m, _ := doc("docs", "m"); !jsonv.Equal(m, jsonv.FromGo(map[string]any{"l": []any{"x", "y", "z"}})) {
		t.Errorf("m after moving back: %v", m)
	}
	if !out.SealedE.OK || out.SealedE.Source != "log" || len(out.SealedE.Steps) != 1 || !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(out.SealedE.Steps))), `"path":"/$nonce"`) {
		t.Errorf("sealed E %+v", out.SealedE)
	}
	if sd, _ := doc("s", "a"); sd["t"] != float64(1) || !seal.ValidNonce(sd["$nonce"].(string)) || sd["$nonce"] == oldNonce {
		t.Errorf("s/a after the undo: %v", sd)
	}
	if !out.NonceF.OK || len(out.NonceF.Steps) != 1 || !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(out.NonceF.Steps))), `"path":"/$nonce"`) {
		t.Errorf("nonce F %+v", out.NonceF)
	}
	if nd, _ := doc("n", "a"); nd["t"] != float64(1) || !seal.ValidNonce(nd["$nonce"].(string)) {
		t.Errorf("n/a after the undo: %v", nd)
	}
	if !out.NonceG.OK || len(out.NonceG.Steps) != 1 || !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(out.NonceG.Steps))), `"path":"/$nonce"`) {
		t.Errorf("nonce G %+v", out.NonceG)
	}
	if od, _ := doc("o", "a"); od["t"] != float64(1) || !seal.ValidNonce(od["$nonce"].(string)) {
		t.Errorf("o/a after the undo: %v", od)
	}
	if !out.NonceH.OK || len(out.NonceH.Steps) != 1 || strings.Contains(string(jsonv.Canonical(jsonv.FromGo(out.NonceH.Steps))), `"path":"/$nonce"`) {
		t.Errorf("nonce H %+v", out.NonceH)
	}
	if _, d, err := alice.Load(ctx, "o", "arr"); err != nil || !jsonv.Equal(d.Value, jsonv.FromGo([]any{1, 2})) {
		t.Errorf("o/arr after the undo: %v %v", d, err)
	}
	// gd conflicted and gp was impossible, so both stand; g was undone and
	// redone; gm was undone.
	wantDone := []string{gd + ">" + gd + ":0", gp + ">" + gp + ":0", g + ">" + out.RedoA.Gesture + ":2"}
	if strings.Join(out.Stack.Done, " ") != strings.Join(wantDone, " ") || len(out.Stack.Undone) != 1 || !strings.HasPrefix(out.Stack.Undone[0], gm+">") {
		t.Errorf("stack %+v", out.Stack)
	}
	if !strings.Contains(out.E2E, "Go client") {
		t.Errorf("e2e refusal %q", out.E2E)
	}
}

// runUndoHarness runs a harness (undoPrelude and scenarios) with app.js's
// undo functions under node, and returns what it prints.
func runUndoHarness(t *testing.T, node, harness string, input map[string]any) []byte {
	t.Helper()
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "nsLogRead", "openEntries", "openSealed", "readDoc", "foldTarget",
		"undoPtr", "undoPtrStr", "ptrGet", "sameAt", "hasPrefix", "widenWrite", "coverPaths", "pathsOverlap", "foldUndo", "moveBack", "invertRev",
		"planUndoResource", "undoSites", "undoStackFrom", "undoGestureList", "undoNSLog", "undoNSLogOr", "undoReadRes", "undoKeysLevel", "undoPlan", "undoImpossible", "undoHeadMoved", "undoRun",
		"undoLatest", "needsNonce"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	src := strings.Replace(harness, "FUNCTIONS", "const GESTURE_RE = /^[a-z2-7]{26}$/;\n"+strings.Join(fns, "\n"), 1)
	dir := t.TempDir()
	hp := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(hp, []byte(src), 0o644); err != nil {
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
	return b
}

// undoLimitedHarness runs the scenarios of TestUndoLimitedWithNode.
const undoLimitedHarness = undoPrelude + `
(async () => {
  const out = {};
  const o = (x) => Object.assign({ nonce: needsNonce(null) }, x);
  const sum = (u) => ({ ok: !!u.ok, gesture: u.gesture || '', source: u.ok ? u.plan.source : '', level: u.ok ? u.plan.level : '', author: u.ok ? u.plan.author : '',
    steps: u.ok ? u.plan.items.map((it) => it.steps) : null, err: u.refused || u.impossible || '' });
  S.ns = 'ls';
  out.bare = sum(await undoRun('ls', input.g, o({})));
  out.only = sum(await undoRun('ls', input.gb, o({ resources: ['a'] })));
  out.undo = sum(await undoRun('ls', input.g, o({ resources: ['a', 'b'] })));
  const latest = await undoLatest('ls', input.g, input.author, ['a', 'b']);
  out.latest = latest ? latest.gesture : '';
  out.redo = sum(await undoRun('ls', out.latest, o({ author: input.author, resources: ['a', 'b'] })));
  S.ns = 'le';
  out.e2e = sum(await undoRun('le', input.ge, o({ resources: ['a'] })));
  S.ns = 'lp';
  out.pruned = sum(await undoRun('lp', input.gp, o({ resources: ['a'] })));
  out.below = sum(await undoRun('lp', input.gw, o({ resources: ['a'] })));
  out.after = sum(await undoRun('lp', input.gp2, o({ resources: ['a'] })));
  out.other = sum(await undoRun('lp', input.gx, o({ resources: ['a', 'b'] })));
  out.belowB = sum(await undoRun('lp', input.gq, o({ resources: ['a', 'b'] })));
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// §11.2 Finding a gesture, §C.5: the playground's undo for a grant limited
// to some resources, which reads neither the namespace log nor its
// document. In a sealed namespace it scans the logs of the documents it
// knows the action touched, learns the level from /keys (§E.2.3) and adds
// fresh nonces; without them it refuses instead of failing on a 403; redo
// finds the undo in those logs; in an e2e namespace it refuses, and names
// the Go client. The undo is impossible rather than done in part when the
// gesture's first revision read follows a pruning horizon, so it may
// continue below, or when it is found in no document named and one has a
// horizon, so it may lie wholly below (§11.2). A document with a horizon
// and no entry of a gesture found in another is left out.
func TestUndoLimitedWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: newTestKeyStore(t), LogPageSize: 3})
	k := clienttest.NewKey("k")
	opc := func(ns string) *client.Client { return s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))) }
	check := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(opc("ls").CreateNamespace(ctx, "ls", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	check(opc("le").CreateNamespace(ctx, "le", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	check(opc("lp").CreateNamespace(ctx, "lp", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	only := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}}}
	liGrant := k.Grant(t, s.Now(), "user:li", []string{"ls", "le", "lp"}, []string{"read", "create", "append"}, only)
	li := s.Client(t, client.WithBearer(liGrant), client.WithKeys(client.NewKeys(nil)))
	op := func(o, path string, v any) map[string]any { return map[string]any{"op": o, "path": path, "value": v} }
	nonced := func(p ...any) []any { return append(p, op("add", "/$nonce", seal.NewNonce())) }
	wa, err := li.Create(ctx, "ls", "a", nonced(client.GenesisPatches(map[string]any{"n": 1})...))
	check(wa, err)
	wb, err := li.Create(ctx, "ls", "b", nonced(client.GenesisPatches(map[string]any{"n": 1})...))
	check(wb, err)
	g := client.NewGesture()
	check(li.Append(ctx, "ls", "a", wa.ID, nonced(op("replace", "/n", 2)), client.WithGesture(g)))
	wb, err = li.Append(ctx, "ls", "b", wb.ID, nonced(op("replace", "/n", 2)), client.WithGesture(g))
	check(wb, err)
	gb := client.NewGesture()
	check(li.Append(ctx, "ls", "b", wb.ID, nonced(op("add", "/x", 1)), client.WithGesture(gb)))
	fk, err := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"ls"}, []string{"read"}))).FetchKeys(ctx, "ls", nil, nil)
	if err != nil || len(fk) != 1 || fk[0].Key == nil {
		t.Fatalf("keys %v %v", fk, err)
	}
	// le: an e2e gesture by the admin on a, which li can read.
	jwk, priv, _ := seal.GenerateRecipient()
	x := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"le"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": jwk}))).E2E(priv)
	check(x.InitKeyring(ctx, "le"))
	we, err := x.CreateDocSealed(ctx, "le", "a", map[string]any{"n": 0})
	check(we, err)
	ge := client.NewGesture()
	check(x.AppendSealed(ctx, "le", "a", we.ID, []any{op("replace", "/n", 1)}, client.WithGesture(ge)))
	// lp: li's gesture gp on a straddles the pruning horizon; gp2 comes
	// after another revision.
	wp, err := li.Create(ctx, "lp", "a", nonced(client.GenesisPatches(map[string]any{"n": 0, "p": 0, "r": 0})...))
	check(wp, err)
	gp, gp2, gw := client.NewGesture(), client.NewGesture(), client.NewGesture()
	wp, err = li.Append(ctx, "lp", "a", wp.ID, nonced(op("add", "/w", 1)), client.WithGesture(gw))
	check(wp, err)
	wp, err = li.Append(ctx, "lp", "a", wp.ID, nonced(op("replace", "/n", 1)), client.WithGesture(gp))
	check(wp, err)
	horizon := wp.ID
	wp, err = li.Append(ctx, "lp", "a", wp.ID, nonced(op("replace", "/p", 1)), client.WithGesture(gp))
	check(wp, err)
	wp, err = li.Append(ctx, "lp", "a", wp.ID, nonced(op("replace", "/r", 1)))
	check(wp, err)
	wp, err = li.Append(ctx, "lp", "a", wp.ID, nonced(op("replace", "/r", 2)), client.WithGesture(gp2))
	check(wp, err)
	// lp/b: li's gesture gq, pruned at b's head, lies wholly below it.
	gq, gx := client.NewGesture(), client.NewGesture()
	wq, err := li.Create(ctx, "lp", "b", nonced(client.GenesisPatches(map[string]any{"q": 0})...))
	check(wq, err)
	wq, err = li.Append(ctx, "lp", "b", wq.ID, nonced(op("replace", "/q", 1)), client.WithGesture(gq))
	check(wq, err)
	s.Clock.Advance(10 * time.Minute)
	pc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:op", []string{"lp"}, []string{"read", "prune"})))
	check(pc.Prune(ctx, "lp", "a", client.PruneRequest{Horizon: horizon}))
	check(pc.Prune(ctx, "lp", "b", client.PruneRequest{Horizon: wq.ID}))
	// gx, on a only after b's prune, is undone though b, named too, has
	// no entry of it after its horizon.
	check(li.Append(ctx, "lp", "a", wp.ID, nonced(op("add", "/v", 1)), client.WithGesture(gx)))
	fkp, err := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"lp"}, []string{"read"}))).FetchKeys(ctx, "lp", nil, nil)
	if err != nil || len(fkp) != 1 || fkp[0].Key == nil {
		t.Fatalf("keys %v %v", fkp, err)
	}

	b := runUndoHarness(t, node, undoLimitedHarness, map[string]any{"base": s.URL, "author": "user:li", "bearer": liGrant,
		"key": base64.RawURLEncoding.EncodeToString(fk[0].Key), "nsKeys": map[string]any{"lp": base64.RawURLEncoding.EncodeToString(fkp[0].Key)}, "g": g, "gb": gb, "ge": ge, "gp": gp, "gp2": gp2, "gw": gw, "gq": gq, "gx": gx})
	type res struct {
		OK                                  bool
		Gesture, Source, Level, Author, Err string
		Steps                               []any
	}
	var out struct {
		Bare, Only, Undo, Redo, E2E, Pruned, Below, After, Other, BelowB res
		Latest                                                           string
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	if out.Bare.OK || !strings.Contains(out.Bare.Err, "open the document") {
		t.Errorf("without resources %+v", out.Bare)
	}
	if out.Only.OK || !strings.Contains(out.Only.Err, "no revisions in a") {
		t.Errorf("a gesture only in a resource not named %+v", out.Only)
	}
	if u := out.Undo; !u.OK || u.Source != "resources" || u.Level != "sealed" || u.Author != "user:li" || len(u.Steps) != 2 ||
		!strings.Contains(string(jsonv.Canonical(jsonv.FromGo(u.Steps))), `"path":"/$nonce"`) {
		t.Errorf("undo %+v", u)
	}
	if out.Latest != out.Undo.Gesture || !out.Redo.OK || out.Redo.Source != "resources" || len(out.Redo.Steps) != 2 {
		t.Errorf("redo %q %+v", out.Latest, out.Redo)
	}
	for _, name := range []string{"a", "b"} {
		lg, err := li.Log(ctx, "ls", name, "", "")
		if err != nil {
			t.Fatal(err)
		}
		_, d, err := li.Load(ctx, "ls", name)
		if err != nil || d.Value.(map[string]any)["n"] != float64(2) || !seal.ValidNonce(d.Value.(map[string]any)["$nonce"].(string)) ||
			lg[len(lg)-1].Undoes != out.Undo.Gesture || lg[len(lg)-2].Undoes != g {
			t.Errorf("ls/%s after the undo and the redo: %v %v", name, d, err)
		}
	}
	if out.E2E.OK || !strings.Contains(out.E2E.Err, "Go client") {
		t.Errorf("e2e %+v", out.E2E)
	}
	if out.Pruned.OK || out.Pruned.Err != "pruned" {
		t.Errorf("a gesture straddling the horizon %+v", out.Pruned)
	}
	if out.Below.OK || out.Below.Err != "pruned" {
		t.Errorf("a gesture wholly below the horizon %+v", out.Below)
	}
	if !out.After.OK || out.After.Level != "sealed" {
		t.Errorf("a gesture after the horizon %+v", out.After)
	}
	if !out.Other.OK || len(out.Other.Steps) != 1 {
		t.Errorf("a gesture beside a document pruned at its head %+v", out.Other)
	}
	if out.BelowB.OK || out.BelowB.Err != "pruned" {
		t.Errorf("a gesture wholly below the horizon of one of two documents %+v", out.BelowB)
	}
	if _, d, err := li.Load(ctx, "lp", "a"); err != nil || d.Value.(map[string]any)["n"] != float64(1) || d.Value.(map[string]any)["r"] != float64(1) {
		t.Errorf("lp/a after the refusal and the undo: %v %v", d, err)
	}
}

// §11.2 Redo: app.js rebuilds an author's stack like client.UndoStack: an
// undo by someone else is shown, not counted; an Undoes naming a missing
// gesture is ignored; redo chains are followed; batch steps count.
func TestUndoStackWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := jsFunction(t, js, "undoStackFrom") + `
const hd = (author, resource, gesture, undoes) => ({ kind: 'head', resource, author, gesture, undoes, created: 'c' });
const log = [
  hd('ann', 'a', 'g1'), hd('ann', 'a', 'g2'),
  { kind: 'batch', author: 'ann', entries: [{ resource: 'a', kind: 'head' }, { resource: 'b', kind: 'head' }], gestures: { a: [{ gesture: 'g3' }], b: [{}, { gesture: 'g3' }] } },
  hd('ann', 'a', 'gx', 'missing'),
  hd('ann', 'a', 'u3', 'g3'), hd('bob', 'a', 'b2', 'g2'), hd('ann', 'a', 'u1', 'g1'), hd('ann', 'a', 'r1', 'u1'),
];
const st = undoStackFrom(log, 'ann');
console.log(JSON.stringify({ done: st.done.map((x) => [x.gesture, x.target, x.undoneBy.map((y) => y.author).join()]), undone: st.undone.map((x) => [x.gesture, x.target, x.resources.join()]) }));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := `{"done":[["g2","g2","bob"],["gx","gx",""],["g1","r1",""]],"undone":[["g3","u3","a,b"]]}`
	if strings.TrimSpace(string(out)) != want {
		t.Fatalf("stack %s, want %s", out, want)
	}
}
