package playground

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// xrevHarness runs app.js's own key schedule and readers (contentKey,
// epochKey, openSealed, decrypted, nsHeadDoc, readDoc and the fold,
// openSealedEntries) under node, with K_e given by kid as /keys or the
// keyring gives it, and runs input.mode's scenario.
const xrevHarness = `
const fs = require('fs');
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
const ID_RE = /^1[a-z2-7]{32}$/;
const short = (id) => id || '';
const KEYS = { epoch: new Map(Object.entries(input.keys || {}).map(([kid, k]) => [kid, Z.unb64u(k)])), res: new Map(), pending: new Map() };
function holdRes(kid, resource, key) { KEYS.res.set(kid + '\n' + resource, key); }
async function fetchKeyFor(kid) { throw new Error('no key for ' + kid); }
function renderEntry() {}
async function nsInfo(ns) { return { level: 'e2e', doc: { encryption: { level: 'e2e' } } }; }
async function validateDoc(doc) { return { errors: [] }; }
const paddedLength = (n) => Z.padLen(n);
let paths = [];
async function api(method, path, o) {
  paths.push(path);
  const headers = input.bearer ? { Authorization: 'Bearer ' + input.bearer } : {};
  const res = await fetch(input.base + path, { method, headers });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { /* not JSON */ }
  const u = new URL(res.url);
  return { status: res.status, json, text, finalPath: u.pathname + u.search, entry: {},
    jose: /^application\/jose\b/i.test(res.headers.get('Content-Type') || ''), hdr: (k) => res.headers.get(k), etag: () => '' };
}
const b64 = (u) => Z.b64u(u);
const S = { ns: '', res: '', hist: [], histNote: '', histErr: null };
function rpath(suffix = '') { return '/r/' + S.ns + '/' + S.res + suffix; }
function renderHistory() {}
FUNCTIONS
(async () => {
  const out = {};
  if (input.mode === 'keys') {
    const ke = Z.unb64u(input.keys[input.kid]);
    out.kn = b64(await Z.namespaceKey(ke, input.ns));
    out.view = b64(await Z.viewKey(Z.unb64u(input.viewOf), input.view));
    out.content = b64(await contentKey(input.kid, ''));
    out.contentRes = b64(await contentKey(input.kid, input.name));
    out.epoch = b64(await epochKey(input.kid));
    const d = await nsHeadDoc(input.ns);
    out.nsDoc = d.doc;
    try { await Z.openJWE(input.zip, await Z.namespaceKey(ke, input.ns)); out.zip = 'opened'; } catch (e) { out.zip = e.message; }
  } else if (input.mode === 'views') {
    const r = { status: 200, jose: true, text: input.whole, entry: {}, hdr: () => '' };
    const d = await decrypted(r, input.ns, '', { ns: input.ns, view: input.view });
    out.whole = d.value; out.wholeErr = d.error || '';
    const raw = await decrypted(Object.assign({}, r, { text: input.wholeRaw }), input.ns, '', { ns: input.ns, view: input.view });
    out.wholeRaw = raw.value; out.wholeRawErr = raw.error || '';
    const body = JSON.parse(input.body);
    await openSealedEntries(body, input.view);
    out.body = body;
  } else {
    for (const c of input.reads) {
      paths = [];
      const d = await readDoc(c.ns, c.name, c.id, await api('GET', c.path));
      out[c.key] = { doc: d.doc, err: d.foldErr || '', since: d.fold ? d.fold.since : '', flagged: d.fold ? d.fold.flagged.length : 0, snapshot: !!d.seal, paths };
      if (c.history) {
        // The History tab: app.js's loadHistory for the resource read at its head.
        S.ns = c.ns; S.res = c.name; S.nsLevel = 'e2e'; S.resState = Object.assign({ kind: 'live', head: c.id }, d);
        await loadHistory();
        out[c.key].hist = S.hist.map((e) => e.kind + ':' + e.id + (e._flag ? ':flagged' : ''));
        out[c.key].histNote = S.histNote; out[c.key].histErr = S.histErr ? S.histErr.status : 0;
      }
    }
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// runXrevHarness runs xrevHarness with input and decodes its output into
// out.
func runXrevHarness(t *testing.T, node string, input map[string]any, out any) {
	t.Helper()
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "revTarget", "notOffered", "readDoc", "nsChainOK",
		"epochKey", "contentKey", "openSealed", "decrypted", "openSnapshot", "foldLog", "nsDocPL", "nsHeadDoc", "openSealedEntries", "loadHistory", "openEntries"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(xrevHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(input)
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	cmd := exec.Command(node, h, sealJS, inPath)
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

func needNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	return node
}

var b64u = base64.RawURLEncoding

// §E.2.1 (v0.81): K_e seals nothing. The playground opens namespace
// content under K_n = HKDF(K_e, "patchlog-e2", ns ‖ 0x0A), resource content
// under K_r, and a view under HKDF(K_n or K_r, "patchlog-view", view)
// (SERVICES.md §E.2.6), each as internal/seal derives them; a sealed
// namespace's document, as a live server seals it, opens; K_e stays what
// keyring entries wrap (krAdd); and a compressed JWE is refused (§E.2.2).
func TestV081XrevKeysWithNode(t *testing.T) {
	t.Parallel()
	node := needNode(t)
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: newTestKeyStore(t)})
	c := s.Client(t, client.WithAuthor("alice"))
	if _, err := c.CreateNamespace(ctx, "s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}, "x-note": "opened"}); err != nil {
		t.Fatal(err)
	}
	keys, err := c.FetchKeys(ctx, "s", nil, nil)
	if err != nil || len(keys) != 1 || keys[0].Key == nil {
		t.Fatalf("keys %v %v", keys, err)
	}
	ke, kid := keys[0].Key, keys[0].Kid
	kn, _ := seal.NamespaceKey(ke, "s")
	kr, _ := seal.ResourceKey(ke, "s", "doc")
	const view = "/s/at/1abc/roots?q=x%20y"
	vk, _ := seal.ViewKey(kr, view)
	zip, err := legacyZipJWE(kn, kid, seal.NamespaceDocPL("s", "1abc"), []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		KN, View, Content, ContentRes, Epoch, Zip string
		NSDoc                                     map[string]any
	}
	runXrevHarness(t, node, map[string]any{"mode": "keys", "base": s.URL, "ns": "s", "name": "doc", "kid": kid,
		"keys": map[string]string{kid: b64u.EncodeToString(ke)}, "viewOf": b64u.EncodeToString(kr), "view": view, "zip": zip}, &out)
	for what, got := range map[string][2]string{
		"namespaceKey":         {out.KN, b64u.EncodeToString(kn)},
		"viewKey":              {out.View, b64u.EncodeToString(vk)},
		"contentKey(kid, '')":  {out.Content, b64u.EncodeToString(kn)},
		"contentKey(kid, doc)": {out.ContentRes, b64u.EncodeToString(kr)},
		"epochKey":             {out.Epoch, b64u.EncodeToString(ke)},
	} {
		if got[0] != got[1] {
			t.Errorf("%s: %s, want %s", what, got[0], got[1])
		}
	}
	if out.NSDoc["x-note"] != "opened" {
		t.Errorf("sealed namespace document: %v", out.NSDoc)
	}
	if !strings.Contains(out.Zip, "zip") {
		t.Errorf("a zip JWE: %q", out.Zip)
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if kr := jsFunction(t, js, "krAdd"); !strings.Contains(kr, "epochKey(") || strings.Contains(kr, "contentKey(") {
		t.Errorf("krAdd wraps something other than K_e:\n%s", kr)
	}
}

// SERVICES.md §E.2.6 View keys: a whole-response view opens under the view
// key of K_n, an entry and a value of another resource under the view key
// of their resource's K_r; a view sealed under K_n itself doesn't open.
func TestV081XrevViewsWithNode(t *testing.T) {
	t.Parallel()
	node := needNode(t)
	ke := seal.NewKey()
	kid := seal.Kid("c", 2)
	const view = "/c/at/1abc/children/docs?x=1"
	kn, _ := seal.NamespaceKey(ke, "c")
	vn, _ := seal.ViewKey(kn, view)
	whole, err := seal.Seal(vn, kid, seal.PL{"ns": "c", "view": view}, []byte(`{"title":"whole"}`))
	if err != nil {
		t.Fatal(err)
	}
	wholeRaw, _ := seal.Seal(kn, kid, seal.PL{"ns": "c", "view": view}, []byte(`{"title":"raw"}`))
	entry := func(name string, plain string) string {
		kr, _ := seal.ResourceKey(ke, "c", name)
		vr, _ := seal.ViewKey(kr, view)
		j, err := seal.Seal(vr, kid, seal.PL{"ns": "c", "name": name, "view": view}, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	body, _ := json.Marshal(map[string]any{"children": []any{
		map[string]any{"name": "a.md", "sealed": entry("a.md", `{"title":"A"}`), "file": map[string]any{"sealed": entry("item", `{"file":"f.txt"}`)}},
	}})
	var out struct {
		Whole, WholeRaw       map[string]any
		WholeErr, WholeRawErr string
		Body                  struct {
			Children []struct {
				Title string `json:"title"`
				Err   string `json:"_sealedErr"`
				File  struct {
					File string `json:"file"`
					Err  string `json:"_sealedErr"`
				} `json:"file"`
			} `json:"children"`
		}
	}
	runXrevHarness(t, node, map[string]any{"mode": "views", "ns": "c", "view": view, "whole": whole, "wholeRaw": wholeRaw, "body": string(body),
		"keys": map[string]string{kid: b64u.EncodeToString(ke)}}, &out)
	if out.Whole["title"] != "whole" || out.WholeErr != "" {
		t.Errorf("whole response: %v %q", out.Whole, out.WholeErr)
	}
	if out.WholeRaw != nil || out.WholeRawErr == "" {
		t.Errorf("a view sealed under K_n itself opened: %v", out.WholeRaw)
	}
	if len(out.Body.Children) != 1 {
		t.Fatalf("body %+v", out.Body)
	}
	ch := out.Body.Children[0]
	if ch.Title != "A" || ch.Err != "" {
		t.Errorf("entry: %+v", ch)
	}
	if ch.File.File != "f.txt" || ch.File.Err != "" {
		t.Errorf("value of another resource: %+v", ch.File)
	}
}

// §7.1 End-to-end namespaces (v0.81): the server never folds. The
// playground reads a head through its redirect to /rev/{head}, 404
// not_offered, and folds it from genesis; at a tombstone horizon a later
// revision folds from last, the tombstone's parent, whose snapshot
// /rev/{last} serves, and so does the History tab, whose range from
// genesis is 410 pruned; a patch set sealed under K_e, which seals nothing,
// is flagged and folded as []; and a 200 in the clear is refused, never
// shown as the document.
func TestV081XrevE3ReadsWithNode(t *testing.T) {
	t.Parallel()
	node := needNode(t)
	ctx := context.Background()
	// A revision of a resource no one wrote, which the stub serves in the clear.
	clearID := "1" + strings.Repeat("a", 32)
	clearPath := "/r/e/clear/rev/" + clearID
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == clearPath {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"n":99}`))
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: newTestKeyStore(t), Archiver: arch, Wrap: wrap})
	writer := clienttest.NewKey("writer")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"keys": []any{writer.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	jwk, priv, _ := seal.GenerateRecipient()
	bearer := writer.Grant(t, s.Now(), "user:writer", []string{"e"}, []string{"read", "create", "append", "delete", "restore", "prune", "config"}, map[string]any{"enc": jwk})
	plain := s.Client(t, client.WithBearer(bearer))
	w := plain.E2E(priv)
	if _, err := w.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	must := func(r *client.WriteResult, err error) *client.WriteResult {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	set := func(n int) []any { return []any{map[string]any{"op": "replace", "path": "/n", "value": n}} }
	// g: never pruned, read at its head.
	g0 := must(w.CreateDocSealed(ctx, "e", "g", map[string]any{"n": 0}))
	g1 := must(w.AppendSealed(ctx, "e", "g", g0.ID, set(1)))
	// A patch set sealed under K_e, which seals nothing since v0.81.
	kid := seal.Kid("e", 1)
	ke, err := w.Key(ctx, kid)
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := json.Marshal(set(7))
	jwe, err := seal.Seal(ke, kid, seal.PatchSetPL("e", "g", g1.ID), pt)
	if err != nil {
		t.Fatal(err)
	}
	g2 := must(plain.Append(ctx, "e", "g", g1.ID, []any{map[string]any{"op": "sealed", "value": jwe}}))
	// d: pruned at a tombstone horizon T, with parent P.
	p0 := must(w.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0}))
	p := must(w.AppendSealed(ctx, "e", "d", p0.ID, set(1)))
	tomb := must(plain.Delete(ctx, "e", "d", p.ID))
	l := must(w.RestoreSealed(ctx, "e", "d", tomb.ID, nil))
	l2 := must(w.AppendSealed(ctx, "e", "d", l.ID, set(2)))
	s.Clock.Advance(10 * time.Minute)
	if _, err := w.PruneE2E(ctx, "e", "d", tomb.ID); err != nil {
		t.Fatal(err)
	}

	type read struct {
		Key, NS, Name, ID, Path string
		History                 bool
	}
	reads := []read{
		{"head", "e", "g", g2.ID, "/r/e/g", true},
		{"later", "e", "d", l2.ID, "/r/e/d/rev/" + l2.ID, true},
		{"last", "e", "d", p.ID, "/r/e/d/rev/" + p.ID, false},
		{"clear", "e", "clear", clearID, clearPath, false},
	}
	in := []map[string]any{}
	for _, r := range reads {
		in = append(in, map[string]any{"key": r.Key, "ns": r.NS, "name": r.Name, "id": r.ID, "path": r.Path, "history": r.History})
	}
	var out map[string]struct {
		Doc      map[string]any
		Err      string
		Since    string
		Flagged  int
		Snapshot bool
		Paths    []string
		Hist     []string
		HistNote string
		HistErr  int
	}
	runXrevHarness(t, node, map[string]any{"mode": "reads", "base": s.URL, "bearer": bearer, "reads": in,
		"keys": map[string]string{kid: b64u.EncodeToString(ke)}}, &out)
	if o := out["head"]; o.Err != "" || o.Since != "" || o.Flagged != 1 || o.Doc["n"] != float64(1) {
		t.Errorf("head: folded from genesis %+v, want n 1 with the K_e patch set flagged", o)
	}
	if o := out["later"]; o.Err != "" || o.Since != p.ID || o.Doc["n"] != float64(2) {
		t.Errorf("after a tombstone horizon: %+v, want n 2 folded from last %s", o, p.ID)
	}
	wantHist := func(what string, got []string, want ...string) {
		t.Helper()
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s history: %v, want %v", what, got, want)
		}
	}
	if o := out["head"]; o.HistErr != 0 || strings.Contains(o.HistNote, "Could not fold") {
		t.Errorf("head history: %+v", o)
	} else {
		wantHist("head", o.Hist, "rev:"+g0.ID, "rev:"+g1.ID, "rev:"+g2.ID+":flagged")
	}
	if o := out["later"]; o.HistErr != 0 || strings.Contains(o.HistNote, "Could not fold") {
		t.Errorf("history across a tombstone horizon: %+v", o)
	} else {
		wantHist("tombstone horizon", o.Hist, "snapshot:"+p.ID, "tombstone:"+tomb.ID, "rev:"+l.ID, "rev:"+l2.ID)
	}
	if o := out["last"]; o.Err != "" || !o.Snapshot || o.Doc["n"] != float64(1) || len(o.Paths) != 1 {
		t.Errorf("at the tombstone's parent: %+v, want its snapshot", o)
	}
	if o := out["clear"]; o.Doc != nil || o.Err == "" {
		t.Errorf("a 200 in the clear at e2e: %+v", o)
	}
}
