package playground

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// jsFunction returns the source of the top-level function name in js, from
// its "function" keyword to its closing brace.
func jsFunction(t *testing.T, js []byte, name string) string {
	t.Helper()
	loc := regexp.MustCompile(`(?m)^(async )?function ` + name + `\(`).FindIndex(js)
	if loc == nil {
		t.Fatalf("app.js has no function %s", name)
	}
	depth := 0
	// The body starts after the parameter list, which may hold a "{}" default.
	for i := bytes.Index(js[loc[0]:], []byte(") {")) + 2 + loc[0]; i < len(js); i++ {
		switch js[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return string(js[loc[0] : i+1])
			}
		}
	}
	t.Fatalf("function %s doesn't end", name)
	return ""
}

// pagingHarness runs app.js's log range readers (extracted, with api and
// decrypted stubbed over fetch and seal.js) against a live server.
const pagingHarness = `
const fs = require('fs');
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
const ID_RE = /^1[a-z2-7]{32}$/;
const short = (id) => id || '';
const S = { ns: '', nsLogErr: '' };
const KEY = Z.unb64u(input.key);
let requests = 0;
async function api(method, path, o) {
  requests++;
  const res = await fetch(input.base + path, { method, redirect: 'follow' });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { /* not JSON */ }
  const u = new URL(res.url);
  return { status: res.status, json, text, finalPath: u.pathname + u.search,
    jose: /^application\/jose\b/i.test(res.headers.get('Content-Type') || ''), hdr: (k) => res.headers.get(k) };
}
async function decrypted(r, ns, resource, want) {
  try {
    const jwe = r.text.trim();
    const pl = Z.parseJWE(jwe).header.pl;
    if (JSON.stringify(pl) !== JSON.stringify(want)) throw new Error('bound to ' + JSON.stringify(pl) + ', not ' + JSON.stringify(want));
    return { value: JSON.parse((await Z.openJWE(jwe, KEY)).text) };
  } catch (err) { return { value: null, error: err.message }; }
}
const noNext = (r) => Object.assign({}, r, { hdr: (k) => (k === 'X-Log-Next' ? null : r.hdr(k)) });
const ids = (arr) => arr.map((x) => (typeof x === 'string' ? jweID(x) : x.id));
FUNCTIONS
(async () => {
  const out = {};
  S.ns = 'docs';
  out.ns = ids(await nsLogRead('docs', await api('GET', '/ns/docs/log')));
  out.nsErr = S.nsLogErr;
  requests = 0;
  let L = await readLogRange(await api('GET', input.resPath));
  out.res = ids(L.arr); out.resErr = L.err; out.resRequests = requests;
  L = await readLogRange(noNext(await api('GET', input.resPath)));
  out.truncatedErr = L.err;
  S.ns = 's';
  out.sealedNS = ids(await nsLogRead('s', await api('GET', '/ns/s/log')));
  out.sealedNSErr = S.nsLogErr;
  out.sealedNSTruncated = ids(await nsLogRead('s', noNext(await api('GET', '/ns/s/log'))));
  out.sealedNSTruncatedErr = S.nsLogErr;
  L = await readLogRange(await api('GET', input.sealedResPath));
  out.sealedRes = ids(L.arr); out.sealedResErr = L.err;
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// The playground reads every page of a log range (§7.1 Paging), sealed
// namespace pages each opened as their own bounds (§E.2.2), and reports a
// page that stops short without X-Log-Next instead of passing it off as
// the whole range. app.js's readers run under node against a server with
// a log page size of 2.
func TestLogPagesWithNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: newTestKeyStore(t), LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("alice"))
	var resIDs, sealedIDs []string
	for _, ns := range []string{"docs", "s"} {
		doc := map[string]any{"read": "public"}
		if ns == "s" {
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		if _, err := c.CreateNamespace(ctx, ns, doc); err != nil {
			t.Fatal(err)
		}
		var id string
		for i := range 5 {
			p := []any{map[string]any{"op": "add", "path": "/n", "value": i}, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}
			var w *client.WriteResult
			if i == 0 {
				w, err = c.Create(ctx, ns, "x", append(client.GenesisPatches(map[string]any{"n": 0}), p[1]))
			} else {
				w, err = c.Append(ctx, ns, "x", id, p)
			}
			if err != nil {
				t.Fatal(err)
			}
			id = w.ID
			if ns == "docs" {
				resIDs = append(resIDs, id)
			} else {
				sealedIDs = append(sealedIDs, id)
			}
		}
	}
	nsIDs := func(ns string) []string {
		h, err := c.NSHead(ctx, ns)
		if err != nil {
			t.Fatal(err)
		}
		es, err := c.With(client.WithKeys(client.NewKeys(nil))).NSLog(ctx, ns, h.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out
	}
	keys, err := c.FetchKeys(ctx, "s", nil, nil)
	if err != nil || len(keys) != 1 || keys[0].Key == nil {
		t.Fatalf("keys %v %v", keys, err)
	}

	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "nsLogRead"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(pagingHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"base": s.URL, "key": base64.RawURLEncoding.EncodeToString(keys[0].Key),
		"resPath": "/r/docs/x/rev/" + resIDs[4] + "/log", "sealedResPath": "/r/s/x/rev/" + sealedIDs[4] + "/log"})
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
	var out struct {
		NS, Res, SealedNS, SealedNSTruncated, SealedRes                []string
		NSErr, ResErr, TruncatedErr, SealedNSErr, SealedNSTruncatedErr string
		SealedResErr                                                   string
		ResRequests                                                    int
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	same := func(what string, got, want []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %v, want %v", what, got, want)
		}
	}
	same("namespace log", out.NS, nsIDs("docs"))
	same("resource log", out.Res, resIDs)
	same("sealed namespace log", out.SealedNS, nsIDs("s"))
	same("sealed resource log", out.SealedRes, sealedIDs)
	if out.NSErr != "" || out.ResErr != "" || out.SealedNSErr != "" || out.SealedResErr != "" {
		t.Errorf("errors on whole ranges: %q %q %q %q", out.NSErr, out.ResErr, out.SealedNSErr, out.SealedResErr)
	}
	if out.ResRequests != 3 {
		t.Errorf("5 entries in pages of 2 took %d requests", out.ResRequests)
	}
	if out.TruncatedErr == "" || out.SealedNSTruncatedErr == "" || len(out.SealedNSTruncated) != 0 {
		t.Errorf("a first page without X-Log-Next passed: %q; sealed %q %v", out.TruncatedErr, out.SealedNSTruncatedErr, out.SealedNSTruncated)
	}
}

func newTestKeyStore(t *testing.T) *keystore.Local {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// Every log range app.js fetches is read through the paged readers: each
// api('GET', …/log…) call sits in a function that hands its answer to
// nsLogRead or readLogRange (and the fold redirect's answer, which readDoc
// gets from its callers, too).
func TestLogReadersUsed(t *testing.T) {
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?m)^(?:async )?function (\w+)\(`)
	n := 0
	for _, m := range regexp.MustCompile("api\\('GET', [^)]*/log[`'?]").FindAllIndex(js, -1) {
		fs := fn.FindAllSubmatch(js[:m[0]], -1)
		if len(fs) == 0 {
			t.Fatalf("a log fetch outside any function at %d", m[0])
		}
		name := string(fs[len(fs)-1][1])
		body := jsFunction(t, js, name)
		if !strings.Contains(body, "nsLogRead(") && !strings.Contains(body, "readLogRange(") {
			t.Errorf("%s fetches a log range without following its pages", name)
		}
		n++
	}
	if n < 3 {
		t.Fatalf("found %d log fetches", n)
	}
	if !strings.Contains(jsFunction(t, js, "readDoc"), "readLogRange(") {
		t.Error("readDoc folds without following the range's pages")
	}
}

// snapshotHarness reads one e2e resource log range with app.js's
// readLogRange against a live server.
const snapshotHarness = `
const fs = require('fs');
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
const ID_RE = /^1[a-z2-7]{32}$/;
const short = (id) => id || '';
async function api(method, path, o) {
  const res = await fetch(input.base + path, { method, headers: { Authorization: 'Bearer ' + input.bearer } });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { /* not JSON */ }
  const u = new URL(res.url);
  return { status: res.status, json, text, finalPath: u.pathname + u.search,
    jose: /^application\/jose\b/i.test(res.headers.get('Content-Type') || ''), hdr: (k) => res.headers.get(k) };
}
FUNCTIONS
(async () => {
  const L = await readLogRange(await api('GET', input.path));
  process.stdout.write(JSON.stringify({ kinds: L.arr.map((x) => x.kind + ':' + x.id), err: L.err }));
})().catch((e) => { console.error(e); process.exit(1); });
`

// A real server prunes an e2e resource at the last entry of the first page
// the playground reads, before it asks for the next: that page's since is
// the horizon, and it holds only the entries after it (the snapshot is
// served as /rev/{H}, never as a log entry), so the range reads as one
// chain (§7.1 Paging).
func TestLogPageFromSnapshotWithNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu     sync.Mutex
		armed  string // the range's id
		pruned string
		w      *client.E2E
	)
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			seg := strings.Split(r.URL.Path, "/") // "", r, e, p, rev, id, log
			if len(seg) != 7 || seg[6] != "log" || r.URL.Query().Get("since") != "" {
				h.ServeHTTP(rw, r)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			next := rec.Header().Get("X-Log-Next")
			mu.Lock()
			arm := armed != "" && armed == seg[5] && next != ""
			if arm {
				armed = ""
			}
			mu.Unlock()
			if arm {
				if _, err := w.PruneE2E(context.Background(), "e", "p", next); err != nil {
					t.Errorf("prune at %s: %v", next, err)
				}
				mu.Lock()
				pruned = next
				mu.Unlock()
			}
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			rw.Write(rec.Body.Bytes())
		})
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: newTestKeyStore(t), Archiver: arch, LogPageSize: 2, Wrap: wrap})
	writer := clienttest.NewKey("writer")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"keys": []any{writer.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	jwk, priv, _ := seal.GenerateRecipient()
	bearer := writer.Grant(t, s.Now(), "user:writer", []string{"e"}, []string{"read", "create", "append", "prune", "config"}, map[string]any{"enc": jwk})
	w = s.Client(t, client.WithBearer(bearer)).E2E(priv)
	if _, err := w.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	var revs []string
	r, err := w.CreateDocSealed(ctx, "e", "p", map[string]any{"n": 0})
	for i := 1; err == nil; i++ {
		revs = append(revs, r.ID)
		if i == 6 {
			break
		}
		r, err = w.AppendSealed(ctx, "e", "p", r.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": i}})
	}
	if err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(10 * time.Minute)
	armed = revs[5]

	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(snapshotHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"base": s.URL, "bearer": bearer, "path": "/r/e/p/rev/" + revs[5] + "/log"})
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
	var out struct {
		Kinds []string
		Err   string
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	var want []string
	for _, id := range revs {
		want = append(want, "rev:"+id)
	}
	mu.Lock()
	defer mu.Unlock()
	if pruned != revs[1] {
		t.Fatalf("pruned at %q, want %s", pruned, revs[1])
	}
	if strings.Join(out.Kinds, ",") != strings.Join(want, ",") || out.Err != "" {
		t.Fatalf("range across a prune: %v (%q), want %v", out.Kinds, out.Err, want)
	}
}

// foldHarness reads e2e documents with app.js's readDoc (and so
// readLogRange, foldLog and openSnapshot) against a live server, with keys
// given by kid and no $schema validation.
const foldHarness = `
const fs = require('fs');
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
const ID_RE = /^1[a-z2-7]{32}$/;
const short = (id) => id || '';
let paths = [];
async function api(method, path, o) {
  paths.push(path);
  const res = await fetch(input.base + path, { method, headers: { Authorization: 'Bearer ' + input.bearer } });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { /* not JSON */ }
  const u = new URL(res.url);
  if (u.pathname.endsWith('/log') && Array.isArray(json) && json.some((m) => m && (m.kind === 'snapshot' || m.snapshot))) throw new Error('a snapshot in the log range ' + u.pathname + u.search);
  return { status: res.status, json, text, finalPath: u.pathname + u.search,
    jose: /^application\/jose\b/i.test(res.headers.get('Content-Type') || ''), hdr: (k) => res.headers.get(k) };
}
async function nsInfo(ns) { return { doc: { encryption: { level: 'e2e' } } }; }
async function contentKey(kid, resource) { if (resource || !input.keys[kid]) throw new Error('no key for ' + kid); return Z.unb64u(input.keys[kid]); }
async function validateDoc(doc) { return { errors: [] }; }
const paddedLength = (n) => Z.padLen(n);
FUNCTIONS
(async () => {
  const out = {};
  for (const id of input.ids) {
    paths = [];
    const d = await readDoc('e', 'p', id, await api('GET', '/r/e/p/rev/' + id));
    out[id] = { doc: d.doc, err: d.foldErr || '', since: d.fold ? d.fold.since : '', flagged: d.fold ? d.fold.flagged.length : 0, paths };
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// The playground folds a pruned e2e resource from its horizon's snapshot,
// which /rev/{H} serves, plus the range after it, which never holds the
// snapshot (§7.1 Paging, §8.6): across pages and on a single page, and at
// the horizon itself from /rev/{H} alone.
func TestE2EFoldFromHorizonWithNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	for _, size := range []int{2, 100} {
		t.Run(fmt.Sprintf("page%d", size), func(t *testing.T) { testE2EFoldFromHorizonWithNode(t, node, size) })
	}
}

func testE2EFoldFromHorizonWithNode(t *testing.T, node string, size int) {
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: newTestKeyStore(t), Archiver: arch, LogPageSize: size})
	writer := clienttest.NewKey("writer")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"keys": []any{writer.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	jwk, priv, _ := seal.GenerateRecipient()
	bearer := writer.Grant(t, s.Now(), "user:writer", []string{"e"}, []string{"read", "create", "append", "prune", "config"}, map[string]any{"enc": jwk})
	w := s.Client(t, client.WithBearer(bearer)).E2E(priv)
	if _, err := w.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	var revs []string
	r, err := w.CreateDocSealed(ctx, "e", "p", map[string]any{"n": 0})
	for i := 1; err == nil; i++ {
		revs = append(revs, r.ID)
		if i == 7 {
			break
		}
		r, err = w.AppendSealed(ctx, "e", "p", r.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": i}})
	}
	if err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(10 * time.Minute)
	hz := revs[2]
	if _, err := w.PruneE2E(ctx, "e", "p", hz); err != nil {
		t.Fatal(err)
	}
	kid := seal.Kid("e", 1)
	key, err := w.Key(ctx, kid)
	if err != nil {
		t.Fatal(err)
	}

	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "foldTarget", "readDoc", "nsChainOK", "openSealed", "openSnapshot", "foldLog"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(foldHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"base": s.URL, "bearer": bearer, "ids": []string{revs[6], revs[3], hz},
		"keys": map[string]string{kid: base64.RawURLEncoding.EncodeToString(key)}})
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
	var out map[string]struct {
		Doc     map[string]any
		Err     string
		Since   string
		Flagged int
		Paths   []string
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	has := func(ps []string, p string) bool {
		for _, x := range ps {
			if x == p {
				return true
			}
		}
		return false
	}
	logPages := func(ps []string) int {
		n := 0
		for _, p := range ps {
			if strings.Contains(p, "/log") {
				n++
			}
		}
		return n
	}
	for i, id := range []string{revs[6], revs[3], hz} {
		o := out[id]
		want := []float64{6, 3, 2}[i]
		if o.Err != "" || o.Flagged != 0 || o.Doc["n"] != want {
			t.Fatalf("fold at %s: %v (%q, %d flagged), want n %v; requests %v", id, o.Doc, o.Err, o.Flagged, want, o.Paths)
		}
	}
	// After the horizon: the fold redirect's range from H (one or more
	// pages, the first one through the redirect), and /rev/{H}.
	if o := out[revs[6]]; o.Since != hz || !has(o.Paths, "/r/e/p/rev/"+hz) || logPages(o.Paths) != (4+size-1)/size-1 {
		t.Fatalf("fold at the head from %q: requests %v", o.Since, o.Paths)
	}
	// At the horizon: /rev/{H} alone.
	if o := out[hz]; len(o.Paths) != 1 {
		t.Fatalf("fold at the horizon: requests %v", o.Paths)
	}
}
