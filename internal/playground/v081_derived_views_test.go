package playground

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/seal"
)

// viewsHarness runs app.js's openSealed and openSealedEntries (extracted)
// over seal.js, with contentKey stubbed to the K_e or K_r the page would
// hold: every key below it, K_n and the view keys, is app.js's own.
const viewsHarness = `
const fs = require('fs');
require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const Z = globalThis.PLSeal;
async function contentKey(kid, resource) {
  const k = input.keys[resource || ''];
  if (!k) throw new Error('no key for ' + kid + ' / ' + resource);
  return Z.unb64u(k);
}
FUNCTIONS
(async () => {
  const out = { whole: {}, entries: null };
  for (const [name, jwe] of Object.entries(input.whole)) {
    try { out.whole[name] = (await openSealed('cat', jwe, '', { ns: 'cat', view: input.view })).value; } catch (e) { out.whole[name] = 'error: ' + e.message; }
  }
  const body = input.entries;
  await openSealedEntries(body, input.view);
  out.entries = body;
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

// The playground opens the views derived seals (KEYS-5): a whole response
// under the view key of K_n, an entry under the view key of its own K_r,
// with view exactly the redirect's path and query (§E.2.6). The bare K_e,
// K_n and K_r open none of them, nor does the view key of another view.
func TestV081PlaygroundOpensDerivedViews(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	const ns = "cat"
	view := "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children/a%2Fb?depth=2&q=%C3%A9"
	ke := seal.NewKey()
	k := derived.Key{NS: ns, Epoch: 1, K: ke}
	v := derived.View{NS: ns, Target: view}
	kn, err := seal.NamespaceKey(ke, ns)
	if err != nil {
		t.Fatal(err)
	}
	kr := map[string][]byte{}
	for _, name := range []string{"x", "y", "z", "w"} {
		if kr[name], err = seal.ResourceKey(ke, ns, name); err != nil {
			t.Fatal(err)
		}
	}
	kid := seal.Kid(ns, 1)
	must := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	viewKey := func(key []byte, view string) []byte {
		t.Helper()
		b, err := seal.ViewKey(key, view)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	body := map[string]any{"roots": []any{"r"}}
	plain, _ := derived.Marshal(body)
	whole := map[string]string{
		"view": must(derived.SealView(k, v, body)),
		"ke":   must(seal.SealUncompressed(ke, kid, v.PL(), plain)),
		"kn":   must(seal.SealUncompressed(kn, kid, v.PL(), plain)),
		// The view key of K_n for the view without its query.
		"other": must(seal.SealUncompressed(viewKey(kn, strings.Split(view, "?")[0]), kid, v.PL(), plain)),
	}
	title := func(name string) []byte { b, _ := derived.Marshal(map[string]any{"title": "T " + name}); return b }
	entries := map[string]any{"children": []any{
		map[string]any{"name": "x", "sealed": must(derived.SealItem(k, v, "x", map[string]any{"title": "T x"}))},
		map[string]any{"name": "y", "sealed": must(seal.SealUncompressed(kr["y"], kid, v.ItemPL(ns, "y"), title("y")))},
		map[string]any{"name": "z", "sealed": must(seal.SealUncompressed(ke, kid, v.ItemPL(ns, "z"), title("z")))},
		map[string]any{"name": "w", "sealed": must(seal.SealUncompressed(viewKey(kn, view), kid, v.ItemPL(ns, "w"), title("w")))},
		// An index hit names its resource "resource".
		map[string]any{"resource": "x", "sealed": must(derived.SealItem(k, v, "x", map[string]any{"title": "T x"}))},
	}}
	// contentKey gives K_n for the namespace ("") and K_r for a resource,
	// as app.js's does.
	keys := map[string]string{"": base64.RawURLEncoding.EncodeToString(kn)}
	for name, b := range kr {
		keys[name] = base64.RawURLEncoding.EncodeToString(b)
	}

	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"openSealed", "openSealedEntries"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(viewsHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"view": view, "keys": keys, "whole": whole, "entries": entries})
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
		Whole   map[string]any
		Entries struct {
			Children []map[string]any
		}
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%v: %s", err, b)
	}

	if got, _ := json.Marshal(out.Whole["view"]); string(got) != `{"roots":["r"]}` {
		t.Errorf("whole response under the view key of K_n: %s", got)
	}
	for _, name := range []string{"ke", "kn", "other"} {
		if s, ok := out.Whole[name].(string); !ok || !strings.HasPrefix(s, "error: ") {
			t.Errorf("whole response sealed under %s opened: %v", name, out.Whole[name])
		}
	}
	if n := len(out.Entries.Children); n != 5 {
		t.Fatalf("%d entries", n)
	}
	for i, opened := range []bool{true, false, false, false, true} {
		e := out.Entries.Children[i]
		if opened {
			if e["title"] != "T x" || e["_opened"] != kid || e["_sealedErr"] != nil {
				t.Errorf("entry %d under the view key of its K_r: %v", i, e)
			}
			continue
		}
		if e["title"] != nil || e["_opened"] != nil || e["_sealedErr"] == nil {
			t.Errorf("entry %d (%v) opened under a key other than the view key of its K_r: %v", i, e["name"], e)
		}
	}
}
