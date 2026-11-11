package playground

import (
	"strings"
	"testing"
)

// v82Xrev3Fns is the readers themselves, treeGet and srGet, with what
// they learn a namespace's level by (nsInfo, sealedLevel) and what
// openSealedEntries needs (v82Xrev2Fns).
var v82Xrev3Fns = append([]string{"nsInfo", "sealedLevel", "treeGet", "srGet"}, v82Xrev2Fns...)

// v82Xrev3Preload is the constants of app.js treeGet and srGet stand
// among; C.ns is the catalog the page shows, which the scenario sets.
const v82Xrev3Preload = `
const TREE = '/playground/tree', INDEX = '/playground/index';
const C = { ns: '', min: [] };
const sleep = () => Promise.resolve();
`

// v82Xrev3Env is v82Xrev2Env, and the level each namespace of
// input.levels has in its namespace document: a sealed one answers
// application/jose, which is all nsInfo needs to learn it (§7.1).
const v82Xrev3Env = v82Xrev2Env + `
  for (const [ns, level] of Object.entries(input.levels || {})) {
    routes['/ns/' + ns] = level === 'sealed' ? { status: 200, jose: true, text: 'eyJ.x.y.z.w', json: null }
      : level ? { status: 200, json: { encryption: { level } } } : { status: 200, json: { read: 'public' } };
  }
`

// at is s's keys sealing for another view: one reader, several answers.
func (s *xrev2Sealer) at(view string) *xrev2Sealer {
	return &xrev2Sealer{t: s.t, view: view, ke: s.ke, keys: s.keys}
}

// SERVICES §E.2.6 Per-entry sealing, at the tree reader itself: what
// openSealedEntries holds of an answer sealed per entry (v082_xrev2_test.go)
// it holds only as far as its caller says which catalog the answer is of
// and that the catalog is sealed. treeGet says so, { ns: C.ns, sealed },
// from the level nsInfo learnt, for an answer that came as JSON. So a
// sealed catalog's listing, fetched as the page fetches it, shows by name
// only a node whose title stands in the clear, with a sealed value that
// doesn't open or with none at all, and refuses an authentic value of
// another namespace filed among the catalog's entries; a plain catalog's
// titles stay.
func TestV082Xrev3TreeGetTellsTheCatalogAndItsLevel(t *testing.T) {
	t.Parallel()
	const pre = "/cat/at/" + xrev2Head + "/"
	paths := map[string]string{"a": "children?of=a", "b": "children?of=b", "bw": "ancestors?of=%2Fr%2Fcat%2Fclearonly", "c": "children?of=c", "d": "children?of=d"}
	s := newXrev2Sealer(t, "")
	sa, sb, sc := s.at(pre+paths["a"]), s.at(pre+paths["b"]), s.at(pre+paths["c"])
	bodies := map[string]string{
		// (a) A title in the clear beside a sealed value that doesn't open: root's value, on another node.
		"a": `{"children": [
		  {"name":"failed","href":"/r/cat/failed","kind":"folder","title":"CLEAR beside a sealed that does not open","sealed":"` + sa.val("cat", "root", `{"title":"T root"}`) + `"},
		  {"name":"opened","href":"/r/cat/opened","kind":"folder","sealed":"` + sa.val("cat", "opened", `{"title":"T opened"}`) + `"}
		 ]}`,
		// (b) No entry carries a sealed value of its own: only the catalog's level says the answer is sealed per entry.
		"b": `{"children": [
		  {"name":"clearonly","href":"/r/cat/clearonly","kind":"folder","title":"CLEAR no sealed","born":"1clear"},
		  {"name":"bornfails","href":"/r/cat/bornfails","kind":"folder","title":"CLEAR beside a born that does not open","born":{"sealed":"` + sb.val("cat", "root", `{"born":"1b"}`) + `"}}
		 ]}`,
		"bw": `{"paths": [["root","clearonly"]], "nodes": {
		  "root": {"href":"/r/cat/root","title":"CLEAR root"},
		  "clearonly": {"href":"/r/cat/clearonly","title":"CLEAR no sealed","born":"1clear"}
		 }}`,
		// (c) Authentic values of namespace secret, which this reader holds the keys of, among cat's entries.
		"c": `{"children": [
		  {"name":"nohref","kind":"folder","title":"CLEAR nohref","sealed":"` + sc.val("secret", "nohref", `{"title":"T secret/nohref"}`) + `"},
		  {"name":"lying","href":"/r/secret/lying","kind":"folder","sealed":"` + sc.val("secret", "lying", `{"title":"T secret/lying"}`) + `"},
		  {"name":"own","href":"/r/cat/own","kind":"folder","sealed":"` + sc.val("cat", "own", `{"title":"T cat/own"}`) + `"}
		 ]}`,
		// (d) A plain catalog's listing, its values in the clear.
		"d": `{"children": [{"name":"docs","href":"/r/pub/docs","kind":"folder","title":"Docs","born":"1b"}]}`,
	}
	type entry = map[string]any
	var out struct {
		A, B, C, D []entry
		BW         struct {
			Paths [][]struct{ Name, Title string }
			Nodes map[string]entry
		}
		Views map[string]string
	}
	runV82(t, v82Xrev3Fns, v82Xrev3Preload, v82Xrev3Env+`
  out.views = {};
  const get = async (k, ns) => {
    C.ns = ns;
    const p = TREE + '/' + ns + '/' + input.paths[k];
    routes[p] = { status: 200, json: JSON.parse(input.bodies[k]), finalPath: TREE + '/' + ns + '/at/' + input.head + '/' + input.paths[k] };
    const res = await treeGet(input.paths[k]);
    out.views[k] = res.view;
    return res.body;
  };
  out.a = (await get('a', 'cat')).children;
  out.b = (await get('b', 'cat')).children;
  const w = await get('bw', 'cat');
  out.bw = { paths: wherePaths(w).paths, nodes: w.nodes };
  out.c = (await get('c', 'cat')).children;
  out.d = (await get('d', 'pub')).children;
`, map[string]any{"keys": s.keys, "paths": paths, "bodies": bodies, "head": xrev2Head,
		"levels": map[string]string{"cat": "sealed", "pub": ""}, "docs": map[string]any{"secret": map[string]any{"read": "public"}}}, &out)

	for k, p := range paths {
		ns := "cat"
		if k == "d" {
			ns = "pub"
		}
		if want := "/" + ns + "/at/" + xrev2Head + "/" + p; out.Views[k] != want {
			t.Fatalf("answer %s: view %q, want %q", k, out.Views[k], want)
		}
	}
	if len(out.A) != 2 || len(out.B) != 2 || len(out.C) != 3 || len(out.D) != 1 {
		t.Fatalf("children: a %v, b %v, c %v, d %v", out.A, out.B, out.C, out.D)
	}

	// (a)
	if c := out.A[0]; c["title"] != nil || c["_sealedErr"] == nil || c["name"] != "failed" || c["href"] != "/r/cat/failed" {
		t.Errorf("(a) a node whose sealed value doesn't open isn't shown by name only: %v", c)
	}
	if c := out.A[1]; c["title"] != "T opened" || c["_sealedErr"] != nil {
		t.Errorf("(a) a node whose sealed value opens: %v", c)
	}

	// (b)
	if c := out.B[0]; c["title"] != nil || c["born"] != nil || c["name"] != "clearonly" {
		t.Errorf("(b) a node of a sealed catalog, with no sealed value, keeps what stands in the clear: %v", c)
	}
	c := out.B[1]
	if b, _ := c["born"].(map[string]any); c["title"] != nil || b == nil || b["born"] != nil || b["_sealedErr"] == nil {
		t.Errorf("(b) a node of a sealed catalog whose only sealed value, born, doesn't open, keeps a clear title: %v", c)
	}
	if len(out.BW.Paths) != 1 || len(out.BW.Paths[0]) != 2 {
		t.Fatalf("(b) paths: %+v", out.BW.Paths)
	}
	for _, x := range out.BW.Paths[0] {
		if x.Title != "" {
			t.Errorf("(b) breadcrumb %q of a sealed catalog shows a title no opened value gave: %q", x.Name, x.Title)
		}
	}
	if n := out.BW.Nodes["clearonly"]; n["title"] != nil || n["born"] != nil || n["href"] != "/r/cat/clearonly" {
		t.Errorf("(b) nodes[clearonly]: %v", n)
	}

	// (c)
	for i, name := range []string{"nohref", "lying"} {
		c := out.C[i]
		if e, _ := c["_sealedErr"].(string); c["name"] != name || c["title"] != nil || !strings.Contains(e, "a value sealed for namespace secret in an entry of cat") {
			t.Errorf("(c) child %q of catalog cat shows a value sealed for another namespace: %v", name, c)
		}
	}
	if c := out.C[2]; c["title"] != "T cat/own" || c["_sealedErr"] != nil {
		t.Errorf("(c) the catalog's own value, beside the refused ones: %v", c)
	}

	// (d)
	if c := out.D[0]; c["title"] != "Docs" || c["born"] != "1b" || c["_sealedErr"] != nil {
		t.Errorf("(d) a plain catalog's values in the clear aren't kept: %v", c)
	}
}

// The same at the index reader: srGet says { ns, sealed } of the
// namespace searched. A hit of a sealed namespace shows resource, id and
// url only unless its sealed value opens, whether that value fails or is
// absent; a hit carrying an authentic value of another namespace is
// refused (a hit has no href to name its namespace: only the caller
// does); a plain namespace's hits keep their values.
func TestV082Xrev3SrGetTellsTheNamespaceAndItsLevel(t *testing.T) {
	t.Parallel()
	view := func(ns string) string { return "/" + ns + "/at/" + xrev2Head + "/search?q=derby" }
	s := newXrev2Sealer(t, view("docs"))
	bodies := map[string]string{
		"docs": `{"ns":"docs","hits": [
		  {"resource":"a","id":"1a","url":"/r/docs/a/rev/1a","schema":"CLEAR","sealed":"` + s.val("docs", "a", `{"schema":"/r/s/doc","score":2}`) + `"},
		  {"resource":"b","id":"1b","url":"/r/docs/b/rev/1b","schema":"CLEAR","/title":["CLEAR"],"sealed":"` + s.val("docs", "a", `{"schema":"/r/s/doc"}`) + `"},
		  {"resource":"c","id":"1c","url":"/r/docs/c/rev/1c","schema":"CLEAR","/title":["CLEAR"],"score":1},
		  {"resource":"x","id":"1x","url":"/r/docs/x/rev/1x","sealed":"` + s.val("secret", "x", `{"schema":"/r/s/secret","/title":["T secret/x"]}`) + `"}
		 ]}`,
		"open": `{"ns":"open","hits": [{"resource":"c","id":"1c","url":"/r/open/c/rev/1c","schema":"/r/s/doc","/title":["Derby"],"score":1}]}`,
	}
	type entry = map[string]any
	var out struct {
		Docs, Open []entry
		Views      map[string]string
	}
	runV82(t, v82Xrev3Fns, v82Xrev3Preload, v82Xrev3Env+`
  out.views = {};
  const get = async (ns) => {
    const p = INDEX + '/' + ns + '/search?q=derby';
    routes[p] = { status: 200, json: JSON.parse(input.bodies[ns]), finalPath: INDEX + '/' + ns + '/at/' + input.head + '/search?q=derby' };
    const res = await srGet(p, ns);
    out.views[ns] = res.view;
    return res.body.hits;
  };
  out.docs = await get('docs');
  out.open = await get('open');
`, map[string]any{"keys": s.keys, "bodies": bodies, "head": xrev2Head,
		"levels": map[string]string{"docs": "sealed", "open": ""}, "docs": map[string]any{"secret": map[string]any{"read": "public"}}}, &out)

	for _, ns := range []string{"docs", "open"} {
		if out.Views[ns] != view(ns) {
			t.Fatalf("view of %s: %q, want %q", ns, out.Views[ns], view(ns))
		}
	}
	if len(out.Docs) != 4 || len(out.Open) != 1 {
		t.Fatalf("hits: %v, %v", out.Docs, out.Open)
	}
	if h := out.Docs[0]; h["schema"] != "/r/s/doc" || h["score"] != float64(2) || h["_sealedErr"] != nil {
		t.Errorf("a hit whose sealed value opens: %v", h)
	}
	// (a)
	if h := out.Docs[1]; h["schema"] != nil || h["/title"] != nil || h["_sealedErr"] == nil || h["resource"] != "b" || h["id"] != "1b" || h["url"] != "/r/docs/b/rev/1b" {
		t.Errorf("(a) a hit whose sealed value doesn't open isn't by name only: %v", h)
	}
	// (b)
	if h := out.Docs[2]; h["schema"] != nil || h["/title"] != nil || h["score"] != nil || h["resource"] != "c" || h["id"] != "1c" || h["url"] != "/r/docs/c/rev/1c" {
		t.Errorf("(b) a hit of a sealed namespace, with no sealed value, keeps what stands in the clear: %v", h)
	}
	// (c)
	h := out.Docs[3]
	if e, _ := h["_sealedErr"].(string); h["schema"] != nil || h["/title"] != nil || !strings.Contains(e, "a value sealed for namespace secret in an entry of docs") {
		t.Errorf("(c) a hit of namespace docs shows a value sealed for another namespace: %v", h)
	}
	// (d)
	if h := out.Open[0]; h["schema"] != "/r/s/doc" || h["score"] != float64(1) || h["/title"] == nil {
		t.Errorf("(d) a plain namespace's hit isn't kept as it came: %v", h)
	}
}
