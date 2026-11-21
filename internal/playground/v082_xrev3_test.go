package playground

import (
	"strings"
	"testing"
)

// v82Xrev3Fns is the readers themselves, treeGet and srGet, with what
// they learn a namespace's level by (nsInfo, sealedLevel) and what
// openSealedEntries needs (v82Xrev2Fns).
var v82Xrev3Fns = append([]string{"nsInfo", "sealedLevel", "srGet"}, v82Xrev2Fns...)

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
