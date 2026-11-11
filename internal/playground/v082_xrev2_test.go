package playground

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v82Xrev2Fns is what openSealedEntries needs to ask whether a namespace
// is a branch of another: the namespace document's reader over api.
var v82Xrev2Fns = []string{"openSealed", "decrypted", "nsDocPL", "nsHeadDoc", "branchBase", "openSealedEntries", "wherePaths"}

// v82Xrev2Env is v82XrevKeys, and K_n by "{ns}/" for a sealed namespace
// document; input.docs are the namespace documents GET /ns/{ns} answers,
// a string being a sealed one (the JWE) at head input.head.
const v82Xrev2Env = v82XrevKeys + `
  globalThis.renderEntry = () => {};
  for (const [ns, d] of Object.entries(input.docs || {})) {
    routes['/ns/' + ns] = typeof d === 'string' ? { status: 200, jose: true, text: d, json: null, finalPath: '/ns/' + ns + '/rev/' + input.head } : { status: 200, json: d };
  }
`

// xrev2Sealer seals values for a view as the services do (SERVICES
// §E.2.6), one epoch key per namespace, and collects the K_r (and K_n) a
// reader would hold.
type xrev2Sealer struct {
	t    *testing.T
	view string
	ke   map[string][]byte
	keys map[string]string
}

const xrev2Head = "1abcdefghijklmnopqrstuvwxyz234567"

func newXrev2Sealer(t *testing.T, view string) *xrev2Sealer {
	return &xrev2Sealer{t: t, view: view, ke: map[string][]byte{}, keys: map[string]string{}}
}

func (s *xrev2Sealer) epoch(ns string) []byte {
	if s.ke[ns] == nil {
		s.ke[ns] = seal.NewKey()
	}
	return s.ke[ns]
}

// val is a per-entry value of ns/name: JWE of plain under the view key of
// its K_r, pl { ns, name, view }.
func (s *xrev2Sealer) val(ns, name, plain string) string {
	s.t.Helper()
	kr, err := seal.ResourceKey(s.epoch(ns), ns, name)
	if err != nil {
		s.t.Fatal(err)
	}
	s.keys[ns+"/"+name] = b64u.EncodeToString(kr)
	vr, err := seal.ViewKey(kr, s.view)
	if err != nil {
		s.t.Fatal(err)
	}
	j, err := seal.Seal(vr, seal.Kid(ns, 1), seal.PL{"ns": ns, "name": name, "view": s.view}, []byte(plain))
	if err != nil {
		s.t.Fatal(err)
	}
	return j
}

// nsDoc is ns's namespace document as a sealed namespace serves it: JWE
// under K_n, pl { ns, id, kind: "doc" } (§E.2.2).
func (s *xrev2Sealer) nsDoc(ns, doc string) string {
	s.t.Helper()
	kn, err := seal.NamespaceKey(s.epoch(ns), ns)
	if err != nil {
		s.t.Fatal(err)
	}
	s.keys[ns+"/"] = b64u.EncodeToString(kn)
	j, err := seal.Seal(kn, seal.Kid(ns, 1), seal.PL{"ns": ns, "id": xrev2Head, "kind": "doc"}, []byte(doc))
	if err != nil {
		s.t.Fatal(err)
	}
	return j
}

// SERVICES §E.2.6 Per-entry sealing: a reader "decrypts the entries it
// holds keys for and shows the rest by name only". In an answer sealed
// per entry the tree service puts a node's title and born in "sealed"
// and nowhere else, so a "title" in the clear beside it is nobody's: the
// breadcrumbs of an ancestors answer showed it, unmarked, for a node
// whose sealed value was absent, didn't open, or opened without a title.
// openSealedEntries now drops it, there and for ordinary children; an
// index hit keeps resource, id and url only. A plain catalog's titles,
// and file metadata in the clear (an item of a public namespace), stay.
func TestV082Xrev2ClearValuesBesideSealedAreDropped(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/ancestors?of=%2Fr%2Fcat%2Fmatches.derby"
	s := newXrev2Sealer(t, view)
	own := func(name string) string { return s.val("cat", name, `{"title":"T `+name+`"}`) }
	where := `{
	 "paths": [["root","clearonly","failed","notitle","matches.derby"], [{"name":"old","href":"/r/cat/old","title":"CLEAR old form"}]],
	 "nodes": {
	  "root": {"href":"/r/cat/root","sealed":"` + own("root") + `"},
	  "clearonly": {"href":"/r/cat/clearonly","title":"CLEAR no sealed","born":"1clear"},
	  "failed": {"href":"/r/cat/failed","title":"CLEAR beside a sealed that does not open","sealed":"` + own("root") + `"},
	  "notitle": {"href":"/r/cat/notitle","title":"CLEAR beside an opened sealed without title","sealed":"` + s.val("cat", "notitle", `{"born":"1b"}`) + `"},
	  "matches.derby": {"href":"/r/cat/matches.derby","sealed":"` + own("matches.derby") + `"}
	 }}`
	children := `{"children": [
	  {"name":"docs","href":"/r/cat/docs","kind":"folder","title":"CLEAR failed","sealed":"` + own("root") + `"},
	  {"name":"clearonly","href":"/r/cat/clearonly","kind":"folder","title":"CLEAR no sealed"},
	  {"name":"matches.derby","href":"/r/cat/matches.derby","kind":"item","item":"/r/pub/derby","file":{"size":3,"type":"text/plain"},"born":{"sealed":"` + s.val("cat", "matches.derby", `{"born":"1b"}`) + `"},"sealed":"` + own("matches.derby") + `"}
	 ]}`
	// A sealed catalog whose answer carries no sealed value at all: only what the caller knows tells.
	bare := `{"children": [{"name":"docs","href":"/r/cat/docs","kind":"folder","title":"CLEAR in a sealed catalog"}]}`
	// A public catalog's file tree over a sealed namespace: titles are the catalog's, in the clear.
	plain := `{"children": [{"name":"matches.derby","href":"/r/pub/matches.derby","kind":"item","title":"Derby","born":"1b","item":"/r/matches/derby","file":{"sealed":"` + s.val("matches", "derby", `{"file":{"name":"derby.md"}}`) + `"}}]}`
	hits := `{"ns":"docs","hits": [
	  {"resource":"a","id":"1a","url":"/r/docs/a/rev/1a","schema":"CLEAR","/title":["CLEAR"],"sealed":"` + s.val("docs", "a", `{"schema":"/r/s/doc","score":2}`) + `"},
	  {"resource":"b","id":"1b","url":"/r/docs/b/rev/1b","schema":"CLEAR","sealed":"` + s.val("docs", "a", `{"schema":"/r/s/doc"}`) + `"},
	  {"resource":"c","id":"1c","url":"/r/docs/c/rev/1c","schema":"CLEAR","score":1}
	 ]}`
	type entry = map[string]any
	var out struct {
		Paths    [][]struct{ Name, Title string }
		Nodes    map[string]entry
		Children []entry
		Bare     []entry
		BareAny  []entry
		Plain    []entry
		Hits     []entry
		HitsAny  []entry
	}
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  const open = async (text, ctx) => { const b = JSON.parse(text); await openSealedEntries(b, input.view, undefined, undefined, ctx); return b; };
  const w = await open(input.where);
  out.paths = wherePaths(w).paths; out.nodes = w.nodes;
  out.children = (await open(input.children)).children;
  out.bare = (await open(input.bare, { ns: 'cat', sealed: true })).children;
  out.bareAny = (await open(input.bare, { ns: 'cat', sealed: false })).children;
  out.plain = (await open(input.plain, { ns: 'pub', sealed: false })).children;
  out.hits = (await open(input.hits, { ns: 'docs', sealed: true })).hits;
  out.hitsAny = (await open(input.hits)).hits;
`, map[string]any{"view": view, "keys": s.keys, "where": where, "children": children, "bare": bare, "plain": plain, "hits": hits}, &out)

	if len(out.Paths) != 2 || len(out.Paths[0]) != 5 || len(out.Paths[1]) != 1 {
		t.Fatalf("paths: %+v", out.Paths)
	}
	for _, x := range append(out.Paths[0], out.Paths[1]...) {
		switch x.Name {
		case "root", "matches.derby":
			if x.Title != "T "+x.Name {
				t.Errorf("breadcrumb %q, whose sealed value opens: title %q", x.Name, x.Title)
			}
		default:
			if x.Title != "" {
				t.Errorf("breadcrumb %q shows a title no opened value gave, in an answer sealed per entry: %q", x.Name, x.Title)
			}
		}
	}
	if n := out.Nodes["clearonly"]; n["title"] != nil || n["born"] != nil {
		t.Errorf("nodes[clearonly] keeps clear values: %v", n)
	}
	if n := out.Nodes["failed"]; n["title"] != nil || n["_sealedErr"] == nil {
		t.Errorf("nodes[failed]: %v", n)
	}
	if n := out.Nodes["notitle"]; n["title"] != nil || n["born"] != "1b" || n["_sealedErr"] != nil {
		t.Errorf("nodes[notitle], opened without a title: %v", n)
	}

	if len(out.Children) != 3 {
		t.Fatalf("children: %v", out.Children)
	}
	if c := out.Children[0]; c["title"] != nil || c["_sealedErr"] == nil {
		t.Errorf("a child whose sealed value doesn't open keeps a clear title: %v", c)
	}
	if c := out.Children[1]; c["title"] != nil {
		t.Errorf("a child without a sealed value, beside sealed ones, keeps a clear title: %v", c)
	}
	c := out.Children[2]
	if f, _ := c["file"].(map[string]any); c["title"] != "T matches.derby" || f == nil || f["size"] != float64(3) {
		t.Errorf("an opened child, and file metadata in the clear: %v", c)
	}
	if b, _ := c["born"].(map[string]any); b == nil || b["born"] != "1b" || b["_sealedErr"] != nil {
		t.Errorf("a born sealed in place is opened as before: %v", c["born"])
	}
	if len(out.Bare) != 1 || out.Bare[0]["title"] != nil {
		t.Errorf("a catalog known sealed, an answer with no sealed value: %v", out.Bare)
	}
	if len(out.BareAny) != 1 || out.BareAny[0]["title"] != "CLEAR in a sealed catalog" {
		t.Errorf("a plain catalog's titles are kept: %v", out.BareAny)
	}
	if len(out.Plain) != 1 {
		t.Fatalf("plain: %v", out.Plain)
	}
	if p, f := out.Plain[0], out.Plain[0]["file"].(map[string]any); p["title"] != "Derby" || p["born"] != "1b" || f["file"] == nil || f["_sealedErr"] != nil {
		t.Errorf("a public catalog over a sealed namespace: titles in the clear stay, the file's value opens: %v", p)
	}

	for name, hs := range map[string][]entry{"sealed": out.Hits, "unknown": out.HitsAny} {
		if len(hs) != 3 {
			t.Fatalf("%s hits: %v", name, hs)
		}
		if h := hs[0]; h["schema"] != "/r/s/doc" || h["score"] != float64(2) || h["/title"] != nil || h["url"] != "/r/docs/a/rev/1a" {
			t.Errorf("%s: an opened hit has its sealed values and none in the clear: %v", name, h)
		}
		if h := hs[1]; h["schema"] != nil || h["_sealedErr"] == nil || h["id"] != "1b" {
			t.Errorf("%s: a hit that doesn't open is by name only: %v", name, h)
		}
	}
	if h := out.Hits[2]; h["schema"] != nil || h["score"] != nil || h["resource"] != "c" {
		t.Errorf("a hit without a sealed value, in a namespace known sealed: %v", h)
	}
	// Hits of several namespaces mix clear and sealed ones: without the caller's word a clear hit stays.
	if h := out.HitsAny[2]; h["schema"] != "CLEAR" {
		t.Errorf("a clear hit, nothing known of its namespace: %v", h)
	}
}

// An entry's own sealed value was opened under whatever namespace its kid
// named: a value of secret/otherns, filed in catalog cat's nodes or
// listed among its children, showed as cat's node. It is now of the
// namespace the caller reads (or, given none, the one its href names) or
// of a branch of that one, which a release preview seals a catalog's
// entries under (§B.5 Previews): a branch by its own namespace document's
// base, sealed or not.
func TestV082Xrev2EntryNamespaceIsBound(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/ancestors?of=%2Fr%2Fcat%2Fmatches.derby"
	s := newXrev2Sealer(t, view)
	title := func(ns, name string) string { return s.val(ns, name, `{"title":"T `+ns+`/`+name+`"}`) }
	body := `{
	 "paths": [["root","otherns","preview","sealedpreview","stranger","remote"]],
	 "nodes": {
	  "root": {"href":"/r/cat/root","sealed":"` + title("cat", "root") + `"},
	  "otherns": {"href":"/r/cat/otherns","sealed":"` + title("secret", "otherns") + `"},
	  "preview": {"href":"/r/cat/preview","sealed":"` + title("cat-r7", "preview") + `"},
	  "sealedpreview": {"href":"/r/cat/sealedpreview","sealed":"` + title("cat-r8", "sealedpreview") + `"},
	  "stranger": {"href":"/r/cat/stranger","sealed":"` + title("other-r7", "stranger") + `"},
	  "remote": {"href":"/r/cat/remote","sealed":"` + title("cat-far", "remote") + `"}
	 },
	 "children": [
	  {"name":"nohref","sealed":"` + title("secret", "nohref") + `"},
	  {"name":"lying","href":"/r/secret/lying","sealed":"` + title("secret", "lying") + `"},
	  {"name":"preview","sealed":"` + title("cat-r7", "preview") + `"}
	 ]}`
	docs := map[string]any{
		"cat-r7":   map[string]any{"base": map[string]any{"ns": "cat", "at": xrev2Head}},
		"cat-r8":   s.nsDoc("cat-r8", `{"base":{"ns":"cat","at":"`+xrev2Head+`"},"encryption":{"level":"sealed","epoch":1}}`),
		"other-r7": map[string]any{"base": map[string]any{"ns": "other", "at": xrev2Head}},
		"cat-far":  map[string]any{"base": map[string]any{"origin": "https://far.example", "ns": "cat", "at": xrev2Head}},
		"secret":   map[string]any{"read": "public"},
	}
	type res struct {
		Paths    [][]struct{ Name, Title string }
		Children []struct {
			Name  string `json:"name"`
			Title string `json:"title"`
			Err   string `json:"_sealedErr"`
		}
	}
	var out struct{ Href, Given res }
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  for (const [k, ctx] of [['href', undefined], ['given', { ns: 'cat', sealed: true }]]) {
    const b = JSON.parse(input.body);
    await openSealedEntries(b, input.view, undefined, undefined, ctx);
    out[k] = { paths: wherePaths(b).paths, children: b.children };
  }
`, map[string]any{"view": view, "keys": s.keys, "body": body, "docs": docs, "head": xrev2Head}, &out)
	want := map[string]string{"root": "T cat/root", "preview": "T cat-r7/preview", "sealedpreview": "T cat-r8/sealedpreview"}
	for name, r := range map[string]res{"by href": out.Href, "by the caller's namespace": out.Given} {
		if len(r.Paths) != 1 || len(r.Paths[0]) != 6 || len(r.Children) != 3 {
			t.Fatalf("%s: %+v", name, r)
		}
		for _, x := range r.Paths[0] {
			if x.Title != want[x.Name] {
				t.Errorf("%s: breadcrumb %q of catalog cat: title %q, want %q", name, x.Name, x.Title, want[x.Name])
			}
		}
		if c := r.Children[2]; c.Title != "T cat-r7/preview" || c.Err != "" {
			t.Errorf("%s: a preview's child, under the catalog's branch: %+v", name, c)
		}
	}
	// Nothing names a namespace for an entry without href read with no context: as before, it opens.
	if c := out.Href.Children[0]; c.Title != "T secret/nohref" {
		t.Errorf("an entry with nothing to compare its kid with: %+v", c)
	}
	for i := 0; i < 2; i++ {
		if c := out.Given.Children[i]; c.Title != "" || !strings.Contains(c.Err, "a value sealed for namespace secret in an entry of cat") {
			t.Errorf("child %q of catalog cat shows a value sealed for another namespace: %+v", c.Name, c)
		}
	}
}

// An entry's "branch", in the clear, was bound to nothing: item
// /r/matches/derby with branch secret opened a value of secret/derby as
// the item's file. It counts only where the branch's own namespace
// document names the item's namespace as its base (§7.6: base never
// changes); a branch of another namespace, of a remote base, or one whose
// document can't be read is refused, and so is its value.
func TestV082Xrev2BranchIsABranchOfTheItemsNamespace(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=docs"
	s := newXrev2Sealer(t, view)
	child := func(branch any, fileNS string) map[string]any {
		return map[string]any{"name": "matches.derby", "href": "/r/cat/matches.derby", "kind": "item", "item": "/r/matches/derby", "branch": branch,
			"file": map[string]any{"sealed": s.val(fileNS, "derby", `{"file":{"name":"`+fileNS+`"}}`)}}
	}
	body := map[string]any{"children": []any{
		child("secret", "secret"),           // 0: a namespace with no document this reader gets
		child("other-r7", "other-r7"),       // 1: a branch, of another namespace
		child("matches-far", "matches-far"), // 2: a branch of a namespace of that name elsewhere
		child("matches-r7", "matches-r7"),   // 3: the item's namespace's branch
		child("matches-r8", "matches-r8"),   // 4: the same, its document sealed
		child("matches", "matches"),         // 5: the item's namespace itself
		child(7, "matches"),                 // 6: no branch named
		child(7, "secret"),                  // 7
		child("../ns/matches-r7", "secret"), // 8: no namespace name
	}}
	docs := map[string]any{
		"other-r7":    map[string]any{"base": map[string]any{"ns": "other", "at": xrev2Head}},
		"matches-far": map[string]any{"base": map[string]any{"origin": "https://far.example", "ns": "matches", "at": xrev2Head}},
		"matches-r7":  map[string]any{"base": map[string]any{"ns": "matches", "at": xrev2Head}},
		"matches-r8":  s.nsDoc("matches-r8", `{"base":{"ns":"matches","at":"`+xrev2Head+`"},"encryption":{"level":"sealed","epoch":1}}`),
	}
	var out struct {
		Children []struct {
			File struct {
				File map[string]any `json:"file"`
				Err  string         `json:"_sealedErr"`
			} `json:"file"`
		} `json:"children"`
		Asked []string
	}
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  const body = input.body; await openSealedEntries(body, input.view); out.children = body.children; out.asked = asked;
`, map[string]any{"view": view, "keys": s.keys, "body": body, "docs": docs, "head": xrev2Head}, &out)
	if len(out.Children) != 9 {
		t.Fatalf("children: %+v", out.Children)
	}
	opens := map[int]string{3: "matches-r7", 4: "matches-r8", 5: "matches", 6: "matches"}
	for i, c := range out.Children {
		ns, ok := opens[i]
		switch {
		case ok && (c.File.File["name"] != ns || c.File.Err != ""):
			t.Errorf("child %d: the file of %s/derby isn't opened: %+v", i, ns, c.File)
		case !ok && (c.File.File != nil || c.File.Err == ""):
			t.Errorf("child %d: item /r/matches/derby shows a file value of a namespace that is no branch of matches: %+v", i, c.File)
		}
	}
	for _, i := range []int{0, 1, 2} {
		if e := out.Children[i].File.Err; !strings.Contains(e, "isn't known to be a branch of its item's namespace matches") {
			t.Errorf("child %d: refusal %q", i, e)
		}
	}
	for _, a := range out.Asked {
		if strings.Contains(a, "..") {
			t.Errorf("a branch that is no namespace name was asked for: %s", a)
		}
	}
}
