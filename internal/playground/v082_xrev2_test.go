package playground

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v82Xrev2Fns is what openSealedEntries needs to ask whether a namespace
// is a branch of another: the namespace document's reader over api.
var v82Xrev2Fns = []string{"openSealed", "decrypted", "nsDocPL", "nsHeadDoc", "branchBase", "openSealedEntries"}

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

// The namespace an entry's content URL names, in the clear, is bound to
// something (v0.85, SERVICES §B.5 Previews, §E.2.6: the URL names the
// release branch's resource; before, the reference's own "branch" member
// did): item /r/matches/derby with a URL in secret must not open a value
// of secret/derby as the item's file. It counts only where that
// namespace's own document names the item's namespace as its base (§7.6:
// base never changes), directly or through a branch of it (a stacked
// release branch); a branch of another namespace, of a remote base, or
// one whose document can't be read is refused, and so is its value. The
// "branch" member is not read.
func TestV082Xrev2BranchIsABranchOfTheItemsNamespace(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=docs"
	s := newXrev2Sealer(t, view)
	child := func(branch any, fileNS string) map[string]any {
		var u any = branch
		if b, ok := branch.(string); ok {
			u = "https://cms.example/r/" + b + "/derby/rev/" + xrev2Head
		}
		// "branch" names a namespace whose value must never pass by it.
		return map[string]any{"name": "matches.derby", "href": "/r/cat/matches.derby", "kind": "item", "item": "/r/matches/derby", "url": u, "branch": "secret",
			"file": map[string]any{"sealed": s.val(fileNS, "derby", `{"file":{"name":"`+fileNS+`"}}`)}}
	}
	body := map[string]any{"children": []any{
		child("secret", "secret"),           // 0: a namespace with no document this reader gets
		child("other-r7", "other-r7"),       // 1: a branch, of another namespace
		child("matches-far", "matches-far"), // 2: a branch of a namespace of that name elsewhere
		child("matches-r7", "matches-r7"),   // 3: the item's namespace's branch
		child("matches-r8", "matches-r8"),   // 4: the same, its document sealed
		child("matches", "matches"),         // 5: the item's namespace itself
		child(7, "matches"),                 // 6: no URL: the item's own
		child(7, "secret"),                  // 7
		child("../ns/matches-r7", "secret"), // 8: no namespace name
		child("matches-r9", "matches-r9"),   // 9: a branch of the item's namespace's branch
		child("matches-r7/x", "matches-r7"), // 10: no content URL of the item
	}}
	docs := map[string]any{
		"other-r7":    map[string]any{"base": map[string]any{"ns": "other", "at": xrev2Head}},
		"matches-far": map[string]any{"base": map[string]any{"origin": "https://far.example", "ns": "matches", "at": xrev2Head}},
		"matches-r7":  map[string]any{"base": map[string]any{"ns": "matches", "at": xrev2Head}},
		"matches-r9":  map[string]any{"base": map[string]any{"ns": "matches-r7", "at": xrev2Head}},
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
	if len(out.Children) != 11 {
		t.Fatalf("children: %+v", out.Children)
	}
	opens := map[int]string{3: "matches-r7", 4: "matches-r8", 5: "matches", 6: "matches", 9: "matches-r9"}
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

// v0.85 (SERVICES §E.2.6 Per-entry sealing; CONFORMANCE E3 scenario 84):
// "Of an entry that carries sealed, it takes from outside it only what
// this section leaves in the clear": names, ids, URLs, heads and the
// listing's structure. Before, a node lost its cleartext title and born
// alone; now any other member in the clear goes too, such as a value a
// later version seals, while values sealed in place and an item's file in
// the clear (a namespace that isn't sealed) stay.
func TestV085ClearNodeMembersAreAnAllowlist(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=docs"
	s := newXrev2Sealer(t, view)
	children := `{"children": [
	  {"name":"matches.derby","href":"/r/cat/matches.derby","kind":"item","item":"/r/pub/derby","head":"1h","url":"https://cms.example/r/pub/derby/rev/1h",
	   "self":true,"order":3,"title":"CLEAR","born":"1clear","summary":"CLEAR","tags":["CLEAR"],"access":{"reader":["CLEAR"]},
	   "file":{"name":"derby.md","size":3,"type":"text/plain","modified":"2026-10-04T12:00:00Z"},"extra":{"sealed":"` + s.val("cat", "matches.derby", `{"extra":2}`) + `"},
	   "meta":{"sealed":"` + s.val("cat", "matches.derby", `{"meta":{"name":"derby.md","size":3,"type":"text/plain"}}`) + `"},
	   "children":[{"name":"docs","href":"/r/cat/docs","kind":"folder","summary":"CLEAR nested"}],
	   "sealed":"` + s.val("cat", "matches.derby", `{"title":"T"}`) + `"}
	 ]}`
	var out struct{ Children []map[string]any }
	runV82(t, v82Xrev2Fns, "", v82Xrev2Env+`
  const b = JSON.parse(input.children); await openSealedEntries(b, input.view); out.children = b.children;
`, map[string]any{"view": view, "keys": s.keys, "children": children}, &out)
	if len(out.Children) != 1 {
		t.Fatalf("children: %+v", out.Children)
	}
	c := out.Children[0]
	if c["title"] != "T" || c["_sealedErr"] != nil {
		t.Fatalf("the entry's sealed value: %+v", c)
	}
	for _, k := range []string{"born", "summary", "tags", "access"} {
		if _, has := c[k]; has {
			t.Errorf("%s, in the clear beside sealed, is kept: %v", k, c[k])
		}
	}
	for _, k := range []string{"name", "href", "kind", "item", "head", "url", "self", "order", "file", "children"} {
		if _, has := c[k]; !has {
			t.Errorf("%s, which §E.2.6 leaves in the clear, was dropped", k)
		}
	}
	// File metadata has a name too, and is no entry: in the clear or just
	// opened, it keeps its members.
	if f, _ := c["file"].(map[string]any); f["name"] != "derby.md" || f["size"] != 3.0 || f["type"] != "text/plain" || f["modified"] == nil {
		t.Errorf("an item's file in the clear lost members: %v", c["file"])
	}
	if m, _ := c["meta"].(map[string]any); m["meta"] == nil || m["meta"].(map[string]any)["size"] != 3.0 || m["meta"].(map[string]any)["type"] != "text/plain" {
		t.Errorf("a value sealed in place, opened, lost members: %v", c["meta"])
	}
	if x, _ := c["extra"].(map[string]any); x["extra"] != 2.0 {
		t.Errorf("a value sealed in place isn't opened: %v", c["extra"])
	}
	if kid := c["children"].([]any)[0].(map[string]any); kid["summary"] != nil || kid["name"] != "docs" {
		t.Errorf("a nested entry of the answer sealed per entry: %v", kid)
	}
}
