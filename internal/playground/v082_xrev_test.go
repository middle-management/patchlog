package playground

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v82XrevKeys is a contentKey for the harness that gives K_r by
// "{ns}/{resource}" from input.keys, as /keys or a grant's keys would.
const v82XrevKeys = `
  globalThis.contentKey = async (kid, resource) => { const k = input.keys[Z.parseKid(kid).ns + '/' + resource]; if (!k) throw new Error('no key for ' + kid + ' / ' + resource); return Z.unb64u(k); };
`

// The seam between the tree service's v0.82 ancestors and where answers
// and the playground's reader (SERVICES §B.5, §E.2.6 Per-entry sealing):
// in a sealed or e2e catalog served per entry, each path node's values
// are in the top-level "nodes" map as { "href", "sealed" }, keyed by the
// node's name, with no "name" member (internal/tree/http.go pathsInto).
// The playground opens each under the K_r of the node its key names,
// comparing pl.name with the key, so breadcrumbs have their titles. An
// entry whose value is another node's, or whose own name isn't its key,
// isn't opened.
func TestV082XrevPlaygroundOpensAncestorsNodes(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/ancestors?of=%2Fr%2Fcat%2Fmatches.derby"
	ke := seal.NewKey()
	keys := map[string]string{}
	val := func(name, plain string) string {
		kr, err := seal.ResourceKey(ke, "cat", name)
		if err != nil {
			t.Fatal(err)
		}
		keys["cat/"+name] = b64u.EncodeToString(kr)
		vr, err := seal.ViewKey(kr, view)
		if err != nil {
			t.Fatal(err)
		}
		j, err := seal.Seal(vr, seal.Kid("cat", 1), seal.PL{"ns": "cat", "name": name, "view": view}, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	own := func(name string) string { return val(name, `{"title":"T `+name+`"}`) }
	// As (*query).ancestors and pathsInto write it, per entry.
	body := map[string]any{
		"at": "1abcdefghijklmnopqrstuvwxyz234567", "of": "/r/cat/matches.derby",
		"node":  map[string]any{"name": "matches.derby", "href": "/r/cat/matches.derby", "kind": "item", "sealed": own("matches.derby")},
		"paths": []any{[]any{"root", "season-2026", "matches.derby"}, []any{"archive", "matches.derby"}, []any{"misnamed", "matches.derby"}, []any{"bare", "matches.derby"}},
		"nodes": map[string]any{
			"root":          map[string]any{"href": "/r/cat/root", "sealed": own("root")},
			"season-2026":   map[string]any{"href": "/r/cat/season-2026", "sealed": own("season-2026"), "born": map[string]any{"sealed": val("season-2026", `{"born":"1b"}`)}},
			"matches.derby": map[string]any{"href": "/r/cat/matches.derby", "sealed": own("matches.derby")},
			// Another node's value filed under this name.
			"archive": map[string]any{"href": "/r/cat/archive", "sealed": own("root")},
			// An entry that names itself otherwise than its key.
			"misnamed": map[string]any{"href": "/r/cat/misnamed", "name": "root", "sealed": own("root")},
			// No href: still an entry of the map, named by its key, never
			// a value of whatever resource its pl names.
			"bare": map[string]any{"sealed": own("root")},
		},
	}
	type entry struct {
		Title string `json:"title"`
		Born  any    `json:"born"`
		Err   string `json:"_sealedErr"`
	}
	var out struct {
		Node  entry            `json:"node"`
		Nodes map[string]entry `json:"nodes"`
		Paths [][]struct{ Name, Href, Title string }
	}
	runV82(t, []string{"openSealed", "openSealedEntries", "wherePaths"}, "", v82XrevKeys+`
  const body = input.body;
  await openSealedEntries(body, input.view);
  out.node = body.node; out.nodes = body.nodes; out.paths = wherePaths(body).paths;
`, map[string]any{"view": view, "keys": keys, "body": body}, &out)
	if out.Node.Title != "T matches.derby" || out.Node.Err != "" {
		t.Errorf("the node's own entry: %+v", out.Node)
	}
	for _, name := range []string{"root", "season-2026", "matches.derby"} {
		if n := out.Nodes[name]; n.Title != "T "+name || n.Err != "" {
			t.Errorf("nodes[%q] isn't opened: title %q, error %q", name, n.Title, n.Err)
		}
	}
	if b, _ := out.Nodes["season-2026"].Born.(map[string]any); b == nil || b["born"] != "1b" || b["_sealedErr"] != nil {
		t.Errorf("nodes[season-2026].born, a value of the node's own: %v", out.Nodes["season-2026"].Born)
	}
	for _, name := range []string{"archive", "misnamed", "bare"} {
		if n := out.Nodes[name]; n.Title != "" || n.Err == "" {
			t.Errorf("nodes[%q], whose value is root's: opened as its own: title %q, error %q", name, n.Title, n.Err)
		}
	}
	if len(out.Paths) != 4 || len(out.Paths[0]) != 3 {
		t.Fatalf("paths: %+v", out.Paths)
	}
	for _, x := range out.Paths[0] {
		if x.Title != "T "+x.Name {
			t.Errorf("breadcrumb %q without its title: %+v", x.Name, x)
		}
	}
	for _, p := range out.Paths[1:] {
		if p[0].Title != "" {
			t.Errorf("breadcrumb %q shows a title that isn't its own: %q", p[0].Name, p[0].Title)
		}
	}
}

// The seam between the tree service's release previews (SERVICES §B.5
// Previews) and the reader's check of a value of another resource
// (§E.2.6 Values of another resource): in a preview the tree service
// reads a placement's item in the release's branch of its namespace and
// seals its file metadata under that branch's keys, so kid and pl.ns name
// the branch (internal/tree/files.go, Graph.Actual), while "item" keeps
// the link documents use, /r/{base}/{name}; the entry names the branch in
// "branch" (internal/tree/http.go entry). The playground compares the
// value with the branch's resource where the entry names a branch, and
// with the item's own namespace where it names none: never both.
func TestV082XrevPlaygroundPreviewFileValue(t *testing.T) {
	t.Parallel()
	const view = "/cat/at/1abcdefghijklmnopqrstuvwxyz234567/children?of=docs"
	ke := map[string][]byte{"cat-r7": seal.NewKey(), "matches-r7": seal.NewKey(), "matches": seal.NewKey()}
	keys := map[string]string{}
	val := func(ns, name, plain string) string {
		kr, err := seal.ResourceKey(ke[ns], ns, name)
		if err != nil {
			t.Fatal(err)
		}
		keys[ns+"/"+name] = b64u.EncodeToString(kr)
		vr, err := seal.ViewKey(kr, view)
		if err != nil {
			t.Fatal(err)
		}
		j, err := seal.Seal(vr, seal.Kid(ns, 1), seal.PL{"ns": ns, "name": name, "view": view}, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	child := func(branch, fileNS, fileName string) map[string]any {
		c := map[string]any{"name": "matches.derby", "href": "/r/cat/matches.derby", "kind": "item", "item": "/r/matches/derby",
			"sealed": val("cat-r7", "matches.derby", `{"title":"Derby"}`),
			"file":   map[string]any{"sealed": val(fileNS, fileName, `{"file":{"name":"derby.md"}}`)}}
		if branch != "" {
			c["branch"] = branch
		}
		return c
	}
	body := map[string]any{"children": []any{
		child("matches-r7", "matches-r7", "derby"), // 0: a preview's entry, as the tree service writes it
		child("", "matches-r7", "derby"),           // 1: no branch named: a value of another namespace than the item's
		child("matches-r7", "matches", "derby"),    // 2: a branch named, the value the base's
		child("matches-r7", "matches-r7", "other"), // 3: the branch's, of another resource
		child("", "matches", "derby"),              // 4: no preview: the item's own
	}}
	var out struct {
		Children []struct {
			Title string `json:"title"`
			Err   string `json:"_sealedErr"`
			File  struct {
				File any    `json:"file"`
				Err  string `json:"_sealedErr"`
			} `json:"file"`
		} `json:"children"`
	}
	// The branches' namespace documents name their bases (§7.6): what the
	// reader confirms a branch by (v082_xrev2_test.go).
	runV82(t, []string{"openSealed", "nsHeadDoc", "branchBase", "openSealedEntries"}, "", v82XrevKeys+`
  routes['/ns/cat-r7'] = { status: 200, json: { base: { ns: 'cat', at: '1abcdefghijklmnopqrstuvwxyz234567' } } };
  routes['/ns/matches-r7'] = { status: 200, json: { base: { ns: 'matches', at: '1abcdefghijklmnopqrstuvwxyz234567' } } };
  const body = input.body;
  await openSealedEntries(body, input.view);
  out.children = body.children;
`, map[string]any{"view": view, "keys": keys, "body": body}, &out)
	if len(out.Children) != 5 {
		t.Fatalf("children: %+v", out.Children)
	}
	for i, c := range out.Children {
		if c.Title != "Derby" || c.Err != "" {
			t.Errorf("child %d: the entry's own values, under the branch catalog's keys: %+v", i, c)
		}
		switch opens := i == 0 || i == 4; {
		case opens && (c.File.File == nil || c.File.Err != ""):
			t.Errorf("child %d: file metadata of the resource the entry draws it from isn't opened: %q", i, c.File.Err)
		case !opens && (c.File.File != nil || !strings.Contains(c.File.Err, "isn't the resource its entry draws it from")):
			t.Errorf("child %d: file metadata of another resource: opened %v, error %q", i, c.File.File, c.File.Err)
		}
	}
	if e := out.Children[2].File.Err; !strings.Contains(e, "matches-r7/derby") {
		t.Errorf("child 2: the refusal names the branch's resource as the one expected: %q", e)
	}
}
