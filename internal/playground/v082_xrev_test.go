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

// The seam between the tree service's release previews (SERVICES §B.5
// Previews) and the reader's check of a value of another resource
// (§E.2.6 Values of another resource): in a preview the tree service
// reads a placement's item in the release's branch of its namespace and
// seals its file metadata under that branch's keys, so kid and pl.ns name
// the branch (internal/tree/files.go, Graph.Actual), while "item" keeps
// the link documents use, /r/{base}/{name}; the entry's content URL names
// the branch's resource (internal/tree/http.go entry; v0.85, §B.5: "whose
// resource its entry's content URL then names"). The playground compares
// the value with the resource that URL names, and with the item's own
// where the entry has none: never both.
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
			c["url"] = "https://cms.example/r/" + branch + "/derby/rev/1abcdefghijklmnopqrstuvwxyz234567"
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
