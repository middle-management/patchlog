package annot

import (
	"strings"
	"testing"
)

var (
	pathAnchorLib  = "/r/s/anchorlib/rev/" + rev('p')
	pathAnchorUser = "/r/s/anchoruser/rev/" + rev('q')
)

func init() {
	store[pathAnchorLib] = `{` + d2020 + `,
		"x-index": "root",
		"$defs": {
			"tag":  {"$anchor": "tag", "type": "string", "x-index": "facet"},
			"link": {"$dynamicAnchor": "link", "type": "string", "x-ref": {"pinned": true}}
		}
	}`
	store[pathAnchorUser] = `{` + d2020 + `,
		"type": "object",
		"properties": {
			"$schema": {"type": "string"},
			"tag":  {"$ref": "` + pathAnchorLib + `#tag"},
			"link": {"$ref": "` + pathAnchorLib + `#link"}
		}
	}`
}

// CIS-13: a $ref's plain name resolves to the anchor of the revision it
// names (§6.1), for annotations and the static x-ref walk alike, never to
// the revision's root.
func TestV073RevisionAnchor(t *testing.T) {
	doc := j(`{"$schema":"` + pathAnchorUser + `","tag":"t","link":"/r/m/x/rev/` + rev('r') + `"}`)
	got, err := Collect(doc, loader)
	if err != nil {
		t.Fatal(err)
	}
	g := strings.Join(short(got), "\n")
	if !strings.Contains(g, `x-index /tag="facet"`) || strings.Contains(g, `"root"`) {
		t.Errorf("Collect:\n%s", g)
	}
	refs, err := FindRefs(doc, loader)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Pointer != "/link" || !refs[0].Pinned || refs[0].SchemaPath != pathAnchorLib+"#/$defs/link" {
		t.Errorf("FindRefs = %+v", refs)
	}
}

// CIS-18: definitions holds subschemas, so its anchors resolve (§6.5).
func TestV073DefinitionsAnchor(t *testing.T) {
	root := j(`{"properties": {"a": {"$ref": "#d"}}, "definitions": {"x": {"$anchor": "d", "type": "string", "x-index": "text"}}}`)
	got, err := CollectWith(root, "", j(`{"a":"v"}`), loader)
	if err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(short(got), "\n"); g != `x-index /a="text"` {
		t.Errorf("Collect: %s", g)
	}
	root = j(`{"properties": {"a": {"$ref": "#d"}}, "definitions": {"x": {"$anchor": "d", "type": "string", "x-ref": {}}}}`)
	refs, err := FindRefsWith(root, "", j(`{"a":"/r/m/x"}`), loader)
	if err != nil || len(refs) != 1 || refs[0].Pointer != "/a" {
		t.Errorf("FindRefs = %+v, %v", refs, err)
	}
}

// CIS-16: patternProperties read \uXXXX as \x{XXXX} (§6.6).
func TestV073PatternTranslation(t *testing.T) {
	root := j(`{"patternProperties": {"^\\u00f1": {"x-index": "text"}}}`)
	got, err := CollectWith(root, "", j(`{"ña":"v","n":"w"}`), loader)
	if err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(short(got), "\n"); g != `x-index /ña="text"` {
		t.Errorf("Collect: %s", g)
	}
	refs, err := FindRefsWith(j(`{"patternProperties": {"^\\u00f1": {"x-ref": {}}}}`), "", j(`{"ña":"/r/m/x"}`), loader)
	if err != nil || len(refs) != 1 {
		t.Errorf("FindRefs = %+v, %v", refs, err)
	}
}
