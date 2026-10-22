package annot

import (
	"strings"
	"testing"
)

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
