package dav

import (
	"encoding/json"
	"testing"
)

// TestBornSealedApartDecodesV074: a sealed catalog's per-entry listing
// may carry a born of another epoch sealed apart, "born": {"sealed":
// JWE} (§E.2.6). The page still decodes, so the entry's sealed title
// leads to the sealed catalog's 404 not_offered (§H.3) rather than a 502
// for a listing that isn't JSON; a born in the clear still reads as the
// string it is.
func TestBornSealedApartDecodesV074(t *testing.T) {
	page := []byte(`{"at":"x","children":[` +
		`{"name":"old","kind":"folder","sealed":"a.b.c.d.e","born":{"sealed":"f.g.h.i.j"}},` +
		`{"name":"new","kind":"folder","title":"New","born":"2026-01-02T03:04:05Z"}]}`)
	var a svcAnswer
	if err := json.Unmarshal(page, &a); err != nil {
		t.Fatalf("a per-entry page with a born sealed apart doesn't decode: %v", err)
	}
	if len(a.Children) != 2 || a.Children[0].Sealed == nil {
		t.Fatalf("children = %+v", a.Children)
	}
	var b string
	if err := json.Unmarshal(a.Children[1].Born, &b); err != nil || b != "2026-01-02T03:04:05Z" {
		t.Fatalf("born in the clear = %q, %v", b, err)
	}
}
