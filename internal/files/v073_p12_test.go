package files

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Addendum I.10 (§H.1): the document renders as these 118 bytes, the fresh
// $nonce left out and "10" before "2", as JCS orders them, where
// ECMAScript's JSON.stringify of a parsed object would put "2" first. A
// listing gives the file that size (§H.3).
func TestRenderingI10(t *testing.T) {
	t.Parallel()
	doc := jsonv.MustParse([]byte(`{"$nonce":"abcdefghijklmnopqrstuvwxyz","10":true,"2":[],"items":[{"id":"a","n":1.5},{}],"title":"Café"}`))
	const want = "{\n" +
		"  \"10\": true,\n" +
		"  \"2\": [],\n" +
		"  \"items\": [\n" +
		"    {\n" +
		"      \"id\": \"a\",\n" +
		"      \"n\": 1.5\n" +
		"    },\n" +
		"    {}\n" +
		"  ],\n" +
		"  \"title\": \"Café\"\n" +
		"}\n"
	r := Rendering(doc)
	sum := sha256.Sum256(r)
	if string(r) != want || len(r) != 118 || hex.EncodeToString(sum[:]) != "c7e8bfb3ff3fed1b111dda8cce06b4f2c1b7615565e828f4777ebf63055e887c" {
		t.Errorf("rendering (%d bytes, sha-256 %x):\n%s", len(r), sum, r)
	}
	if m := MetaOf(doc); m != (Meta{Size: 118, Type: JSONType}) {
		t.Errorf("MetaOf = %+v", m)
	}
	// The document itself is unchanged: the $nonce is left out of the
	// rendering only.
	if _, has := doc.(map[string]any)["$nonce"]; !has {
		t.Error("Rendering removed $nonce from the document")
	}
}
