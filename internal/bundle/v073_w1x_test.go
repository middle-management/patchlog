package bundle_test

import (
	"bytes"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// W1X: a bundle's origin is the exporting deployment's canonical origin
// (§C.3, §G.4.1), which an import copies into every batch's source.origin
// (§3.5): a header or `written` origin in another form is refused when
// the bundle is read, not at the import's first batch.
func TestW1XBundleOriginCanonical(t *testing.T) {
	t.Parallel()
	b := writeHistory(t, "r7", "derby", func(w *bundle.Writer) ids.ID {
		l, id := history(t, "r7", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}), nil, "")
		noErr(t, w.Line(l))
		return id
	})
	if _, err := bundle.Verify(bytes.NewReader(b)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, o := range []string{"https://Staging.Example", "https://old.example:443", "https://old.example/", "https://bücher.example", "old.example"} {
		verifyErr(t, editHeader(t, b, func(h map[string]any) { h["origin"] = o }), "origin")
	}
	hist := jsonv.MustParse(lines(b)[1]).(map[string]any)
	hist["written"] = map[string]any{"origin": "https://Base.example", "ns": "matches"}
	verifyErr(t, join([][]byte{lines(b)[0], jsonv.Canonical(jsonv.FromGo(hist))}), "written")
}
