package bundle_test

import (
	"bytes"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
)

// v0.90 §G.5.1 Importing (CONFORMANCE FED-29, Federation 40): a bundle
// whose access gives a namespace as other than e2e, or doesn't list it,
// with a rev line of it that is one sealed op, is refused at step 1,
// with the operator's override or without, into a target of any level,
// an e2e one included: nothing is written.
func TestV090BImportRefusesSealedOpOutsideE2E(t *testing.T) {
	t.Parallel()
	src, _, _, _ := v82E2EBranch(t)
	head := src.head("m", "derby")
	entries := must(src.c.Log(ctx, "m", "derby", head.ID, ""))
	for _, access := range []map[string]string{{"m": bundle.AccessPrivate}, {"m": bundle.AccessSealed}, nil} {
		var buf bytes.Buffer
		w := must(bundle.NewWriter(&buf, bundle.Header{Origin: stagingOrigin, Created: "2026-11-24T12:00:00Z",
			At:     map[string]string{"m": must(src.c.NSHead(ctx, "m")).ID},
			Docs:   map[string]bundle.DocInfo{"m/derby": {History: bundle.Full, Head: head.ID}},
			Access: access}))
		for _, e := range entries {
			noErr(t, w.Line(bundle.HistoryLine("m", "derby", e, false)))
		}
		must(w.Close())
		for _, override := range []bool{false, true} {
			dst := newEncDeployment(t, cmsOrigin)
			importErr(t, dst, buf.Bytes(), bundle.ImportOptions{AllowLessProtected: override}, "is a sealed op, as only an e2e namespace's history has")
			v82NothingWritten(t, dst, "the sealed-op bundle", "m")
			// Into an existing e2e target of the same name too: the
			// bundle's access decides, not the target's level.
			dst = newEncDeployment(t, cmsOrigin)
			dst.ns("m", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
			before := must(dst.c.NSHead(ctx, "m")).ID
			importErr(t, dst, buf.Bytes(), bundle.ImportOptions{AllowLessProtected: override}, "is a sealed op, as only an e2e namespace's history has")
			if got := must(dst.c.NSHead(ctx, "m")).ID; got != before {
				t.Fatalf("access %v, override %v: the refused import wrote to the e2e target", access, override)
			}
		}
	}
}
