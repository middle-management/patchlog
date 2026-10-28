package bundle_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
)

// TOOLS-8 (§G.4.4, Open 118): upstream patch sets carry a fresh $nonce
// where either side requires nonces. Here the target cat-demo requires
// them and its upstream namespace, which exists beforehand, doesn't: the
// import of cat-demo gives its upstream patch sets nonces, and a later
// partial import of demo, which pins cat-demo's items, compares the held
// upstream chain as nonced, finding it present, so it writes nothing there.
func TestV074PartialImportHeldUpstreamNonces(t *testing.T) {
	t.Parallel()
	b := contentBundle(t, contentShape{layouts: 2, pages: 2, items: 3, comments: 1, verifications: 1})
	dst := newDeployment(t, cmsOrigin, fastLimits)
	dst.ns("cat-demo", map[string]any{"read": "public", "nonce": "required"})
	dst.ns("cat-demo-upstream", map[string]any{"read": "public"})
	imp := func(only ...string) (*bundle.Report, error) {
		return bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true, Only: only,
			Sleep: func(context.Context, time.Duration) error { return nil }})
	}
	for _, only := range [][]string{{"demo-schemas"}, {"cat-demo"}} {
		if _, err := imp(only...); err != nil {
			t.Fatalf("-only %v: %v", only, err)
		}
	}
	// The held upstream chain is compared as one with a fresh $nonce in
	// each patch set, as the import of cat-demo wrote it.
	nonced := must(bundle.NoncedUpstreams(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Only: []string{"demo"}}))
	if !nonced["cat-demo-upstream"] {
		t.Fatalf("the held upstream cat-demo-upstream isn't compared as nonced: %v", nonced)
	}
	h := must(dst.c.NSHead(ctx, "cat-demo-upstream"))
	if _, err := imp("demo"); err != nil {
		t.Fatalf("-only demo: %v", err)
	}
	if after := must(dst.c.NSHead(ctx, "cat-demo-upstream")); after.ID != h.ID {
		t.Fatalf("the held upstream namespace was written: %s, then %s", h.ID, after.ID)
	}
}
