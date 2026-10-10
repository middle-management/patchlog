package bundle_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
)

// A bundle imported a few namespaces at a time, those the others reference
// first, leaves the target as one whole import does (ImportOptions.Only):
// layouts pin catalogue items, which they name upstream once rewritten,
// and every document is typed by demo-schemas' schemas.
func TestImportOnly(t *testing.T) {
	t.Parallel()
	b := contentBundle(t, contentShape{layouts: 3, pages: 6, items: 5, comments: 4, verifications: 1})
	imp := func(dst *deployment, only ...string) (*bundle.Report, error) {
		return bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true, Only: only,
			Sleep: func(context.Context, time.Duration) error { return nil }})
	}
	whole := newDeployment(t, cmsOrigin, fastLimits)
	must(imp(whole))
	staged := newDeployment(t, cmsOrigin, fastLimits)
	rep := must(imp(staged, "demo-schemas"))
	if !slices.Equal(rep.Only, []string{"demo-schemas"}) || !slices.Equal(rep.Order, []string{"demo-schemas"}) {
		t.Fatalf("only %v, order %v", rep.Only, rep.Order)
	}
	for _, d := range rep.Docs {
		if !strings.HasPrefix(d.Doc, "demo-schemas/") {
			t.Fatalf("reported %s", d.Doc)
		}
	}
	if _, err := staged.c.NSHead(ctx, "cat-demo-upstream"); !client.IsNotFound(err) {
		t.Fatalf("a namespace the import leaves out: %v", err)
	}
	must(imp(staged, "cat-demo", "domain-verifications"))
	must(imp(staged, "demo", "demo-comments"))
	nss := []string{"demo-schemas", "demo", "demo-upstream", "cat-demo", "cat-demo-upstream", "demo-comments", "demo-comments-upstream",
		"domain-verifications", "domain-verifications-upstream"}
	if got, want := heads(t, staged.c, nss...), heads(t, whole.c, nss...); !slices.Equal(got, want) {
		t.Fatalf("staged imports differ from a whole one:\n%v\n%v", got, want)
	}
	// Run again, each part finds its documents present.
	rep = must(imp(staged, "demo"))
	if len(rep.Batches) != 0 {
		t.Fatalf("%d batches on a re-run", len(rep.Batches))
	}
}

// A partial import checks the target for what its documents reference in
// the namespaces it leaves out, and writes nothing if it lacks them: the
// schema revisions they pin, the documents they name live, and the
// upstream revisions of the snapshot documents they pin.
func TestImportOnlyMissing(t *testing.T) {
	t.Parallel()
	b := contentBundle(t, contentShape{layouts: 3, pages: 6, items: 5, comments: 4, verifications: 1})
	dst := newDeployment(t, cmsOrigin, fastLimits)
	imp := func(only ...string) error {
		_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true, Only: only,
			Sleep: func(context.Context, time.Duration) error { return nil }})
		return err
	}
	problems := func(err error, want ...string) {
		t.Helper()
		var ce *bundle.CheckError
		if !errors.As(err, &ce) {
			t.Fatalf("got %v, want a check error", err)
		}
		all := strings.Join(ce.Problems, "\n")
		for _, w := range want {
			if !strings.Contains(all, w) {
				t.Fatalf("no problem mentions %q:\n%s", w, all)
			}
		}
		for _, ns := range []string{"demo", "demo-upstream", "demo-comments"} {
			if _, err := dst.c.NSHead(ctx, ns); !client.IsNotFound(err) {
				t.Fatalf("%s written: %v", ns, err)
			}
		}
	}
	// Nothing yet: the schemas pinned (full documents, by id).
	problems(imp("demo"), "demo-schemas/layout, which the import leaves out, is missing in the target: imported documents pin its revision")
	// Comments name pages live.
	problems(imp("demo-comments"), "which the import leaves out, is missing in the target: imported documents name it")
	noErr(t, imp("demo-schemas"))
	// Layouts pin catalogue items, which must be upstream as the bundle
	// has them.
	problems(imp("demo"), "cat-demo/item-0, which the import leaves out, isn't in cat-demo-upstream/item-0 as the bundle has it (an import of it would create it there)",
		"import namespace cat-demo first")
	if err := imp("bogus"); err == nil || !strings.Contains(err.Error(), "no namespace bogus") {
		t.Fatalf("an unknown namespace: %v", err)
	}
	noErr(t, imp("cat-demo"))
	noErr(t, imp("demo"))
	noErr(t, imp("demo-comments"))
}

// A pinned namespace whose target requires nonces: its upstream chain
// carries a fresh $nonce in each patch set, which the held check leaves
// out of the comparison, as a whole import does.
func TestImportOnlyNonces(t *testing.T) {
	t.Parallel()
	b := contentBundle(t, contentShape{layouts: 2, pages: 2, items: 3, comments: 1, verifications: 1})
	dst := newDeployment(t, cmsOrigin, fastLimits)
	dst.ns("cat-demo", map[string]any{"read": "public", "nonce": "required"})
	for _, only := range [][]string{{"demo-schemas"}, {"cat-demo"}, {"demo"}} {
		if _, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true, Only: only,
			Sleep: func(context.Context, time.Duration) error { return nil }}); err != nil {
			t.Fatalf("-only %v: %v", only, err)
		}
	}
}

// Documents the target deleted since the import, which comments name live,
// stay deleted on a re-run, as a whole re-import leaves them.
func TestImportOnlyDeleted(t *testing.T) {
	t.Parallel()
	b := contentBundle(t, contentShape{layouts: 1, pages: 2, items: 1, comments: 4, verifications: 1})
	dst := newDeployment(t, cmsOrigin, fastLimits)
	imp := func(only ...string) error {
		_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 1, CreateNamespaces: true, Only: only,
			Sleep: func(context.Context, time.Duration) error { return nil }})
		return err
	}
	noErr(t, imp())
	for _, p := range []string{"page-0", "page-1"} {
		must(dst.c.Delete(ctx, "demo", p, dst.head("demo", p).ID))
	}
	noErr(t, imp("demo-comments"))
}

// A string that pins a left-out snapshot document without a declared
// reference isn't rewritten, by a whole import either, so the import
// doesn't need that document's namespace first.
func TestImportOnlyUndeclared(t *testing.T) {
	t.Parallel()
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{"a": fakeID("at a"), "b": fakeID("at b")},
		Docs: map[string]bundle.DocInfo{}, Access: map[string]string{"a": bundle.AccessPublic, "b": bundle.AccessPublic}}
	h.Docs["a/a1"] = bundle.DocInfo{History: bundle.Snapshot, Head: fakeID("a/a1")}
	h.Docs["b/b1"] = bundle.DocInfo{History: bundle.Snapshot, Head: fakeID("b/b1")}
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	noErr(t, w.SnapshotDoc("a", "a1", fakeID("a/a1"), map[string]any{"note": rev("b", "b1", fakeID("b/b1"))}, false))
	noErr(t, w.SnapshotDoc("b", "b1", fakeID("b/b1"), map[string]any{"x": 1.0}, false))
	must(w.Close())
	dst := newDeployment(t, cmsOrigin)
	rep, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(buf.Bytes()), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true, Only: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Undeclared) != 1 || !rep.Undeclared[0].Bundled {
		t.Fatalf("undeclared %+v", rep.Undeclared)
	}
}
