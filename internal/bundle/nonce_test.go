package bundle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

func (d *deployment) nsDoc(ns string) map[string]any {
	d.t.Helper()
	return must(d.c.NSDoc(ctx, ns, must(d.c.NSHead(ctx, ns)).ID)).Value
}

// §G.4.4, §C.7: the upstream namespace of a snapshot import takes its
// target's nonce requirement, and the patch sets generated there carry a
// fresh $nonce, so the target fast-forwards from them.
func TestSnapshotImportRequiredNonces(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"score": "0-0"})
	export := func() []byte {
		f := &fixture{src: src}
		b, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot})
		return b
	}
	dst := newDeployment(t, cmsOrigin)
	dst.ns("matches", map[string]any{"read": "public", "nonce": "required"})

	importB(t, dst, export(), bundle.ImportOptions{})
	if d := dst.nsDoc("matches-upstream"); d["nonce"] != "required" {
		t.Fatalf("upstream namespace %v", d)
	}
	up, tg := dst.head("matches-upstream", "derby"), dst.head("matches", "derby")
	if up.ID != tg.ID {
		t.Fatalf("upstream %+v, target %+v (the first import fast-forwards)", up, tg)
	}
	n1, _ := dst.doc("matches", "derby")["$nonce"].(string)
	if !seal.ValidNonce(n1) {
		t.Fatalf("no fresh nonce: %v", dst.doc("matches", "derby"))
	}

	// A later snapshot: a diff with a fresh nonce, replayed or
	// fast-forwarded onto the target.
	src.append("matches", "derby", op("replace", "/score", "1-0"))
	b2 := export()
	importB(t, dst, b2, bundle.ImportOptions{})
	d := dst.doc("matches", "derby")
	if n2, _ := d["$nonce"].(string); d["score"] != "1-0" || !seal.ValidNonce(n2) || n2 == n1 {
		t.Fatalf("second import %v", d)
	}
	// Diffs ignore $nonce: an unchanged snapshot writes nothing.
	if rep := importB(t, dst, b2, bundle.ImportOptions{}); len(rep.Batches) != 0 {
		t.Fatalf("re-import wrote %+v", rep.Batches)
	}
}

// §C.7, §G.4.4: full history written without nonces can't be imported
// into a namespace that requires them, and the importer says so before
// writing anything; history that carries them can.
func TestFullImportRequiredNonces(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"score": "0-0"})
	src.ns("secure", map[string]any{"read": "public", "nonce": "required"})
	w := must(src.c.Create(ctx, "secure", "derby", append(client.GenesisPatches(map[string]any{"score": "0-0"}), op("add", "/$nonce", seal.NewNonce()))))
	must(src.c.Append(ctx, "secure", "derby", w.ID, ops(op("replace", "/score", "1-0"), op("add", "/$nonce", seal.NewNonce()))))
	f := &fixture{src: src}

	dst := newDeployment(t, cmsOrigin)
	dst.ns("matches", map[string]any{"read": "public", "nonce": "required"})
	b, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}})
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	var ae *bundle.AccessError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "requires nonces") || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("full import: %v", err)
	}
	if h := dst.head("matches", "derby"); h.State != client.NotFound {
		t.Fatalf("written: %+v", h)
	}

	dst.ns("secure", map[string]any{"read": "public", "nonce": "required"})
	b, _, _ = f.export(t, bundle.ExportOptions{Select: []string{"secure/derby"}})
	importB(t, dst, b, bundle.ImportOptions{})
	if dst.head("secure", "derby").ID != src.head("secure", "derby").ID {
		t.Fatal("full history not imported with its ids")
	}
}
