package merge_test

import (
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// E2E-12 (§F.3 kept bullet, §E.3.1, §8.2; v0.78 "End-to-end from creation,
// or never"): in a namespace e2e from its creation every document
// references sealed blobs only, so a branch's restore with [] of a
// document holding one is re-sealed declaring the last live document's
// list, and merges as any other item: no pre-raise blob can block it.
func TestV081ReSealedRestoreKeepsDeclaredBlobs(t *testing.T) {
	t.Parallel()
	e := newE3(t, nil)
	ref := must(e.x.UploadBlob(ctx, "m", "derby", "image/png", []byte("goal")))
	e.append("m", "derby", op("add", "/img", ref))
	bid, _ := ref["$blob"].(string)
	e.branch("r7")
	h := must(e.c.Head(ctx, "r7", "derby"))
	ts := must(e.c.Delete(ctx, "r7", "derby", h.ID)).ID
	must(e.x.RestoreSealed(ctx, "r7", "derby", ts, nil))

	p := e.plan("m", "r7")
	r := p.Resource("derby")
	if r == nil || r.Class != merge.FastForward || !r.HasItem() || len(r.Conflicts) > 0 {
		t.Fatalf("derby's restore: %+v", r)
	}
	must(p.Apply(ctx))
	sameDoc(t, e.doc("m", "derby"), map[string]any{"title": "Derby", "score": "0-0", "img": ref})
	head := must(e.c.Head(ctx, "m", "derby"))
	log := must(e.c.Log(ctx, "m", "derby", head.ID, ""))
	_, declared, ok := seal.SealedOp(log[len(log)-1].Patches)
	if !ok || !reflect.DeepEqual(declared, []string{bid}) {
		t.Fatalf("the re-sealed restore declares %v (sealed %v), want [%s]", declared, ok, bid)
	}
	if p := e.plan("m", "r7"); p.Resource("derby") != nil && p.Resource("derby").HasItem() {
		t.Fatalf("derby offered again: %+v", p.Resource("derby"))
	}
}
