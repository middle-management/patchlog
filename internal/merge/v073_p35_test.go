package merge_test

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/merge"
)

// v0.73 §E.3.1, §F.3 kept bullet (MF-5, P35; v0.78 dropped the pre-raise
// case from §F.3, and the check stays as a defensive one): an E3 base
// whose head of a resource references a blob a sealed op can't declare
// makes no item for that resource when the merge keeps the base, as the
// sealed empty set would repeat it: the rest of the batch commits, and the
// resource is offered again.
func TestV073P35KeptUndeclarableBlobMakesNoItem(t *testing.T) {
	t.Parallel()
	c, x, b := v05UndeclarableBase(t)
	// The branch drops the blob, which a sealed op can't declare.
	must(x.AppendSealed(ctx, "r7", "derby", b, ops(rm("/img"), op("replace", "/score", "1-0"))))

	p := must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward})
	noErr(t, p.Resolve("derby")) // keep the base
	r := p.Resource("derby")
	if r.Kept || r.HasItem() || !strings.Contains(r.Note, "image/png") || !strings.Contains(r.Note, "offered again") {
		t.Fatalf("kept over an undeclarable blob: %+v", r)
	}
	if !p.Clean() || len(p.Items()) != 1 {
		t.Fatalf("plan %+v", p.Items())
	}
	res := must(p.Apply(ctx))
	if len(res.Items) != 1 || res.Items[0].Resource != "cup" {
		t.Fatalf("batch %+v", res.Items)
	}
	if got := must(c.Head(ctx, "m", "derby")).ID; got != b {
		t.Fatalf("derby moved to %s", got)
	}
	_, d := must2(x.LoadE2E(ctx, "m", "cup"))
	if d.Value.(map[string]any)["score"] != "2-0" {
		t.Fatalf("cup %v", d.Value)
	}
	// The next plan offers derby again.
	p = must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	if r := p.Resource("derby"); r == nil || r.Class != merge.FastForward && r.Class != merge.Replay {
		t.Fatalf("derby not offered again: %+v", r)
	}
}
