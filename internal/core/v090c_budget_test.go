package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/rules"
)

// v90cDoubling is a schema whose evaluation takes about 2^(levels+1)
// steps and that every value passes.
func v90cDoubling(levels int) map[string]any {
	defs := map[string]any{fmt.Sprintf("a%d", levels): true}
	for i := 0; i < levels; i++ {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/a%d", i+1)}
		defs[fmt.Sprintf("a%d", i)] = map[string]any{"allOf": []any{next, next}}
	}
	return map[string]any{"$ref": "#/$defs/a0", "$defs": defs}
}

// v90cDocRule is a read rule on /doc that every document passes, in about
// steps validation steps per revision judged.
func v90cDocRule(t *testing.T, levels int) (map[string]any, int) {
	t.Helper()
	rule := map[string]any{"op": "test", "path": "/doc", "schema": v90cDoubling(levels)}
	r, err := rules.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	m := rules.Budget(1 << 30)
	r.Passes(map[string]any{"doc": map[string]any{"title": "x"}}, m)
	return rule, m.Steps
}

// v90cWorld is a v75World whose validationSteps is budget, with derby
// written n times.
func v90cWorld(t *testing.T, budget, n int) (*v75World, []string) {
	t.Helper()
	w := newV75World(t, v75Opts{engine: func(o *Options) { o.MaxValidationSteps = budget }})
	var revs []string
	for i := 0; i < n; i++ {
		w.put("matches", "derby", map[string]any{"title": fmt.Sprintf("v%d", i+1)})
		h, err := w.e.ResourceHead(context.Background(), "matches", "derby", w.admin)
		if err != nil {
			t.Fatal(err)
		}
		revs = append(revs, h.Head)
	}
	return w, revs
}

// v0.90 §6.6 Validation work ("A paged read that runs out after its first
// entry ends its page there instead (§7.1)"; CONFORMANCE Limits 94): li's
// read rule on /doc takes more than half the deployment's validationSteps
// per revision. Her range of derby's log from genesis ends after its first
// entry, where the request's one budget runs out, with More, and she pages
// on from it; a rule that takes more than the whole budget for one
// revision is 404, as the read check is. At her view's /heads each
// revision is judged with a budget of its own: every one is listed. Until
// v0.90's reading every revision had a budget of its own at a resource's
// URLs too.
func TestV090CRangeEndsWhereBudgetRunsOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rule, steps := v90cDocRule(t, 9)
	w, revs := v90cWorld(t, steps+steps/2, 4)
	li := w.li(map[string]any{"rules": []any{rule}})
	lg, err := w.e.ResourceLog(ctx, "matches", "derby", "", "", 100, li)
	if err != nil || lg.Status != 200 {
		t.Fatalf("li's range: %+v %v", lg, err)
	}
	if len(lg.Entries) != 1 || !lg.More || lg.Last != revs[0] {
		t.Fatalf("li's range: %d entries, more %v, last %s; want the first alone (%s), more", len(lg.Entries), lg.More, lg.Last, revs[0])
	}
	// She pages on, one entry a request.
	for i := 1; i < len(revs); i++ {
		lg, err = w.e.ResourceLog(ctx, "matches", "derby", "", revs[i-1], 100, li)
		if err != nil || lg.Status != 200 || len(lg.Entries) != 1 || lg.Last != revs[i] || lg.More != (i < len(revs)-1) {
			t.Fatalf("page %d: %+v %v", i, lg, err)
		}
	}
	// Her view's /heads judges each revision with its own budget.
	red, st := v76fRedirect(t, w, "matches", "", li)
	if st != 0 {
		t.Fatalf("li's redirect: %d", st)
	}
	if names, st := v76fHeads(t, w, "matches", red.View, red.At, li); st != 0 || len(names) != 1 || names[0] != "derby" {
		t.Fatalf("li's /heads: %v %d, want derby", names, st)
	}

	// More than the whole budget for one revision: inside the first
	// entry, 404.
	w2, _ := v90cWorld(t, steps/2, 2)
	li2 := w2.li(map[string]any{"rules": []any{rule}})
	if _, err := w2.e.ResourceLog(ctx, "matches", "derby", "", "", 100, li2); v75Status(err) != 404 {
		t.Fatalf("a range whose first entry runs out: %v, want 404", err)
	}
}
