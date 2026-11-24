package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/rules"
)

// v0.90 §6.6 Validation work, §7.7 (CONFORMANCE Limits 101): a grant
// whose read rule on /doc takes more than half of validationSteps per
// revision, having read v1, long-polls x's log from v1, v2 and v3
// written after it: the wait's one budget runs out judging v3, so it answers as a page
// ends, 200 with v2 alone and X-Revision v2, and the next poll, from v2,
// has a budget of its own and gets v3. Where one revision takes more than
// the whole budget, the poll from v1 is 204 with X-Revision v1, the last
// entry judged whole, never the 404 a range's read gives.
func TestV090CLongPollEntriesShareTheBudget(t *testing.T) {
	t.Parallel()
	rule := map[string]any{"op": "test", "path": "/doc", "schema": doubling(9)}
	r, err := rules.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	m := rules.Budget(1 << 30)
	r.Passes(map[string]any{"doc": map[string]any{"v": 1.0}}, m)
	steps := m.Steps

	world := func(budget int) (*tenv, string, []string) {
		f := newAuthFixture(t, nil, func(o *core.Options) { o.MaxValidationSteps = budget })
		e := f.tenv
		v1 := e.create("sec", "x", map[string]any{"v": 1.0}, f.adminG)
		v2 := e.appendRev("sec", "x", v1, ops(op("replace", "/v", 2.0)), f.adminG)
		v3 := e.appendRev("sec", "x", v2, ops(op("replace", "/v", 3.0)), f.adminG)
		g, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:r", "ns": []any{"sec"}, "can": []any{"read"},
			"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
		if err != nil {
			t.Fatal(err)
		}
		return e, narrowed(t, g, map[string]any{"rules": []any{rule}}), []string{v1, v2, v3}
	}

	// Answered at once (no cursor), as a wait woken by both writes is.
	// She read v1 before, whose answer is kept (§7.9 Cost): judging v2's
	// entry, whose patches need v1 readable, costs v2's judgment alone.
	e, g, v := world(steps + steps/2)
	expect(t, e.get("/r/sec/x/rev/"+v[0]+"/log", g), 200)
	lp := e.get("/r/sec/x/log?live=long-poll&since="+v[0], g)
	if lp.Code != 200 || lp.H.Get("X-Revision") != v[1] {
		t.Fatalf("the poll from v1: %d %s, X-Revision %q; want 200 with v2 alone", lp.Code, lp.Body, lp.H.Get("X-Revision"))
	}
	if es := lp.Arr(); len(es) != 1 {
		t.Fatalf("the poll from v1: %d entries, want v2 alone: %s", len(es), lp.Body)
	}
	lp = e.get("/r/sec/x/log?live=long-poll&since="+v[1], g)
	if lp.Code != 200 || lp.H.Get("X-Revision") != v[2] {
		t.Fatalf("the poll from v2: %d %s, X-Revision %q; want 200 with v3", lp.Code, lp.Body, lp.H.Get("X-Revision"))
	}

	// One revision runs out the whole budget: 204 naming v1.
	e, g, v = world(steps / 2)
	lp = e.get("/r/sec/x/log?live=long-poll&since="+v[0], g)
	if lp.Code != 204 || lp.H.Get("X-Revision") != v[0] {
		t.Fatalf("a poll whose first entry runs out: %d %s, X-Revision %q; want 204 naming v1", lp.Code, lp.Body, lp.H.Get("X-Revision"))
	}
	// A range's read of the same is 404.
	if r := e.get("/r/sec/x/rev/"+v[2]+"/log?since="+v[0], g); r.Code != 404 {
		t.Fatalf("the range: %d %s, want 404", r.Code, r.Body)
	}
}
