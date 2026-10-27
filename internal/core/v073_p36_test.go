package core

import (
	"context"
	"testing"
)

// P36 LEVELS-KEYS-BRANCHES: keys and branches after a raise to e2e
// (Addendum E Levels, §E.2.3, §G.5.2).

// p36Branch creates branch name of base at at ("" for the base's head).
func p36Branch(e *Engine, base, name, at string) (*WriteResult, error) {
	return e.CreateBranch(context.Background(), p29Req(base), BranchRequest{Name: name, At: at, IfNoneMatch: true})
}

// v0.73 Addendum E Levels, Branches of a raised base (ENC-44, CONFORMANCE
// ENC-10, Levels scenario 4): a branch of a base raised to e2e can't be
// created with an at before the raise (422 invalid with errors at
// /base/at, a branch field), since the epoch key in force at an earlier at
// also opens what the base sealed after it. The raise lies before the
// entry that made the namespace e2e, so at may be that entry or a later
// one.
func TestV073P36BranchAtBeforeRaise(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p29Engine(t)
	cfg := mkNS(t, e, "n", map[string]any{})
	w, err := e.WriteResource(ctx, p29Req("n"), Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"v": 1.0})}}}})
	if err != nil {
		t.Fatal(err)
	}
	before := w.NSID
	rw, err := e.WriteConfig(ctx, p29Req("n"), ConfigChange{IfMatch: cfg, Patches: []any{p29Add("/encryption", map[string]any{"level": "e2e"})}})
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error) {
		t.Helper()
		st, body := p29Status(t, err)
		errs, _ := body["errors"].([]any)
		if st != 422 || body["code"] != "invalid" || len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/base/at" {
			t.Fatalf("%s: %d %v, want 422 invalid at /base/at", what, st, body)
		}
	}
	_, err = p36Branch(e, "n", "early", before)
	refused("a branch at an entry before the raise", err)
	if _, err := p36Branch(e, "n", "atraise", rw.NSID); err != nil {
		t.Fatalf("a branch at the raising entry: %v", err)
	}
	if _, err := p36Branch(e, "n", "head", ""); err != nil {
		t.Fatalf("a branch at the head: %v", err)
	}
	// A namespace e2e from its creation has no raise: any at of its chain.
	mkNS(t, e, "c", map[string]any{"encryption": map[string]any{"level": "e2e"}})
	var first string
	if err := e.read(ctx, func(t *tx) error {
		n := t.nsByName("c")
		var seq int64
		t.must(t.QueryRow(`SELECT MIN(seq) FROM ns_log WHERE ns = ?`, n.id).Scan(&seq))
		first = t.nsLogID(seq).String()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p36Branch(e, "c", "cb", first); err != nil {
		t.Fatalf("a branch of a namespace e2e from its creation: %v", err)
	}
}
