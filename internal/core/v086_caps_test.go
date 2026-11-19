package core

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// countRefusedPurge builds a schema in namespace schemaNS ("s", or the
// base "n" itself) that a document of base n names, and branches
// branches of n, each of which reads that document through and so
// references the schema; it returns the statements of the refused purge
// of the schema and the refusal.
func countRefusedPurge(t *testing.T, schemaNS string, branches, page int) (int, *Error) {
	t.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	lim.BranchesPerNamespace = 1 << 20
	max := DefaultMaximums()
	max.LogPageSize = page
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, Limits: lim, Maximums: max, Purger: discardPurger{},
		RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	mkNS(t, e, "s", map[string]any{"read": "public"})
	mkNS(t, e, "n", map[string]any{"read": "public"})
	write := func(ns, name string, doc map[string]any) string {
		t.Helper()
		r := who
		r.NS = ns
		res, err := e.WriteResource(ctx, r, Item{Resource: name, IfNoneMatch: true,
			Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}}})
		if err != nil {
			t.Fatalf("write %s/%s: %v", ns, name, err)
		}
		return res.Items[0].IDs[0]
	}
	sid := write(schemaNS, "team", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})
	write("n", "x", map[string]any{"$schema": "/r/" + schemaNS + "/team/rev/" + sid})
	for i := 0; i < branches; i++ {
		r := who
		r.NS = "n"
		if _, err := e.CreateBranch(ctx, r, BranchRequest{Name: fmt.Sprintf("b%03d", i), IfNoneMatch: true}); err != nil {
			t.Fatalf("branch %d: %v", i, err)
		}
	}
	var mu sync.Mutex
	total := 0
	e.onStatement = func(string, []any) {
		mu.Lock()
		total++
		mu.Unlock()
	}
	r := who
	r.NS = schemaNS
	_, err = e.Purge(ctx, r, "team", sid, false)
	e.onStatement = nil
	ae, _ := err.(*Error)
	if ae == nil || ae.Status != 409 || ae.Body["code"] != "in_use" {
		t.Fatalf("purge with %d branches: %v, want 409 in_use", branches, err)
	}
	return total, ae
}

// §6.1 Refusals, Limits scenario 94 (v0.86): an in_use refusal lists the
// first logPageSize referencing namespaces and "more", so its search
// stops at the first readable one past the page: with a page of 5 it
// costs the same statements whether 20 namespaces reference the schema
// or 60. Before, it judged every one of them (54 s at 10,000 branches,
// docs/capacity/branches/report.md).
func TestV086RefusedPurgeStopsAtAPage(t *testing.T) {
	t.Parallel()
	const page = 5
	// The schema in a namespace of its own, and in the base whose
	// branches read it through (docs/capacity's purge_schema_refused).
	for _, schemaNS := range []string{"s", "n"} {
		few, fe := countRefusedPurge(t, schemaNS, 20, page)
		many, me := countRefusedPurge(t, schemaNS, 60, page)
		t.Logf("schema in %s: %d statements with 20 branches, %d with 60", schemaNS, few, many)
		if many != few {
			t.Errorf("schema in %s: %d statements with 60 referencing branches, %d with 20: the search didn't stop at the page", schemaNS, many, few)
		}
		for _, ae := range []*Error{fe, me} {
			// The first five by name; the base n sorts after every branch.
			if got := fmt.Sprint(ae.Body["referencing"]); got != "[b000 b001 b002 b003 b004]" || ae.Body["more"] != true {
				t.Errorf("schema in %s: refusal %v", schemaNS, ae.Body)
			}
		}
		// Up to a page of them, the search is whole and there is no more.
		_, ae := countRefusedPurge(t, schemaNS, 4, page)
		if got := fmt.Sprint(ae.Body["referencing"]); got != "[b000 b001 b002 b003 n]" || ae.Body["more"] != nil {
			t.Errorf("schema in %s: a page of referencing namespaces: %v", schemaNS, ae.Body)
		}
	}
}
