package catalog_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// §F.8: merging a catalog branch goes through the catalog service, which
// checks every move and placement of the batch as in §B.11.4 and signs one
// grant covering exactly that batch.
func TestMergeGrants(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	head := func(name string) string { return must(w.ops.Head(ctx, "cat", name)).ID }
	src := map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	batch := func(items ...map[string]any) map[string]any {
		arr := []any{}
		for _, it := range items {
			arr = append(arr, it)
		}
		return map[string]any{"batch": map[string]any{"items": arr, "source": src}}
	}
	desk := w.caller("user:anna", "match-desk")
	newx := client.GenesisPatches(map[string]any{"parents": parents("season")})

	// Unplacing and placing, by someone with the powers: one grant.
	b := batch(
		map[string]any{"resource": "matches.derby", "ifMatch": head("matches.derby"), "steps": []any{"delete"}},
		map[string]any{"resource": "matches.newx", "ifNoneMatch": "*", "steps": []any{newx}},
	)
	r := w.do("POST", "/merge-grants", desk, b)
	if r.status != 200 {
		t.Fatalf("merge grant: %d %v", r.status, r.body)
	}
	core := w.core(r.body["grant"].(string))
	req := client.BatchRequest{Source: src, Items: []client.BatchItem{
		{Resource: "matches.derby", IfMatch: head("matches.derby"), Steps: []client.Step{client.DeleteStep()}},
		{Resource: "matches.newx", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(newx)}},
	}}
	// The grant covers exactly that batch: another resource is refused.
	other := client.BatchRequest{Source: src, Items: []client.BatchItem{{Resource: "matches.shared", IfMatch: head("matches.shared"), Steps: []client.Step{client.DeleteStep()}}}}
	if _, err := core.Batch(ctx, "cat", other, false); !isStatus(err, 403) {
		t.Fatalf("another batch under the merge grant: %v", err)
	}
	res, err := core.Batch(ctx, "cat", req, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.NSID == "" || live(w.ops, "cat", "matches.derby") || !live(w.ops, "cat", "matches.newx") {
		t.Fatalf("batch: %+v", res)
	}
	w.caughtUp()

	// A move that widens (fan-club gets desk under derbies) is refused for
	// non-admins; so is a change of $access.
	r = w.do("POST", "/merge-grants", desk, batch(map[string]any{"resource": "matches.newx", "ifMatch": head("matches.newx"),
		"steps": []any{[]any{map[string]any{"op": "replace", "path": "/parents", "value": parents("derbies")}}}}))
	if msg, _ := r.body["message"].(string); r.status != 403 || !strings.Contains(msg, "would give") {
		t.Fatalf("widening move: %d %v", r.status, r.body)
	}
	r = w.do("POST", "/merge-grants", desk, batch(map[string]any{"resource": "season", "ifMatch": head("season"),
		"steps": []any{[]any{map[string]any{"op": "add", "path": "/$access/group:x", "value": toAny("reader")}}}}))
	if r.status != 403 {
		t.Fatalf("$access by a non-admin: %d %v", r.status, r.body)
	}
	// Without powers on the folder: refused.
	r = w.do("POST", "/merge-grants", w.caller("user:bo", "fan-club"), batch(map[string]any{"resource": "matches.shared", "ifMatch": head("matches.shared"), "steps": []any{"delete"}}))
	if r.status != 403 {
		t.Fatalf("unplace without move: %d %v", r.status, r.body)
	}
	// A stale precondition is refused before anything is signed.
	r = w.do("POST", "/merge-grants", desk, batch(map[string]any{"resource": "matches.shared", "ifMatch": head("season"), "steps": []any{"delete"}}))
	if r.status != 409 {
		t.Fatalf("stale: %d %v", r.status, r.body)
	}
}
