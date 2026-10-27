package catalog_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// §F.8, §12.2: the merge grant of a catalog batch allows exactly the
// batch's pairs of /resource and /action, and rulesPerGrant counts every
// rule form, nested ones included (32 by default). A batch of a dozen
// items still gets a grant the origin accepts: its rule has one
// alternative per action, not per item.
func TestV073P02MergeGrantManyItems(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	head := func(name string) string { return must(w.ops.Head(ctx, "cat", name)).ID }
	src := map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	place := client.GenesisPatches(map[string]any{"parents": parents("season")})
	body := []any{map[string]any{"resource": "matches.derby", "ifMatch": head("matches.derby"), "steps": []any{"delete"}}}
	req := client.BatchRequest{Source: src, Items: []client.BatchItem{
		{Resource: "matches.derby", IfMatch: head("matches.derby"), Steps: []client.Step{client.DeleteStep()}}}}
	for i := 0; i < 15; i++ {
		name := fmt.Sprintf("matches.p%d", i)
		body = append(body, map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{place}})
		req.Items = append(req.Items, client.BatchItem{Resource: name, IfNoneMatch: true, Steps: []client.Step{client.PatchStep(place)}})
	}
	r := w.doWith("POST", "/merge-grants", w.caller("svc:merge"), map[string]any{"batch": map[string]any{"items": body, "source": src}},
		map[string]string{"Approver-Authorization": "Bearer " + w.caller("user:anna", "match-desk")})
	if r.status != 200 {
		t.Fatalf("merge grant: %d %v", r.status, r.body)
	}
	core := w.core(r.body["grant"].(string))
	// Still exactly the batch's pairs: another action on one of its
	// resources is refused, and so is one of its actions on another
	// resource.
	title := client.PatchStep([]any{map[string]any{"op": "add", "path": "/title", "value": "x"}})
	refused := func(what, name, ifMatch string, st client.Step) {
		t.Helper()
		it := client.BatchItem{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == "", Steps: []client.Step{st}}
		if _, err := core.Batch(ctx, "cat", client.BatchRequest{Source: src, Items: []client.BatchItem{it}}, false); !isStatus(err, 403) {
			t.Fatalf("%s %s under the merge grant: %v", what, name, err)
		}
	}
	refused("append to", "matches.derby", head("matches.derby"), title)
	refused("create", "matches.p99", "", client.PatchStep(place))
	refused("delete", "matches.shared", head("matches.shared"), client.DeleteStep())
	if _, err := core.Batch(ctx, "cat", req, false); err != nil {
		t.Fatalf("the batch under its merge grant: %v", err)
	}
	if live(w.ops, "cat", "matches.derby") || !live(w.ops, "cat", "matches.p14") {
		t.Fatal("the batch did not apply")
	}
	// A created item may be neither deleted nor appended to under it.
	refused("delete", "matches.p0", head("matches.p0"), client.DeleteStep())
	refused("append to", "matches.p0", head("matches.p0"), title)
}
