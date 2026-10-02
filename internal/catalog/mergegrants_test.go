package catalog_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
)

// §F.8: merging a catalog branch goes through the catalog service, which
// checks every move and placement of the batch as in §B.11.4 (for the
// approver) and signs one grant covering exactly that batch, with a key
// used for nothing else, only for the merge service.
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
	svc := w.caller("svc:merge")
	desk := w.caller("user:anna", "match-desk")
	// ask posts as the merge service, with approver's powers checked.
	ask := func(approver string, body map[string]any) resp {
		t.Helper()
		return w.doWith("POST", "/merge-grants", svc, body, map[string]string{"Approver-Authorization": "Bearer " + approver})
	}
	newx := client.GenesisPatches(map[string]any{"parents": parents("season")})

	// Unplacing and placing, approved by someone with the powers: one grant.
	b := batch(
		map[string]any{"resource": "matches.derby", "ifMatch": head("matches.derby"), "steps": []any{"delete"}},
		map[string]any{"resource": "matches.newx", "ifNoneMatch": "*", "steps": []any{newx}},
	)
	// Only the merge service gets merge grants.
	if r := w.do("POST", "/merge-grants", desk, b); r.status != 403 {
		t.Fatalf("merge grant to someone else: %d %v", r.status, r.body)
	}
	r := ask(desk, b)
	if r.status != 200 {
		t.Fatalf("merge grant: %d %v", r.status, r.body)
	}
	if r.body["approvedBy"] != "user:anna" {
		t.Fatalf("approvedBy %v", r.body)
	}
	g := must(grant.Decode(r.body["grant"].(string), 0))
	root := g.Blocks[0]
	if root.Kid != "catalog-merge" || root.Sub != "svc:merge" || root.Attrs["approvedBy"] != "user:anna" || len(root.Groups) != 0 {
		t.Fatalf("merge grant root %+v", root)
	}
	if root.Exp == nil || root.Exp.Sub(w.s.Now()).Minutes() > 10 {
		t.Fatalf("merge grant expiry %v", root.Exp)
	}
	core := w.core(r.body["grant"].(string))
	req := client.BatchRequest{Source: src, Items: []client.BatchItem{
		{Resource: "matches.derby", IfMatch: head("matches.derby"), Steps: []client.Step{client.DeleteStep()}},
		{Resource: "matches.newx", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(newx)}},
	}}
	// The grant covers exactly that batch: another resource is refused, and
	// so is another action on one of its resources.
	other := client.BatchRequest{Source: src, Items: []client.BatchItem{{Resource: "matches.shared", IfMatch: head("matches.shared"), Steps: []client.Step{client.DeleteStep()}}}}
	if _, err := core.Batch(ctx, "cat", other, false); !isStatus(err, 403) {
		t.Fatalf("another batch under the merge grant: %v", err)
	}
	wrongAction := client.BatchRequest{Source: src, Items: []client.BatchItem{{Resource: "matches.derby", IfMatch: head("matches.derby"),
		Steps: []client.Step{client.PatchStep([]any{map[string]any{"op": "add", "path": "/title", "value": "x"}})}}}}
	if _, err := core.Batch(ctx, "cat", wrongAction, false); !isStatus(err, 403) {
		t.Fatalf("another action under the merge grant: %v", err)
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
	// non-admins.
	r = ask(desk, batch(map[string]any{"resource": "matches.newx", "ifMatch": head("matches.newx"),
		"steps": []any{[]any{map[string]any{"op": "replace", "path": "/parents", "value": parents("derbies")}}}}))
	if msg, _ := r.body["message"].(string); r.status != 403 || !strings.Contains(msg, "would give") {
		t.Fatalf("widening move: %d %v", r.status, r.body)
	}
	// A change of $access: refused for non-admins; for an admin, checked
	// and answered admin, with no grant (§F.8: submitted under the admin's).
	access := batch(map[string]any{"resource": "season", "ifMatch": head("season"),
		"steps": []any{[]any{map[string]any{"op": "add", "path": "/$access/group:x", "value": toAny("reader")}}}})
	if r = ask(desk, access); r.status != 403 {
		t.Fatalf("$access by a non-admin: %d %v", r.status, r.body)
	}
	r = ask(w.caller("user:chief", "catalog-admins"), access)
	if r.status != 200 || r.body["admin"] != true || r.body["grant"] != nil {
		t.Fatalf("$access by an admin: %d %v", r.status, r.body)
	}
	// Without powers on the folder: refused.
	if r = ask(w.caller("user:bo", "fan-club"), batch(map[string]any{"resource": "matches.shared", "ifMatch": head("matches.shared"), "steps": []any{"delete"}})); r.status != 403 {
		t.Fatalf("unplace without move: %d %v", r.status, r.body)
	}
	// A stale precondition is refused before anything is signed.
	if r = ask(desk, batch(map[string]any{"resource": "matches.shared", "ifMatch": head("season"), "steps": []any{"delete"}})); r.status != 409 {
		t.Fatalf("stale: %d %v", r.status, r.body)
	}

	// §B.11.4 Create a folder: move on every folder it goes into. Powers
	// on it come only from its own $access: an item placed into a new
	// folder without $access is refused, unless the approver is an admin.
	folder := client.GenesisPatches(map[string]any{"title": "Highlights", "parents": parents("season")})
	if r = ask(desk, batch(map[string]any{"resource": "highlights", "ifNoneMatch": "*", "steps": []any{folder}})); r.status != 200 {
		t.Fatalf("folder by desk: %d %v", r.status, r.body)
	}
	if r = ask(w.caller("user:li"), batch(map[string]any{"resource": "highlights", "ifNoneMatch": "*", "steps": []any{folder}})); r.status != 403 {
		t.Fatalf("folder without move: %d %v", r.status, r.body)
	}
	intoNew := batch(
		map[string]any{"resource": "highlights", "ifNoneMatch": "*", "steps": []any{folder}},
		map[string]any{"resource": "matches.newx", "ifMatch": head("matches.newx"),
			"steps": []any{[]any{map[string]any{"op": "replace", "path": "/parents", "value": parents("highlights")}}}})
	if r = ask(desk, intoNew); r.status != 403 {
		t.Fatalf("a move into a new folder nobody holds powers on: %d %v", r.status, r.body)
	}
}

// Without a merge key the catalog service issues no merge grants.
func TestMergeGrantsNeedMergeKey(t *testing.T) {
	w := setup(t)
	w.seed()
	w.mergeKey.Priv = nil
	w.start()
	w.caughtUp()
	r := w.doWith("POST", "/merge-grants", w.caller("svc:merge"), map[string]any{"batch": map[string]any{
		"items":  []any{map[string]any{"resource": "matches.derby", "ifMatch": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "steps": []any{"delete"}}},
		"source": map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}, nil)
	if msg, _ := r.body["message"].(string); r.status != 403 || !strings.Contains(msg, "merge key") {
		t.Fatalf("without a merge key: %d %v", r.status, r.body)
	}
}

// §B.11.4 Create a folder (POST /grants): move on every folder in to; the
// grant fixes the name and parents and, for non-admins, refuses $access.
func TestCreateFolderGrant(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	desk := w.caller("user:anna", "match-desk")
	is := w.issue(desk, map[string]any{"node": "highlights", "want": toAny("create"), "to": toAny("season")}, 200)
	c := w.core(is.body["grant"].(string))
	withAccess := map[string]any{"title": "H", "parents": parents("season"), "$access": acc("group:fan-club", "desk")}
	// Refused by the grant's rule (403), or by the namespace's own (422).
	if _, err := c.Create(ctx, "cat", "highlights", w.nonced(client.GenesisPatches(withAccess))); !isStatus(err, 403) && !isStatus(err, 422) {
		t.Fatalf("a folder with $access under a non-admin's grant: %v", err)
	}
	if _, err := c.Create(ctx, "cat", "highlights", w.nonced(client.GenesisPatches(map[string]any{"title": "H", "parents": parents("derbies")}))); !isStatus(err, 403) {
		t.Fatalf("a folder elsewhere: %v", err)
	}
	if _, err := c.Create(ctx, "cat", "highlights", w.nonced(client.GenesisPatches(map[string]any{"title": "H", "parents": parents("season")}))); err != nil {
		t.Fatal(err)
	}
	// Without move on the target, and for a taken name: refused.
	w.issue(w.caller("user:li"), map[string]any{"node": "more", "want": toAny("create"), "to": toAny("season")}, 403)
	w.issue(desk, map[string]any{"node": "highlights", "want": toAny("create"), "to": toAny("season")}, 409)
	w.issue(desk, map[string]any{"node": "matches.x", "want": toAny("create"), "to": toAny("season")}, 400)
	// Nobody holds tree powers on the new folder: only admins may move or
	// place into it until an admin gives some.
	w.caughtUp()
	w.issue(desk, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("highlights")}, 403)
	w.issue(w.caller("user:chief", "catalog-admins", "match-desk"), map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("highlights")}, 200)
}
