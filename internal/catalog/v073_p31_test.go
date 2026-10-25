package catalog_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// mergeAsk posts a batch of items to POST /merge-grants as the merge
// service, with approver's grant in Approver-Authorization and, if set,
// admin's in Admin-Authorization (§F.8, F-T4).
func (w *world) mergeAsk(approver, admin string, items ...map[string]any) resp {
	w.t.Helper()
	arr := []any{}
	for _, it := range items {
		arr = append(arr, it)
	}
	hdr := map[string]string{"Approver-Authorization": "Bearer " + approver}
	if admin != "" {
		hdr["Admin-Authorization"] = "Bearer " + admin
	}
	body := map[string]any{"batch": map[string]any{"items": arr,
		"source": map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	return w.doWith("POST", "/merge-grants", w.caller("svc:merge"), body, hdr)
}

// catHead is the catalog's head revision of name (a tombstone's id for a
// deleted node).
func (w *world) catHead(name string) string {
	w.t.Helper()
	return must(w.ops.Head(context.Background(), "cat", name)).ID
}

// moveItem is a batch item replacing name's parents with folders.
func (w *world) moveItem(name string, folders ...string) map[string]any {
	w.t.Helper()
	return map[string]any{"resource": name, "ifMatch": w.catHead(name),
		"steps": []any{[]any{map[string]any{"op": "replace", "path": "/parents", "value": parents(folders...)}}}}
}

func mergeMsg(r resp) string { m, _ := r.body["message"].(string); return m }

// adminDryRun reports whether r is an admin dry run's answer (§F.8):
// 200, admin, no grant, checked as checkedAs.
func adminDryRun(r resp, checkedAs string) bool {
	return r.status == 200 && r.body["admin"] == true && r.body["grant"] == nil && r.body["checkedAs"] == checkedAs
}

// TestMergeNoWideningWhoeverApprovedV073 (TC-46, scenario 44): a catalog
// merge is checked as the approver's own organising requests would be,
// with no widening whoever approved. A move that widens needs
// catalog-admins: approved by an admin, it gets no merge-key grant but an
// admin dry run (admin: true, no grant), to go under an admin's grant;
// approved by anyone else, it is refused (403), even with an admin's
// grant to go under (§F.8, §B.11.4).
func TestMergeNoWideningWhoeverApprovedV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	chief, desk := w.caller("user:chief", "catalog-admins", "match-desk"), w.caller("user:anna", "match-desk")

	// derby under derbies gives fan-club desk, where it had reader.
	widen := w.moveItem("matches.derby", "derbies")
	r := w.mergeAsk(chief, "", widen)
	if !adminDryRun(r, "user:chief") {
		t.Fatalf("a widening move approved by an admin: %d %v", r.status, r.body)
	}
	r = w.mergeAsk(desk, "", widen)
	if r.status != 403 || !strings.Contains(mergeMsg(r), "would give group:fan-club the role desk") {
		t.Fatalf("a widening move approved by desk: %d %v", r.status, r.body)
	}
	// A decision at the checkpoint: the catalog, and matches, whose
	// includes and roles it read (§B.11.4).
	if cp := w.checkpointOf("matches"); !reflect.DeepEqual(r.body["checkpoint"], cp) {
		t.Errorf("refusal checkpoint %v, now %v", r.body["checkpoint"], cp)
	}
	if r = w.mergeAsk(desk, chief, widen); r.status != 403 {
		t.Fatalf("a widening move approved by desk, with an admin's grant: %d %v", r.status, r.body)
	}
	// A narrowing move needs no admin: a merge-key grant, for an admin
	// approver too.
	narrow := w.moveItem("matches.shared", "season")
	for _, tok := range []string{chief, desk} {
		if r = w.mergeAsk(tok, "", narrow); r.status != 200 || r.body["grant"] == nil || r.body["admin"] != nil {
			t.Fatalf("a narrowing move: %d %v", r.status, r.body)
		}
	}
}

// TestMergeReplacingAgainstDeletedRowsV073 (TC-46): re-placing a deleted
// placement in a catalog merge is judged against the deleted placement's
// rows (§B.11.4 No widening, §B.11.7): one that widens them needs
// catalog-admins, one that doesn't gets a restore grant.
func TestMergeReplacingAgainstDeletedRowsV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	must(w.ops.Delete(ctx, "cat", "matches.derby", w.catHead("matches.derby")))
	w.caughtUp()
	chief, desk := w.caller("user:chief", "catalog-admins", "match-desk"), w.caller("user:anna", "match-desk")
	replace := func(folders ...string) map[string]any {
		return map[string]any{"resource": "matches.derby", "ifMatch": w.catHead("matches.derby"),
			"steps": []any{[]any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"parents": parents(folders...)}}}}}
	}

	// Under derbies fan-club would have desk; its rows (under season) had
	// reader.
	r := w.mergeAsk(desk, "", replace("derbies"))
	if r.status != 403 || !strings.Contains(mergeMsg(r), "re-placing matches.derby would give group:fan-club the role desk") {
		t.Fatalf("a widening re-place approved by desk: %d %v", r.status, r.body)
	}
	if r = w.mergeAsk(chief, "", replace("derbies")); !adminDryRun(r, "user:chief") {
		t.Fatalf("a widening re-place approved by an admin: %d %v", r.status, r.body)
	}
	// Back under season: its rows, a restore under the merge key.
	r = w.mergeAsk(desk, "", replace("season"))
	if r.status != 200 || r.body["grant"] == nil {
		t.Fatalf("a re-place within its rows: %d %v", r.status, r.body)
	}
	chk := r.body["checks"].([]any)[0].(map[string]any)
	if chk["change"] != "place" || fmt.Sprint(chk["actions"]) != "[restore]" {
		t.Errorf("re-place check %v", chk)
	}
}

// TestMergeWideningElsewhereV073 (TC-46, carry-over): no widening covers
// every node a batch's changes reach, not only moved subtrees: a new
// folder that a dangling parents entry already names gives that node its
// roles, and deleting a node of a cycle gives the others theirs (§B.11.2:
// a cyclic node contributes nothing). The refusal to someone who doesn't
// see the widened node names only the batch's change, not the node
// (§B.11, §B.11.5).
func TestMergeWideningElsewhereV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "h", map[string]any{"title": "h"})
	w.doc("cat", "matches.h", map[string]any{"parents": parents("ghost")}) // dangling: no role, hidden from all
	w.doc("cat", "c1", map[string]any{"title": "c1", "parents": parents("c2"), "$access": acc("group:match-desk", "desk")})
	w.doc("cat", "c2", map[string]any{"title": "c2", "parents": parents("c1"), "$access": acc("group:fan-club", "desk")})
	w.start()
	w.caughtUp()
	ghost := map[string]any{"resource": "ghost", "ifNoneMatch": "*",
		"steps": []any{client.GenesisPatches(map[string]any{"title": "Ghost", "parents": parents("derbies")})}}
	r := w.mergeAsk(w.caller("user:anna", "match-desk"), "", ghost)
	if r.status != 403 || !strings.Contains(mergeMsg(r), "ghost") || strings.Contains(mergeMsg(r), "matches.h") {
		t.Fatalf("a folder that widens a hidden node, approved by desk: %d %v", r.status, r.body)
	}
	if r = w.mergeAsk(w.caller("user:chief", "catalog-admins"), "", ghost); !adminDryRun(r, "user:chief") {
		t.Fatalf("the same, approved by an admin: %d %v", r.status, r.body)
	}
	// Without c1, c2 is no longer cyclic, and its own fan-club desk counts.
	unc := map[string]any{"resource": "c1", "ifMatch": w.catHead("c1"), "steps": []any{"delete"}}
	if r = w.mergeAsk(w.caller("user:chief", "catalog-admins"), "", unc); !adminDryRun(r, "user:chief") {
		t.Fatalf("deleting a node of a cycle, approved by an admin: %d %v", r.status, r.body)
	}
}

// TestMergeAdminDryRunAsAdminV073 (TC-47, F-T4): a batch that needs
// catalog-admins is checked as the approver's, who must be one, and as a
// dry run with the admin whose grant it goes under as the caller, sent in
// Admin-Authorization: the place list applies to both. Admin-
// Authorization must hold an admin's grant, and a batch that needs none
// is the approver's alone.
func TestMergeAdminDryRunAsAdminV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "newone", map[string]any{"title": "new"})
	w.start()
	w.caughtUp()
	desk := w.caller("user:anna", "match-desk")
	chief := w.caller("user:chief", "catalog-admins", "match-desk")
	dora := w.caller("user:dora", "catalog-admins", "match-desk")
	ada := w.caller("user:ada", "catalog-admins") // not in matches' place list
	place := map[string]any{"resource": "matches.newone", "ifNoneMatch": "*",
		"steps": []any{client.GenesisPatches(map[string]any{"parents": parents("season"), "$access": acc("user:guest", "reader")})}}

	if r := w.mergeAsk(chief, "", place); !adminDryRun(r, "user:chief") {
		t.Fatalf("$access approved by an admin: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(chief, dora, place); !adminDryRun(r, "user:dora") || r.body["approvedBy"] != "user:chief" {
		t.Fatalf("$access approved by an admin, under another's grant: %d %v", r.status, r.body)
	}
	// The dry run is the admin's: outside the place list, refused.
	if r := w.mergeAsk(chief, ada, place); r.status != 403 || !strings.Contains(mergeMsg(r), "place") {
		t.Fatalf("$access under an admin outside the place list: %d %v", r.status, r.body)
	}
	// And the approver's checks still apply.
	if r := w.mergeAsk(ada, chief, place); r.status != 403 || !strings.Contains(mergeMsg(r), "place") {
		t.Fatalf("$access approved by an admin outside the place list: %d %v", r.status, r.body)
	}
	for _, admin := range []string{"", chief} {
		if r := w.mergeAsk(desk, admin, place); r.status != 403 || r.body["checkpoint"] == nil {
			t.Fatalf("$access approved by desk (admin's grant %v): %d %v", admin != "", r.status, r.body)
		}
	}
	if r := w.mergeAsk(chief, w.caller("user:bob", "match-desk"), place); r.status != 403 || !strings.Contains(mergeMsg(r), "Admin-Authorization") {
		t.Fatalf("Admin-Authorization from a non-admin: %d %v", r.status, r.body)
	}
	// A batch that needs no admin is the approver's, with or without an
	// admin's grant.
	unplace := map[string]any{"resource": "matches.shared", "ifMatch": w.catHead("matches.shared"), "steps": []any{"delete"}}
	if r := w.mergeAsk(desk, chief, unplace); r.status != 200 || r.body["grant"] == nil || r.body["checkedAs"] != "user:anna" {
		t.Fatalf("an unplace approved by desk, with an admin's grant: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(w.caller("user:li"), chief, unplace); r.status != 403 {
		t.Fatalf("an unplace approved by a reader, with an admin's grant: %d %v", r.status, r.body)
	}
}

// TestE2ECatalogNoMergeGrantsV073 (TC-45, scenario 48): an end-to-end
// catalog gets no merge grants and no batch check: 404 not_offered, for an
// admin approver too (§F.8).
func TestE2ECatalogNoMergeGrantsV073(t *testing.T) {
	t.Parallel()
	w := setupE2ECatalog(t)
	w.start()
	item := map[string]any{"resource": "matches.derby", "ifNoneMatch": "*",
		"steps": []any{client.GenesisPatches(map[string]any{"parents": parents("season")})}}
	for _, tok := range []string{w.caller("user:bob", "match-desk"), w.caller("user:ada", "catalog-admins")} {
		if r := w.mergeAsk(tok, "", item); r.status != 404 || r.body["code"] != "not_offered" {
			t.Errorf("merge grant in an e2e catalog: %d %v", r.status, r.body)
		}
	}
}

// TestMergeChecksAsOrganisingV073 (TC-48, carry-over): merge checks are
// organising checks (§F.8, §B.11.4): only admins make roots, or move,
// delete or edit a node without parents or with a parent hidden from the
// approver; a node hidden from the approver, or a new parent that isn't a
// live folder or is hidden, is 404; a node can't go under itself, for
// admins too; and powers come through the reworked helpers (powers): a
// role through a group the catalog's key may not assert gives none, and a
// folder without $access has, per subject, the powers held at all its
// parents. No refusal names a node hidden from the approver.
func TestMergeChecksAsOrganisingV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "top", map[string]any{"title": "Top", "parents": []any{}, "$access": acc("group:match-desk", "desk")})
	w.doc("matches", "mixed", map[string]any{"title": "mixed"})
	w.doc("cat", "matches.mixed", map[string]any{"parents": parents("season", "rumours")}) // rumours is hidden from desk
	w.doc("cat", "opsf", map[string]any{"title": "opsf", "parents": parents("root"), "$access": acc("group:ops", "desk", "user:o", "reader")})
	w.doc("cat", "p1", map[string]any{"title": "P1", "parents": parents("root"), "$access": acc("group:a", "desk", "group:c", "desk")})
	w.doc("cat", "p2", map[string]any{"title": "P2", "parents": parents("root"), "$access": acc("group:b", "desk", "group:c", "desk")})
	w.doc("cat", "f", map[string]any{"title": "F", "parents": parents("p1", "p2")})
	w.start()
	w.caughtUp()
	desk, chief := w.caller("user:anna", "match-desk"), w.caller("user:chief", "catalog-admins")
	del := func(name string) map[string]any {
		return map[string]any{"resource": name, "ifMatch": w.catHead(name), "steps": []any{"delete"}}
	}
	folder := func(name string, under ...string) map[string]any {
		return map[string]any{"resource": name, "ifNoneMatch": "*",
			"steps": []any{client.GenesisPatches(map[string]any{"title": name, "parents": parents(under...)})}}
	}

	// Roots: only admins move a node to the top, or delete a root.
	if r := w.mergeAsk(desk, "", w.moveItem("matches.derby")); r.status != 403 || !strings.Contains(mergeMsg(r), "roots") {
		t.Errorf("desk moves a node to the top: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(chief, "", w.moveItem("matches.derby")); r.status != 200 || r.body["grant"] == nil {
		t.Errorf("an admin moves a node to the top: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(desk, "", del("top")); r.status != 403 || !strings.Contains(mergeMsg(r), "root") {
		t.Errorf("desk deletes a root: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(chief, "", del("top")); r.status != 200 {
		t.Errorf("an admin deletes a root: %d %v", r.status, r.body)
	}

	// Hidden parents: a node with one is refused without naming it; a
	// hidden or missing new parent is 404, as a node hidden from desk is.
	if r := w.mergeAsk(desk, "", del("matches.mixed")); r.status != 403 || strings.Contains(mergeMsg(r), "rumours") {
		t.Errorf("desk deletes a node with a hidden parent: %d %v", r.status, r.body)
	}
	for _, to := range [][]string{{"season", "rumours"}, {"season", "nowhere"}} {
		if r := w.mergeAsk(desk, "", w.moveItem("matches.derby", to...)); r.status != 404 {
			t.Errorf("desk moves derby to %v: %d %v", to, r.status, r.body)
		}
	}
	if r := w.mergeAsk(desk, "", del("matches.rumour1")); r.status != 404 || r.body["checkpoint"] == nil {
		t.Errorf("desk deletes a node hidden from it: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(w.caller("user:eve", "editors-in-chief"), "", del("matches.rumour1")); r.status != 200 {
		t.Errorf("editors-in-chief delete rumour1: %d %v", r.status, r.body)
	}

	// Not under itself, for admins too.
	if r := w.mergeAsk(chief, "", w.moveItem("season", "rumours")); r.status != 403 || !strings.Contains(mergeMsg(r), "itself or below it") {
		t.Errorf("an admin moves season under rumours: %d %v", r.status, r.body)
	}

	// A role through ops, which the catalog's key may not assert, gives
	// no power; f, without $access, gives c the desk it has at both its
	// parents, and a only at one, none.
	if r := w.mergeAsk(w.caller("user:o", "ops"), "", folder("underops", "opsf")); r.status != 403 {
		t.Errorf("a folder under opsf through ops: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(w.caller("user:c", "c"), "", folder("nf", "f")); r.status != 200 || r.body["grant"] == nil {
		t.Errorf("c makes a folder in f: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(w.caller("user:a", "a"), "", folder("nf", "f")); r.status != 403 {
		t.Errorf("a makes a folder in f: %d %v", r.status, r.body)
	}
}

// TestMergeCreateAppliesToNullV073 (carry-over, GB-8): a batch's create
// applies to the document null, as the core applies it (§6.2 step 3): a
// genesis that tests "" for null folds, and one that writes nothing is
// refused.
func TestMergeCreateAppliesToNullV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	desk := w.caller("user:anna", "match-desk")
	create := func(ops ...any) map[string]any {
		return map[string]any{"resource": "highlights", "ifNoneMatch": "*", "steps": []any{ops}}
	}
	isNull := map[string]any{"op": "test", "path": "", "value": nil}
	doc := map[string]any{"op": "add", "path": "", "value": map[string]any{"title": "H", "parents": parents("season")}}
	if r := w.mergeAsk(desk, "", create(isNull, doc)); r.status != 200 || r.body["grant"] == nil {
		t.Fatalf("a create testing null: %d %v", r.status, r.body)
	}
	if r := w.mergeAsk(desk, "", create(isNull)); r.status != 400 {
		t.Fatalf("a create writing nothing: %d %v", r.status, r.body)
	}
}

// TestMergePurgedPlacementV073: creating a purged placement in a merge
// batch is 410, as a Place of one is (§B.11.4, §8.3).
func TestMergePurgedPlacementV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	must(w.ops.Delete(ctx, "cat", "matches.derby", w.catHead("matches.derby")))
	purger := w.core(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"purge"}))
	must(purger.Purge(ctx, "cat", "matches.derby", w.catHead("matches.derby"), false))
	w.caughtUp()
	r := w.mergeAsk(w.caller("user:anna", "match-desk"), "", map[string]any{"resource": "matches.derby", "ifNoneMatch": "*",
		"steps": []any{client.GenesisPatches(map[string]any{"parents": parents("season")})}})
	if r.status != 410 || r.body["code"] != "gone" {
		t.Fatalf("a purged placement: %d %v", r.status, r.body)
	}
}

// TestMergeMoveKeptParentsV073 (review): a batch item that changes a
// node's parents is a Move whose to is every parent it has after the
// batch, those it keeps included (§B.11.4 move, §F.8): it needs move on
// each, as the approver's own Move does, so adding a parent to a node in
// a folder without move there is refused, and so is renaming such a node
// in the same step. A kept parent that isn't a live folder, or is hidden
// from the approver, is 404, as a to entry is.
func TestMergeMoveKeptParentsV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	// k gives match-desk no role, so no move there.
	w.doc("cat", "k", map[string]any{"title": "K", "parents": parents("season"), "$access": acc("group:other", "reader")})
	w.doc("matches", "x", map[string]any{"title": "x"})
	w.doc("cat", "matches.x", map[string]any{"parents": parents("k")})
	w.doc("matches", "y", map[string]any{"title": "y"})
	w.doc("cat", "matches.y", map[string]any{"parents": parents("season", "ghost")}) // ghost: dangling
	w.doc("matches", "z", map[string]any{"title": "z"})
	w.doc("cat", "matches.z", map[string]any{"parents": parents("derbies", "rumours")}) // rumours: hidden from desk
	w.start()
	w.caughtUp()
	anna, chief := w.caller("user:anna", "match-desk"), w.caller("user:chief", "catalog-admins")
	move := func(name string, title any, folders ...string) map[string]any {
		ops := []any{map[string]any{"op": "replace", "path": "/parents", "value": parents(folders...)}}
		if title != nil {
			ops = append(ops, map[string]any{"op": "add", "path": "/title", "value": title})
		}
		return map[string]any{"resource": name, "ifMatch": w.catHead(name), "steps": []any{ops}}
	}

	// The approver's own Move to [k, season] is 403.
	if r := w.do("POST", "/grants", anna, map[string]any{"node": "matches.x", "want": []any{"move"}, "to": []any{"k", "season"}}); r.status != 403 {
		t.Fatalf("organising Move to [k, season]: %d %v", r.status, r.body)
	}
	for _, title := range []any{nil, "renamed"} {
		r := w.mergeAsk(anna, "", move("matches.x", title, "k", "season"))
		if r.status != 403 || !strings.Contains(mergeMsg(r), "move is assigned on k") {
			t.Errorf("a move keeping k (title %v), no move at k: %d %v", title, r.status, r.body)
		}
	}
	// With move at every parent, it is a merge-key grant.
	if r := w.mergeAsk(chief, "", move("matches.x", "renamed", "k", "season")); r.status != 200 || r.body["grant"] == nil {
		t.Errorf("the same approved by an admin: %d %v", r.status, r.body)
	}

	// A kept parent that isn't a live folder: 404, as a to entry, for an
	// admin too.
	for _, tok := range []string{anna, chief} {
		if r := w.mergeAsk(tok, "", move("matches.y", nil, "derbies", "ghost")); r.status != 404 || !strings.Contains(mergeMsg(r), "ghost") {
			t.Errorf("a move keeping dangling ghost: %d %v", r.status, r.body)
		}
	}
	// A kept parent hidden from the approver: 404, as a to entry hidden
	// from it, before the 403 for moving a node with a hidden parent.
	if r := w.mergeAsk(anna, "", move("matches.z", nil, "season", "rumours")); r.status != 404 || r.body["checkpoint"] == nil {
		t.Errorf("a move keeping hidden rumours: %d %v", r.status, r.body)
	}
	if r := w.do("POST", "/grants", anna, map[string]any{"node": "matches.z", "want": []any{"move"}, "to": []any{"season", "rumours"}}); r.status != 404 {
		t.Errorf("organising Move keeping hidden rumours: %d %v", r.status, r.body)
	}
	// An edit that keeps the parents names no to: a rename still needs
	// move at every current parent (403 at k), and isn't 404.
	edit := map[string]any{"resource": "matches.y", "ifMatch": w.catHead("matches.y"),
		"steps": []any{[]any{map[string]any{"op": "add", "path": "/title", "value": "y2"}}}}
	if r := w.mergeAsk(anna, "", edit); r.status != 403 {
		t.Errorf("a rename of a node with a dangling parent: %d %v", r.status, r.body)
	}
}
