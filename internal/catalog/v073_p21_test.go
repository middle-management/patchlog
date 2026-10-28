package catalog_test

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
)

// moveWith writes a Move grant's change: the patch set begins with the
// test of /parents the answer gives (§B.11.4 Move), unless the answer
// gives none (a node whose document has no parents member).
func (w *world) moveWith(answer map[string]any, node string, ops ...any) error {
	w.t.Helper()
	ctx := context.Background()
	h := must(w.ops.Head(ctx, "cat", node))
	if p, ok := answer["parents"]; ok {
		ops = append([]any{map[string]any{"op": "test", "path": "/parents", "value": p}}, ops...)
	}
	_, err := w.core(answer["grant"].(string)).Append(ctx, "cat", node, h.ID, ops)
	return err
}

func replaceParents(ps ...string) any {
	return map[string]any{"op": "replace", "path": "/parents", "value": parents(ps...)}
}

// TestRootsNeedAdminsV073 (TC-20, scenarios 3 and 4): roots and an empty
// to need catalog-admins. A caller not in it needs a non-empty to (403),
// and can't move, rename, unplace or delete a node without parents that
// it sees (403); a root hidden from it is 404, as a missing node. An
// admin may give to: [] for Place, Move and Create a folder, and the
// grant then fixes /doc/parents to none: absent or [] (§B.11.4).
func TestRootsNeedAdminsV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	// top is a root bob sees, with desk (move, place) on it.
	w.doc("cat", "top", map[string]any{"title": "Top", "parents": []any{}, "$access": acc("group:match-desk", "desk")})
	w.doc("cat", "matches.toproot", map[string]any{"parents": []any{}, "$access": acc("group:match-desk", "desk")})
	w.doc("matches", "toproot", map[string]any{"title": "toproot"})
	w.doc("matches", "newone", map[string]any{"title": "newone"})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins", "match-desk")

	// A request that takes to and gives none is malformed.
	w.issue(bob, map[string]any{"node": "previews", "want": toAny("create")}, 400)
	w.issue(admin, map[string]any{"node": "matches.derby", "want": toAny("move")}, 400)

	// Not in catalog-admins: an empty to, or a root it sees, is 403.
	w.issue(bob, map[string]any{"node": "previews", "want": toAny("create"), "to": []any{}}, 403)
	w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": []any{}}, 403)
	w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": []any{}}, 403)
	w.issue(bob, map[string]any{"node": "top", "want": toAny("move"), "to": toAny("season")}, 403)
	w.issue(bob, map[string]any{"node": "top", "want": toAny("delete")}, 403)
	w.issue(bob, map[string]any{"node": "matches.toproot", "want": toAny("delete")}, 403)
	// A rename is a move to the current parents: none, for a root.
	w.issue(bob, map[string]any{"node": "top", "want": toAny("move"), "to": []any{}}, 403)
	// root is hidden from bob: 404, as a missing node.
	w.issue(bob, map[string]any{"node": "root", "want": toAny("delete")}, 404)
	w.issue(bob, map[string]any{"node": "root", "want": toAny("move"), "to": toAny("season")}, 404)

	// An admin may make roots, and name the hidden root.
	b := w.issue(admin, map[string]any{"node": "newroot", "want": toAny("create"), "to": []any{}}, 200).body
	ac := w.core(b["grant"].(string))
	if _, err := ac.CreateDoc(ctx, "cat", "newroot", map[string]any{"title": "x", "parents": parents("season")}); !isStatus(err, 403) {
		t.Errorf("a root grant writing parents: %v", err)
	}
	must(ac.CreateDoc(ctx, "cat", "newroot", map[string]any{"title": "New root", "parents": []any{}}))
	b = w.issue(admin, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": []any{}}, 200).body
	must(w.core(b["grant"].(string)).CreateDoc(ctx, "cat", "matches.newone", map[string]any{}))
	b = w.issue(admin, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": []any{}}, 200).body
	if err := w.moveWith(b, "matches.derby", map[string]any{"op": "remove", "path": "/parents"}); err != nil {
		t.Fatalf("admin's move to a root: %v", err)
	}
	w.caughtUp()
	w.issue(admin, map[string]any{"node": "root", "want": toAny("move"), "to": toAny("newroot")}, 200)
	b = w.issue(admin, map[string]any{"node": "newroot", "want": toAny("delete")}, 200).body
	must(w.core(b["grant"].(string)).Delete(ctx, "cat", "newroot", must(w.ops.Head(ctx, "cat", "newroot")).ID))
	b = w.issue(admin, map[string]any{"node": "matches.derby", "want": toAny("delete")}, 200).body
	must(w.core(b["grant"].(string)).Delete(ctx, "cat", "matches.derby", must(w.ops.Head(ctx, "cat", "matches.derby")).ID))
}

// TestHiddenNodesV073 (TC-22, scenarios 1, 6, 8, 23 and 35): to a caller
// not in catalog-admins, an organising request naming a node or a to
// folder hidden from it is 404, as one naming a missing node, with the
// same answer. A dangling placement is judged as if its item were live,
// and cyclic nodes are hidden. A new folder's name, and a Place of an
// item whose placement is live, are 409 even when hidden (names are not
// secrets). A node with a parent hidden from the caller can't be moved,
// unplaced or deleted (403, naming nothing hidden) (§B.11.4, §B.11.5).
func TestHiddenNodesV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "c1", map[string]any{"title": "c1", "parents": parents("c2"), "$access": acc("group:match-desk", "desk")})
	w.doc("cat", "c2", map[string]any{"title": "c2", "parents": parents("c1"), "$access": acc("group:match-desk", "desk")})
	w.doc("cat", "matches.unborn", map[string]any{"parents": parents("season")})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins")

	// Scenario 1: a new folder's name is exempt; rumours (TR) is hidden.
	w.issue(bob, map[string]any{"node": "previews", "want": toAny("create"), "to": toAny("season")}, 200)
	hidden := w.issue(bob, map[string]any{"node": "previews", "want": toAny("create"), "to": toAny("rumours")}, 404).body
	missing := w.issue(bob, map[string]any{"node": "previews", "want": toAny("create"), "to": toAny("nosuch")}, 404).body
	if hidden["code"] != missing["code"] || strings.Replace(hidden["message"].(string), "rumours", "nosuch", 1) != missing["message"] {
		t.Errorf("a hidden folder and a missing one answer differently: %v, %v", hidden, missing)
	}
	// A hidden node, as a missing one.
	w.issue(bob, map[string]any{"node": "matches.rumour1", "want": toAny("move"), "to": toAny("season")}, 404)
	w.issue(bob, map[string]any{"node": "matches.rumour1", "want": toAny("delete")}, 404)
	w.issue(bob, map[string]any{"node": "rumours", "want": toAny("delete")}, 404)
	w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("rumours")}, 404)
	w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("rumours")}, 404)
	// Scenario 23: names are not secrets.
	w.issue(bob, map[string]any{"node": "rumours", "want": toAny("create"), "to": toAny("season")}, 409)
	w.issue(bob, map[string]any{"item": "/r/matches/rumour1", "want": toAny("place"), "to": toAny("season")}, 409)
	// An admin sees every node.
	w.issue(admin, map[string]any{"node": "matches.rumour1", "want": toAny("move"), "to": toAny("season")}, 200)

	// Scenario 6: a dangling placement whose item doesn't exist yet is
	// judged as if it were live: visible, and bob has move at season.
	b := w.issue(bob, map[string]any{"node": "matches.unborn", "want": toAny("delete")}, 200).body
	must(w.core(b["grant"].(string)).Delete(ctx, "cat", "matches.unborn", must(w.ops.Head(ctx, "cat", "matches.unborn")).ID))
	// So is one whose item is deleted.
	must(w.ops.Delete(ctx, "matches", "derby", must(w.ops.Head(ctx, "matches", "derby")).ID))
	w.caughtUp()
	w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("delete")}, 200)
	w.issue(w.caller("user:fred", "fan-club"), map[string]any{"node": "matches.derby", "want": toAny("delete")}, 403)
	w.issue(w.caller("user:nobody"), map[string]any{"node": "matches.derby", "want": toAny("delete")}, 404)

	// Scenario 8: a cyclic node is hidden; an admin may still delete it.
	w.issue(bob, map[string]any{"node": "c1", "want": toAny("delete")}, 404)
	w.issue(admin, map[string]any{"node": "c1", "want": toAny("delete")}, 200)

	// Scenario 35: desk's rule refers to /resource, so desk shows bob no
	// folder; derby's placement stays visible to him, but its parent
	// season is hidden: 403, naming nothing hidden.
	must(w.ops.Restore(ctx, "matches", "derby", must(w.ops.Head(ctx, "matches", "derby")).ID, []any{}))
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/desk/rules", "value": []any{
		map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^secret-"}}}}})
	if !w.placedFor(bob, "/r/matches/derby") || w.listsFolder(bob, "season") {
		t.Fatal("derby should show, season not")
	}
	r := w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("delete")}, 403)
	if strings.Contains(r.body["message"].(string), "season") {
		t.Errorf("the refusal names the hidden parent: %v", r.body)
	}
}

// TestOrganisingAnswerOrderV073 (TC-25, scenario 9): organising answers
// are 400, then 404 for a node that isn't an untombstoned node of the
// catalog or a to entry that isn't a live folder, then 403 for the place
// list, powers and an item namespace the catalog doesn't trust, then 409.
// There is no 422 not_folder or untrusted any more (§B.11.4).
func TestOrganisingAnswerOrderV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "newone", map[string]any{"title": "newone"})
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	anna := w.caller("user:anna", "translators")
	place := func(token, item string, to any, status int) map[string]any {
		t.Helper()
		return w.issue(token, map[string]any{"item": item, "want": toAny("place"), "to": to}, status).body
	}
	// 400 before all else.
	place(bob, "/r/matches/newone", toAny("bad name!"), 400)
	// A to entry that is a placement, or no node, is 404.
	if b := place(bob, "/r/matches/newone", toAny("matches.derby"), 404); b["code"] != "not_found" {
		t.Errorf("a placement as a folder: %v", b)
	}
	w.issue(bob, map[string]any{"node": "nf", "want": toAny("create"), "to": toAny("matches.derby")}, 404)
	w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("matches.shared")}, 404)
	// The 404 comes before the place list's 403 and the untrusted 403.
	place(anna, "/r/matches/newone", toAny("nosuch"), 404)
	place(anna, "/r/matches/newone", toAny("season"), 403)
	place(bob, "/r/teams/x", toAny("nosuch"), 404)
	// Scenario 9: an untrusted item namespace is 403.
	if b := place(bob, "/r/teams/x", toAny("season"), 403); b["code"] != "forbidden" {
		t.Errorf("an untrusted namespace: %v", b)
	}
	// The 403s before the 409: anna, outside the place list, asking to
	// place an item already placed.
	place(anna, "/r/matches/derby", toAny("season"), 403)
	place(bob, "/r/matches/derby", toAny("season"), 409)
}

// TestPlacePurgedPlacementV073 (TC-26, scenario 43): a Place of an item
// whose placement was purged is 410 gone, after the 400, 404 and 403
// answers; one whose placement is live stays 409. The core's head is the
// service's only record of the purge, so the 410 carries no checkpoint
// (§B.11.4 Place).
func TestPlacePurgedPlacementV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"read", "purge"})))
	tomb := must(w.ops.Delete(ctx, "cat", "matches.derby", must(w.ops.Head(ctx, "cat", "matches.derby")).ID))
	must(purger.Purge(ctx, "cat", "matches.derby", tomb.ID, false))
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	place := map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("season")}
	w.issue(w.caller("user:anna", "translators"), place, 403)
	w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("rumours")}, 404)
	r := w.issue(bob, place, 410)
	if _, has := r.body["checkpoint"]; r.body["code"] != "gone" || has {
		t.Errorf("place over a purged placement: %v", r.body)
	}
	w.issue(bob, map[string]any{"item": "/r/matches/shared", "want": toAny("place"), "to": toAny("season")}, 409)
}

// TestMoveUnderItselfV073 (TC-28, scenario 29): a Move whose to entry is
// the node or below it is 403, an admin's too (§B.11.4 Move).
func TestMoveUnderItselfV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "cup", map[string]any{"title": "Cup", "parents": parents("season")})
	w.doc("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cup")})
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins")
	for _, tok := range []string{bob, admin} {
		for _, to := range []string{"sub", "cup"} {
			if r := w.issue(tok, map[string]any{"node": "cup", "want": toAny("move"), "to": toAny(to)}, 403); r.body["code"] != "forbidden" {
				t.Errorf("move under %s: %v", to, r.body)
			}
		}
	}
	w.issue(bob, map[string]any{"node": "sub", "want": toAny("move"), "to": toAny("season")}, 200)
}

// TestMoveChangesOtherMembersV073 (TC-29, scenario 13): a Move grant may
// also change the node's other members, $access excepted; a rename is a
// move to the node's current parents (§B.11.4 Move, §B.11.3).
func TestMoveChangesOtherMembersV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "cup", map[string]any{"title": "Cup", "parents": parents("season")})
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	rename := w.issue(bob, map[string]any{"node": "cup", "want": toAny("move"), "to": toAny("season")}, 200).body
	// $access: the catalog's rules and its key's refuse (§B.11.3).
	if err := w.moveWith(rename, "cup", map[string]any{"op": "add", "path": "/$access", "value": acc("group:fan-club", "desk")}); !isStatus(err, 403) && !isStatus(err, 422) {
		t.Errorf("a Move grant writing $access: %v", err)
	}
	if err := w.moveWith(rename, "cup", map[string]any{"op": "replace", "path": "/title", "value": "The Cup"}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	_, d, err := w.ops.Load(context.Background(), "cat", "cup")
	if err != nil || d.Value.(map[string]any)["title"] != "The Cup" {
		t.Errorf("renamed: %v %v", d, err)
	}
}

// TestMovePinsParentsV073 (TC-30, TC-31, scenario 26): unless the caller
// is in catalog-admins, a Move grant requires its patch set to begin with
// a test of /parents against the node's parents as decided, which the
// answer gives as parents: a stale test fails at step 3 (422), a missing
// or different one fails the grant's rule (403). Move and Unplace answers
// carry parents and head, the node's as decided; since v0.74 parents goes
// with every Move, an admin's included, and every Unplace, not only with
// a Move grant that pins them (§B.11.4).
func TestMovePinsParentsV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "cup", map[string]any{"title": "Cup", "parents": parents("season"), "$access": acc("group:match-desk", "desk")})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins")
	_, derby, err := w.ops.Load(ctx, "cat", "matches.derby")
	if err != nil {
		t.Fatal(err)
	}
	head := must(w.ops.Head(ctx, "cat", "matches.derby")).ID

	b := w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("cup")}, 200).body
	if !reflect.DeepEqual(b["parents"], derby.Value.(map[string]any)["parents"]) || b["head"] != head {
		t.Fatalf("move answer: parents %v head %v, want %v %s", b["parents"], b["head"], derby.Value, head)
	}
	for _, k := range []string{"grant", "checkpoint", "ns", "resource", "can", "exp", "at"} {
		if _, ok := b[k]; !ok {
			t.Errorf("move answer without %s: %v", k, b)
		}
	}
	// An admin's Move pins nothing, but gives parents and head; Unplace
	// gives both; Place and Create a folder give neither.
	ab := w.issue(admin, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("cup")}, 200).body
	if !reflect.DeepEqual(ab["parents"], derby.Value.(map[string]any)["parents"]) || ab["head"] != head {
		t.Errorf("admin's move answer: %v", ab)
	}
	_, shared, err := w.ops.Load(ctx, "cat", "matches.shared")
	if err != nil {
		t.Fatal(err)
	}
	if u := w.issue(bob, map[string]any{"node": "matches.shared", "want": toAny("delete")}, 200).body; u["head"] != must(w.ops.Head(ctx, "cat", "matches.shared")).ID ||
		!reflect.DeepEqual(u["parents"], shared.Value.(map[string]any)["parents"]) {
		t.Errorf("unplace answer: %v", u)
	}
	for _, req := range []map[string]any{
		{"node": "previews", "want": toAny("create"), "to": toAny("season")},
		{"item": "/r/matches/fresh", "want": toAny("place"), "to": toAny("season")},
	} {
		r := w.issue(bob, req, 200).body
		_, hp := r["parents"]
		_, hh := r["head"]
		if hp || hh {
			t.Errorf("%v answer: %v", req, r)
		}
	}

	// Without the leading test the rule refuses.
	mc := w.core(b["grant"].(string))
	if _, err := mc.Append(ctx, "cat", "matches.derby", head, []any{replaceParents("cup")}); !isStatus(err, 403) {
		t.Errorf("move without the test: %v", err)
	}
	// Scenario 26: an editor-in-chief moves derby into TR meanwhile; bob's
	// move, sent against the new head, fails its test (step 3), and one
	// testing the parents it has now isn't the move judged (the rule).
	w.patch("cat", "matches.derby", replaceParents("rumours"))
	if err := w.moveWith(b, "matches.derby", replaceParents("cup")); !isStatus(err, 422) {
		t.Errorf("move after the node moved: %v", err)
	}
	now := must(w.ops.Head(ctx, "cat", "matches.derby")).ID
	if _, err := mc.Append(ctx, "cat", "matches.derby", now, []any{
		map[string]any{"op": "test", "path": "/parents", "value": parents("rumours")}, replaceParents("cup")}); !isStatus(err, 403) {
		t.Errorf("move testing the parents it has now: %v", err)
	}
	if _, err := mc.Append(ctx, "cat", "matches.derby", now, []any{replaceParents("cup")}); !isStatus(err, 403) {
		t.Errorf("move without the test after the node moved: %v", err)
	}
	// An admin's grant needs no test, though its answer gives parents.
	if _, err := w.core(ab["grant"].(string)).Append(ctx, "cat", "matches.derby", now, []any{replaceParents("cup")}); err != nil {
		t.Errorf("admin's move: %v", err)
	}
}

// TestMoveExpiresWithinMaxLagV073 (TC-32, scenario 32): a Move grant's
// exp is at most the catalog's maxLag after its decision (default 60 s),
// which bounds how long an overtaken judgement can be used; other
// organising grants keep their lifetime (§B.11.8, §7.4).
func TestMoveExpiresWithinMaxLagV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	expIn := func(req map[string]any) time.Duration {
		t.Helper()
		b := w.issue(bob, req, 200).body
		return must(time.Parse(time.RFC3339Nano, b["exp"].(string))).Sub(w.s.Now())
	}
	move := map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("season")}
	if d := expIn(move); d > 60*time.Second || d <= 0 {
		t.Errorf("move grant lives %s, want at most the catalog's maxLag of 60s", d)
	}
	if d := expIn(map[string]any{"node": "matches.derby", "want": toAny("delete")}); d < 14*time.Minute {
		t.Errorf("unplace grant lives %s", d)
	}
	// A stricter maxLag, as of the checkpoint.
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "replace", "path": "/maxLag", "value": "PT20S"}}))
	w.caughtUp()
	if d := expIn(move); d > 20*time.Second || d <= 0 {
		t.Errorf("move grant lives %s, want at most 20s", d)
	}
	// The grant still works within that.
	b := w.issue(bob, move, 200).body
	if err := w.moveWith(b, "matches.derby", map[string]any{"op": "add", "path": "/parents/0/order", "value": "a1"}); err != nil {
		t.Errorf("a move within maxLag: %v", err)
	}
}

// TestDeleteFolderV073 (TC-33, scenarios 7 and 8): want ["delete"] on a
// folder needs move on every current parent, and the grant fixes
// /doc/parents to them by href. A tombstoned folder is 404, to admins
// too, and so is a request to restore it: folders are restored only by
// catalog-admins under grants of their own (§B.11.4).
func TestDeleteFolderV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "previews", map[string]any{"title": "Previews", "parents": parents("season")})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins")
	w.issue(w.caller("user:anna", "translators"), map[string]any{"node": "previews", "want": toAny("delete")}, 403)
	b := w.issue(bob, map[string]any{"node": "previews", "want": toAny("delete")}, 200).body
	if b["can"].([]any)[0] != "delete" || b["head"] != must(w.ops.Head(ctx, "cat", "previews")).ID {
		t.Errorf("delete answer: %v", b)
	}
	dc := w.core(b["grant"].(string))
	// Moved meanwhile, the folder can't be deleted with the grant.
	w.patch("cat", "previews", map[string]any{"op": "add", "path": "/parents/-", "value": map[string]any{"href": "/r/cat/derbies"}})
	if _, err := dc.Delete(ctx, "cat", "previews", must(w.ops.Head(ctx, "cat", "previews")).ID); !isStatus(err, 403) {
		t.Errorf("delete after a move: %v", err)
	}
	w.patch("cat", "previews", map[string]any{"op": "remove", "path": "/parents/1"})
	// A live folder isn't restored.
	w.issue(bob, map[string]any{"node": "previews", "want": toAny("restore")}, 409)
	must(dc.Delete(ctx, "cat", "previews", must(w.ops.Head(ctx, "cat", "previews")).ID))
	w.caughtUp()
	for _, tok := range []string{bob, admin} {
		w.issue(tok, map[string]any{"node": "previews", "want": toAny("delete")}, 404)
		w.issue(tok, map[string]any{"node": "previews", "want": toAny("move"), "to": toAny("season")}, 404)
		w.issue(tok, map[string]any{"node": "previews", "want": toAny("restore")}, 404)
		w.issue(tok, map[string]any{"item": "/r/cat/previews", "want": toAny("restore")}, 404)
	}
}

// setupE2ECatalog is a world whose catalog is end-to-end (Addendum E):
// the service doesn't follow it without a keyring recipient key, but
// authenticates callers and answers organising requests.
func setupE2ECatalog(t *testing.T) *world {
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	opsKey, idp, catKey := clienttest.NewKey("ops"), clienttest.NewKey("idp"), clienttest.NewKey("catalog-01")
	w := &world{t: t, s: s, idp: idp, cat: catKey, opsKey: opsKey, mergeKey: clienttest.NewKey("catalog-merge")}
	catEntry := catKey.Entry("read", "create", "append", "delete", "restore")
	catEntry["maxTtl"] = "PT15M"
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{
		"read": "grant", "keys": []any{opsKey.Entry("*"), idp.Entry(), catEntry}, "encryption": map[string]any{"level": "e2e"},
		"catalog": map[string]any{"trust": toAny("matches"), "mode": "dag"},
		"roles":   map[string]any{"desk": map[string]any{"move": true, "place": true}},
	}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{
		"read": "grant", "keys": []any{opsKey.Entry("*"), idp.Entry(), catKey.Entry("read", "create", "append", "restore")},
		"roles":    map[string]any{"desk": map[string]any{"can": toAny("read")}},
		"catalogs": map[string]any{"cat": map[string]any{"place": toAny("group:match-desk")}},
	}))
	w.db = filepath.Join(t.TempDir(), "catalog.db")
	w.svcClient = s.Client(t, client.WithBearer(opsKey.Grant(t, s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
		map[string]any{"exp": s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	return w
}

// TestE2ECatalogNotOfferedV073 (TC-39): an end-to-end catalog, whose
// writes fail rules on /doc, gets no organising grants: 404 not_offered,
// for admins too (§B.11.4).
func TestE2ECatalogNotOfferedV073(t *testing.T) {
	t.Parallel()
	w := setupE2ECatalog(t)
	w.start()
	for _, tok := range []string{w.caller("user:bob", "match-desk"), w.caller("user:ada", "catalog-admins")} {
		for _, req := range []map[string]any{
			{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("season")},
			{"node": "matches.derby", "want": toAny("move"), "to": toAny("season")},
			{"node": "matches.derby", "want": toAny("delete")},
			{"node": "previews", "want": toAny("create"), "to": toAny("season")},
			{"node": "previews", "want": toAny("restore")},
		} {
			if r := w.issue(tok, req, 404); r.body["code"] != "not_offered" {
				t.Errorf("%v: %v", req, r.body)
			}
		}
	}
}

// TestCheckpointNamesWhatWasReadV073 (TC-40, v0.56 note 4): a decision's
// checkpoint names every namespace whose state it read: for a non-admin
// Move, every trusted namespace (includes, and folders' visibility), so
// a write to another trusted namespace moves it, while an admin's Move
// names only the catalog and the node's item's namespace; for a catalog
// folder in POST /read-grants, every trusted namespace, whose roles
// decide its visibility (§B.11.4 checkpoint).
func TestCheckpointNamesWhatWasReadV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "deskonly", map[string]any{"title": "Desk only", "parents": parents("root"), "$access": acc("group:match-desk", "desk")})
	ctx := context.Background()
	op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins")
	move := map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("deskonly")}
	check := func(when string) {
		t.Helper()
		all := w.checkpointOf("matches", "teams")
		if r := w.issue(bob, move, 200); !reflect.DeepEqual(r.body["checkpoint"], all) {
			t.Errorf("%s: non-admin move checkpoint %v, want %v", when, r.body["checkpoint"], all)
		}
		if r := w.issue(admin, move, 200); !reflect.DeepEqual(r.body["checkpoint"], w.checkpointOf("matches")) {
			t.Errorf("%s: admin move checkpoint %v, want %v", when, r.body["checkpoint"], w.checkpointOf("matches"))
		}
		// Folders' visibility reads every trusted namespace.
		if r := w.issue(bob, map[string]any{"node": "nf", "want": toAny("create"), "to": toAny("season")}, 200); !reflect.DeepEqual(r.body["checkpoint"], w.checkpointOf("teams", "matches")) {
			t.Errorf("%s: create folder checkpoint %v", when, r.body["checkpoint"])
		}
		// A catalog folder in POST /read-grants is 400 in this catalog,
		// neither sealed nor end-to-end, which reads only the catalog's
		// level (§B.11.5); in a sealed one its visibility reads every
		// trusted namespace (TestReadGrantsCatalogNodesV073).
		rg := w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/cat/season")})
		if e := entry(rg, 0); e == nil || e["status"] != 400.0 || !reflect.DeepEqual(rg.body["checkpoint"], w.checkpointOf()) {
			t.Errorf("%s: read-grants folder %v, want checkpoint %v", when, rg.body, w.checkpointOf())
		}
	}
	check("before")
	before := w.checkpointOf("matches", "teams")
	ot := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"teams"}, []string{"read", "config"})))
	must(ot.PatchConfig(ctx, "teams", must(ot.NSHead(ctx, "teams")).Config, []any{map[string]any{"op": "add", "path": "/roles", "value": map[string]any{"desk": map[string]any{"can": toAny("read")}}}}))
	waitFor(t, "the service to apply the teams write", func() bool { return w.svc.Tree().Checkpoint("teams") != before["teams"] })
	check("after a /roles change in teams")
}

// trustTeams adds teams to the catalog's trusted namespaces, with item
// t1, before start: it lists no catalog key, so no role counts there and
// its placements are hidden from every caller not in catalog-admins.
func (w *world) trustTeams() {
	w.t.Helper()
	t, ctx := w.t, context.Background()
	op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")},
		"roles": map[string]any{"reader": map[string]any{"can": toAny("read")}}}))
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
	ot := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"teams"}, []string{"create", "read"})))
	must(ot.Create(ctx, "teams", "t1", client.GenesisPatches(map[string]any{"title": "t1"})))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
}

// TestHiddenAnsweredAsMissingV073 (TC-22, TC-40): to a caller not in
// catalog-admins, a request naming a node or a to folder hidden from it
// is answered as one naming a missing node, checkpoint included, so
// nothing about the hidden node appears: a folder's name, or any to, reads
// every trusted namespace whether or not a live folder has it, in
// organising requests and for a catalog node in POST /read-grants alike
// (§B.11, §B.11.4 checkpoint, §B.11.5). With two trusted namespaces, a
// placement's own namespace is not all a folder's visibility reads.
func TestHiddenAnsweredAsMissingV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.trustTeams()
	w.start()
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	bob := w.caller("user:bob", "match-desk")
	// same compares two answers, the first naming hidden where the second
	// names missing.
	same := func(what string, a, b map[string]any, hidden, missing string) {
		t.Helper()
		am, _ := a["message"].(string)
		if a["code"] != b["code"] || strings.Replace(am, hidden, missing, 1) != b["message"] || !reflect.DeepEqual(a["checkpoint"], b["checkpoint"]) {
			t.Errorf("%s: %s answers %v, %s %v", what, hidden, a, missing, b)
		}
		if _, has := a["checkpoint"]; !has {
			t.Errorf("%s: no checkpoint in %v", what, a)
		}
	}
	for _, c := range []struct {
		what            string
		hidden, missing string
		req             func(name string) map[string]any
	}{
		{"create under", "rumours", "nosuch", func(n string) map[string]any {
			return map[string]any{"node": "nf", "want": toAny("create"), "to": toAny(n)}
		}},
		{"create under a placement", "matches.derby", "nosuch", func(n string) map[string]any {
			return map[string]any{"node": "nf", "want": toAny("create"), "to": toAny(n)}
		}},
		{"place under", "rumours", "nosuch", func(n string) map[string]any {
			return map[string]any{"item": "/r/matches/fresh", "want": toAny("place"), "to": toAny(n)}
		}},
		{"move", "rumours", "nosuch", func(n string) map[string]any {
			return map[string]any{"node": n, "want": toAny("move"), "to": toAny("season")}
		}},
		{"move under", "rumours", "nosuch", func(n string) map[string]any {
			return map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny(n)}
		}},
		{"delete", "rumours", "nosuch", func(n string) map[string]any {
			return map[string]any{"node": n, "want": toAny("delete")}
		}},
		{"restore", "rumours", "nosuch", func(n string) map[string]any {
			return map[string]any{"node": n, "want": toAny("restore")}
		}},
		{"delete a placement", "matches.rumour1", "matches.ghost", func(n string) map[string]any {
			return map[string]any{"node": n, "want": toAny("delete")}
		}},
	} {
		same(c.what, w.issue(bob, c.req(c.hidden), 404).body, w.issue(bob, c.req(c.missing), 404).body, c.hidden, c.missing)
	}

	// A catalog node in POST /read-grants, asked for alone, whose answer
	// carries one checkpoint (v0.73): in this catalog, neither sealed nor
	// end-to-end, both are 400 (§B.11.5); in a sealed one a hidden node
	// is 404 as a missing one is (TestReadGrantsCatalogNodesV073).
	answer := func(node string) map[string]any {
		t.Helper()
		rg := w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/cat/" + node)})
		e := entry(rg, 0)
		if e == nil {
			t.Fatalf("read-grants: %d %v", rg.status, rg.body)
		}
		e["checkpoint"] = rg.body["checkpoint"]
		return e
	}
	same("read-grants", answer("rumours"), answer("nosuch"), "rumours", "nosuch")
}

// TestOrganisingGrantsRefuseAccessV073 (TC-29): a non-admin's Move grant
// may change the node's other members, $access excepted, and its Place
// grant may not create a placement with $access, by the grant's own rules
// as Create a folder's, not only the catalog's key's and namespace's
// (§B.11.3, §B.11.4).
func TestOrganisingGrantsRefuseAccessV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "cup", map[string]any{"title": "Cup", "parents": parents("season"), "$access": acc("group:match-desk", "desk")})
	w.doc("matches", "newone", map[string]any{"title": "newone"})
	ctx := context.Background()
	// A catalog whose namespace and key carry no $access rules.
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{
		map[string]any{"op": "remove", "path": "/rules"},
		map[string]any{"op": "remove", "path": "/keys/2/rules"}}))
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")

	b := w.issue(bob, map[string]any{"node": "cup", "want": toAny("move"), "to": toAny("season")}, 200).body
	for _, op := range []any{
		map[string]any{"op": "add", "path": "/$access", "value": acc("group:fan-club", "desk")},
		map[string]any{"op": "add", "path": "/$access/group:fan-club", "value": toAny("desk")},
		map[string]any{"op": "remove", "path": "/$access"},
	} {
		if err := w.moveWith(b, "cup", op); !isStatus(err, 403) {
			t.Errorf("a Move grant writing $access with %v: %v", op, err)
		}
	}
	if err := w.moveWith(b, "cup", map[string]any{"op": "replace", "path": "/title", "value": "The Cup"}); err != nil {
		t.Errorf("a rename: %v", err)
	}

	b = w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("season")}, 200).body
	pc := w.core(b["grant"].(string))
	if _, err := pc.CreateDoc(ctx, "cat", "matches.newone", map[string]any{"parents": parents("season"), "$access": acc("group:fan-club", "desk")}); !isStatus(err, 403) {
		t.Errorf("a Place grant creating a placement with $access: %v", err)
	}
	must(pc.CreateDoc(ctx, "cat", "matches.newone", map[string]any{"parents": parents("season")}))
}

// TestWideningRefusalNamesNothingHiddenV073 (TC-22): a non-admin's Move
// refused for widening at a node hidden from the caller names only the
// moved node, not the hidden one nor the subject and role it would gain;
// at a node the caller sees, it names all three (§B.11, §B.11.4 No
// widening, §B.11.5).
func TestWideningRefusalNamesNothingHiddenV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.trustTeams()
	w.doc("cat", "zfolder", map[string]any{"title": "Z", "parents": parents("season")})
	w.doc("cat", "teams.t1", map[string]any{"parents": parents("zfolder")})
	w.doc("cat", "afolder", map[string]any{"title": "A", "parents": parents("season")})
	w.start()
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	bob := w.caller("user:bob", "match-desk")
	w.issue(bob, map[string]any{"node": "teams.t1", "want": toAny("delete")}, 404)

	// Into derbies, fan-club gets desk below zfolder, first at teams.t1.
	r := w.issue(bob, map[string]any{"node": "zfolder", "want": toAny("move"), "to": toAny("derbies")}, 403)
	msg, _ := r.body["message"].(string)
	for _, s := range []string{"teams.t1", "fan-club", "desk"} {
		if strings.Contains(msg, s) {
			t.Errorf("the refusal names %s, hidden from the caller: %q", s, msg)
		}
	}
	if !strings.Contains(msg, "zfolder") || r.body["checkpoint"] == nil {
		t.Errorf("the refusal: %v", r.body)
	}
	// afolder, which bob sees, is named with the subject and role.
	r = w.issue(bob, map[string]any{"node": "afolder", "want": toAny("move"), "to": toAny("derbies")}, 403)
	if msg, _ := r.body["message"].(string); !strings.Contains(msg, "group:fan-club the role desk on /r/cat/afolder") {
		t.Errorf("the refusal at a visible node: %q", msg)
	}
}
