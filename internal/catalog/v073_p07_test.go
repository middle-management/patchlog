package catalog_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/tree"
)

// patchMatches changes the matches namespace document (a * key's config
// write, §C.1.1) and waits for the service to apply it.
func (w *world) patchMatches(ops ...any) {
	w.t.Helper()
	ctx := context.Background()
	opm := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, ops))
	w.caughtUp()
}

// placedFor reports whether token's listings show item's placement
// (where, §B.5), as a reader of that subject set sees it.
func (w *world) placedFor(token, item string) bool {
	w.t.Helper()
	r, _ := w.follow("/cat/where?item="+item, token)
	if r.status != 200 {
		w.t.Fatalf("where %s: %d %v", item, r.status, r.body)
	}
	return r.body["placement"] != nil
}

// listsFolder reports whether token's listings show folder's children
// (§B.11.5: a hidden folder is 404, as one not in the catalog).
func (w *world) listsFolder(token, folder string) bool {
	w.t.Helper()
	r, _ := w.follow("/cat/children?of="+folder, token)
	switch r.status {
	case 200:
		return true
	case 404:
		return false
	}
	w.t.Fatalf("children of %s: %d %v", folder, r.status, r.body)
	return false
}

// TestSubjectsV073 (TC-1, scenario 14): a caller's subject set is its sub
// only if it starts with user:, plus group:{g} for each group (§B.11.2
// Subjects). A sub of another kind, or a bare one, collects nothing, and
// a group written with the group: prefix is another group, not the one
// named without it, for roles and for the admin group alike (§B.11.3).
func TestSubjectsV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	read := func(item string) map[string]any {
		return map[string]any{"item": item, "want": toAny("read")}
	}

	// Scenario 14: the identity provider issues sub "group:editors-in-chief".
	w.issue(w.caller("group:editors-in-chief"), read("/r/matches/rumour1"), 403)
	w.issue(w.caller("user:eve", "editors-in-chief"), read("/r/matches/rumour1"), 200)
	// A bare sub is no subject: li's user:li entry on season isn't hers.
	w.issue(w.caller("li"), read("/r/matches/derby"), 403)
	w.issue(w.caller("user:li"), read("/r/matches/derby"), 200)
	// Nor is a sub of another kind.
	w.issue(w.caller("svc:li"), read("/r/matches/derby"), 403)
	// A group named "group:editors-in-chief" is group:group:editors-in-chief.
	w.issue(w.caller("user:eve", "group:editors-in-chief"), read("/r/matches/rumour1"), 403)

	// Nor is "group:catalog-admins" the admin group: no widening holds.
	widen := map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}
	w.issue(w.caller("user:ada", "group:catalog-admins", "match-desk"), widen, 403)
	w.issue(w.caller("user:ada", "catalog-admins", "match-desk"), widen, 200)

	// Listings: a bare sub isn't in the subject set, so it doesn't key
	// li's listings as user:li's direct entries do (§B.11.5).
	_, loc := w.follow("/cat/children?of=season", w.caller("li"))
	if got, want := gsOf(loc), grantcheck.SubjectSetID(nil); got != want {
		t.Errorf("bare sub's subject set %s, want the empty set's %s", got, want)
	}
	r, loc := w.follow("/cat/children?of=season", w.caller("user:li"))
	if got, want := gsOf(loc), grantcheck.SubjectSetID([]string{"user:li"}); got != want || r.status != 200 {
		t.Errorf("user:li's subject set %s (%d), want %s", got, r.status, want)
	}
	if w.listsFolder(w.caller("li"), "season") {
		t.Error("a bare sub sees season through user:li's entry")
	}
}

// TestKeySubScopeV073 (TC-2): a role counts only through the catalog's
// key in the content namespace: its sub scope, if it has one, must match
// the caller's sub, whichever subject collected the role, and then the
// caller's sub is part of its listings' subject set; a subject set without
// a user: subject fails every sub scope (§B.11.2 Through the key,
// §B.11.5).
func TestKeySubScopeV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	fred, fiona := w.caller("user:fred", "fan-club"), w.caller("user:fiona", "fan-club")
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}

	// Without a sub scope, both share a subject set: fan-club's.
	_, l1 := w.follow("/cat/children?of=season", fred)
	_, l2 := w.follow("/cat/children?of=season", fiona)
	if gsOf(l1) != gsOf(l2) || gsOf(l1) != grantcheck.SubjectSetID([]string{"group:fan-club"}) {
		t.Fatalf("subject sets without a sub scope: %s %s", l1, l2)
	}
	w.issue(fiona, read, 200)

	// The catalog's key in matches gets a sub scope (keys[2] is its entry).
	w.patchMatches(map[string]any{"op": "add", "path": "/keys/2/sub", "value": "user:(anna|fred)"})
	w.issue(fred, read, 200)
	// fiona's reader comes through fan-club, which the key may assert, but
	// her sub fails the key's sub scope: no role counts.
	w.issue(fiona, read, 403)
	// A bare sub matches no user: pattern either.
	w.issue(w.caller("fred", "fan-club"), read, 403)

	// Each one's sub is now in its subject set.
	r1, l1 := w.follow("/cat/children?of=season", fred)
	r2, l2 := w.follow("/cat/children?of=season", fiona)
	if gsOf(l1) != grantcheck.SubjectSetID([]string{"group:fan-club", "user:fred"}) ||
		gsOf(l2) != grantcheck.SubjectSetID([]string{"group:fan-club", "user:fiona"}) {
		t.Errorf("subject sets with a sub scope: %s %s", l1, l2)
	}
	if r1.status != 200 || childNames(r1.body) != "matches.derby,matches.shared" {
		t.Errorf("fred on season: %d %v", r1.status, r1.body)
	}
	if r2.status != 404 || w.placedFor(fiona, "/r/matches/derby") {
		t.Errorf("fiona sees what the key can't grant her: %d %v", r2.status, r2.body)
	}
	// A subject set without a user: subject fails the sub scope.
	if w.listsFolder(w.caller("fred", "fan-club"), "season") {
		t.Error("a subject set without a user: subject passes a sub scope")
	}
	// /read-grants uses the same test for catalog nodes (§B.11.5).
	rg := w.do("POST", "/read-grants", fiona, map[string]any{"items": toAny("/r/cat/season")})
	if entry(rg, 0)["error"] == nil {
		t.Errorf("read-grants: fiona gets season: %v", rg.body)
	}
	rg = w.do("POST", "/read-grants", fred, map[string]any{"items": toAny("/r/cat/season")})
	if entry(rg, 0)["error"] != nil {
		t.Errorf("read-grants: fred is refused season: %v", rg.body)
	}
}

// TestVisibilityKeyRulesV073 (TC-3, scenarios 15, 16 and 27): a role
// counts for read when its own rules and the key's scope rules pass as a
// read would evaluate them, with /principal holding the groups the key
// may assert and, as roles, that role. For an item, /resource is its
// name; for a folder, the role's rules may not refer to /resource, and the
// key's scope rules only to /principal/groups and /principal/roles. A
// rule on /now, or on anything else in /principal, makes the role not
// count (§B.11.5).
func TestVisibilityKeyRulesV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "pub-a", map[string]any{"title": "a"})
	w.doc("cat", "matches.pub-a", map[string]any{"parents": parents("season")})
	w.start()
	w.caughtUp()
	fan, anna := w.caller("user:fred", "fan-club"), w.caller("user:anna", "translators")

	// Scenario 27: the translator role's rule (writes within /i18n) doesn't
	// refer to /resource, so season is listed for it.
	if r, _ := w.follow("/cat/children?of=season", anna); r.status != 200 || childNames(r.body) != "matches.derby,matches.pub-a,matches.shared" {
		t.Errorf("translator on season: %d %v", r.status, r.body)
	}
	if rg := w.do("POST", "/read-grants", anna, map[string]any{"items": toAny("/r/cat/season")}); entry(rg, 0)["error"] != nil {
		t.Errorf("read-grants: the translator is refused season: %v", rg.body)
	}

	// A role whose rule tests /principal/roles is evaluated with that
	// role as /principal/roles: it counts, for items and folders.
	w.patchMatches(
		map[string]any{"op": "add", "path": "/roles/self", "value": map[string]any{"can": toAny("read"),
			"rules": []any{map[string]any{"op": "test", "path": "/principal/roles", "schema": map[string]any{"contains": map[string]any{"const": "self"}}}}}},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "self"})
	w.patch("cat", "season", map[string]any{"op": "add", "path": "/$access/group:selves", "value": toAny("self")})
	w.caughtUp()
	selves := w.caller("user:sel", "selves")
	if !w.placedFor(selves, "/r/matches/derby") || !w.listsFolder(selves, "season") {
		t.Error("a role testing /principal/roles for itself doesn't count")
	}

	// Scenario 16: a key rule requiring roles still lets every role count,
	// since visibility tests it with the role (§B.11.3).
	w.patchMatches(map[string]any{"op": "add", "path": "/keys/2/rules", "value": []any{
		map[string]any{"op": "test", "path": "/principal/roles", "schema": map[string]any{"minItems": 1}}}})
	if !w.placedFor(fan, "/r/matches/derby") || !w.listsFolder(fan, "season") {
		t.Error("a key rule on /principal/roles hides what the role reads")
	}

	// Scenario 15: key rules admitting only /resource ^pub-: the items the
	// key can't grant read for are hidden, and so is every folder, since
	// the key's rules refer to /resource.
	w.patchMatches(map[string]any{"op": "replace", "path": "/keys/2/rules", "value": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^pub-"}}}})
	if w.placedFor(fan, "/r/matches/derby") {
		t.Error("an item the key's rules refuse is listed")
	}
	if !w.placedFor(fan, "/r/matches/pub-a") {
		t.Error("an item the key's rules allow is hidden")
	}
	if w.listsFolder(fan, "season") {
		t.Error("a folder is listed through a key whose rules refer to /resource")
	}

	// A key rule on /action passes for reads, but folders need key rules
	// on /principal/groups and /principal/roles alone.
	w.patchMatches(map[string]any{"op": "replace", "path": "/keys/2/rules", "value": []any{
		map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": toAny("read", "append")}}}})
	if !w.placedFor(fan, "/r/matches/derby") || w.listsFolder(fan, "season") {
		t.Error("a key rule on /action: items should show, folders not")
	}

	// A key rule reading /now, or /principal/id, makes no role count.
	for _, rule := range []any{
		map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": "2999-01-01T00:00:00Z"}},
		map[string]any{"op": "test", "path": "/principal/id", "exists": false},
	} {
		w.patchMatches(map[string]any{"op": "replace", "path": "/keys/2/rules", "value": []any{rule}})
		if w.placedFor(fan, "/r/matches/derby") || w.listsFolder(fan, "season") {
			t.Errorf("a key rule %v lets roles count", rule)
		}
	}

	// The key's can lacking read (scenario 15): nothing is visible.
	w.patchMatches(
		map[string]any{"op": "remove", "path": "/keys/2/rules"},
		map[string]any{"op": "replace", "path": "/keys/2/can", "value": toAny("create", "append", "restore")})
	if w.placedFor(fan, "/r/matches/pub-a") || w.listsFolder(fan, "season") {
		t.Error("a key without read in can lets roles count for read")
	}
}

// TestAdminPowersV073 (TC-21, scenario 4): a caller in catalog-admins
// needs no tree power for any organising request; the place list, key
// rules and the 404/409 answers still apply (§B.11.4).
func TestAdminPowersV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "newone", map[string]any{"title": "new"})
	w.start()
	w.caughtUp()
	// ada is an admin with no role anywhere; editors-in-chief puts her in
	// matches' place list, and gives her desk on rumours only.
	ada := w.caller("user:ada", "catalog-admins", "editors-in-chief")
	w.issue(ada, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("season")}, 200)
	w.issue(ada, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}, 200)
	w.issue(ada, map[string]any{"node": "matches.shared", "want": toAny("delete")}, 200)
	w.issue(ada, map[string]any{"node": "previews", "want": toAny("create"), "to": toAny("season")}, 200)
	// The place list still applies to admins (§B.11.4 Place, F-T5).
	w.issue(w.caller("user:ada", "catalog-admins"), map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("season")}, 403)
	// So do the 409s.
	w.issue(ada, map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("season")}, 409)
	w.issue(ada, map[string]any{"node": "season", "want": toAny("create"), "to": toAny("root")}, 409)
	// A non-admin with the same roles has no power on season.
	eve := w.caller("user:eve", "editors-in-chief")
	w.issue(eve, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("season")}, 403)
	w.issue(eve, map[string]any{"node": "matches.shared", "want": toAny("delete")}, 403)

	// Merge checks (§F.8): an admin approver needs no power either.
	head := func(name string) string { return must(w.ops.Head(context.Background(), "cat", name)).ID }
	b := map[string]any{"batch": map[string]any{"source": map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"items": []any{map[string]any{"resource": "matches.shared", "ifMatch": head("matches.shared"), "steps": []any{"delete"}}}}}
	ask := func(approver string) resp {
		return w.doWith("POST", "/merge-grants", w.caller("svc:merge"), b, map[string]string{"Approver-Authorization": "Bearer " + approver})
	}
	if r := ask(ada); r.status != 200 {
		t.Errorf("merge approved by an admin without move: %d %v", r.status, r.body)
	}
	if r := ask(eve); r.status != 403 {
		t.Errorf("merge approved by a non-admin without move: %d %v", r.status, r.body)
	}
}

// TestBrokenParentsGiveNoPowerV073 (TC-23, scenario 46): powers count only
// at a live folder that isn't cyclic, and only through subjects the
// catalog's key in the catalog may assert. A missing, tombstoned, cyclic
// or non-folder parent gives none, so a non-admin can't move a node from
// it or unplace it (403); an admin can (§B.11.2 Tree powers, §B.11.4).
func TestBrokenParentsGiveNoPowerV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	desk := func(extra ...any) map[string]any {
		return acc(append([]any{"group:match-desk", "desk"}, extra...)...)
	}
	// c1 and c2 are a cycle; tomb will be deleted; opsf's role comes
	// through group:ops, which the catalog's key denies (§B.11.3).
	w.doc("cat", "c1", map[string]any{"title": "c1", "parents": parents("c2"), "$access": desk()})
	w.doc("cat", "c2", map[string]any{"title": "c2", "parents": parents("c1"), "$access": desk()})
	w.doc("cat", "tomb", map[string]any{"title": "tomb", "parents": parents("root"), "$access": desk()})
	w.doc("cat", "opsf", map[string]any{"title": "opsf", "parents": parents("root"), "$access": acc("group:ops", "desk")})
	for _, n := range []string{"p1", "p2", "p3", "p4"} {
		w.doc("matches", n, map[string]any{"title": n})
	}
	w.doc("cat", "matches.p1", map[string]any{"parents": parents("season", "ghost")}) // ghost never existed
	w.doc("cat", "matches.p2", map[string]any{"parents": parents("season", "tomb")})
	w.doc("cat", "matches.p3", map[string]any{"parents": parents("season", "c1")})
	w.doc("cat", "matches.p4", map[string]any{"parents": parents("season", "matches.derby")})
	w.start()
	w.caughtUp()
	tomb := must(w.ops.Head(context.Background(), "cat", "tomb"))
	must(w.ops.Delete(context.Background(), "cat", "tomb", tomb.ID))
	w.caughtUp()

	bob := w.caller("user:bob", "match-desk")
	admin := w.caller("user:ada", "catalog-admins")
	for _, n := range []string{"matches.p1", "matches.p2", "matches.p3", "matches.p4"} {
		// bob has move at season, but not at the other parent.
		w.issue(bob, map[string]any{"node": n, "want": toAny("move"), "to": toAny("season")}, 403)
		w.issue(bob, map[string]any{"node": n, "want": toAny("delete")}, 403)
		w.issue(admin, map[string]any{"node": n, "want": toAny("move"), "to": toAny("season")}, 200)
		w.issue(admin, map[string]any{"node": n, "want": toAny("delete")}, 200)
	}
	// Leaving only season, which bob has move at, is fine.
	w.doc("cat", "matches.p5", map[string]any{"parents": parents("season")})
	w.doc("matches", "p5", map[string]any{"title": "p5"})
	w.caughtUp()
	w.issue(bob, map[string]any{"node": "matches.p5", "want": toAny("delete")}, 200)

	// A role collected through a group the catalog's key may not assert
	// gives no power.
	w.issue(w.caller("user:o", "ops"), map[string]any{"node": "underops", "want": toAny("create"), "to": toAny("opsf")}, 403)
	w.issue(w.caller("user:o", "ops", "match-desk"), map[string]any{"node": "underops", "want": toAny("create"), "to": toAny("season")}, 200)

	// The same in merge checks (§F.8): a broken parent gives no power.
	head := func(name string) string { return must(w.ops.Head(context.Background(), "cat", name)).ID }
	b := map[string]any{"batch": map[string]any{"source": map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"items": []any{map[string]any{"resource": "matches.p1", "ifMatch": head("matches.p1"), "steps": []any{"delete"}}}}}
	if r := w.doWith("POST", "/merge-grants", w.caller("svc:merge"), b, map[string]string{"Approver-Authorization": "Bearer " + bob}); r.status != 403 {
		t.Errorf("merge deleting under a dangling parent: %d %v", r.status, r.body)
	}
}

// TestInheritedPowersV073 (TC-24, scenarios 2 and 46): at a folder without
// $access but with parents, a subject's role has a power when the same
// subject's role has it at every parents entry, recursively; a broken
// parent gives none (§B.11.2 Tree powers, §B.11.4 Create a folder).
func TestInheritedPowersV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "p1", map[string]any{"title": "P1", "parents": parents("root"), "$access": acc("group:a", "desk", "group:c", "desk")})
	w.doc("cat", "p2", map[string]any{"title": "P2", "parents": parents("root"), "$access": acc("group:b", "desk", "group:c", "desk")})
	w.doc("cat", "f", map[string]any{"title": "F", "parents": parents("p1", "p2")})
	w.doc("cat", "g", map[string]any{"title": "G", "parents": parents("f")})
	w.doc("cat", "half", map[string]any{"title": "half", "parents": parents("p1", "ghost")})
	w.doc("matches", "m", map[string]any{"title": "m"})
	w.doc("cat", "matches.m", map[string]any{"parents": parents("f")})
	w.start()
	w.caughtUp()
	create := func(token, under string, status int) {
		t.Helper()
		w.issue(token, map[string]any{"node": "new-" + under, "want": toAny("create"), "to": toAny(under)}, status)
	}
	a, ab, c := w.caller("user:a", "a"), w.caller("user:ab", "a", "b"), w.caller("user:c", "c")
	// Scenario 2: powers are judged per subject. a has desk at P1 only;
	// a member of both a and b has it at each parent, but through
	// different subjects.
	create(a, "f", 403)
	create(ab, "f", 403)
	// c's desk holds at both parents: F has its move, and so does G below
	// it, which takes F's.
	create(c, "f", 200)
	create(c, "g", 200)
	w.issue(c, map[string]any{"node": "matches.m", "want": toAny("move"), "to": toAny("g")}, 200)
	// A parents entry that dangles gives none.
	create(c, "half", 403)

	// Scenario 46: a member of b deletes P2. a still can't act in F: the
	// tombstoned parent gives no power, so deleting a node never widens.
	p2 := must(w.ops.Head(context.Background(), "cat", "p2"))
	must(w.ops.Delete(context.Background(), "cat", "p2", p2.ID))
	w.caughtUp()
	create(a, "f", 403)
	w.issue(a, map[string]any{"node": "matches.m", "want": toAny("move"), "to": toAny("p1")}, 403)
	create(c, "f", 403)
}

// TestFolderRolesByNameV073 (TC-49): no widening covers folders, and a
// folder's roles compare by name; includes apply only to an item's roles,
// read from its own content namespace (§B.11.4 No widening). The same
// test classifies release changes (DiffAccess, §F.9).
func TestFolderRolesByNameV073(t *testing.T) {
	t.Parallel()
	cfg := map[string]any{"catalog": map[string]any{"trust": toAny("matches")}}
	docs := func(subUnder string) map[string]any {
		return map[string]any{
			"root":      map[string]any{"parents": []any{}},
			"fa":        map[string]any{"parents": parents("root"), "$access": acc("group:g", "desk")},
			"fr":        map[string]any{"parents": parents("root"), "$access": acc("group:g", "reader")},
			"sub":       map[string]any{"parents": parents(subUnder)},
			"matches.i": map[string]any{"parents": parents("sub")},
		}
	}
	before := tree.BuildGraph("cat", cfg, docs("fa"))
	after := tree.BuildGraph("cat", cfg, docs("fr"))
	incs := map[string]catalog.Includes{"matches": {"desk": {"reader"}}}
	d := catalog.DiffAccess(before, after, incs)
	// sub gains reader by name; matches.i's reader is included by desk.
	if got := fmt.Sprint(d.Widens); got != "[{sub group:g reader}]" {
		t.Errorf("widens %s", got)
	}
	if got := fmt.Sprint(d.Narrows); got != "[{matches.i group:g desk} {sub group:g desk}]" {
		t.Errorf("narrows %s", got)
	}
	// An item moving from desk to reader alone narrows: includes apply.
	b2, a2 := tree.BuildGraph("cat", cfg, map[string]any{
		"root":      map[string]any{"parents": []any{}},
		"fa":        map[string]any{"parents": parents("root"), "$access": acc("group:g", "desk")},
		"fr":        map[string]any{"parents": parents("root"), "$access": acc("group:g", "reader")},
		"matches.i": map[string]any{"parents": parents("fa")},
	}), tree.BuildGraph("cat", cfg, map[string]any{
		"root":      map[string]any{"parents": []any{}},
		"fa":        map[string]any{"parents": parents("root"), "$access": acc("group:g", "desk")},
		"fr":        map[string]any{"parents": parents("root"), "$access": acc("group:g", "reader")},
		"matches.i": map[string]any{"parents": parents("fr")},
	})
	if d := catalog.DiffAccess(b2, a2, incs); d.Kind() != "narrows" {
		t.Errorf("an item's move from desk to reader: %s %v", d.Kind(), d)
	}
}

// TestDeletedPlacementRowsV073 (TC-27, scenario 11): a deleted
// placement's rows are kept, as they were when its catalog tombstone was
// seen, until it is placed again or purged, across restarts (Rebuild),
// and a non-admin's re-place (a restore-only grant) that would widen them
// is refused (§B.11.4 Place, No widening; §B.11.7).
func TestDeletedPlacementRowsV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	kept := func(name string) int {
		var n int
		must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective WHERE node = ? AND tombstoned = 2`, "/r/cat/"+name).Scan(&n))
		return n
	}
	must(w.ops.Delete(ctx, "cat", "matches.derby", must(w.ops.Head(ctx, "cat", "matches.derby")).ID))
	w.caughtUp()
	// season's four entries: match-desk, translators, fan-club and user:li.
	if n := kept("matches.derby"); n != 4 {
		t.Fatalf("kept rows of the deleted placement: %d", n)
	}

	// Scenario 11: an editor-in-chief who also is in match-desk sees TR
	// (rumours), has place there and is in the place list; re-placing
	// derby into TR would give group:editors-in-chief desk.
	eic := w.caller("user:eve", "editors-in-chief", "match-desk")
	toTR := map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("rumours")}
	r := w.issue(eic, toTR, 403)
	if msg, _ := r.body["message"].(string); !strings.Contains(msg, "group:editors-in-chief") || r.body["checkpoint"] == nil {
		t.Errorf("widening re-place: %v", r.body)
	}
	// Into season: a restore-only grant.
	toSeason := map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("season")}
	if b := w.issue(eic, toSeason, 200).body; fmt.Sprint(b["can"]) != "[restore]" {
		t.Errorf("re-place into season: %v", b)
	}
	// An admin may widen.
	w.issue(w.caller("user:ada", "catalog-admins", "editors-in-chief"), toTR, 200)

	// Rebuild keeps them.
	w.stop()
	w.start()
	w.caughtUp()
	if n := kept("matches.derby"); n != 4 {
		t.Errorf("kept rows after a restart: %d", n)
	}
	w.issue(eic, toTR, 403)

	// Placed again, they go and the rows are computed again.
	g := w.grantFor(eic, toSeason)
	tomb := must(w.ops.Head(ctx, "cat", "matches.derby"))
	must(w.core(g).Restore(ctx, "cat", "matches.derby", tomb.ID, []any{map[string]any{"op": "replace", "path": "",
		"value": map[string]any{"parents": parents("season")}}}))
	w.caughtUp()
	if n := kept("matches.derby"); n != 0 {
		t.Errorf("kept rows once placed again: %d", n)
	}
	w.issue(w.caller("user:fred", "fan-club"), map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)

	// Deleted again, then purged: the rows go (§8.3).
	must(w.ops.Delete(ctx, "cat", "matches.derby", must(w.ops.Head(ctx, "cat", "matches.derby")).ID))
	w.caughtUp()
	if n := kept("matches.derby"); n != 4 {
		t.Fatalf("kept rows of the deleted placement, again: %d", n)
	}
	purger := w.core(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"purge"}))
	must(purger.Purge(ctx, "cat", "matches.derby", must(w.ops.Head(ctx, "cat", "matches.derby")).ID, false))
	w.caughtUp()
	var n int
	must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective WHERE node = '/r/cat/matches.derby'`).Scan(&n))
	if n != 0 {
		t.Errorf("rows of a purged placement: %d", n)
	}
}
