package catalog_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grantcheck"
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
