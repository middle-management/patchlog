package catalog_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// follow requests path with token, following the pointer into the
// reader's URL space, and returns the final response and its URL.
func (w *world) follow(path, token string) (resp, string) {
	w.t.Helper()
	r := w.do("GET", path, token, nil)
	if r.status != 302 {
		w.t.Fatalf("GET %s: %d %v", path, r.status, r.body)
	}
	loc := r.header.Get("Location")
	return w.do("GET", loc, token, nil), loc
}

func childNames(b map[string]any) string {
	var out []string
	for _, x := range b["children"].([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return strings.Join(out, ",")
}

// TestListingVisibility: listings are filtered by the subject set, a node
// being visible when the walk up collects a role granting read without
// conditions (§B.11.5).
func TestListingVisibility(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	// Roles of matches for the test: scoped reads only derby3 (a rule on
	// /resource), member reads with a rule on /principal/groups, timed
	// reads with a rule on /now, and hidden reads but is outside the
	// catalog key's roles scope.
	opm := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{
		map[string]any{"op": "add", "path": "/roles/scoped", "value": map[string]any{"can": toAny("read"),
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": toAny("derby3")}}}}},
		map[string]any{"op": "add", "path": "/roles/member", "value": map[string]any{"can": toAny("read"),
			"rules": []any{map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "members"}}}}}},
		map[string]any{"op": "add", "path": "/roles/timed", "value": map[string]any{"can": toAny("read"),
			"rules": []any{map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": "2999-01-01T00:00:00Z"}}}}},
		map[string]any{"op": "add", "path": "/roles/hidden", "value": map[string]any{"can": toAny("read")}},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "scoped"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "member"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "timed"},
	}))
	w.doc("cat", "extra", map[string]any{"title": "Extra", "parents": parents("root"), "$access": acc(
		"group:scopers", "scoped", "group:members", "member", "group:others", "member", "group:timers", "timed", "group:hiders", "hidden")})
	w.doc("matches", "x1", map[string]any{"title": "x1"})
	w.doc("cat", "matches.x1", map[string]any{"parents": parents("extra")})
	w.doc("cat", "matches.derby2", map[string]any{"parents": parents("extra")}) // dangling
	w.start()
	w.caughtUp()

	where := func(token, item string) map[string]any {
		t.Helper()
		r, _ := w.follow("/cat/where?item="+item, token)
		if r.status != 200 {
			t.Fatalf("where %s: %d %v", item, r.status, r.body)
		}
		return r.body
	}
	placed := func(token, item string) bool { return where(token, item)["placement"] != nil }

	// fan-club reads plainly: season and its items, not the embargoed folder.
	fan := w.caller("user:fred", "fan-club")
	r, _ := w.follow("/cat/children?of=season", fan)
	if childNames(r.body) != "matches.derby,matches.shared" {
		t.Errorf("fan on season: %v", r.body)
	}
	// Pagination counts visible nodes only: two fit in limit=2, and no next
	// page hints at the hidden folder after them.
	r, _ = w.follow("/cat/children?of=season&limit=2", fan)
	if childNames(r.body) != "matches.derby,matches.shared" || r.body["next"] != nil {
		t.Errorf("fan on season, limit 2: %v", r.body)
	}
	r, _ = w.follow("/cat/children?of=season&limit=1", fan)
	if childNames(r.body) != "matches.derby" || r.body["next"] == nil {
		t.Errorf("fan on season, limit 1: %v", r.body)
	}
	// Translators' role reads with rules on /writes, which pass as a read
	// evaluates them (no writes: within is true, §B.11.5 v0.38): its items
	// are visible, but not the folder (for a folder only a role without
	// rules counts).
	anna := w.caller("user:anna", "translators")
	if r, _ := w.follow("/cat/children?of=season", anna); r.status != 404 {
		t.Errorf("translator on season: %d %v", r.status, r.body)
	}
	if !placed(anna, "/r/matches/derby") {
		t.Error("translator doesn't see derby's placement")
	}
	// Grants still go by role names (§B.11.4): the translator may read.
	w.issue(anna, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)

	// A role with rules on /resource only: an item where they pass is
	// visible, the folder isn't (it has rules).
	sc := w.caller("user:sam", "scopers")
	w.doc("cat", "matches.derby3", map[string]any{"parents": parents("extra")})
	w.doc("matches", "derby3", map[string]any{"title": "d3"})
	w.caughtUp()
	if r, _ := w.follow("/cat/children?of=extra", sc); r.status != 404 {
		t.Errorf("scoped reader on a folder: %d", r.status)
	}
	if !placed(sc, "/r/matches/derby3") {
		t.Error("scoped reader doesn't see derby3, which its rule allows")
	}
	if placed(sc, "/r/matches/x1") {
		t.Error("scoped reader sees x1, which its rule refuses")
	}
	// Rules on /principal/groups: evaluated with the subject set's groups.
	if !placed(w.caller("user:m", "members"), "/r/matches/x1") {
		t.Error("member doesn't see x1")
	}
	if placed(w.caller("user:o", "others"), "/r/matches/x1") {
		t.Error("a member-role holder outside the group sees x1")
	}
	// Rules on /now never count; nor a role outside the key's roles scope.
	if placed(w.caller("user:ti", "timers"), "/r/matches/x1") {
		t.Error("a /now rule makes x1 visible")
	}
	if placed(w.caller("user:hi", "hiders"), "/r/matches/x1") {
		t.Error("a role the catalog key can't grant makes x1 visible")
	}
	// A dangling placement is visible to no one through roles.
	if placed(w.caller("user:m", "members"), "/r/matches/derby2") {
		t.Error("a dangling placement is visible")
	}

	// §B.11.7: a change to /roles recomputes visibility. Without its rule,
	// timed reads plainly, and the folder and its items show.
	ti := w.caller("user:ti", "timers")
	cfg = must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "remove", "path": "/roles/timed/rules"}}))
	w.caughtUp()
	r, _ = w.follow("/cat/children?of=extra", ti)
	if r.status != 200 || childNames(r.body) != "matches.derby3,matches.x1" {
		t.Errorf("timed after its rule went: %d %v", r.status, r.body)
	}
	// /read-grants uses the same test for catalog nodes.
	rg := w.do("POST", "/read-grants", ti, map[string]any{"items": toAny("/r/cat/extra", "/r/cat/season")})
	gs := rg.body["grants"].([]any)
	if gs[0].(map[string]any)["error"] != nil || gs[1].(map[string]any)["error"] == nil {
		t.Errorf("read-grants for catalog nodes: %v", gs)
	}
	rg = w.do("POST", "/read-grants", anna, map[string]any{"items": toAny("/r/cat/season")})
	if rg.body["grants"].([]any)[0].(map[string]any)["error"] == nil {
		t.Errorf("read-grants: the translator gets a folder it can't list: %v", rg.body)
	}
}

// TestUnfilteredListings: problems, orphans and manifests need
// namespace-wide read on the catalog and the content namespaces they
// cover; readers with it on the catalog and every trusted namespace get
// unfiltered listings under g/all, kept no longer than their grants
// (§B.11.5).
func TestUnfilteredListings(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	fan := w.caller("user:fred", "fan-club")
	for _, op := range []string{"problems", "orphans", "manifest?of=season"} {
		if r, _ := w.follow("/cat/"+op, fan); r.status != 403 {
			t.Errorf("%s for a role reader: %d %v", op, r.status, r.body)
		}
	}
	// Namespace-wide read on the catalog only: the subject set's listing.
	catWide := w.opsKey.Grant(t, w.s.Now(), "user:cw", []string{"cat"}, []string{"read"}, map[string]any{"groups": toAny("fan-club")})
	_, locFan := w.follow("/cat/children?of=season", fan)
	r, loc := w.follow("/cat/children?of=season", catWide)
	if loc != locFan || childNames(r.body) != "matches.derby,matches.shared" {
		t.Errorf("catalog-wide reader: %s (fan %s) %v", loc, locFan, r.body)
	}
	if r, _ := w.follow("/cat/problems", catWide); r.status != 403 {
		t.Errorf("problems for a catalog-only reader: %d", r.status)
	}
	// On both: g/all, unfiltered, expiring with the grant.
	exp := w.s.Now().Add(90 * time.Second)
	wide := w.opsKey.Grant(t, w.s.Now(), "user:nw", []string{"cat", "matches"}, []string{"read"}, map[string]any{"exp": exp.Format(time.RFC3339)})
	r, loc = w.follow("/cat/children?of=season", wide)
	if !strings.Contains(loc, "/g/all/children") || childNames(r.body) != "matches.derby,matches.shared,rumours" {
		t.Errorf("namespace-wide reader: %s %v", loc, r.body)
	}
	cc := r.header.Get("Cache-Control")
	age, err := strconv.Atoi(strings.TrimPrefix(cc, "private, max-age="))
	if err != nil || age > 90 || age < 80 {
		t.Errorf("g/all Cache-Control %q", cc)
	}
	other := w.opsKey.Grant(t, w.s.Now(), "user:nw2", []string{"cat", "matches"}, []string{"read"}, map[string]any{"groups": toAny("x")})
	if _, loc2 := w.follow("/cat/children?of=season", other); loc2 != loc {
		t.Errorf("namespace-wide readers don't share g/all: %s vs %s", loc2, loc)
	}
	for _, op := range []string{"problems", "orphans", "manifest?of=season"} {
		if r, _ := w.follow("/cat/"+op, wide); r.status != 200 {
			t.Errorf("%s for a namespace-wide reader: %d %v", op, r.status, r.body)
		}
	}
	// Presenting g/all without the grants for it redirects to one's own.
	if r := w.do("GET", loc, fan, nil); r.status != 302 || r.header.Get("Location") != locFan {
		t.Errorf("g/all for a role reader: %d %s", r.status, r.header.Get("Location"))
	}
}

// TestRestoreThroughCatalog: a deleted item is restored by the roles its
// placement had when the tombstone was seen, frozen then (§B.11.4,
// §B.11.7).
func TestRestoreThroughCatalog(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	fan := w.caller("user:fred", "fan-club")
	admin := w.caller("user:ada", "catalog-admins", "match-desk")
	restore := func(token, item string, status int) resp {
		t.Helper()
		return w.issue(token, map[string]any{"item": item, "want": toAny("restore")}, status)
	}

	// Live, or never existed: nothing to restore.
	restore(bob, "/r/matches/derby", 409)
	w.doc("cat", "matches.final", map[string]any{"parents": parents("season")})
	w.caughtUp()
	restore(bob, "/r/matches/final", 404)
	w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("restore", "read")}, 400)

	// Delete derby: its rows freeze (season: match-desk desk, fan-club reader, …).
	hd := must(w.ops.Head(ctx, "matches", "derby"))
	must(w.ops.Delete(ctx, "matches", "derby", hd.ID))
	w.caughtUp()
	var frozen int
	must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective WHERE node = '/r/cat/matches.derby' AND tombstoned = 1`).Scan(&frozen))
	if frozen == 0 {
		t.Fatal("no frozen rows for the deleted item")
	}
	// The dangling placement grants nothing else.
	w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 403)
	// Moving the deleted item's placement where fan-club has desk is
	// checked like any other move, against the roles the item would have
	// now (§B.11.7 v0.38): it widens, so only an admin may.
	w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}, 403)
	move := func(token string, to ...string) {
		t.Helper()
		g := w.grantFor(token, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny(to...)})
		h := must(w.ops.Head(ctx, "cat", "matches.derby"))
		must(w.core(g).Append(ctx, "cat", "matches.derby", h.ID, []any{map[string]any{"op": "replace", "path": "/parents", "value": parents(to...)}}))
		w.caughtUp()
	}
	move(admin, "derbies")
	restore(fan, "/r/matches/derby", 403) // reader had no restore, and desk under derbies came after
	// From derbies, a restore would give fan-club desk, which its frozen
	// rows don't have: refused, so a move can't widen what a restore
	// publishes (§B.11.7).
	if r := restore(bob, "/r/matches/derby", 403); !strings.Contains(r.body["message"].(string), "would give group:fan-club the role desk") {
		t.Errorf("widening restore: %v", r.body)
	}
	// Back under season (only an admin may: translators would gain
	// translator), the restore no longer widens.
	move(admin, "season")
	// Frozen rows survive a restart.
	w.stop()
	w.start()
	w.caughtUp()
	b := restore(bob, "/r/matches/derby", 200).body
	if fmt.Sprint(b["can"]) != "[restore]" || fmt.Sprint(b["roles"]) != "[desk]" || b["resource"] != "derby" || b["ns"] != "matches" {
		t.Fatalf("restore grant %v", b)
	}
	rc := w.core(b["grant"].(string))
	tomb := must(w.ops.Head(ctx, "matches", "derby"))
	if tomb.State != client.Tombstoned {
		t.Fatalf("derby %v", tomb.State)
	}
	if _, err := rc.Restore(ctx, "matches", "shared", must(w.ops.Head(ctx, "matches", "shared")).ID, []any{}); !isStatus(err, 403) {
		t.Errorf("restore grant on another item: %v", err)
	}
	res, err := rc.Restore(ctx, "matches", "derby", tomb.ID, []any{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// Once live, the grant can't write: the write is an append (§6.2 step 2).
	if _, err := rc.Append(ctx, "matches", "derby", res.ID, []any{map[string]any{"op": "add", "path": "/x", "value": 1}}); !isStatus(err, 403) {
		t.Errorf("restore grant appending to the live item: %v", err)
	}
	// (Another restore than the one made, which a retry would return.)
	if _, err := rc.Restore(ctx, "matches", "derby", tomb.ID, []any{map[string]any{"op": "add", "path": "/y", "value": 1}}); !isStatus(err, 403) {
		t.Errorf("restore grant on the live item: %v", err)
	}
	w.caughtUp()
	must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective WHERE node = '/r/cat/matches.derby' AND tombstoned = 1`).Scan(&frozen))
	if frozen != 0 {
		t.Errorf("frozen rows after the restore: %d", frozen)
	}
	// Restored, its rows are computed from where it is now: under derbies
	// fan-club has desk.
	w.issue(fan, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}, 403)
	move(admin, "season", "derbies")
	w.issue(fan, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}, 200)

	// An item deleted while unplaced gets nothing from a placement made
	// afterwards: placing a deleted item can't undelete it.
	w.doc("matches", "lone", map[string]any{"title": "lone"})
	must(w.ops.Delete(ctx, "matches", "lone", must(w.ops.Head(ctx, "matches", "lone")).ID))
	w.caughtUp()
	w.doc("cat", "matches.lone", map[string]any{"parents": parents("season")})
	w.caughtUp()
	restore(bob, "/r/matches/lone", 403)
	restore(admin, "/r/matches/lone", 403)

	// Purged: 410.
	w.doc("matches", "doomed", map[string]any{"title": "doomed"})
	w.doc("cat", "matches.doomed", map[string]any{"parents": parents("season")})
	w.caughtUp()
	must(w.ops.Delete(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID))
	w.caughtUp()
	restore(bob, "/r/matches/doomed", 200)
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "purge"})))
	must(purger.Purge(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID, false))
	w.caughtUp()
	restore(bob, "/r/matches/doomed", 410)
}
