package catalog_test

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// TestNoMergeKeyNotOfferedV074 (Open 106): a catalog service without a
// merge key issues no merge grants, 404 not_offered, as for an
// end-to-end catalog, to the merge service and to anyone else, before
// who asks is judged (§F.8, §12.1).
func TestNoMergeKeyNotOfferedV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.mergeKey.Priv = nil
	w.start()
	w.caughtUp()
	body := map[string]any{"batch": map[string]any{
		"items":  []any{map[string]any{"resource": "matches.derby", "ifMatch": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "steps": []any{"delete"}}},
		"source": map[string]any{"ns": "cat-r1", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	for _, tok := range []string{w.caller("svc:merge"), w.caller("user:bob", "match-desk")} {
		if r := w.do("POST", "/merge-grants", tok, body); r.status != 404 || r.body["code"] != "not_offered" {
			t.Errorf("merge grant without a merge key: %d %v", r.status, r.body)
		}
	}
}

// TestKeySubScopeUserOnlyV074 (Open 102): a key's sub scope matches the
// caller's sub only if it starts with user: (§B.11.4 Through the key). A
// svc: sub fails it, even under a pattern made for it, so a role
// collected through the caller's groups doesn't count either.
func TestKeySubScopeUserOnlyV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	bot := w.caller("svc:bot", "fan-club")
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}
	// Without a sub scope fan-club's reader at season counts for svc:bot.
	w.issue(bot, read, 200)
	// keys[2] is the catalog's key in matches.
	w.patchMatches(map[string]any{"op": "add", "path": "/keys/2/sub", "value": "(svc|user):.*"})
	w.issue(bot, read, 403)
	w.issue(w.caller("user:fred", "fan-club"), read, 200)
}

// TestParentsInEveryAnswerV074: POST /grants answers parents, the node's
// parents as decided, for every Move, an admin's included, and for every
// Unplace or delete of a folder, not only for a Move grant that pins them
// (§B.11.4 checkpoint).
func TestParentsInEveryAnswerV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "highlights", map[string]any{"title": "Highlights", "parents": parents("season")})
	w.start()
	w.caughtUp()
	desk := w.caller("user:anna", "match-desk")
	chief := w.caller("user:chief", "catalog-admins")
	for _, c := range []struct {
		what, token, node string
		req               map[string]any
		want              []any
	}{
		{"an admin's Move", chief, "matches.derby", map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}, parents("season")},
		{"a non-admin's Move", desk, "matches.derby", map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("season")}, parents("season")},
		{"an Unplace", desk, "matches.shared", map[string]any{"node": "matches.shared", "want": toAny("delete")}, parents("season", "derbies")},
		{"an admin's Unplace", chief, "matches.derby", map[string]any{"node": "matches.derby", "want": toAny("delete")}, parents("season")},
		{"a folder delete", desk, "highlights", map[string]any{"node": "highlights", "want": toAny("delete")}, parents("season")},
		{"an admin's folder delete", chief, "rumours", map[string]any{"node": "rumours", "want": toAny("delete")}, parents("season")},
	} {
		r := w.issue(c.token, c.req, 200)
		if !reflect.DeepEqual(r.body["parents"], c.want) {
			t.Errorf("%s: parents %v, want %v", c.what, r.body["parents"], c.want)
		}
		if r.body["head"] != w.catHead(c.node) {
			t.Errorf("%s: head %v, want %s", c.what, r.body["head"], w.catHead(c.node))
		}
	}
}

// TestUntrustedBeforePurgedV074: item requests other than Place answer
// 403 first for an item in a namespace the catalog doesn't trust, before
// the 410 of a purged namespace the service still holds as purged from
// when it trusted it: read, create and restore on POST /grants, and a
// /read-grants item (§B.11.4, §B.11.5).
func TestUntrustedBeforePurgedV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	w.purge("matches")
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{
		map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
	head := must(w.ops.NSHead(ctx, "cat")).ID
	waitFor(t, "the catalog to stop trusting matches", func() bool { return w.svc.Tree().Checkpoint("cat") == head })

	bob := w.caller("user:bob", "match-desk")
	for _, req := range []map[string]any{
		{"item": "/r/matches/derby", "want": toAny("read")},
		{"item": "/r/matches/fresh", "want": toAny("create")},
		{"item": "/r/matches/derby", "want": toAny("restore")},
	} {
		if r := w.do("POST", "/grants", bob, req); r.status != 403 || r.body["code"] != "forbidden" {
			t.Errorf("%v: %d %v (want 403)", req, r.status, r.body)
		}
	}
	rg := w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/matches/derby")})
	if e := entry(rg, 0); e["status"] != 403.0 || e["code"] != "forbidden" {
		t.Errorf("read-grants: %v (want status 403)", e)
	}
}

// TestItemVisibilityWithRulesV074 (Open 105): an item request judges
// "a role that makes it visible" as listings do (§B.11.5), the role's
// and the key's scope rules evaluated for a read of the item: a purged
// item is 403, not 410, to a caller whose role there has a rule that
// fails for its name, and so is a Restore of a deleted one, though the
// role counts for read and restore (§B.11.4).
func TestItemVisibilityWithRulesV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	for _, n := range []string{"doomed", "gone"} {
		w.doc("matches", n, map[string]any{"title": n})
		w.doc("cat", "matches."+n, map[string]any{"parents": parents("season")})
	}
	w.start()
	w.caughtUp()
	ctx := context.Background()
	must(w.ops.Delete(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID))
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "purge"})))
	must(purger.Purge(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID, false))
	must(w.ops.Delete(ctx, "matches", "gone", must(w.ops.Head(ctx, "matches", "gone")).ID))
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	purged := map[string]any{"item": "/r/matches/doomed", "want": toAny("read")}
	restore := map[string]any{"item": "/r/matches/gone", "want": toAny("restore")}
	// desk counts at season for match-desk: the purged item is 410, the
	// deleted one restorable.
	w.issue(bob, purged, 410)
	w.issue(bob, restore, 200)
	// desk's rule makes it visible only on "other".
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/desk/rules",
		"value": []any{map[string]any{"op": "test", "path": "/resource", "value": "other"}}})
	w.issue(bob, purged, 403)
	w.issue(bob, restore, 403)
	// A rule that reads /now never counts for visibility (§B.11.5).
	w.patchMatches(map[string]any{"op": "replace", "path": "/roles/desk/rules",
		"value": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	w.issue(bob, purged, 403)
	w.issue(bob, restore, 403)
}

// TestNoVisibleParentIsRootV074 (Open 101): in a subject set's listings a
// visible node with no visible parent is a root, none at all included:
// a placement whose own $access shares it, its only parent a folder
// since deleted, is listed in roots, and its one path ends at it, not
// counted incomplete (§B.11.5). Unfiltered listings keep §B.5's roots
// and orphans.
func TestNoVisibleParentIsRootV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	guest := w.caller("user:guest")
	rootsOf := func(token string) []string {
		t.Helper()
		r, _ := w.follow("/cat/roots", token)
		if r.status != 200 {
			t.Fatalf("roots: %d %v", r.status, r.body)
		}
		var out []string
		for _, x := range r.body["roots"].([]any) {
			out = append(out, x.(map[string]any)["name"].(string))
		}
		return out
	}
	check := func(when string) {
		t.Helper()
		if got := rootsOf(guest); !reflect.DeepEqual(got, []string{"matches.other"}) {
			t.Errorf("%s: guest's roots %v", when, got)
		}
		r, _ := w.follow("/cat/ancestors?of=matches.other", guest)
		if r.status != 200 || r.body["incomplete"] != nil || !reflect.DeepEqual(r.body["paths"], []any{[]any{}}) {
			t.Errorf("%s: guest's ancestors of matches.other: %d %v", when, r.status, r.body)
		}
	}
	// derbies is hidden from guest: matches.other is its root.
	check("under a hidden folder")
	must(w.ops.Delete(ctx, "cat", "derbies", w.catHead("derbies")))
	w.caughtUp()
	check("under a deleted folder")
	// Unfiltered, it is an orphan, not a root (§B.5).
	all := w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches"}, []string{"read"})
	if got := rootsOf(all); slices.Contains(got, "matches.other") {
		t.Errorf("unfiltered roots %v list the orphan", got)
	}
}

// TestRestoreFrozenUserRowV074: Restore's visibility check judges the
// item's frozen rows (§B.11.7) with the caller's own subjects (§B.11.2),
// user:{sub} among them, not with the subject set its listings are keyed
// by: zed's role in the frozen rows came through user:zed, a direct
// entry no node of the current graph names any more, and at the
// placement now zed holds the same role through a group (§B.11.4
// Restore).
func TestRestoreFrozenUserRowV074(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "zgone", map[string]any{"title": "zgone"})
	w.doc("cat", "matches.zgone", map[string]any{"parents": parents("rumours"), "$access": acc("user:zed", "desk")})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	must(w.ops.Delete(ctx, "matches", "zgone", must(w.ops.Head(ctx, "matches", "zgone")).ID))
	w.caughtUp()
	w.patch("cat", "matches.zgone", map[string]any{"op": "replace", "path": "/$access", "value": acc("group:zgroup", "desk")})
	w.caughtUp()
	zed := w.caller("user:zed", "zgroup", "catalog-admins")
	w.issue(zed, map[string]any{"item": "/r/matches/zgone", "want": toAny("restore")}, 200)
}
