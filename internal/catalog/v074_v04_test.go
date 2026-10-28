package catalog_test

import (
	"context"
	"reflect"
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
