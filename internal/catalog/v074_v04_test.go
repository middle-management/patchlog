package catalog_test

import (
	"reflect"
	"testing"
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
