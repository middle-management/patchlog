package catalog_test

import (
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
