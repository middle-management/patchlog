package catalog_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// nowRule refers to /now, and wholeRule to the whole envelope, which
// holds /now: neither passes for a read (§C.2 item 5).
var (
	nowRule   = map[string]any{"op": "test", "path": "/now", "exists": true}
	wholeRule = map[string]any{"op": "test", "path": "", "schema": map[string]any{"type": "object"}}
)

// refusedByNow fails unless r is the read check's refusal of a grant whose
// rules refer to /now: 403 forbidden, no-store, decided at no checkpoint
// and with nothing of the request's (§C.2 item 5; as the tree service
// answers it, internal/tree).
func refusedByNow(t *testing.T, what string, r resp) {
	t.Helper()
	if r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Cache-Control") != "no-store" ||
		r.body["checkpoint"] != nil || r.body["items"] != nil || r.body["grant"] != nil {
		t.Errorf("%s: %d %q %v", what, r.status, r.header.Get("Cache-Control"), r.body)
	}
}

// TestV081NowReadGrantsSealed (§C.2 item 5, §B.11.5, v0.78): a grant with a
// block rule on /now, or on the whole envelope, is refused every read, so
// POST /read-grants hands it no read grant and, in a sealed catalog, no
// keys, of items or catalog nodes alike: 403, as the tree service refuses
// its listings. The same grant without the rule gets both.
func TestV081NowReadGrantsSealed(t *testing.T) {
	t.Parallel()
	w := setupWith(t, true)
	w.seed()
	w.start()
	w.caughtUp()
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	items := map[string]any{"items": toAny("/r/matches/derby", "/r/cat/season")}
	fan := func(rules ...any) string {
		x := map[string]any{"groups": toAny("fan-club"), "enc": jwk}
		if rules != nil {
			x["rules"] = rules
		}
		return w.idp.Grant(t, w.s.Now(), "user:fred", []string{"cat"}, []string{}, x)
	}
	r := w.do("POST", "/read-grants", fan(), items)
	if r.status != 200 || entry(r, 0)["grant"] == nil || entry(r, 0)["keys"] == nil || entry(r, 1)["keys"] == nil {
		t.Fatalf("read-grants without a rule on /now: %d %v", r.status, r.body)
	}
	refusedByNow(t, "read-grants, a block rule on /now", w.do("POST", "/read-grants", fan(nowRule), items))
	refusedByNow(t, "read-grants, a block rule on the whole envelope", w.do("POST", "/read-grants", fan(wholeRule), items))
	// Beside other rules too.
	refusedByNow(t, "read-grants, a block rule on /now with others", w.do("POST", "/read-grants",
		fan(map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "fan-club"}}}, nowRule), items))
}

// TestV081NowGrants (§C.2 item 5, §B.11.4, v0.78): POST /grants hands out
// decisions that are reads (Resolve's roles at the item, a purged item's
// and a hidden node's visibility, §B.11.5) and read grants, so a grant
// with a block rule on /now is 403 there, for every request, before its
// body is read: as the tree service refuses it its listings, and as
// one whose rules refer to /now finds the core's reads refused.
func TestV081NowGrants(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	desk := w.caller("user:anna", "match-desk")
	clock := w.idp.Grant(t, w.s.Now(), "user:anna", []string{"cat"}, []string{},
		map[string]any{"groups": toAny("match-desk"), "rules": []any{nowRule}})
	reqs := []map[string]any{
		{"item": "/r/matches/derby", "want": toAny("read")},
		{"item": "/r/matches/derby", "want": toAny("append")},
		{"node": "matches.derby", "want": toAny("delete")},
	}
	for _, req := range reqs {
		w.issue(desk, req, 200)
		refusedByNow(t, "POST /grants with a block rule on /now", w.do("POST", "/grants", clock, req))
	}
	refusedByNow(t, "POST /grants with a block rule on /now, a malformed body", w.do("POST", "/grants", clock, []any{}))
}

// TestV081NowReadRoles (§C.2 item 5: "a role with such a rule doesn't
// count for read", v0.78): a caller's grant whose only role that lists
// read has a rule on /now reads nothing, and is 403 at POST /read-grants
// and POST /grants, as the tree service answers it; one with another read
// role besides gets what that role alone gets, nothing more.
func TestV081NowReadRoles(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "cat")).Config
	must(opc.PatchConfig(ctx, "cat", cfg, []any{
		map[string]any{"op": "add", "path": "/roles/clocked", "value": map[string]any{"can": toAny("read"), "rules": []any{nowRule}}},
		map[string]any{"op": "add", "path": "/roles/viewer", "value": map[string]any{"can": toAny("read")}},
	}))
	w.caughtUp()
	with := func(roles ...string) string {
		return w.opsKey.Grant(t, w.s.Now(), "user:fred", []string{"cat"}, []string{"read"},
			map[string]any{"groups": toAny("fan-club"), "roles": toAny(roles...)})
	}
	items := map[string]any{"items": toAny("/r/matches/derby", "/r/matches/rumour1", "/r/matches/other")}
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}

	refusedByNow(t, "read-grants, the only read role on /now", w.do("POST", "/read-grants", with("clocked"), items))
	refusedByNow(t, "POST /grants, the only read role on /now", w.do("POST", "/grants", with("clocked"), read))

	alone, both := w.do("POST", "/read-grants", with("viewer"), items), w.do("POST", "/read-grants", with("clocked", "viewer"), items)
	if alone.status != 200 || both.status != 200 {
		t.Fatalf("read-grants: viewer %d %v, clocked and viewer %d %v", alone.status, alone.body, both.status, both.body)
	}
	for i := range 3 {
		a, b := entry(alone, i), entry(both, i)
		if a["status"] != b["status"] || (a["grant"] == nil) != (b["grant"] == nil) {
			t.Errorf("item %d: viewer %v, clocked and viewer %v", i, a, b)
		}
	}
	if entry(alone, 0)["grant"] == nil || entry(alone, 1)["status"] != 403.0 {
		t.Errorf("viewer: %v", alone.body)
	}
	if a, b := w.do("POST", "/grants", with("viewer"), read), w.do("POST", "/grants", with("clocked", "viewer"), read); a.status != 200 || b.status != 200 {
		t.Errorf("POST /grants: viewer %d %v, clocked and viewer %d %v", a.status, a.body, b.status, b.body)
	}
}

// TestV081NowMergeGrantsWrite (§F.8, §C.2 item 5): POST /merge-grants
// issues a write grant only, under the merge key, for the merge service to
// submit a batch to the catalog, and rules on /now for writes are
// unchanged (v0.78), so an approver whose grant has a block rule on /now
// is checked as before.
func TestV081NowMergeGrantsWrite(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	clock := w.idp.Grant(t, w.s.Now(), "user:anna", []string{"cat"}, []string{},
		map[string]any{"groups": toAny("match-desk"), "rules": []any{nowRule}})
	del := map[string]any{"resource": "matches.derby", "ifMatch": w.catHead("matches.derby"), "steps": []any{"delete"}}
	if r := w.mergeAsk(clock, "", del); r.status != 200 || r.body["grant"] == nil {
		t.Fatalf("merge grant approved under a block rule on /now: %d %v", r.status, r.body)
	}
}
