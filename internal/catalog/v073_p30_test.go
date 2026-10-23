package catalog_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/seal"
)

// p30Same reports whether two refusals are alike but for the item they
// name: the same status, code and message, item for item.
func p30Same(a, b map[string]any, itemA, itemB string) bool {
	am, _ := a["message"].(string)
	return a["status"] == b["status"] && a["code"] == b["code"] && am != "" && strings.ReplaceAll(am, itemA, itemB) == b["message"]
}

// TestCreateFolderTakenNamesV073 (TC-34, scenarios 23 and 41): Create a
// folder is 409 for a name a node has or had, or that a parents entry
// names, hidden ones included (names are not secrets), decided at the
// checkpoint, which the refusal carries; a name a node had is the core's
// head's, which carries none. Otherwise a dangling edge to the name would
// re-attach, and its node gain the new folder's roles. The 409 comes after
// the 403s (§B.11.4 Create a folder).
func TestCreateFolderTakenNamesV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	// Scenario 41: an admin's placement whose parent ghost never existed:
	// it dangles, and lone has no roles.
	w.doc("matches", "lone", map[string]any{"title": "lone"})
	w.doc("cat", "matches.lone", map[string]any{"parents": parents("ghost")})
	w.doc("cat", "old", map[string]any{"title": "Old", "parents": parents("season")})
	ctx := context.Background()
	must(w.ops.Delete(ctx, "cat", "old", must(w.ops.Head(ctx, "cat", "old")).ID))
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	fan := w.caller("user:fred", "fan-club")
	create := func(name string) map[string]any {
		return map[string]any{"node": name, "want": toAny("create"), "to": toAny("season")}
	}
	cp := w.checkpointOf("matches")

	// Named by a dangling parents entry: taken, at the checkpoint.
	if r := w.issue(bob, create("ghost"), 409); !reflect.DeepEqual(r.body["checkpoint"], cp) {
		t.Errorf("ghost: %v (checkpoint want %v)", r.body, cp)
	}
	// A hidden folder's name (scenario 23), decided at the checkpoint too.
	if r := w.issue(bob, create("rumours"), 409); !reflect.DeepEqual(r.body["checkpoint"], cp) {
		t.Errorf("rumours: %v (checkpoint want %v)", r.body, cp)
	}
	// A name a node had: the core's head says so, with no checkpoint.
	if r := w.issue(bob, create("old"), 409); r.body["checkpoint"] != nil {
		t.Errorf("old: %v", r.body)
	}
	// After the 403s: fred has no move at season.
	w.issue(fan, create("ghost"), 403)
	// A fresh name is granted, and a placement naming it once it exists
	// is a dangling edge no more.
	w.issue(bob, create("fresh"), 200)
	// The dangling placement kept lone without roles.
	w.issue(w.caller("user:li"), map[string]any{"item": "/r/matches/lone", "want": toAny("read")}, 403)
}

// TestCreateAnswerOrderV073 (TC-35): Create answers 410 in a purged
// namespace (TestPurgedNamespaceItemsV073), then 409 for a name that
// exists or existed, placed or not and whoever asks, since names are not
// secrets, then 403 for an item without a placement or a caller without a
// role kept (§B.11.4 Create).
func TestCreateAnswerOrderV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "loose", map[string]any{"title": "loose"})
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	nobody := w.caller("user:nobody")
	create := func(item string) map[string]any { return map[string]any{"item": item, "want": toAny("create")} }

	cp := w.checkpointOf("matches")
	for _, tok := range []string{bob, nobody} {
		// An existing item without a placement: 409, not 403.
		if r := w.issue(tok, create("/r/matches/loose"), 409); !reflect.DeepEqual(r.body["checkpoint"], cp) {
			t.Errorf("loose: %v", r.body)
		}
		w.issue(tok, create("/r/matches/derby"), 409)
	}
	// A new name without a placement, and one placed for a caller without
	// a role kept: 403, with one message.
	unplaced := w.issue(bob, create("/r/matches/newname"), 403).body
	w.doc("cat", "matches.newer", map[string]any{"parents": parents("season")})
	w.caughtUp()
	noRole := w.issue(nobody, create("/r/matches/newer"), 403).body
	unplaced["status"], noRole["status"] = 403.0, 403.0
	if !p30Same(unplaced, noRole, "/r/matches/newname", "/r/matches/newer") {
		t.Errorf("unplaced %v, no role %v", unplaced, noRole)
	}
	w.issue(bob, create("/r/matches/newer"), 200)
}

// TestItemAnswerOrderV073 (TC-36, scenario 42's append): item requests
// other than Place and Create answer 410 in a purged namespace
// (TestPurgedNamespaceItemsV073); 404 for a name that never existed,
// placed or not; for a purged item, 403 without a role that counts for
// read at its placement, computed as for a live item, and 410 gone
// otherwise; then 403 when no role is kept, with one message whether the
// item is unplaced, its placement dangles, or no role counts (§B.11.4).
func TestItemAnswerOrderV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "loose", map[string]any{"title": "loose"})
	w.doc("matches", "doomed", map[string]any{"title": "doomed"})
	w.doc("cat", "matches.doomed", map[string]any{"parents": parents("season")})
	w.doc("cat", "matches.unborn", map[string]any{"parents": parents("season")})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	fan := w.caller("user:fred", "fan-club")
	nobody := w.caller("user:nobody")
	req := func(item, verb string) map[string]any { return map[string]any{"item": item, "want": toAny(verb)} }

	// Never existed: 404 for anyone, placed or not.
	for _, tok := range []string{fan, nobody} {
		w.issue(tok, req("/r/matches/ghost", "read"), 404)
		w.issue(tok, req("/r/matches/unborn", "append"), 404)
	}
	// Purged: 403 without read at its placement, 410 gone with it.
	must(w.ops.Delete(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID))
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "purge"})))
	must(purger.Purge(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID, false))
	w.caughtUp()
	w.issue(nobody, req("/r/matches/doomed", "append"), 403)
	if r := w.issue(fan, req("/r/matches/doomed", "append"), 410); r.body["code"] != "gone" || r.body["checkpoint"] == nil {
		t.Errorf("purged item: %v", r.body)
	}
	// No role kept: unplaced, a dangling placement (a deleted item) and a
	// placement without a role are alike.
	must(w.ops.Delete(ctx, "matches", "other", must(w.ops.Head(ctx, "matches", "other")).ID))
	w.caughtUp()
	loose := w.issue(fan, req("/r/matches/loose", "read"), 403).body
	for _, item := range []string{"/r/matches/rumour1", "/r/matches/other", "/r/matches/doomed"} {
		tok := fan
		if item == "/r/matches/doomed" {
			tok = nobody
		}
		b := w.issue(tok, req(item, "read"), 403).body
		loose["status"], b["status"] = 403.0, 403.0
		if !p30Same(loose, b, "/r/matches/loose", item) {
			t.Errorf("unplaced %v, %s %v", loose, item, b)
		}
	}
}

// TestRestoreAnswerOrderV073 (TC-37, scenarios 12, 25 and 42): Restore
// answers 410 in a purged namespace (TestPurgedNamespaceItemsV073); 404
// for a name that never existed; 403 without a role that counts for read
// both at the placement now, computed as for a live item, and, if
// deleted, in the frozen rows; then 410 for a purged item and 409 for a
// live one; then 403 when restore isn't kept in both, there is no
// placement, or it would widen (§B.11.4 Restore).
func TestRestoreAnswerOrderV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	anna := w.caller("user:anna", "translators")
	fan := w.caller("user:fred", "fan-club")
	nobody := w.caller("user:nobody")
	restore := func(tok, item string, status int) map[string]any {
		t.Helper()
		return w.issue(tok, map[string]any{"item": item, "want": toAny("restore")}, status).body
	}

	// Scenario 12: live, anna (translator: read, no restore) passes the
	// read check: 409.
	restore(anna, "/r/matches/derby", 409)
	restore(fan, "/r/matches/derby", 409)
	restore(nobody, "/r/matches/derby", 403)
	must(w.ops.Delete(ctx, "matches", "derby", must(w.ops.Head(ctx, "matches", "derby")).ID))
	w.caughtUp()
	restore(anna, "/r/matches/derby", 403)
	restore(bob, "/r/matches/derby", 200)

	// Scenario 25: match-desk leaves season after derby's deletion: desk
	// is in derby's frozen rows but no longer at its placement, so it
	// counts in neither for read: 403, as for a caller without a role.
	w.patch("cat", "season", map[string]any{"op": "remove", "path": "/$access/group:match-desk"})
	w.caughtUp()
	if b := restore(bob, "/r/matches/derby", 403); b["message"] != "no role of yours allows restore on /r/matches/derby" {
		t.Errorf("scenario 25: %v", b)
	}
	// Moving the deleted placement into rumours, where bob has no role
	// either, is the same.
	w.patch("cat", "season", map[string]any{"op": "add", "path": "/$access/group:match-desk", "value": toAny("desk")})
	w.caughtUp()
	restore(bob, "/r/matches/derby", 200)
	w.patch("cat", "matches.derby", map[string]any{"op": "replace", "path": "/parents", "value": parents("rumours")})
	w.caughtUp()
	restore(bob, "/r/matches/derby", 403)

	// Scenario 42: purged, its placement in season: 403 without a role
	// that counts for read there, 410 with one.
	must(w.ops.Delete(ctx, "matches", "shared", must(w.ops.Head(ctx, "matches", "shared")).ID))
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "purge"})))
	must(purger.Purge(ctx, "matches", "shared", must(w.ops.Head(ctx, "matches", "shared")).ID, false))
	w.caughtUp()
	restore(nobody, "/r/matches/shared", 403)
	restore(anna, "/r/matches/shared", 410)
	restore(w.caller("user:ops2", "ops"), "/r/matches/shared", 403) // a group the key may not assert

	// Never existed: 404, whoever asks.
	restore(nobody, "/r/matches/ghost", 404)
}

// TestPurgedNamespaceItemsV073 (TC-38, §8.5): every name of a purged
// content namespace answers 410 purged with head, its purge-ns entry,
// first among item answers: for creates, restores, other verbs and
// /read-grants items alike, names the service never saw included; a
// decision at the checkpoint carries it. A purged item of a namespace
// that isn't purged stays 410 gone. Where the service hasn't applied the
// purge of a sealed namespace yet, the core's 410 purged on its document
// stands in, with the core's head and no checkpoint.
func TestPurgedNamespaceItemsV073(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.seed()
			w.doc("cat", "matches.unborn", map[string]any{"parents": parents("season")})
			w.start()
			w.caughtUp()
			bob, admin := w.caller("user:bob", "match-desk"), w.caller("user:ada", "catalog-admins", "match-desk")
			head := w.purge("matches")
			cp := map[string]any{"cat": w.svc.Tree().Checkpoint("cat"), "matches": head}
			for _, c := range []struct {
				tok string
				req map[string]any
			}{
				{bob, map[string]any{"item": "/r/matches/derby", "want": toAny("restore")}},
				{bob, map[string]any{"item": "/r/matches/ghost", "want": toAny("restore")}},
				{bob, map[string]any{"item": "/r/matches/unborn", "want": toAny("create")}},
				{admin, map[string]any{"item": "/r/matches/fresh", "want": toAny("create")}},
				{bob, map[string]any{"item": "/r/matches/shared", "want": toAny("read", "append")}},
				{w.caller("user:nobody"), map[string]any{"item": "/r/matches/rumour1", "want": toAny("read")}},
			} {
				r := w.issue(c.tok, c.req, 410)
				if r.body["code"] != "purged" || r.body["head"] != head || !reflect.DeepEqual(r.body["checkpoint"], cp) {
					t.Errorf("%v: %v (head %s, checkpoint %v)", c.req, r.body, head, cp)
				}
			}
			rg := w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/matches/derby", "/r/matches/ghost")})
			for i := range 2 {
				if e := entry(rg, i); e == nil || e["status"] != 410.0 || e["code"] != "purged" || e["head"] != head {
					t.Errorf("read-grants entry %d: %v", i, e)
				}
			}
			if !reflect.DeepEqual(rg.body["checkpoint"], cp) {
				t.Errorf("read-grants checkpoint %v, want %v", rg.body["checkpoint"], cp)
			}
		})
	}

	// The core's 410 purged, before the service applies the purge.
	t.Run("core", func(t *testing.T) {
		t.Parallel()
		w := setupWith(t, true)
		w.seed()
		rt := &holdRT{ns: "matches", base: transport}
		w.svcClient = w.s.Client(t, client.WithHTTPClient(&http.Client{Transport: rt}), client.WithKeys(client.NewKeys(nil)),
			client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
				map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
		w.start()
		w.caughtUp()
		bob := w.caller("user:bob", "match-desk")
		rt.hold.Store(true)
		ctx := context.Background()
		pc := w.s.Client(t, client.WithKeys(client.NewKeys(nil)), client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "config", "purge-ns"})))
		must(pc.PatchConfig(ctx, "matches", must(pc.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		head := must(pc.PurgeNamespace(ctx, "matches", must(pc.NSHead(ctx, "matches")).ID))
		r := w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("restore")}, 410)
		if r.body["code"] != "purged" || r.body["head"] != head || r.body["checkpoint"] != nil {
			t.Errorf("before the service applies the purge: %v (head %s)", r.body, head)
		}
		rt.hold.Store(false)
	})
}

// TestReadGrantsAnswerShapeV073 (TC-41): POST /read-grants answers 200
// { items: [{ item, grant?, public?, keys?, keysWithheld?, status?,
// code? }], checkpoint }: one entry per item in request order, status and
// code for an item refused, and one checkpoint over every namespace any
// decision read, so a teams item adds teams; no entry carries a
// checkpoint or an error object, and exp stays beside a grant (§B.11.4).
func TestReadGrantsAnswerShapeV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.trustTeams()
	w.start()
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	fan := w.caller("user:fred", "fan-club")
	items := toAny("/r/matches/derby", "/r/matches/rumour1", "/r/matches/ghost", "/r/teams/t1", "nonsense")
	rg := w.do("POST", "/read-grants", fan, map[string]any{"items": items})
	var keys []string
	for k := range rg.body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if rg.status != 200 || fmt.Sprint(keys) != "[checkpoint items]" || !reflect.DeepEqual(rg.body["checkpoint"], w.checkpointOf("matches", "teams")) {
		t.Fatalf("read-grants: %d %v", rg.status, rg.body)
	}
	for i, want := range []struct {
		status float64
		code   string
	}{{0, ""}, {403, "forbidden"}, {404, "not_found"}, {403, "forbidden"}, {400, "bad_input"}} {
		e := entry(rg, i)
		status, _ := e["status"].(float64)
		code, _ := e["code"].(string)
		if e["item"] != items[i] || status != want.status || code != want.code || e["error"] != nil || e["checkpoint"] != nil ||
			(want.status == 0) != (e["grant"] != nil && e["exp"] != nil) {
			t.Errorf("entry %d: %v", i, e)
		}
	}
	// Items of matches only: the checkpoint names the catalog and matches.
	rg = w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby", "/r/matches/ghost")})
	if !reflect.DeepEqual(rg.body["checkpoint"], w.checkpointOf("matches")) {
		t.Errorf("read-grants of matches items: %v", rg.body)
	}
}

// TestReadGrantsCatalogNodesV073 (TC-42, scenario 21): a catalog node in
// POST /read-grants is 400 in a catalog that is neither sealed nor
// end-to-end, visible or not; in a sealed one a visible node gets its
// keys and no grant, and a hidden one is 404, answered as a node not in
// the catalog (§B.11.5).
func TestReadGrantsCatalogNodesV073(t *testing.T) {
	t.Parallel()
	t.Run("unsealed", func(t *testing.T) {
		t.Parallel()
		w := setup(t)
		w.seed()
		w.start()
		w.caughtUp()
		rg := w.do("POST", "/read-grants", w.caller("user:fred", "fan-club"), map[string]any{"items": toAny("/r/cat/season", "/r/cat/rumours", "/r/cat/matches.derby")})
		for i := range 3 {
			if e := entry(rg, i); e["status"] != 400.0 || e["code"] != "bad_input" {
				t.Errorf("entry %d: %v", i, e)
			}
		}
	})
	t.Run("sealed", func(t *testing.T) {
		t.Parallel()
		w := setupWith(t, true)
		w.seed()
		w.start()
		w.caughtUp()
		jwk, _, err := seal.GenerateRecipient()
		if err != nil {
			t.Fatal(err)
		}
		fan := w.idp.Grant(t, w.s.Now(), "user:fred", []string{"cat"}, []string{}, map[string]any{"groups": toAny("fan-club"), "enc": jwk})
		items := toAny("/r/cat/season", "/r/cat/rumours", "/r/cat/nosuch", "/r/cat/matches.rumour1", "/r/cat/matches.ghost")
		rg := w.do("POST", "/read-grants", fan, map[string]any{"items": items})
		if e := entry(rg, 0); e["status"] != nil || e["grant"] != nil || e["keys"] == nil {
			t.Errorf("visible folder: %v", e)
		}
		// A folder's visibility reads every trusted namespace (§B.11.4).
		if !reflect.DeepEqual(rg.body["checkpoint"], w.checkpointOf("matches")) {
			t.Errorf("checkpoint %v, want %v", rg.body["checkpoint"], w.checkpointOf("matches"))
		}
		for _, pair := range [][2]int{{1, 2}, {3, 4}} {
			h, m := entry(rg, pair[0]), entry(rg, pair[1])
			hn, mn := strings.TrimPrefix(items[pair[0]].(string), "/r/cat/"), strings.TrimPrefix(items[pair[1]].(string), "/r/cat/")
			if h["status"] != 404.0 || h["code"] != "not_found" || h["keys"] != nil || !p30Same(h, m, hn, mn) {
				t.Errorf("hidden %v, missing %v", h, m)
			}
		}
	})
}

// TestReadGrantsVisibleRolesV073 (TC-43, scenario 47): a /read-grants item
// is refused as POST /grants refuses a read of it, counting only the roles
// that make it visible, by the listing visibility test: a role whose rule
// refers to /now doesn't, though POST /grants grants it, which doesn't
// evaluate rules. A hidden item is answered as one without a placement,
// and the grant carries only the roles that make the item visible
// (§B.11.5).
func TestReadGrantsVisibleRolesV073(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "opener", map[string]any{"title": "opener"})
	w.start()
	w.caughtUp()
	w.patchMatches(
		map[string]any{"op": "add", "path": "/roles/timed", "value": map[string]any{"can": toAny("read"),
			"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}}},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "timed"})
	w.patch("cat", "season", map[string]any{"op": "add", "path": "/$access/group:timers", "value": toAny("timed")},
		map[string]any{"op": "replace", "path": "/$access/group:fan-club", "value": toAny("reader", "timed")})
	w.caughtUp()

	// Scenario 47: rumour1 is placed only in rumours, hidden from bob;
	// opener has no placement. Both are refused alike.
	bob := w.caller("user:bob", "match-desk")
	rg := w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/matches/rumour1", "/r/matches/opener")})
	if a, b := entry(rg, 0), entry(rg, 1); a["status"] != 403.0 || !p30Same(a, b, "/r/matches/rumour1", "/r/matches/opener") {
		t.Errorf("hidden %v, unplaced %v", a, b)
	}

	// A role with a /now rule makes nothing visible.
	timer := w.caller("user:tim", "timers")
	w.issue(timer, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)
	if e := entry(w.do("POST", "/read-grants", timer, map[string]any{"items": toAny("/r/matches/derby")}), 0); e["status"] != 403.0 {
		t.Errorf("read-grants through a /now role: %v", e)
	}
	// The grant carries the roles that make the item visible only.
	fan := w.caller("user:fred", "fan-club")
	if b := w.issue(fan, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200).body; fmt.Sprint(b["roles"]) != "[reader timed]" {
		t.Errorf("POST /grants roles %v", b["roles"])
	}
	e := entry(w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")}), 0)
	tok, _ := e["grant"].(string)
	if tok == "" {
		t.Fatalf("read-grants: %v", e)
	}
	if g := must(grant.Decode(tok, 0)); fmt.Sprint(g.Blocks[0].Roles) != "[reader]" {
		t.Errorf("read grant roles %v", g.Blocks[0].Roles)
	}
}

// TestReadGrantsPublicSealedV073 (TC-44): an item in a public sealed
// namespace comes back with its keys alone, no grant and no "public":
// true, which is only for items of public namespaces that aren't sealed;
// the keys still pass the role check (§B.11.5).
func TestReadGrantsPublicSealedV073(t *testing.T) {
	t.Parallel()
	w := setupWith(t, true)
	w.seed()
	w.start()
	w.caughtUp()
	w.patchMatches(map[string]any{"op": "add", "path": "/read", "value": "public"})
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	fan := w.idp.Grant(t, w.s.Now(), "user:fred", []string{"cat"}, []string{}, map[string]any{"groups": toAny("fan-club"), "enc": jwk})
	rg := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby", "/r/matches/rumour1")})
	d, r := entry(rg, 0), entry(rg, 1)
	if ks, _ := d["keys"].([]any); d["public"] != nil || d["grant"] != nil || d["status"] != nil || len(ks) != 2 {
		t.Errorf("public sealed item: %v", d)
	}
	if r["status"] != 403.0 || r["keys"] != nil || r["public"] != nil {
		t.Errorf("public sealed item the caller can't see: %v", r)
	}
}

// p30KeysRT fails the service's POST /keys of one namespace while set.
type p30KeysRT struct {
	ns   string
	fail atomic.Bool
	base http.RoundTripper
}

func (k *p30KeysRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if k.fail.Load() && r.Method == "POST" && r.URL.Path == "/ns/"+k.ns+"/keys" {
		return &http.Response{StatusCode: 503, Status: "503 Service Unavailable", Request: r,
			Header: http.Header{"Content-Type": {"application/json"}},
			Body:   io.NopCloser(strings.NewReader(`{"code":"held","message":"held by the test"}`))}, nil
	}
	return k.base.RoundTrip(r)
}

// TestReadGrantsKeysBehindV073 (TC-19, catalog half): an item whose keys
// the service can't fetch yet is undecided: status 503 with code behind
// (§12.1, §E.2.6), and decided once they can be.
func TestReadGrantsKeysBehindV073(t *testing.T) {
	t.Parallel()
	w := setupWith(t, true)
	w.seed()
	rt := &p30KeysRT{ns: "matches", base: transport}
	w.svcClient = w.s.Client(t, client.WithHTTPClient(&http.Client{Transport: rt}), client.WithKeys(client.NewKeys(nil)),
		client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
			map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	fan := w.idp.Grant(t, w.s.Now(), "user:fred", []string{"cat"}, []string{}, map[string]any{"groups": toAny("fan-club"), "enc": jwk})
	body := map[string]any{"items": toAny("/r/matches/derby")}
	if e := entry(w.do("POST", "/read-grants", fan, body), 0); e["status"] != nil || e["keys"] == nil {
		t.Fatalf("read-grants: %v", e)
	}
	rt.fail.Store(true)
	w.svc.Tree().Keys().Forget("matches")
	if e := entry(w.do("POST", "/read-grants", fan, body), 0); e["status"] != 503.0 || e["code"] != "behind" || e["grant"] != nil || e["keys"] != nil {
		t.Errorf("keys unavailable: %v", e)
	}
	rt.fail.Store(false)
	if e := entry(w.do("POST", "/read-grants", fan, body), 0); e["status"] != nil || e["keys"] == nil {
		t.Errorf("keys available again: %v", e)
	}
}

// p30PurgeHeld purges ns, unsealed, while the service's follower of it is
// held (holdRT), so the service hasn't applied the purge: its document is
// still served (§8.5), and only the core's head of a name tells. It
// returns the purge-ns entry.
func (w *world) p30PurgeHeld(rt *holdRT, ns string) string {
	w.t.Helper()
	ctx := context.Background()
	rt.hold.Store(true)
	w.t.Cleanup(func() { rt.hold.Store(false) })
	pc := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{ns}, []string{"read", "config", "purge-ns"})))
	must(pc.PatchConfig(ctx, ns, must(pc.NSHead(ctx, ns)).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	return must(pc.PurgeNamespace(ctx, ns, must(pc.NSHead(ctx, ns)).ID))
}

// p30HeldWorld is the default world whose service follows ns through a
// holdRT.
func p30HeldWorld(t *testing.T, ns string) (*world, *holdRT) {
	w := setup(t)
	w.seed()
	rt := &holdRT{ns: ns, base: transport}
	w.svcClient = w.s.Client(t, client.WithHTTPClient(&http.Client{Transport: rt}),
		client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
			map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	return w, rt
}

// TestCreatePurgedBeforeApplyV073 (TC-35, TC-38): a Create in a purged
// content namespace is 410 purged with head, for every name, also before
// the service applies the purge of an unsealed namespace, whose document
// stays readable: the core's head of a fresh name is 410 purged at
// namespace level, not a purged item, so it isn't the 409 "exists or
// existed" (§B.11.4 Create, §8.5). Decided at the core's head, it carries
// no checkpoint. A name the service saw stays 409 at its checkpoint.
func TestCreatePurgedBeforeApplyV073(t *testing.T) {
	t.Parallel()
	w, rt := p30HeldWorld(t, "matches")
	admin := w.caller("user:ada", "catalog-admins", "match-desk")
	head := w.p30PurgeHeld(rt, "matches")
	r := w.issue(admin, map[string]any{"item": "/r/matches/fresh", "want": toAny("create")}, 410)
	if r.body["code"] != "purged" || r.body["head"] != head || r.body["checkpoint"] != nil {
		t.Errorf("create of a fresh name: %v (want 410 purged, head %s, no checkpoint)", r.body, head)
	}
	r = w.issue(admin, map[string]any{"item": "/r/matches/derby", "want": toAny("create")}, 409)
	if r.body["code"] != "conflict" || r.body["checkpoint"] == nil {
		t.Errorf("create of a name the service saw: %v (want 409 at the checkpoint)", r.body)
	}
}

// TestCreatePurgedCatalogV073 (§8.5, §B.11.4): the core's head of a name
// in a purged catalog is 410 purged at namespace level: Create a folder
// answers 410 purged with head, not 409 "exists or existed", and Place
// 410 purged, not 410 gone for a purged placement. Decided at the core's
// head, neither carries a checkpoint.
func TestCreatePurgedCatalogV073(t *testing.T) {
	t.Parallel()
	w, rt := p30HeldWorld(t, "cat")
	admin := w.caller("user:ada", "catalog-admins", "match-desk")
	w.doc("matches", "unplaced", map[string]any{"title": "unplaced"})
	head := w.p30PurgeHeld(rt, "cat")
	for _, req := range []map[string]any{
		{"node": "highlights", "want": toAny("create"), "to": []any{}},
		{"item": "/r/matches/unplaced", "want": toAny("place"), "to": []any{}},
	} {
		r := w.do("POST", "/grants", admin, req)
		if r.status != 410 || r.body["code"] != "purged" || r.body["head"] != head || r.body["checkpoint"] != nil {
			t.Errorf("%v: %d %v (want 410 purged, head %s, no checkpoint)", req, r.status, r.body, head)
		}
	}
}
