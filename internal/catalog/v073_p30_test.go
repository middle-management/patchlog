package catalog_test

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
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
