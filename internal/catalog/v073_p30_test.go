package catalog_test

import (
	"context"
	"reflect"
	"testing"
)

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
