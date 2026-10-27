package catalog_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// TestMergePurgedCatalogV073P37 (§8.5, §B.11.4, §F.8): a merge batch item
// over a catalog the core holds as purged is 410 purged with the purge-ns
// entry as head, as an organising request's is (coreHead), also before
// the service applies the purge of an unsealed catalog, whose document
// stays readable: the core's head of a fresh name is purged at namespace
// level (client.Head.PurgedNS), not a purged placement, so it is neither
// 410 gone nor the 409 of a name that exists or existed.
func TestMergePurgedCatalogV073P37(t *testing.T) {
	t.Parallel()
	w, rt := p30HeldWorld(t, "cat")
	head := w.p30PurgeHeld(rt, "cat")
	r := w.mergeAsk(w.caller("user:chief", "catalog-admins"), "", map[string]any{"resource": "matches.fresh", "ifNoneMatch": "*",
		"steps": []any{client.GenesisPatches(map[string]any{"parents": parents("season")})}})
	if r.status != 410 || r.body["code"] != "purged" || r.body["head"] != head {
		t.Fatalf("a merge item in a purged catalog: %d %v (want 410 purged, head %s)", r.status, r.body, head)
	}
}
