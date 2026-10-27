package catalog_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// TestCheckpointNamesItsNamespaces (§B.11.4, v0.51): a decision's
// checkpoint is { ns: ns_id } of the catalog and of the named item's
// namespace, which are all it depends on, so a write to another content
// namespace the catalog trusts moves listings' at but not the checkpoint
// of a decision on a matches item. POST /read-grants carries one
// checkpoint, over every namespace its decisions read (v0.73): the
// catalog's and each item's namespace's, a public one the service
// doesn't follow, read at the head, having none. A catalog node, 400 in a
// catalog that is neither sealed nor end-to-end, reads only the catalog's
// level (in a sealed one, a folder's visibility reads every trusted
// namespace, v0.56 note 4). Every item but the node comes back with a
// grant or "public": true, so the reader may read them all.
func TestCheckpointNamesItsNamespaces(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	// teams, a second trusted namespace; open, a public one the catalog
	// doesn't trust.
	for _, ns := range []string{"teams", "open"} {
		read := "grant"
		if ns == "open" {
			read = "public"
		}
		op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, ns)))
		must(op.CreateNamespace(ctx, ns, map[string]any{"read": read, "keys": []any{w.opsKey.Entry("*")}}))
	}
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "cat")).Config
	must(opc.PatchConfig(ctx, "cat", cfg, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
	ot := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"teams", "open"}, []string{"read", "create"})))
	must(ot.CreateDoc(ctx, "open", "notice", map[string]any{"title": "notice"}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })

	bob := w.caller("user:bob", "match-desk")
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}
	items := toAny("/r/matches/derby", "/r/open/notice")
	cp := w.checkpointOf("matches")
	at := w.listingAt(bob)
	check := func(when string) {
		t.Helper()
		if r := w.issue(bob, read, 200); !reflect.DeepEqual(r.body["checkpoint"], cp) {
			t.Errorf("%s: grant checkpoint %v, want %v", when, r.body["checkpoint"], cp)
		}
		rg := w.do("POST", "/read-grants", bob, map[string]any{"items": items})
		if !reflect.DeepEqual(rg.body["checkpoint"], cp) {
			t.Errorf("%s: read-grants checkpoint %v, want %v", when, rg.body["checkpoint"], cp)
		}
		for i := range items {
			e := entry(rg, i)
			if e == nil || e["status"] != nil || e["checkpoint"] != nil || (i == 0) != (e["grant"] != nil) || (i == 1) != (e["public"] == true) {
				t.Errorf("%s: entry %d: %v", when, i, e)
			}
		}
		rg = w.do("POST", "/read-grants", bob, map[string]any{"items": append(items, "/r/cat/season")})
		if !reflect.DeepEqual(rg.body["checkpoint"], cp) || entry(rg, 2)["status"] != 400.0 {
			t.Errorf("%s: read-grants naming a folder: %v, want checkpoint %v", when, rg.body, cp)
		}
	}
	check("before")

	// A write to teams moves listings' at, and nothing a matches decision
	// depends on.
	before := w.svc.Tree().Checkpoint("teams")
	must(ot.CreateDoc(ctx, "teams", "reds", map[string]any{"title": "Reds"}))
	waitFor(t, "the service to apply the teams write", func() bool { return w.svc.Tree().Checkpoint("teams") != before })
	if at2 := w.listingAt(bob); at2 == at {
		t.Errorf("listing at %s didn't move", at2)
	}
	if now := w.checkpointOf("matches"); !reflect.DeepEqual(now, cp) {
		t.Fatalf("checkpoint of cat and matches moved: %v, was %v", now, cp)
	}
	check("after a teams write")
}
