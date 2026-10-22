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
// of a decision on a matches item. In POST /read-grants each entry
// carries its own: a placement node names its item's namespace, a folder
// every trusted namespace, whose roles decide its visibility (v0.56 note
// 4); a public item of a followed namespace carries the checkpoint its
// exposure was read at, and one of a namespace the service doesn't
// follow, read at the head, none. Every item comes back with a grant,
// "public": true or its node's answer, so the reader may read them all.
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
	items := toAny("/r/matches/derby", "/r/cat/matches.derby", "/r/cat/season", "/r/open/notice")
	cp := w.checkpointOf("matches")
	at := w.listingAt(bob)
	check := func(when string) {
		t.Helper()
		if r := w.issue(bob, read, 200); !reflect.DeepEqual(r.body["checkpoint"], cp) {
			t.Errorf("%s: grant checkpoint %v, want %v", when, r.body["checkpoint"], cp)
		}
		rg := w.do("POST", "/read-grants", bob, map[string]any{"items": items})
		for i, want := range []any{cp, cp, w.checkpointOf("matches", "teams"), nil} {
			e := entry(rg, i)
			if e == nil || e["error"] != nil || (i == 0) != (e["grant"] != nil) || (i == 3) != (e["public"] == true) {
				t.Errorf("%s: entry %d: %v", when, i, e)
				continue
			}
			if got, has := e["checkpoint"]; has != (want != nil) || has && !reflect.DeepEqual(got, want) {
				t.Errorf("%s: entry %d (%v): checkpoint %v, want %v", when, i, e["item"], got, want)
			}
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
