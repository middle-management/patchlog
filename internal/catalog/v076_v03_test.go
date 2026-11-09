package catalog_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// v076V03Public creates public namespace ns, which cat's catalog.trust
// doesn't list, holding item x.
func (w *world) v076V03Public(ns string) {
	w.t.Helper()
	ctx := context.Background()
	op := w.s.Client(w.t, client.WithBearer(w.s.OperatorGrant(w.t, ns)))
	must(op.CreateNamespace(ctx, ns, map[string]any{"read": "public", "keys": []any{w.opsKey.Entry("*")}}))
	oc := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{ns}, []string{"read", "create"})))
	must(oc.Create(ctx, ns, "x", client.GenesisPatches(map[string]any{"title": "x"})))
}

// §B.11.5 Every item at once, §B.11.4 (v0.76): an item of a namespace
// the catalog doesn't trust is 403 untrusted first, even a public one's,
// before "public": true.
func TestV076V03ReadGrantsUntrustedPublic(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.v076V03Public("pub")
	w.start()
	w.caughtUp()

	fan := w.caller("user:fred", "fan-club")
	r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/pub/x", "/r/matches/derby")})
	if r.status != 200 {
		t.Fatalf("read-grants: %d %v", r.status, r.body)
	}
	e := entry(r, 0)
	if e["status"] != float64(403) || e["code"] != "forbidden" || e["public"] != nil || e["grant"] != nil {
		t.Errorf("untrusted public item: %v", e)
	}
	if e := entry(r, 1); e["grant"] == nil {
		t.Errorf("trusted item: %v", e)
	}
}

// v076V03Content creates content namespace ns, which cat trusts and whose
// catalogs names cat, listing the catalog's kid with catalogEntry's
// requireAt (nil for none) and holding item x, placed under season, whose
// $access gives fan-club reader. The service's grant reads it too.
func (w *world) v076V03Content(ns string, requireAt any) {
	w.t.Helper()
	ctx := context.Background()
	entry := w.cat.Entry("read", "create", "append", "restore")
	entry["maxTtl"] = "PT15M"
	entry["readScope"] = "resource"
	if requireAt != nil {
		entry["requireAt"] = requireAt
	}
	op := w.s.Client(w.t, client.WithBearer(w.s.OperatorGrant(w.t, ns)))
	must(op.CreateNamespace(ctx, ns, map[string]any{
		"read": "grant", "keys": []any{w.opsKey.Entry("*"), w.idp.Entry(), entry},
		"roles":    map[string]any{"reader": map[string]any{"can": toAny("read")}},
		"catalogs": map[string]any{"cat": map[string]any{"place": toAny("group:match-desk")}},
	}))
	oc := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{ns}, []string{"read", "create"})))
	must(oc.Create(ctx, ns, "x", client.GenesisPatches(map[string]any{"title": "x"})))
	opc := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "cat")).Config
	must(opc.PatchConfig(ctx, "cat", cfg, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": ns}}))
	w.doc("cat", ns+".x", map[string]any{"parents": parents("season")})
}

// §B.11.3 Scoped keys bound the catalog service, §B.11.9 Where (v0.76):
// in a content namespace the catalog's key is one whose requireAt names
// the catalog. Listing the kid without requireAt, or with requireAt
// naming another namespace, grants nothing there (403 after the purge
// 410), and roles counting only through it show nothing in listings.
func TestV076V03ContentKeyRequireAt(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.v076V03Content("pa", nil)
	w.v076V03Content("pb", "other")
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "pa", "pb"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	for _, ns := range []string{"pa", "pb"} {
		waitFor(t, ns+" to be followed", func() bool { return w.svc.Tree().Checkpoint(ns) != "" })
	}

	fan := w.caller("user:fred", "fan-club")
	w.issue(fan, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)
	for _, ns := range []string{"pa", "pb"} {
		r := w.issue(fan, map[string]any{"item": "/r/" + ns + "/x", "want": toAny("read")}, 403)
		if msg, _ := r.body["message"].(string); !strings.Contains(msg, "does not list the catalog's key") {
			t.Errorf("%s: %v", ns, r.body)
		}
	}
	r, _ := w.follow("/cat/children?of=season", fan)
	if r.status != 200 {
		t.Fatalf("children of season: %d %v", r.status, r.body)
	}
	if got := childNames(r.body); strings.Contains(got, "pa.x") || strings.Contains(got, "pb.x") || !strings.Contains(got, "matches.derby") {
		t.Errorf("children of season: %s", got)
	}
	rg := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/pa/x", "/r/pb/x")})
	for i := range 2 {
		if e := entry(rg, i); e["status"] != 403.0 || e["grant"] != nil {
			t.Errorf("read-grants entry %d: %v", i, e)
		}
	}
}
