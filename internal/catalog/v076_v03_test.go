package catalog_test

import (
	"context"
	"testing"

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
