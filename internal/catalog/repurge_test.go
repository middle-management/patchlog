package catalog_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
)

// TestUntrustRepurge (D.8, §B.11.5): the ns:{catalog} purge of a catalog
// service with edge grants whose catalog stops trusting a namespace is
// queued with the apply that commits the new trust list, like every
// purge of the tree service, and sent once more RepurgeDelay later: a
// g/all listing read before the commit and handed to the edge after the
// first purge would otherwise stay there for its edge lifetime.
func TestUntrustRepurge(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.edgeOwnKey = true
	w.repurgeDelay, w.repurgeInterval = time.Minute, time.Millisecond
	w.start()
	w.caughtUp()
	purges := func() string {
		w.pmu.Lock()
		defer w.pmu.Unlock()
		return fmt.Sprint(w.purges)
	}
	if got := purges(); got != "[]" {
		t.Fatalf("purges before the trust list changed: %s", got)
	}

	// The catalog trusts teams instead of matches: ns:cat at once, and,
	// the service's clock (the core's) not having moved, nothing more.
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config,
		[]any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{"teams"}}}))
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	if got := purges(); got != "[[ns:cat]]" {
		t.Fatalf("purges %s, want [[ns:cat]]", got)
	}
	// Once more after the delay.
	w.s.Clock.Advance(time.Minute)
	waitFor(t, "the second purge of ns:cat", func() bool { return purges() != "[[ns:cat]]" })
	if got := purges(); got != "[[ns:cat] [ns:cat]]" {
		t.Errorf("purges %s, want [[ns:cat] [ns:cat]]", got)
	}
}
