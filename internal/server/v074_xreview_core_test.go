package server

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// Addendum E Levels, Invariant; §G.5.2 (v0.74 cross review): a raise a
// remote branch recorded but couldn't make, as v0.23 left every branch of
// a source raised from none to e2e (recorded for a rebase, the branch still
// at none), is made when the server starts, before anything is served, not
// at the first sync a whole follow interval later: right after the restart
// the branch's resources answer 200, sealed, not 503 encryption_unavailable.
func TestV074RemoteRecordedRaiseMadeAtStart(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	// The raise's config writes fail (the patch set maximum), so it is
	// recorded and the branch stays below its source's level.
	b = reopen(func(o *core.Options) {
		o.Limits, o.Maximums = core.DefaultLimits(), core.DefaultMaximums()
		o.Limits.PatchSetSize, o.Maximums.PatchSetSize = 128<<10, 128<<10
	})
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if l := levelOf(b.configOf("r")); l != "" {
		t.Fatalf("raised to %q although its config writes fail", l)
	}
	expectCode(t, b.get("/r/r/x/rev/"+x), 503, "encryption_unavailable")
	// Restarted with the maximum back, and no sync: the raise is made at
	// start, leaves first.
	b = reopen()
	for _, ns := range []string{"rx", "r"} {
		if l := levelOf(b.configOf(ns)); l != "sealed" {
			t.Fatalf("%s: level %q right after the restart, want sealed", ns, l)
		}
	}
	for _, p := range []string{"/r/r/x/rev/" + x, "/r/rx/x/rev/" + x} {
		if g := b.get(p); g.Code != 200 || !isJOSE(g) {
			t.Fatalf("%s right after the restart: %d %s, want 200 sealed", p, g.Code, g.Body)
		}
	}
	if ls, err := b.e.RemoteLevels(context.Background(), "r"); err != nil || len(ls) != 0 {
		t.Fatalf("levels %+v %v, want none once the raise is made", ls, err)
	}
}
