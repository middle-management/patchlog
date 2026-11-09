package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// §1 Conformance, §G.5.2, §12.1 (v0.76, B-63): remote branch R of A's N,
// on a server with a key store; A raises N to sealed and R's raise fails
// (its config writes are over the patch set maximum). A read of a resource
// R reads through, and a PATCH with a test op, answer 502 upstream naming
// A, without Retry-After, as for a level the server lacks, never 503 and
// never the clear; a purge still works (204).
func TestV076EncFailedRaiseIs502(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	y := a.create("m", "y", map[string]any{"v": 2.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
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
	upstream := func(what string, r *resp) {
		t.Helper()
		expectCode(t, r, 502, "upstream")
		if r.H.Get("Retry-After") != "" || r.Str("origin") != originA {
			t.Fatalf("%s: %v %s, want 502 upstream with origin %s and no Retry-After", what, r.H, r.Body, originA)
		}
	}
	upstream("read", b.get("/r/r/x/rev/"+x))
	upstream("read through rx", b.get("/r/rx/x/rev/"+x))
	upstream("PATCH with a test op", b.write("PATCH", "r", "x", x, ops(op("test", "/v", 1.0))))
	expect(t, b.purge("r", "y", y, "admin"), 204)
}
