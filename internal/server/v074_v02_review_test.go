package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// Addendum E Levels, Invariant; §1, §G.5.2 (v0.74 review of LEVELS-5):
// once B sees its source raised to sealed and its own raise fails for a
// reason other than a lacking level, it serves none of what it had at at
// below that level: reads and writes of those resources answer 502
// upstream naming the origin, without Retry-After (v0.76: §1's "or hasn't
// succeeded", no longer 503), and their /heads rows lack created, size and
// digest; resources created on the branch are unaffected.
func TestV074RemoteFailedRaiseHeld(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt, func(o *core.RemoteOptions) { o.FollowInterval = 90 * time.Second }), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	mine := b.create("r", "mine", map[string]any{"own": true})
	expect(t, b.get("/r/r/x/rev/"+x), 200) // cached before the raise
	b = reopen(func(o *core.Options) {
		o.Limits, o.Maximums = core.DefaultLimits(), core.DefaultMaximums()
		o.Limits.PatchSetSize, o.Maximums.PatchSetSize = 128<<10, 128<<10
	})
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if ra := a.get("/r/m/x/rev/" + x); !isJOSE(ra) {
		t.Fatalf("A serves %d %s, want sealed", ra.Code, ra.Body)
	}
	for _, r := range []*resp{b.get("/r/r/x/rev/" + x), b.get("/r/r/x"), b.write("PATCH", "r", "x", x, ops(op("replace", "/v", 2.0)))} {
		expectCode(t, r, 502, "upstream")
		if r.H.Get("Retry-After") != "" || r.Str("origin") != originA {
			t.Fatalf("held answer %v %s, want no Retry-After and origin %s", r.H, r.Body, originA)
		}
	}
	rows := headRows(t, b.get("/ns/r/rev/"+b.nsHead("r")+"/heads"))
	if row := rows["x"]; row == nil || row["target"] == nil || row["created"] != nil || row["size"] != nil || row["digest"] != nil {
		t.Fatalf("x row %v, want target without created, size, digest", row)
	}
	if row := rows["mine"]; row["created"] == nil || row["digest"] == nil {
		t.Fatalf("own row %v", row)
	}
	expect(t, b.get("/r/r/mine/rev/"+mine), 200)
	b.appendRev("r", "mine", mine, ops(op("replace", "/own", false)))
}
