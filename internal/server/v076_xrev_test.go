package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// Cross-review, Protection 44 (content moving between namespaces, v0.76):
// remote branch r whose raise to sealed fails -> GET /ns/r/rev/{ns_id}/heads
// -> the rows r answers 502 for carry no created, size or digest; so does
// the local branch rx reading through it.
func TestV076Scenario44Heads(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "x", map[string]any{"v": 1.0})
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
		t.Fatalf("raised to %q", l)
	}
	expectCode(t, b.get("/r/r/x"), 502, "upstream")
	for _, ns := range []string{"r", "rx"} {
		r := b.get("/ns/" + ns + "/rev/" + b.nsHead(ns) + "/heads")
		expect(t, r, 200)
		rows, _ := r.Obj()["heads"].([]any)
		found := false
		for _, x := range rows {
			m := x.(map[string]any)
			if m["resource"] != "x" {
				continue
			}
			found = true
			for _, k := range []string{"created", "size", "digest"} {
				if _, ok := m[k]; ok {
					t.Errorf("%s: row x carries %s: %v", ns, k, m)
				}
			}
		}
		if !found {
			t.Errorf("%s: no row for x: %s", ns, r.Body)
		}
	}
}
