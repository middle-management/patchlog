package server

import (
	"encoding/json"
	"testing"
)

// E2E-13 (Reading this spec, Addendum E Levels Invariant, §1 Conformance,
// §G.5.2; CONFORMANCE scenario 74): a remote branch R on B of N on A,
// where A, running an earlier draft, raises N to e2e after at. B's raise
// to follow it can't succeed, since only a creation sets e2e: B raises R
// and its dependents as far as Levels allow, to sealed, and answers 502
// upstream for every resource N had at at, read through or written on
// since, on R and on a branch of R, for reads and for writes other than
// purges, whatever level R reaches and however often it syncs: sealed is
// less protection than N's content now has. A resource R created, which N
// never had, is served as usual. A's document is rewritten in transit, as
// this server raises no namespace to e2e.
func TestV082RemoteSourceRaisedToE2EHeld(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "grant"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	w := a.create("m", "w", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant"})), 201)
	// Before the raise: R reads N's resources through, writes on one and
	// creates one of its own.
	expect(t, b.get("/r/r/x/rev/"+x), 200)
	w2 := b.wr("r", "w", w, ops(op("replace", "/v", 2.0)))
	y := b.wr("r", "y", "", addRoot(map[string]any{"own": true}))
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	expect(t, a.patchNS("m", ops(op("add", "/x-note", "raised")), ""), 201)
	raised := a.nsHead("m")
	rt.set(proxyA(t, a, nil, "/ns/m/rev/"+raised, func(body []byte) []byte {
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("A's document: %v", err)
			return body
		}
		doc["encryption"] = map[string]any{"level": "e2e", "epoch": 1.0}
		out, _ := json.Marshal(doc)
		return out
	}), "")
	held := func(what string) {
		t.Helper()
		for _, ns := range []string{"r", "rx"} {
			if l := levelOf(b.configOf(ns)); l != "sealed" {
				t.Fatalf("%s: %s is at level %q, want sealed", what, ns, l)
			}
			for _, path := range []string{"/r/" + ns + "/x", "/r/" + ns + "/x/rev/" + x, "/r/" + ns + "/x/rev/" + x + "/log",
				"/r/" + ns + "/w", "/r/" + ns + "/w/rev/" + w2, "/r/" + ns + "/w/rev/" + w, "/r/" + ns + "/w/rev/" + w2 + "/log"} {
				g := b.get(path)
				if g.Code != 502 || g.Str("code") != "upstream" || isJOSE(g) || g.H.Get("Retry-After") != "" {
					t.Fatalf("%s: GET %s: %d %v %.200s, want 502 upstream", what, path, g.Code, g.H, g.Body)
				}
			}
			// Writes other than purges are refused the same way.
			for name, parent := range map[string]string{"x": x, "w": w2} {
				if r := b.write("PATCH", ns, name, parent, withNonce(ops(op("add", "/late", true)))); r.Code != 502 || r.Str("code") != "upstream" {
					t.Fatalf("%s: a write to %s/%s: %d %s, want 502 upstream", what, ns, name, r.Code, r.Body)
				}
			}
			// What R created itself, which N never had: served, sealed
			// as R now is.
			if g := b.get("/r/" + ns + "/y/rev/" + y); g.Code != 200 || !isJOSE(g) {
				t.Fatalf("%s: %s's own resource: %d %s", what, ns, g.Code, g.Body)
			}
		}
	}
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	held("after the sync that saw the raise")
	// Later syncs retry what can be made; the raise to e2e can't.
	for range 2 {
		if err := syncRemotes(t, b); err != nil {
			t.Fatal(err)
		}
	}
	held("after later syncs")
	// A write to R's own resource still works.
	b.wr("r", "y", y, withNonce(ops(op("add", "/more", true))))
	// A purge of a held resource is the way out for it (§1).
	expect(t, b.purge("r", "w", w2, "admin"), 204)
	if g := b.get("/r/r/w"); g.Code != 410 {
		t.Fatalf("a purged held resource: %d %s", g.Code, g.Body)
	}
}
