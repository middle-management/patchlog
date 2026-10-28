package server

import (
	"testing"
)

// headRows is a /heads page's rows by resource.
func headRows(t *testing.T, r *resp) map[string]map[string]any {
	t.Helper()
	expect(t, r, 200)
	out := map[string]map[string]any{}
	for _, h := range r.Obj()["heads"].([]any) {
		m := h.(map[string]any)
		out[m["resource"].(string)] = m
	}
	return out
}

// §7.4, §1 (v0.74, LEVELS-8): on a server that lacks the level its
// remote branch's source was raised to, /heads rows of the resources §1
// answers 502 for lack created, size and digest, at the branch and at a
// local branch reading through it; resources created on the branch keep
// them.
func TestV074RemoteLostHeadsFields(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	x1 := a.create("m", "x", map[string]any{"v": 1.0})
	a.create("m", "y", map[string]any{"v": 2.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	b.appendRev("r", "x", x1, ops(op("replace", "/v", 10.0)))
	b.create("r", "mine", map[string]any{"own": true})
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	b.create("rx", "local", map[string]any{"own": true})
	full := func(m map[string]any) bool { return m["created"] != nil && m["size"] != nil && m["digest"] != nil }
	for _, ns := range []string{"r", "rx"} {
		for name, row := range headRows(t, b.get("/ns/"+ns+"/rev/"+b.nsHead(ns)+"/heads")) {
			if !full(row) {
				t.Fatalf("%s before the raise: %s %v", ns, name, row)
			}
		}
	}
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	expectCode(t, b.get("/r/r/y"), 502, "upstream")
	for _, ns := range []string{"r", "rx"} {
		rows := headRows(t, b.get("/ns/"+ns+"/rev/"+b.nsHead(ns)+"/heads"))
		for _, name := range []string{"x", "y"} {
			row := rows[name]
			if row == nil || row["target"] == nil || row["created"] != nil || row["size"] != nil || row["digest"] != nil {
				t.Fatalf("%s: %s row %v, want target without created, size, digest", ns, name, row)
			}
		}
		if !full(rows["mine"]) {
			t.Fatalf("%s: own row %v", ns, rows["mine"])
		}
	}
	if !full(headRows(t, b.get("/ns/rx/rev/"+b.nsHead("rx")+"/heads"))["local"]) {
		t.Fatal("rx's own resource lost its fields")
	}
}
