package core

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// TestDerivedEntries writes entries of every kind, in a namespace and a
// branch of it, and checks that only single writes' head and tombstone
// entries are stored derived (entrybody.go), that every entry's body as a
// read rebuilds it hashes to its id after the one before it (§3.5), and
// that the log serves a derived entry's hashed members as rebuilt.
func TestDerivedEntries(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	req := func(ns string) Request { r := who; r.NS = ns; return r }
	must := func(id string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	x := must(put(e, "n", "x", "", 1))
	x = must(put(e, "n", "x", x, 2))
	y := must(put(e, "n", "y", "", 1))
	// A tombstone, and a write with gesture members (unhashed, §7.4).
	if _, err := e.WriteResource(ctx, req("n"), Item{Resource: "y", IfMatch: y, Steps: []Step{{Delete: true}}}); err != nil {
		t.Fatal(err)
	}
	g := "abcdefghijklmnopqrstuvwxyz"
	if _, err := e.WriteResource(ctx, req("n"), Item{Resource: "x", IfMatch: x,
		Steps: []Step{{Gesture: g, Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": float64(3)}}}}}); err != nil {
		t.Fatal(err)
	}
	// A batch, kept whole.
	if _, err := e.Batch(ctx, req("n"), []Item{
		{Resource: "b1", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
		{Resource: "b2", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
	}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	// A branch (a branch entry in n), written to: its own rows of x.
	if _, err := e.CreateBranch(ctx, req("n"), BranchRequest{Name: "b", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	head := func(ns, name string) string {
		t.Helper()
		l, err := e.ResourceLog(ctx, ns, name, "", "", 0, Credentials{})
		if err != nil || len(l.Entries) == 0 {
			t.Fatalf("log of %s/%s: %v", ns, name, err)
		}
		return l.Entries[len(l.Entries)-1]["id"].(string)
	}
	must(put(e, "b", "x", head("b", "x"), 4))
	must(put(e, "b", "z", "", 1))
	// A purge in n, propagated to the branch (purge entries in both).
	if _, err := e.Purge(ctx, req("n"), "b1", head("n", "b1"), false); err != nil {
		t.Fatal(err)
	}
	must(put(e, "n", "x", head("n", "x"), 5))

	if err := e.checkDerived(ctx); err != nil {
		t.Fatal(err)
	}
	// Every entry: derived only for single writes' heads and tombstones,
	// and its body, rebuilt where derived, chains (§3.5).
	byKind := map[string][2]int{}
	if err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT l.seq, l.id, p.id, COALESCE(l.body, ''), l.kind, ` + derivedCols + ` FROM ns_log l LEFT JOIN ns_log p ON p.seq = l.prev_seq` + derivedJoins + ` ORDER BY l.seq`)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var seq int64
			var id, prev []byte
			var body string
			var kind int
			var d derived
			t.must(rows.Scan(&seq, &id, &prev, &body, &kind, &d.kind, &d.name, &d.id, &d.created))
			c := byKind[nsKindNames[kind]]
			if body == "" {
				c[0]++
				body = string(entryBody(d.kind, d.name.String, ids.FromBytes(d.id)))
			} else {
				c[1]++
			}
			byKind[nsKindNames[kind]] = c
			var p *ids.ID
			if prev != nil {
				x := ids.FromBytes(prev)
				p = &x
			}
			if ids.Hash(p, []byte(body)) != ids.FromBytes(id) {
				panic("entry " + ids.FromBytes(id).String() + " doesn't chain: " + body)
			}
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for k, c := range byKind {
		switch {
		case (k == "head" || k == "tombstone") && (c[0] == 0 || c[1] != 0):
			t.Errorf("%s entries: %d derived, %d stored; want all derived", k, c[0], c[1])
		case k != "head" && k != "tombstone" && c[0] != 0:
			t.Errorf("%s entries: %d derived", k, c[0])
		}
	}
	for _, k := range []string{"head", "tombstone", "config", "batch", "branch", "purge"} {
		if _, ok := byKind[k]; !ok {
			t.Errorf("no %s entry written", k)
		}
	}
	// The log serves a derived entry's members as rebuilt, its created
	// that of its revision, and its gesture members.
	for _, ns := range []string{"n", "b"} {
		lg, err := e.NamespaceLog(ctx, ns, "", "", 0, Credentials{})
		if err != nil || lg.Status != 200 {
			t.Fatalf("log of %s: %v %+v", ns, err, lg)
		}
		var prev *ids.ID
		sawGesture := false
		for _, en := range lg.Entries {
			hashed := map[string]any{}
			for _, k := range []string{"kind", "resource", "target", "entries", "name", "at", "forced", "source"} {
				if v, ok := en[k]; ok {
					hashed[k] = v
				}
			}
			id, _ := ids.Parse(en["id"].(string))
			if ids.Hash(prev, jsonv.Canonical(jsonv.FromGo(hashed))) != id {
				t.Errorf("%s: served entry %v doesn't hash to its id", ns, en)
			}
			prev = &id
			if en["kind"] == "head" || en["kind"] == "tombstone" {
				rl, err := e.ResourceLog(ctx, ns, en["resource"].(string), en["target"].(string), "", 0, Credentials{})
				if err == nil && rl.Status == 200 && len(rl.Entries) > 0 {
					if rc := rl.Entries[len(rl.Entries)-1]["created"]; rc != en["created"] {
						t.Errorf("%s: entry %v created %v, its revision %v", ns, en["id"], en["created"], rc)
					}
				}
			}
			if en["gesture"] == g {
				sawGesture = true
			}
		}
		if ns == "n" && !sawGesture {
			t.Errorf("%s: the gesture members aren't served", ns)
		}
	}
}
