package server

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// D.4: large heads aren't cached as head snapshots; intermediate snapshots
// bound every fold, and never make pruned revisions readable (§8.6).
func TestSnapshots(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *core.Options) {
		o.HeadSnapshotMax = 64
		o.SnapshotEveryRevisions = 3
		o.SnapshotEveryBytes = 1 << 20
	})
	e.mkNS("main", map[string]any{"read": "public"})
	pad := strings.Repeat("x", 200) // every document is over HeadSnapshotMax
	revs := []string{e.create("main", "a", map[string]any{"n": 0.0, "pad": pad})}
	for i := 1; i <= 10; i++ {
		revs = append(revs, e.appendRev("main", "a", revs[i-1], ops(op("replace", "/n", float64(i)))))
	}
	check := func() {
		t.Helper()
		for i, id := range revs {
			d := e.get("/r/main/a/rev/" + id)
			expect(t, d, 200)
			if n := d.Obj()["n"]; n != float64(i) {
				t.Fatalf("rev %d: n = %v", i, n)
			}
		}
		if n := e.doc("main", "a")["n"]; n != 10.0 {
			t.Fatalf("head n = %v", n)
		}
	}
	check()
	// A fresh engine has no document cache: everything folds from storage.
	e.e.FlushCaches()
	check()

	// Restore of a large document folds its last live document.
	tomb := e.del("main", "a", revs[10])
	r := e.write("PATCH", "main", "a", tomb, []any{})
	expect(t, r, 201)
	e.e.FlushCaches()
	if n := e.doc("main", "a")["n"]; n != 10.0 {
		t.Fatalf("restored n = %v", n)
	}

	// Prune below revs[7]: revisions 0–6 are gone although intermediate
	// snapshots existed at revs[2] and revs[5]; a kept one survives.
	e.clock.Advance(time.Hour)
	r = e.do(req{method: "POST", path: "/r/main/a/prune", author: "admin",
		body: map[string]any{"horizon": revs[7], "keep": []any{revs[1]}}})
	expect(t, r, 200)
	e.e.FlushCaches()
	for i, id := range revs {
		d := e.get("/r/main/a/rev/" + id)
		switch {
		case i == 1 || i >= 7:
			expect(t, d, 200)
			if n := d.Obj()["n"]; n != float64(i) {
				t.Fatalf("rev %d: n = %v", i, n)
			}
		default:
			expectCode(t, d, 410, "pruned")
		}
	}
	// A later prune's keep replaces the earlier one.
	r = e.do(req{method: "POST", path: "/r/main/a/prune", author: "admin",
		body: map[string]any{"horizon": revs[9]}})
	expect(t, r, 200)
	e.e.FlushCaches()
	expectCode(t, e.get("/r/main/a/rev/"+revs[1]), 410, "pruned")
	expectCode(t, e.get("/r/main/a/rev/"+revs[8]), 410, "pruned")
	expect(t, e.get("/r/main/a/rev/"+revs[9]), 200)
}
