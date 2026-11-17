package catalog_test

import (
	"fmt"
	"reflect"
	"testing"
)

// Scenario 132 (SERVICES §B.11.2 Where a path stops, v0.85: "it collects
// nothing more than 64 levels above the node (§B.5)"; §B.5 Cycles:
// "Walks, §B.11.2's walk up included, stop at depth 64"; §B.11.5).
// Folder a gives the readers group reader, and below it runs a chain of
// 65 folders without $access, the deepest z. A placement in z with its
// own $access for the group is visible, and is a root for her: z, whose
// walk up ends one level short of a, is hidden, so ancestors gives the
// placement's own path alone and no tooDeep, which would show a hidden
// node; children of z is 404, as for a node not in the catalog; and an
// item placed only in z without $access gets no grant. One level up, the
// folder 64 levels below a still inherits a's role.
func TestV085InheritedAccessStops64LevelsUp(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "a", map[string]any{"title": "A", "parents": parents("root"), "$access": acc("group:deep-readers", "reader")})
	prev := "a"
	for i := 1; i <= 65; i++ {
		name := fmt.Sprintf("f%d", i)
		if i == 65 {
			name = "z"
		}
		w.doc("cat", name, map[string]any{"title": name, "parents": parents(prev)})
		prev = name
	}
	for _, n := range []string{"p", "q"} {
		w.doc("matches", n, map[string]any{"title": n})
	}
	w.doc("cat", "matches.p", map[string]any{"parents": parents("z"), "$access": acc("group:deep-readers", "reader")})
	w.doc("cat", "matches.q", map[string]any{"parents": parents("z")})
	w.start()
	w.caughtUp()
	li := w.caller("user:lena", "deep-readers")

	r, _ := w.follow("/cat/ancestors?of=matches.p", li)
	if r.status != 200 || !reflect.DeepEqual(r.body["paths"], []any{[]any{"matches.p"}}) {
		t.Errorf("ancestors of the placement: %d %v, want its own path alone", r.status, r.body)
	}
	if _, has := r.body["tooDeep"]; has {
		t.Errorf("ancestors of the placement reports tooDeep: %v", r.body)
	}
	if r, _ := w.follow("/cat/children?of=z", li); r.status != 404 {
		t.Errorf("children of z, 65 levels below a: %d %v, want 404", r.status, r.body)
	}
	if r, _ := w.follow("/cat/children?of=f64", li); r.status != 200 {
		t.Errorf("children of f64, 64 levels below a: %d %v, want 200", r.status, r.body)
	}
	if r := w.do("POST", "/grants", li, map[string]any{"item": "/r/matches/q", "want": toAny("read")}); r.status != 403 {
		t.Errorf("a grant for an item placed only in z: %d %v, want 403", r.status, r.body)
	}
	if r := w.do("POST", "/grants", li, map[string]any{"item": "/r/matches/p", "want": toAny("read")}); r.status != 200 {
		t.Errorf("a grant for the placement with its own $access: %d %v, want 200", r.status, r.body)
	}
}
