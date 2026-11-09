package merge_test

import (
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// OTHER-2 (§F.3 Conflicts inside arrays, v0.76): a write whose last
// segment addresses an array element counts as a write to the whole
// outermost array holding it, not only the innermost one. A write to an
// object key inside an element stays as it is, which includes the shifted
// array itself where it is an object's member (§6.4.1): an insertion into
// /a/0/b writes /a (its element) and /a/0/b (the array it shifts).
func TestV076MergeWritesOutermostArray(t *testing.T) {
	t.Parallel()
	doc := map[string]any{"a": []any{map[string]any{"b": []any{1.0, 2.0}, "k": 1.0}, map[string]any{"c": []any{3.0}}}}
	for _, c := range []struct {
		patch map[string]any
		want  []string
	}{
		{op("add", "/a/0/b/1", 3), []string{"/a", "/a/0/b"}},
		{op("add", "/a/0/b/-", 3), []string{"/a"}},
		{rm("/a/1/c/0"), []string{"/a"}},
		{op("replace", "/a/0/b/0", 3), []string{"/a"}},
		{op("replace", "/a/0/k", 2), []string{"/a/0/k"}},
		{op("add", "/x", []any{}), []string{"/x"}},
	} {
		w := must(merge.Writes(doc, true, []client.Step{client.PatchStep(ops(c.patch))}))
		if !reflect.DeepEqual(w, c.want) {
			t.Errorf("%v: writes %v want %v", c.patch, w, c.want)
		}
	}

	// So a branch appending to one element's array and the base appending
	// to another's conflict: both write /a.
	e := newEnv(t)
	e.create("matches", "grid", doc)
	e.branch("matches", "r7")
	e.append("r7", "grid", op("add", "/a/0/b/-", 4))
	e.append("matches", "grid", op("add", "/a/1/c/-", 5))
	r := e.plan("matches", "r7", merge.Options{}).Resource("grid")
	if !hasConflict(r, merge.ConflictOverlap) || !reflect.DeepEqual(r.BranchWrites, []string{"/a"}) || !reflect.DeepEqual(r.BaseWrites, []string{"/a"}) {
		t.Fatalf("grid: %+v", r)
	}
}
