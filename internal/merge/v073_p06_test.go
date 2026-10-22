package merge_test

import (
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// Spec v0.56–v0.73 for the merge, rebase and release tools (P06).

func cp(from, path string) map[string]any {
	return map[string]any{"op": "copy", "from": from, "path": path}
}

// §F.3 (neither): the branch side's writes count the from of every copy
// too; the target side's don't.
func TestV073BranchCopyFromConflicts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", cp("/title", "/subtitle"))
	e.append("matches", "derby", op("replace", "/title", "The Derby"))
	// The target copies from what the branch changes: no conflict.
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.append("matches", "cup", cp("/score", "/half"))

	p := e.plan("matches", "r7", merge.Options{})
	r := p.Resource("derby")
	if !hasConflict(r, merge.ConflictOverlap) {
		t.Fatalf("derby: a replayed copy from a path the target changed doesn't conflict: %+v", r)
	}
	if !reflect.DeepEqual(r.BranchWrites, []string{"/subtitle", "/title"}) {
		t.Fatalf("branch writes %v", r.BranchWrites)
	}
	c := p.Resource("cup")
	if c.NeedsPerson() || !reflect.DeepEqual(c.BaseWrites, []string{"/half"}) {
		t.Fatalf("cup: %+v", c)
	}

	// The exported forms, with the array rule applied to the from.
	doc := map[string]any{"a": []any{1, 2}, "b": map[string]any{}}
	steps := []client.Step{client.PatchStep(ops(cp("/a/0", "/b/x")))}
	if w := must(merge.BranchWrites(doc, true, steps)); !reflect.DeepEqual(w, []string{"/a", "/b/x"}) {
		t.Fatalf("branch writes %v", w)
	}
	if w := must(merge.Writes(doc, true, steps)); !reflect.DeepEqual(w, []string{"/b/x"}) {
		t.Fatalf("target writes %v", w)
	}
}

// §6.4.1 (v0.67) in the merge tools: an insertion or removal that shifts
// an array's elements writes the array itself, which under the array rule
// (§F.3) is an element of its parent array when arrays nest.
func TestV073MergeWritesShiftedArray(t *testing.T) {
	t.Parallel()
	doc := map[string]any{"rows": []any{[]any{"a", "b"}, []any{"c"}}}
	for _, c := range []struct {
		patch map[string]any
		want  []string
	}{
		{op("add", "/rows/0/0", "z"), []string{"/rows", "/rows/0"}},
		{rm("/rows/0/0"), []string{"/rows", "/rows/0"}},
		{op("add", "/rows/0/-", "z"), []string{"/rows/0"}},
		{rm("/rows/1/0"), []string{"/rows/1"}},
	} {
		w := must(merge.Writes(doc, true, []client.Step{client.PatchStep(ops(c.patch))}))
		if !reflect.DeepEqual(w, c.want) {
			t.Fatalf("%v: writes %v want %v", c.patch, w, c.want)
		}
	}
	// So a branch inserting into one row and a target editing another
	// conflict: the insertion shifted the row, an element of rows.
	e := newEnv(t)
	e.create("matches", "grid", doc)
	e.branch("matches", "r7")
	e.append("r7", "grid", op("add", "/rows/0/0", "z"))
	e.append("matches", "grid", op("replace", "/rows/1/0", "d"))
	if r := e.plan("matches", "r7", merge.Options{}).Resource("grid"); !hasConflict(r, merge.ConflictOverlap) {
		t.Fatalf("grid: %+v", r)
	}
}

// §6.2 step 3 (v0.65) in the merge tools: a create's patch set applies to
// the document null, so the tools fold a branch's create of [test "" null,
// add "" …] as the server does.
func TestV073MergeFoldsCreateOntoNull(t *testing.T) {
	steps := []client.Step{client.PatchStep(ops(op("test", "", nil), op("add", "", map[string]any{"a": 1.0})))}
	w, err := merge.Writes(nil, false, steps)
	if err != nil || !reflect.DeepEqual(w, []string{""}) {
		t.Fatalf("writes %v, %v", w, err)
	}
	d, deleted, err := merge.ApplySteps(nil, false, false, append(steps, client.PatchStep(ops(op("replace", "/a", 2.0)))))
	if err != nil || deleted || !reflect.DeepEqual(d, map[string]any{"a": 2.0}) {
		t.Fatalf("fold %v %v %v", d, deleted, err)
	}
	// A root replace on null creates too.
	if _, _, err := merge.ApplySteps(nil, false, false, []client.Step{client.PatchStep(ops(op("replace", "", map[string]any{})))}); err != nil {
		t.Fatalf("root replace on null: %v", err)
	}
}
