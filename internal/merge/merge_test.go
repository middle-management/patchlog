package merge_test

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
)

var ctx = context.Background()

// must panics on error; the test fails with the error and stack.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func noErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func op(o, path string, v any) map[string]any {
	return map[string]any{"op": o, "path": path, "value": v}
}

func rm(path string) map[string]any { return map[string]any{"op": "remove", "path": path} }

func ops(o ...map[string]any) []any {
	out := make([]any, len(o))
	for i, x := range o {
		out[i] = x
	}
	return out
}

var devAuthors = map[string]any{"authors": []any{map[string]any{"sub": "alice", "kid": "dev"}}}

type env struct {
	t *testing.T
	s *clienttest.Server
	c *client.Client
}

func newEnv(t *testing.T) *env {
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	e := &env{t: t, s: s, c: c}
	// Authentication is off, so entries record no grant and, for a merger
	// without one, merge.authors matches on sub alone (merge.EntryListed).
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "merge": devAuthors}))
	e.create("matches", "derby", map[string]any{"title": "Derby", "score": "0-0", "blocks": []any{"a", "b", "c"}})
	e.create("matches", "cup", map[string]any{"title": "Cup", "score": "1-1"})
	return e
}

func (e *env) create(ns, name string, doc any) string {
	e.t.Helper()
	return must(e.c.CreateDoc(ctx, ns, name, doc)).ID
}

func (e *env) head(ns, name string) *client.Head {
	e.t.Helper()
	return must(e.c.Head(ctx, ns, name))
}

func (e *env) append(ns, name string, patches ...map[string]any) string {
	e.t.Helper()
	h := e.head(ns, name)
	return must(e.c.Append(ctx, ns, name, h.ID, ops(patches...))).ID
}

func (e *env) del(ns, name string) string {
	e.t.Helper()
	h := e.head(ns, name)
	return must(e.c.Delete(ctx, ns, name, h.ID)).ID
}

func (e *env) doc(ns, name string) any {
	e.t.Helper()
	_, d := must2(e.c.Load(ctx, ns, name))
	if d == nil {
		return nil
	}
	return d.Value
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func (e *env) branch(base, name string) {
	e.t.Helper()
	must(e.c.CreateBranch(ctx, base, client.BranchRequest{Name: name}))
}

func (e *env) plan(target, branch string, opt merge.Options) *merge.Plan {
	e.t.Helper()
	return must(merge.NewPlan(ctx, e.c, target, branch, opt))
}

func classes(p *merge.Plan) map[string]merge.Class {
	out := map[string]merge.Class{}
	for _, r := range p.Resources {
		out[r.Name] = r.Class
	}
	return out
}

func wantClasses(t *testing.T, p *merge.Plan, want map[string]merge.Class) {
	t.Helper()
	got := classes(p)
	if len(got) != len(want) {
		t.Fatalf("classes %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: class %s, want %s (all: %v)", k, got[k], v, got)
		}
	}
}

func hasConflict(r *merge.Resource, kind string) bool {
	for _, c := range r.Conflicts {
		if c.Kind == kind {
			return true
		}
	}
	return false
}

func TestFastForwardReproducesIDs(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "derby", op("replace", "/score", "2-0"))
	e.del("r7", "cup")
	e.create("r7", "final", map[string]any{"title": "Final"})

	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward, "final": merge.FastForward})
	if f := p.Resource("final"); !f.IfNoneMatch || f.IfMatch != "" {
		t.Fatalf("final: want ifNoneMatch, got %+v", f)
	}
	if d := p.Resource("derby"); len(d.Steps) != 2 || len(d.Expected) != 2 || d.IfMatch == "" {
		t.Fatalf("derby item %+v", d)
	}
	if !p.Clean() {
		t.Fatal("not clean")
	}
	dry := must(p.DryRun(ctx))
	if len(dry.Items) != 3 {
		t.Fatalf("dry run %+v", dry)
	}
	res := must(p.Apply(ctx))
	for _, n := range []string{"derby", "cup", "final"} {
		b, h := e.head("matches", n), e.head("r7", n)
		if b.ID != h.ID || b.State != h.State {
			t.Fatalf("%s: base %+v, branch %+v", n, b, h)
		}
	}
	// The batch entry carries source { ns, at }.
	nh := must(e.c.NSHead(ctx, "matches"))
	log := must(e.c.NSLog(ctx, "matches", nh.ID, ""))
	last := log[len(log)-1]
	if last.ID != res.NSID || last.Kind != "batch" || last.Source["ns"] != "r7" || last.Source["at"] != p.BranchAt {
		t.Fatalf("batch entry %+v", last)
	}

	// Merging again: already merged, nothing to do.
	p2 := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p2, map[string]merge.Class{"derby": merge.Merged, "cup": merge.Merged, "final": merge.Merged})
	if r := must(p2.Apply(ctx)); !r.Noop {
		t.Fatalf("second apply %+v", r)
	}

	// Freeze records merged.at.
	must(merge.Freeze(ctx, e.c, "r7", res.NSID))
	bh := must(e.c.NSHead(ctx, "r7"))
	doc := must(e.c.NSDoc(ctx, "r7", bh.ID))
	if doc.Value["frozen"] != true || doc.Value["merged"].(map[string]any)["at"] != res.NSID {
		t.Fatalf("frozen doc %v", doc.Value)
	}
}

func TestBaseAheadIsNothing(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	must(e.plan("matches", "r7", merge.Options{}).Apply(ctx))
	e.append("matches", "derby", op("replace", "/score", "1-1"))
	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.Behind})
	if st := p.Resource("derby").Status(); st != "behind" {
		t.Fatalf("status %s", st)
	}
	if len(p.Items()) != 0 {
		t.Fatal("items for a resource the base is ahead on")
	}
}

func TestReplayWithoutOverlap(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	h := e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("matches", "derby", op("replace", "/title", "The Derby"))
	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.Replay})
	r := p.Resource("derby")
	if r.NeedsPerson() || r.Status() != "clean" || r.Expected != nil {
		t.Fatalf("replay %+v", r)
	}
	if len(r.BranchWrites) != 1 || r.BranchWrites[0] != "/score" || r.BaseWrites[0] != "/title" {
		t.Fatalf("writes %v %v", r.BranchWrites, r.BaseWrites)
	}
	res := must(p.Apply(ctx))
	if res.IDs["derby"][0] == h {
		t.Fatal("replay reproduced the branch id")
	}
	d := e.doc("matches", "derby").(map[string]any)
	if d["score"] != "1-0" || d["title"] != "The Derby" {
		t.Fatalf("doc %v", d)
	}
}

func TestOverlapAndArrayRule(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("matches", "derby", op("replace", "/score", "0-1"))
	// Array rule: base inserts at /blocks/0, branch removes /blocks/2 in
	// another resource; as pointers they don't overlap, as arrays they do.
	e.create("matches", "semi", map[string]any{"blocks": []any{"a", "b", "c"}, "x": 1})
	e.branch("matches", "r8")
	e.append("r8", "semi", rm("/blocks/2"))
	e.append("matches", "semi", op("add", "/blocks/0", "z"))

	p := e.plan("matches", "r7", merge.Options{})
	r := p.Resource("derby")
	if r.Class != merge.Replay || !hasConflict(r, merge.ConflictOverlap) || r.Status() != "conflicting" {
		t.Fatalf("derby %+v", r)
	}
	if _, err := p.Apply(ctx); !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("apply with conflicts: %v", err)
	}
	// Resolve against B.
	noErr(t, p.Resolve("derby", client.PatchStep(ops(op("replace", "/score", "1-1")))))
	if !p.Clean() {
		t.Fatal("still conflicting")
	}
	must(p.Apply(ctx))
	if d := e.doc("matches", "derby").(map[string]any); d["score"] != "1-1" {
		t.Fatalf("resolved doc %v", d)
	}

	p8 := e.plan("matches", "r8", merge.Options{})
	s := p8.Resource("semi")
	if !hasConflict(s, merge.ConflictOverlap) {
		t.Fatalf("array rule: %+v", s)
	}
	if s.BranchWrites[0] != "/blocks" || s.BaseWrites[0] != "/blocks" {
		t.Fatalf("writes %v %v", s.BranchWrites, s.BaseWrites)
	}
	// Different keys of an object inside the array are still the array.
	w, err := merge.Writes(map[string]any{"a": []any{map[string]any{"k": 1}}}, true, []client.Step{client.PatchStep(ops(op("replace", "/a/0/k", 2)))})
	if err != nil || len(w) != 1 || w[0] != "/a/0/k" {
		t.Fatalf("nested writes %v %v", w, err)
	}
	w, err = merge.Writes(map[string]any{"a": []any{1}}, true, []client.Step{client.PatchStep(ops(op("add", "/a/-", 2)))})
	if err != nil || len(w) != 1 || w[0] != "/a" {
		t.Fatalf("append writes %v %v", w, err)
	}
}

func TestDeleteChangeNeedsPerson(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.del("r7", "derby")
	e.append("matches", "derby", op("replace", "/score", "5-5"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.del("matches", "cup")
	p := e.plan("matches", "r7", merge.Options{})
	if r := p.Resource("derby"); !hasConflict(r, merge.ConflictDeleteVsChange) {
		t.Fatalf("derby %+v", r)
	}
	if r := p.Resource("cup"); !hasConflict(r, merge.ConflictChangeVsDelete) {
		t.Fatalf("cup %+v", r)
	}
	if p.Clean() {
		t.Fatal("clean")
	}
	// Keep the base for derby, and let the branch restore cup.
	noErr(t, p.Resolve("derby"))
	noErr(t, p.Resolve("cup", client.PatchStep(ops(op("replace", "/score", "2-1")))))
	must(p.Apply(ctx))
	if h := e.head("matches", "cup"); h.State != client.Live {
		t.Fatalf("cup %+v", h)
	}
	if d := e.doc("matches", "derby").(map[string]any); d["score"] != "5-5" {
		t.Fatalf("derby %v", d)
	}
}

func TestBaseMovesBetweenPlanAndApply(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward})
	e.append("matches", "derby", op("replace", "/title", "Moved"))
	res := must(p.Apply(ctx))
	if res.Attempts != 2 {
		t.Fatalf("attempts %d", res.Attempts)
	}
	if p.Resource("derby").Class != merge.Replay {
		t.Fatalf("derby not re-classified: %+v", p.Resource("derby"))
	}
	if e.head("matches", "cup").ID != e.head("r7", "cup").ID {
		t.Fatal("cup lost its fast-forward ids")
	}
	d := e.doc("matches", "derby").(map[string]any)
	if d["score"] != "1-0" || d["title"] != "Moved" {
		t.Fatalf("doc %v", d)
	}

	// A move that overlaps turns into a conflict on re-classification.
	e.append("r7", "cup", op("replace", "/score", "3-1"))
	p2 := e.plan("matches", "r7", merge.Options{})
	e.append("matches", "cup", op("replace", "/score", "9-9"))
	if _, err := p2.Apply(ctx); !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("want conflicts, got %v", err)
	}
}

func TestSecondMergePicksUpNewChanges(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.append("matches", "cup", op("replace", "/title", "Cup!")) // cup replays
	must(e.plan("matches", "r7", merge.Options{}).Apply(ctx))

	e.append("r7", "derby", op("replace", "/score", "2-0"))
	e.append("r7", "cup", op("replace", "/score", "3-1"))
	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.Replay})
	d, c := p.Resource("derby"), p.Resource("cup")
	if len(d.Steps) != 1 || len(c.Steps) != 1 || c.NeedsPerson() {
		t.Fatalf("derby %+v cup %+v", d, c)
	}
	must(p.Apply(ctx))
	if e.head("matches", "derby").ID != e.head("r7", "derby").ID {
		t.Fatal("derby ids differ")
	}
	cd := e.doc("matches", "cup").(map[string]any)
	if cd["score"] != "3-1" || cd["title"] != "Cup!" {
		t.Fatalf("cup %v", cd)
	}
	// Nothing new: all merged.
	p3 := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p3, map[string]merge.Class{"derby": merge.Merged, "cup": merge.Merged})
}

func TestStackedRetargetAfterFastForward(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-2"))
	e.branch("r7", "b2")
	e.append("b2", "derby", op("replace", "/score", "2-0"))
	e.create("b2", "extra", map[string]any{"n": 1})

	must(e.plan("matches", "r7", merge.Options{}).Apply(ctx))
	res, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "b2", New: "b2-b", Onto: "matches"})
	if err != nil {
		t.Fatal(err)
	}
	wantClasses(t, res.First, map[string]merge.Class{"derby": merge.FastForward, "extra": merge.FastForward})
	for _, n := range []string{"derby", "extra", "cup"} {
		if a, b := e.head("b2-b", n), e.head("b2", n); a.ID != b.ID {
			t.Fatalf("%s: %s vs %s", n, a.ID, b.ID)
		}
	}
	if _, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "b2", New: "b2-c", Onto: "matches", Switch: true}); err == nil {
		t.Fatal("switch to a successor with another base")
	}
}

func TestRebaseAndSwitch(t *testing.T) {
	e := newEnv(t)
	must(e.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7", Patches: ops(op("add", "/cleanup", map[string]any{"merged": "P7D"}))}))
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.append("matches", "cup", op("replace", "/title", "Cup!"))

	res, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Switched || res.FirstResult == nil {
		t.Fatalf("result %+v", res)
	}
	if e.head("r7-b", "derby").ID != e.head("r7", "derby").ID {
		t.Fatal("derby ids differ after rebase")
	}
	cd := e.doc("r7-b", "cup").(map[string]any)
	if cd["score"] != "2-1" || cd["title"] != "Cup!" {
		t.Fatalf("cup %v", cd)
	}
	nh := must(e.c.NSHead(ctx, "r7-b"))
	nd := must(e.c.NSDoc(ctx, "r7-b", nh.ID))
	if nd.Value["cleanup"] == nil {
		t.Fatalf("cleanup not copied: %v", nd.Value)
	}
	// The old branch is frozen with its successor.
	h := e.head("r7", "derby")
	_, err = e.c.Append(ctx, "r7", "derby", h.ID, ops(op("replace", "/score", "9-9")))
	ae, ok := client.AsAPIError(err)
	if !client.IsFrozen(err) || !ok || ae.Successor() != "r7-b" {
		t.Fatalf("write to old branch: %v", err)
	}
	// Merging the successor into the base: derby fast-forwards to the same
	// ids the old branch had.
	p := e.plan("matches", "r7-b", merge.Options{})
	must(p.Apply(ctx))
	if e.head("matches", "derby").ID != e.head("r7", "derby").ID {
		t.Fatal("derby ids differ after merging the successor")
	}
	// Status of the old generation against its successor: all merged.
	st := must(merge.Status(ctx, e.c, "r7-b", "r7"))
	for _, s := range st {
		if s.Status != "merged" {
			t.Fatalf("status %+v", st)
		}
	}
}

func TestRebaseCatchUpAfterResume(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.append("matches", "cup", op("replace", "/title", "Cup!"))
	must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b"}))
	// The old branch keeps working; a later rebase resumes and replays only
	// what is new, from the merge point of the first replay.
	e.append("r7", "cup", op("replace", "/score", "3-1"))
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true}))
	c := res.First.Resource("cup")
	if c.Class != merge.Replay || len(c.Steps) != 1 || c.NeedsPerson() {
		t.Fatalf("cup %+v", c)
	}
	if d := e.doc("r7-b", "cup").(map[string]any); d["score"] != "3-1" || d["title"] != "Cup!" {
		t.Fatalf("cup %v", d)
	}
}

func TestSquash(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "derby", op("replace", "/score", "2-0"), op("add", "/blocks/1", "x"))
	e.append("r7", "derby", rm("/title"))
	e.create("r7", "final", map[string]any{"t": 1})
	e.append("r7", "final", op("add", "/u", 2))
	e.del("r7", "cup")
	p := e.plan("matches", "r7", merge.Options{Squash: true})
	for _, r := range p.Items() {
		if len(r.Steps) != 1 || !r.Squashed || r.Expected != nil {
			t.Fatalf("%s: %+v", r.Name, r)
		}
	}
	must(p.Apply(ctx))
	for _, n := range []string{"derby", "final"} {
		if !jsonv.Equal(e.doc("matches", n), e.doc("r7", n)) {
			t.Fatalf("%s: %v vs %v", n, e.doc("matches", n), e.doc("r7", n))
		}
	}
	if e.head("matches", "derby").ID == e.head("r7", "derby").ID {
		t.Fatal("squash kept ids")
	}
	if e.head("matches", "cup").State != client.Tombstoned {
		t.Fatal("cup not deleted")
	}
}

func TestExplicitConfig(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	must(e.c.PatchConfig(ctx, "r7", must(e.c.NSHead(ctx, "r7")).Config, ops(op("add", "/cleanup", map[string]any{"merged": "P1D"}))))
	p := e.plan("matches", "r7", merge.Options{Config: ops(op("add", "/x-release", 7))})
	must(p.Apply(ctx))
	h := must(e.c.NSHead(ctx, "matches"))
	d := must(e.c.NSDoc(ctx, "matches", h.ID))
	if d.Value["x-release"] != float64(7) || d.Value["cleanup"] != nil {
		t.Fatalf("base config %v", d.Value)
	}
}

func TestPurges(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	// A purge in the base propagates to the branch (§8.3).
	must(e.c.Purge(ctx, "matches", "cup", e.head("matches", "cup").ID, false))
	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.Purged})
	must(p.Apply(ctx))
	must(merge.Freeze(ctx, e.c, "r7", must(e.c.NSHead(ctx, "matches")).ID))
	must(e.c.PurgeNamespace(ctx, "r7", must(e.c.NSHead(ctx, "r7")).ID))
	p = e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.Purged, "cup": merge.Purged})
}
