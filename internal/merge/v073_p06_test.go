package merge_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
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

func nsDoc(t *testing.T, c *client.Client, ns string) map[string]any {
	t.Helper()
	h := must(c.NSHead(ctx, ns))
	return must(c.NSDoc(ctx, ns, h.ID)).Value
}

// §F.5 step 1, §2.1 (v0.68, v0.69): the successor of a sealed branch whose
// read is public is created with read "grant": as a target a sealed public
// namespace ranks public, below the old branch, which ranks sealed as a
// source whatever its read. The replay then goes in.
func TestV073RebaseSealedPublicSuccessorGrant(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	nonced := func(ps ...map[string]any) []any { return append(ops(ps...), op("add", "/$nonce", seal.NewNonce())) }
	must(c.Create(ctx, "matches", "derby", nonced(op("add", "", map[string]any{"score": "0-0"}))))
	e.branch("matches", "r7") // no read patch: read public, sealed
	if d := nsDoc(t, c, "r7"); d["read"] != "public" {
		t.Fatalf("r7 %v", d)
	}
	must(c.Append(ctx, "r7", "derby", e.head("r7", "derby").ID, nonced(op("replace", "/score", "1-0"))))

	res, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true})
	noErr(t, err)
	if !res.Created || res.FirstResult == nil || !res.Switched {
		t.Fatalf("rebase %+v", res)
	}
	if d := nsDoc(t, c, "r7-b"); d["read"] != "grant" {
		t.Fatalf("successor read %v, want grant", d["read"])
	}
	if e.head("r7-b", "derby").ID != e.head("r7", "derby").ID {
		t.Fatal("derby didn't fast-forward into the successor")
	}
}

// §F.5 step 1: the old branch's read is its document's, "grant" by
// default; a successor copying a base that became public since doesn't
// take the base's.
func TestV073RebaseSuccessorKeepsDefaultRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	must(e.c.CreateNamespace(ctx, "drafts", map[string]any{}))
	e.create("drafts", "memo", map[string]any{"t": "a"})
	e.branch("drafts", "d7")
	e.append("d7", "memo", op("replace", "/t", "b"))
	h := must(e.c.NSHead(ctx, "drafts"))
	must(e.c.PatchConfig(ctx, "drafts", h.Config, ops(op("add", "/read", "public"))))
	if _, ok := nsDoc(t, e.c, "d7")["read"]; ok {
		t.Fatal("d7 has a read member")
	}
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "d7", New: "d7-b"}))
	if !res.Created || res.FirstResult == nil {
		t.Fatalf("rebase %+v", res)
	}
	if d := nsDoc(t, e.c, "d7-b"); d["read"] != "grant" {
		t.Fatalf("successor read %v, want grant", d["read"])
	}
}

// §F.5 step 1 (v0.68): a rebase never replays into a successor that ranks
// below the old branch, a resumed one included; the error names both
// ranks, and nothing is written.
func TestV073RebaseRefusesLowerSuccessor(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	must(e.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7", Patches: ops(op("add", "/read", "grant"))}))
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.branch("matches", "r7-b") // public, as matches
	before := must(e.c.NSHead(ctx, "r7-b")).ID
	_, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true})
	if err == nil || !strings.Contains(err.Error(), "ranks public") || !strings.Contains(err.Error(), "ranks private") {
		t.Fatalf("rebase into a public successor of a private branch: %v", err)
	}
	if after := must(e.c.NSHead(ctx, "r7-b")).ID; after != before {
		t.Fatal("something was replayed into the successor")
	}
	if f, _ := nsDoc(t, e.c, "r7")["frozen"].(bool); f {
		t.Fatal("the old branch was switched")
	}
}

// §7.4, §F.5 (v0.63): a successor may be a branch of a namespace further up
// the old branch's base chain, so Switch is allowed when Onto is in it
// (retargeting a stacked branch after a fast-forward merge, §F.4), and
// refused when it isn't.
func TestV073RebaseSwitchUpTheChain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.branch("r7", "b2")
	e.append("b2", "derby", op("replace", "/score", "2-0"))
	must(e.plan("matches", "r7", merge.Options{}).Apply(ctx))
	must(e.c.CreateNamespace(ctx, "elsewhere", map[string]any{"read": "public"}))
	if _, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "b2", New: "b2-x", Onto: "elsewhere", Switch: true}); err == nil || !strings.Contains(err.Error(), "base chain") {
		t.Fatalf("switch to a successor outside the base chain: %v", err)
	}
	res, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "b2", New: "b2-b", Onto: "matches", Switch: true})
	if res == nil || !res.Created || res.FirstResult == nil {
		t.Fatalf("rebase onto the base's base: %+v, %v", res, err)
	}
	// The switch is the server's to accept (§7.4): until it accepts a
	// successor up the chain it is a 422 there, never the tool's refusal.
	if err != nil {
		t.Logf("switch: %v", err)
		if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 || res.Switched {
			t.Fatalf("switch: %v", err)
		}
	} else if !res.Switched {
		t.Fatalf("not switched: %+v", res)
	}
}
