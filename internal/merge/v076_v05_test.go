package merge_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
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

// Review V76-05 (§F.3 "(an index or `-`)"): a write whose last segment is
// an object member, even one named "-", addresses no array element and is
// not widened; neither is a root member "/-" of an object document. An
// add appending with "-" still widens to the outermost array.
func TestV076MergeDashMemberNotWidened(t *testing.T) {
	t.Parallel()
	doc := map[string]any{"-": 0.0, "a": []any{map[string]any{"b": map[string]any{"-": 1.0}, "l": []any{}}, map[string]any{"x": 1.0}}}
	for _, c := range []struct {
		patch map[string]any
		want  []string
	}{
		{op("replace", "/a/0/b/-", 2), []string{"/a/0/b/-"}},
		{op("replace", "/-", 2), []string{"/-"}},
		{op("add", "/a/0/l/-", 2), []string{"/a"}},
	} {
		w := must(merge.Writes(doc, true, []client.Step{client.PatchStep(ops(c.patch))}))
		if !reflect.DeepEqual(w, c.want) {
			t.Errorf("%v: writes %v want %v", c.patch, w, c.want)
		}
	}

	// The branch changes a[0].b's member "-", the base a[1].x: no overlap.
	e := newEnv(t)
	e.create("matches", "grid", doc)
	e.branch("matches", "r7")
	e.append("r7", "grid", op("replace", "/a/0/b/-", 2))
	e.append("matches", "grid", op("replace", "/a/1/x", 2))
	r := e.plan("matches", "r7", merge.Options{}).Resource("grid")
	if r.Class != merge.Replay || len(r.Conflicts) > 0 {
		t.Fatalf("grid: %+v", r)
	}
}

// Review V76-05 (§F.3 kept bullet, §F.5): a rebase with Switch whose first
// replay leaves a resource out (here derby, re-sealed over an undeclarable
// blob) stops before the switch with ErrLeftOut: frozen, the old branch
// would be the only place holding derby's change, and its editors would
// move to a successor without it. The rest is replayed; LeaveOut switches
// anyway.
func TestV076RebaseSwitchStopsOnLeftOut(t *testing.T) {
	t.Parallel()
	c, x, b := v05UndeclarableBase(t)
	body := must(x.SealPatches(ctx, "r7", "derby", b, ops(op("replace", "/score", "1-0"))))
	must(c.Append(ctx, "r7", "derby", b, body))
	opt := merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{E2E: x}}
	res, err := merge.Rebase(ctx, c, opt)
	if !errors.Is(err, merge.ErrLeftOut) || res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"derby"}) {
		t.Fatalf("rebase: %v, %+v", err, res)
	}
	if frozen, _ := must(c.NSDoc(ctx, "r7", must(c.NSHead(ctx, "r7")).ID)).Value["frozen"].(bool); frozen {
		t.Fatal("r7 frozen although derby was left out")
	}
	_, d := must2(x.LoadE2E(ctx, "r7b", "cup"))
	if d.Value.(map[string]any)["score"] != "2-0" {
		t.Fatalf("r7b cup %v", d.Value)
	}
	// Without Switch the rebase only reports it.
	res = must(merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: "r7b", Plan: merge.Options{E2E: x}}))
	if res.Switched || res.First.Resource("derby").HasItem() {
		t.Fatalf("rebase without switch: %+v", res)
	}
	opt.LeaveOut = true
	res = must(merge.Rebase(ctx, c, opt))
	if !res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"derby"}) {
		t.Fatalf("rebase with LeaveOut: %+v", res)
	}
}

// Review V76-05: a resource kept over a tombstone in a rebase can't be
// recorded either (§F.3), so Switch stops on it too unless LeaveOut.
func TestV076RebaseSwitchStopsOnKeptOverTombstone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "cup", op("replace", "/score", "1-0"))
	e.del("matches", "cup")
	keep := func(ctx context.Context, p *merge.Plan) error { return p.Resolve("cup") }
	opt := merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Prepare: keep}
	res, err := merge.Rebase(ctx, e.c, opt)
	if !errors.Is(err, merge.ErrLeftOut) || res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"cup"}) {
		t.Fatalf("rebase: %v, %+v", err, res)
	}
	opt.LeaveOut = true
	if res = must(merge.Rebase(ctx, e.c, opt)); !res.Switched {
		t.Fatalf("rebase with LeaveOut: %+v", res)
	}
}

// Review V76-05: a catch-up that leaves a resource out reports it with
// ErrLeftOut; the switch is done by then. derby's change reaches r7 while
// the first replay is prepared, so only the catch-up holds it.
func TestV076RebaseCatchUpReportsLeftOut(t *testing.T) {
	t.Parallel()
	c, x, b := v05UndeclarableBase(t)
	first := true
	prepare := func(ctx context.Context, p *merge.Plan) error {
		if first {
			first = false
			body, err := x.SealPatches(ctx, "r7", "derby", b, ops(op("replace", "/score", "1-0")))
			if err != nil {
				return err
			}
			_, err = c.Append(ctx, "r7", "derby", b, body)
			return err
		}
		return nil
	}
	res, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{E2E: x}, Prepare: prepare})
	if !errors.Is(err, merge.ErrLeftOut) || !res.Switched || res.CatchUp == nil || !reflect.DeepEqual(res.LeftOut, []string{"derby"}) {
		t.Fatalf("rebase: %v, %+v", err, res)
	}
}

// v05UndeclarableBase returns a client and key holder over "m", e2e from
// its creation, whose derby's head references a blob a sealed op can't
// declare (one with a nonce, of type image/png, §E.3.1), as a writer that
// doesn't follow §E.3.1 can seal it (no declared list), with cup beside
// it, and a branch r7 of m at e2e. b is derby's head.
func v05UndeclarableBase(t *testing.T) (c *client.Client, x *client.E2E, b string) {
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c = s.Client(t, client.WithAuthor("alice"))
	_, priv, err := seal.GenerateRecipient()
	noErr(t, err)
	x = c.E2E(priv)
	must(c.CreateNamespace(ctx, "m", map[string]any{"encryption": map[string]any{"level": "e2e"}, "merge": devAuthors}))
	must(x.InitKeyring(ctx, "m"))
	data := []byte("a picture referenced with a nonce")
	img := client.BlobRef(ids.Of(data).String(), "image/png", len(data), seal.NewNonce())
	body := must(x.SealPatchesBlobs(ctx, "m", "derby", "", client.GenesisPatches(map[string]any{"title": "Derby", "score": "0-0", "img": img}), nil))
	b = must(c.Create(ctx, "m", "derby", body)).ID
	must(x.CreateDocSealed(ctx, "m", "cup", map[string]any{"title": "Cup", "score": "0-0"}))
	must(c.CreateBranch(ctx, "m", client.BranchRequest{Name: "r7"}))
	must(x.InitKeyring(ctx, "r7"))
	cupHead := must(c.Head(ctx, "r7", "cup")).ID
	must(x.AppendSealed(ctx, "r7", "cup", cupHead, ops(op("replace", "/score", "2-0"))))
	return c, x, b
}

// v05WantNoItem applies a plan of r7 into m in which derby fast-forwards
// to a document that references the undeclarable blob: derby gets no item and a
// note saying it is offered again, cup is committed, and the next plan
// offers derby again.
func v05WantNoItem(t *testing.T, c *client.Client, x *client.E2E, b string) {
	t.Helper()
	p := must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward})
	r := p.Resource("derby")
	if r.HasItem() || len(r.Conflicts) > 0 || !strings.Contains(r.Note, "image/png") || !strings.Contains(r.Note, "offered again") {
		t.Fatalf("derby re-sealed over an undeclarable blob: %+v", r)
	}
	if !p.Clean() || len(p.Items()) != 1 {
		t.Fatalf("plan %+v", p.Items())
	}
	res := must(p.Apply(ctx))
	if len(res.Items) != 1 || res.Items[0].Resource != "cup" {
		t.Fatalf("batch %+v", res.Items)
	}
	if got := must(c.Head(ctx, "m", "derby")).ID; got != b {
		t.Fatalf("derby moved to %s", got)
	}
	_, d := must2(x.LoadE2E(ctx, "m", "cup"))
	if d.Value.(map[string]any)["score"] != "2-0" {
		t.Fatalf("cup %v", d.Value)
	}
	p = must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	if r := p.Resource("derby"); r == nil || r.Class != merge.FastForward || r.HasItem() || !strings.Contains(r.Note, "offered again") {
		t.Fatalf("derby not offered again: %+v", r)
	}
}

// OTHER-3 (§E.3.1, v0.76; v0.78 dropped the pre-raise case from §F.3, and
// the check stays as a defensive one): a replayed or re-sealed item whose
// resulting document references a blob a sealed op can't declare stays
// unmerged and is offered again, as an unrecordable kept resource does,
// instead of failing the whole batch with 422 blob.
func TestV076ReSealedUndeclarableBlobMakesNoItem(t *testing.T) {
	t.Parallel()
	// The branch appends to derby, keeping /img and changing /score. A
	// sealed op can't declare the blob, so this op declares none.
	t.Run("append", func(t *testing.T) {
		t.Parallel()
		c, x, b := v05UndeclarableBase(t)
		body := must(x.SealPatches(ctx, "r7", "derby", b, ops(op("replace", "/score", "1-0"))))
		must(c.Append(ctx, "r7", "derby", b, body))
		v05WantNoItem(t, c, x, b)
	})
	// The branch deletes derby and restores it unchanged with [], which
	// keeps the last live document's declared list (§8.2, §E.3.1): the
	// re-sealed restore would declare the blob. (A document referencing
	// sealed blobs only merges so: TestV081ReSealedRestoreKeepsDeclaredBlobs.)
	t.Run("restore", func(t *testing.T) {
		t.Parallel()
		c, x, b := v05UndeclarableBase(t)
		ts := must(c.Delete(ctx, "r7", "derby", b)).ID
		must(x.RestoreSealed(ctx, "r7", "derby", ts, nil))
		v05WantNoItem(t, c, x, b)
	})
}
