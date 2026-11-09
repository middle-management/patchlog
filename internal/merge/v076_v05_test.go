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

// v05RaisedBase returns a client and key holder over "m", raised from
// sealed to e2e, whose derby's head is from before the raise and
// references a blob uploaded at E2 (with a nonce, which a sealed op can't
// declare, §E.3.1), with cup beside it, and a branch r7 of m at e2e. b is
// derby's head.
func v05RaisedBase(t *testing.T) (c *client.Client, x *client.E2E, b string) {
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c = s.Client(t, client.WithAuthor("alice"))
	_, priv, err := seal.GenerateRecipient()
	noErr(t, err)
	x = c.E2E(priv)
	must(c.CreateNamespace(ctx, "m", map[string]any{"encryption": map[string]any{"level": "sealed"}, "merge": devAuthors}))
	data := []byte("a picture uploaded at E2")
	nonce := seal.NewNonce()
	bid := must(c.UploadBlob(ctx, "m", "derby", "image/png", nonce, data))
	b = must(c.Create(ctx, "m", "derby", ops(op("add", "", map[string]any{"title": "Derby", "score": "0-0", "img": client.BlobRef(bid, "image/png", len(data), nonce)}), op("add", "/$nonce", seal.NewNonce())))).ID
	must(c.Create(ctx, "m", "cup", ops(op("add", "", map[string]any{"title": "Cup", "score": "0-0"}), op("add", "/$nonce", seal.NewNonce()))))
	for _, k := range must(c.FetchKeys(ctx, "m", nil, nil)) {
		x.AddKey(k.Kid, k.Key)
	}
	h := must(c.NSHead(ctx, "m"))
	must(c.PatchConfig(ctx, "m", h.Config, ops(op("add", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0}))))
	must(x.InitKeyring(ctx, "m"))
	must(c.CreateBranch(ctx, "m", client.BranchRequest{Name: "r7"}))
	must(x.InitKeyring(ctx, "r7"))
	cupHead := must(c.Head(ctx, "r7", "cup")).ID
	must(x.AppendSealed(ctx, "r7", "cup", cupHead, ops(op("replace", "/score", "2-0"))))
	return c, x, b
}

// v05WantNoItem applies a plan of r7 into m in which derby fast-forwards
// to a document that references the E2 blob: derby gets no item and a
// note saying it is offered again, cup is committed, and the next plan
// offers derby again.
func v05WantNoItem(t *testing.T, c *client.Client, x *client.E2E, b string) {
	t.Helper()
	p := must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward})
	r := p.Resource("derby")
	if r.HasItem() || len(r.Conflicts) > 0 || !strings.Contains(r.Note, "image/png") || !strings.Contains(r.Note, "offered again") {
		t.Fatalf("derby re-sealed over an E2 blob: %+v", r)
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

// OTHER-3 (§F.3 kept bullet, §E.3.1, v0.76): a replayed or re-sealed item
// whose resulting document references a blob a sealed op can't declare
// stays unmerged and is offered again, as a kept head does, instead of
// failing the whole batch with 422 blob.
func TestV076ReSealedPreRaiseBlobMakesNoItem(t *testing.T) {
	t.Parallel()
	// The branch appends to derby, keeping /img and changing /score. An
	// e2e write can't declare the E2 blob, so this op declares none.
	t.Run("append", func(t *testing.T) {
		t.Parallel()
		c, x, b := v05RaisedBase(t)
		body := must(x.SealPatches(ctx, "r7", "derby", b, ops(op("replace", "/score", "1-0"))))
		must(c.Append(ctx, "r7", "derby", b, body))
		v05WantNoItem(t, c, x, b)
	})
	// The branch deletes derby and restores it unchanged with [], which
	// keeps the last live document's declared list (§8.2, §E.3.1): the
	// re-sealed restore would declare the E2 blob.
	t.Run("restore", func(t *testing.T) {
		t.Parallel()
		c, x, b := v05RaisedBase(t)
		ts := must(c.Delete(ctx, "r7", "derby", b)).ID
		must(x.RestoreSealed(ctx, "r7", "derby", ts, nil))
		v05WantNoItem(t, c, x, b)
	})
}
