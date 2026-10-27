package merge

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// §E.3.1 Declared blobs: a sealed op declares only blobs of the sealed type
// without a nonce.
func TestV073UndeclarableBlob(t *testing.T) {
	sealed := map[string]any{"$blob": "1aaa", "type": client.SealedBlobType, "size": 9.0,
		"sealed": map[string]any{"key": "k", "type": "image/png", "size": 3.0}}
	for _, c := range []struct {
		doc  any
		want string
	}{
		{map[string]any{"img": sealed}, ""},
		{map[string]any{"title": "x"}, ""},
		{map[string]any{"a": []any{sealed, map[string]any{"$blob": "1bbb", "type": "image/png", "size": 3.0, "nonce": "abcdefghijklmnopqrstuvwxyz"}}}, "1bbb"},
		{map[string]any{"img": map[string]any{"$blob": "1ccc", "type": client.SealedBlobType, "size": 9.0, "nonce": "abcdefghijklmnopqrstuvwxyz"}}, "1ccc with a nonce"},
		{map[string]any{"img": map[string]any{"$blob": "1ddd", "type": "image/png", "size": 3.0}}, `1ddd of type "image/png"`},
		// Schema documents hold no references (§7.8).
		{map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "x": map[string]any{"$blob": "1eee", "type": "image/png"}}, ""},
	} {
		got := undeclarableBlob(c.doc)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Fatalf("%v: %q, want %q", c.doc, got, c.want)
		}
	}
}

// §F.3 kept bullet (v0.73): at E3 a resource kept at a live base head that
// references a blob a sealed op can't declare gets no item: it stays
// unmerged and is offered again, and the plan says why. One whose head
// references only declarable blobs is recorded with the sealed empty set.
func TestV073E3KeptUndeclarableBlobNoItem(t *testing.T) {
	for _, block := range []string{"", `blob 1ddd of type "image/png"`} {
		r := &Resource{Name: "derby", Class: Replay, Base: "1base", BaseState: client.Live.String(), IfMatch: "1base", keepBlock: block}
		r.conflict(ConflictOverlap, "both sides wrote", "/img")
		p := &Plan{Target: "m", Branch: "r7", TargetLevel: "e2e", Resources: []*Resource{r}}
		if err := p.Resolve("derby"); err != nil {
			t.Fatal(err)
		}
		if !p.Clean() || !r.Dropped {
			t.Fatalf("%q: %+v", block, r)
		}
		if block == "" {
			if !r.Kept || !r.HasItem() || r.IfMatch != "1base" || len(p.Items()) != 1 {
				t.Fatalf("kept without undeclarable blobs: %+v", r)
			}
			continue
		}
		if r.Kept || r.HasItem() || len(p.Items()) != 0 || r.IfMatch != "" {
			t.Fatalf("kept over an undeclarable blob has an item: %+v", r)
		}
		if !strings.Contains(r.Note, block) || !strings.Contains(r.Note, "offered again (§F.3, §E.3.1)") {
			t.Fatalf("note %q", r.Note)
		}
		if st := p.Status(); len(st) != 1 || st[0].Note != r.Note {
			t.Fatalf("status %+v", st)
		}
	}
}

// §F.9 plan digest steps: plaintext patch sets without fresh $nonce ops
// and without a fresh top-level $nonce in a root operation's value, or
// "delete"; gestures, undoes and signatures left out.
func TestV073DigestSteps(t *testing.T) {
	fresh := "abcdefghijklmnopqrstuvwxyz"
	steps := []client.Step{
		client.PatchStep([]any{
			map[string]any{"op": "replace", "path": "/title", "value": "x"},
			map[string]any{"op": "add", "path": "/$nonce", "value": fresh},
			map[string]any{"op": "replace", "path": "/$nonce", "value": fresh},
			map[string]any{"op": "add", "path": "/$nonce", "value": "not-fresh"},
			map[string]any{"op": "remove", "path": "/$nonce"},
			map[string]any{"op": "add", "path": "/a/$nonce", "value": fresh},
		}).WithGesture("1ggggggggggggggggggggggggggggggg", ""),
		client.PatchStep([]any{map[string]any{"op": "add", "path": "", "value": map[string]any{"t": 1.0, "$nonce": fresh, "in": map[string]any{"$nonce": fresh}}}}),
		client.PatchStep([]any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"$nonce": "short"}}}),
		client.DeleteStep(),
	}
	got := string(jsonv.Canonical(jsonv.FromGo(digestSteps(steps))))
	want := `[[{"op":"replace","path":"/title","value":"x"},{"op":"add","path":"/$nonce","value":"not-fresh"},{"op":"remove","path":"/$nonce"},{"op":"add","path":"/a/$nonce","value":"` + fresh + `"}],` +
		`[{"op":"add","path":"","value":{"in":{"$nonce":"` + fresh + `"},"t":1}}],` +
		`[{"op":"replace","path":"","value":{"$nonce":"short"}}],"delete"]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// §F.9 plan shape: batches in submission order, a step with no items
// isn't one, and a precondition on an earlier batch's item is
// { "batch", "item" }, indices from 0.
func TestV073PlanObject(t *testing.T) {
	branches := []*ReleaseBranch{{Key: "cat", NS: "cat-r7", Target: "cat", At: "1catat"}, {Key: "m", NS: "m-r7", Target: "m", At: "1mat"}}
	s2 := &ReleaseStep{Step: 2, Key: "cat"}
	s3 := &ReleaseStep{Step: 3, Key: "m"}
	s3b := &ReleaseStep{Step: 3, Key: "x"}
	s4 := &ReleaseStep{Step: 4, Key: "cat"}
	items := map[*ReleaseStep][]any{
		s2: {digestItem("a", map[string]any{"ifMatch": "1a"}, nil), digestItem("node", map[string]any{"ifMatch": "1n"}, nil)},
		s3: {},
		s4: {digestItem("new", map[string]any{"ifNoneMatch": "*"}, nil), digestItem("node", map[string]any{"after": map[string]any{"step": 2, "key": "cat", "item": "node"}}, nil)},
	}
	plan, err := PlanObject("/r/rel/r7/rev/1rev", branches, []*ReleaseStep{s2, s3, s3b, s4}, items)
	if err != nil {
		t.Fatal(err)
	}
	got := string(jsonv.Canonical(jsonv.FromGo(plan)))
	want := `{"batches":[` +
		`{"items":[{"ifMatch":"1a","resource":"a","steps":[]},{"ifMatch":"1n","resource":"node","steps":[]}],"ns":"cat","source":{"at":"1catat","ns":"cat-r7"}},` +
		`{"items":[{"ifNoneMatch":"*","resource":"new","steps":[]},{"ifMatch":{"batch":0,"item":1},"resource":"node","steps":[]}],"ns":"cat","source":{"at":"1catat","ns":"cat-r7"}}` +
		`],"release":"/r/rel/r7/rev/1rev"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if PlanDigest(plan) != ids.Of([]byte(want)).String() {
		t.Fatal("the digest isn't text(trunc160(sha256(canonical(plan))))")
	}
}

// LegacyPlan rewrites rp as an earlier version stored it, for tests of a
// merge that version stopped part-way: no format, no branch at, and the
// step digests of the steps not done yet as that version rendered them.
func LegacyPlan(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan) error {
	for _, st := range rp.Steps {
		if st.Done != "" {
			continue
		}
		_, its, err := stepPlan(ctx, c, opt, rp, st, false)
		if err != nil {
			return err
		}
		st.Digest = stepDigest(st, legacyDigestItems(its))
	}
	rp.Format = 0
	for _, b := range rp.Branches {
		b.At = ""
	}
	return nil
}

// §F.9 "a merge that stops part-way resumes from that plan": a plan an
// earlier version stored (format 0) has step digests over items rendered
// as that version did ($nonce members and $nonce op values left out, items
// by name); a step of such a plan is approved under either rendering, one
// of the current format only under its own.
func TestV073LegacyStepDigests(t *testing.T) {
	fresh := "abcdefghijklmnopqrstuvwxyz"
	items := []stepItem{
		{"zeta", map[string]any{"ifMatch": "1z"}, []client.Step{client.PatchStep([]any{
			map[string]any{"op": "add", "path": "/$nonce", "value": fresh},
			map[string]any{"op": "add", "path": "/a", "value": map[string]any{"$nonce": fresh, "b": 1.0}},
		})}},
		{"alpha", map[string]any{"ifNoneMatch": "*"}, []client.Step{client.DeleteStep()}},
	}
	got := string(jsonv.Canonical(jsonv.FromGo(legacyDigestItems(items))))
	want := `[{"ifNoneMatch":"*","resource":"alpha","steps":["delete"]},` +
		`{"ifMatch":"1z","resource":"zeta","steps":[[{"op":"add","path":"/$nonce"},{"op":"add","path":"/a","value":{"b":1}}]]}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	st := &ReleaseStep{Step: 1, Key: "schemas", Resources: []string{"zeta", "alpha"}}
	legacy, current := stepDigest(st, legacyDigestItems(items)), stepDigest(st, digestItems(st, items))
	if legacy == current {
		t.Fatal("the renderings agree; the test shows nothing")
	}
	for _, c := range []struct {
		format int
		digest string
		want   bool
	}{{0, legacy, true}, {0, current, true}, {PlanFormat, current, true}, {PlanFormat, legacy, false}, {0, "1other", false}} {
		st.Digest = c.digest
		if got := approvedStep(&ReleasePlan{Format: c.format}, st, items); got != c.want {
			t.Fatalf("format %d, digest %s: approved %v", c.format, c.digest, got)
		}
	}
}
