package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// §C.7, §F.3: in a target that requires nonces, the step that keeps a
// resource at the base's version only adds a fresh $nonce, and resolution
// and squash sets get one too.
func TestRequiredNoncesMerge(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "nonce": "required", "merge": devAuthors}))
	nonced := func(ps ...map[string]any) []any {
		return append(ops(ps...), op("add", "/$nonce", seal.NewNonce()))
	}
	for _, n := range []string{"derby", "cup", "semi"} {
		must(c.Create(ctx, "matches", n, nonced(op("add", "", map[string]any{"score": "0-0"}))))
	}
	e.branch("matches", "r7")
	for _, n := range []string{"derby", "cup"} {
		must(c.Append(ctx, "r7", n, e.head("r7", n).ID, nonced(op("replace", "/score", "1-0"))))
		must(c.Append(ctx, "matches", n, e.head("matches", n).ID, nonced(op("replace", "/score", "0-1"))))
	}
	must(c.Append(ctx, "r7", "semi", e.head("r7", "semi").ID, nonced(op("replace", "/score", "1-0"))))
	must(c.Append(ctx, "r7", "semi", e.head("r7", "semi").ID, nonced(op("add", "/x", true))))

	p := e.plan("matches", "r7", merge.Options{Squash: true})
	if !p.TargetNonce {
		t.Fatal("TargetNonce not set")
	}
	lastNonce := func(st client.Step) bool {
		ps, _ := st.Patches.([]any)
		o, _ := ps[len(ps)-1].(map[string]any)
		v, _ := o["value"].(string)
		return o["op"] == "add" && o["path"] == "/$nonce" && seal.ValidNonce(v)
	}
	// Kept at the base: a lone fresh nonce.
	noErr(t, p.Resolve("derby"))
	d := p.Resource("derby")
	if ps, _ := d.Steps[0].Patches.([]any); !d.Kept || len(ps) != 1 || !lastNonce(d.Steps[0]) {
		t.Fatalf("keep step %+v", d.Steps)
	}
	// A resolution set.
	noErr(t, p.Resolve("cup", client.PatchStep(ops(op("replace", "/score", "1-1")))))
	if cs := p.Resource("cup").Steps; len(cs) != 1 || !lastNonce(cs[0]) {
		t.Fatalf("resolution %+v", cs)
	}
	// A squash set, its nonce fresh rather than the branch's.
	sm := p.Resource("semi")
	if !sm.Squashed || len(sm.Steps) != 1 || !lastNonce(sm.Steps[0]) {
		t.Fatalf("squash %+v", sm)
	}
	if ps := sm.Steps[0].Patches.([]any); len(ps) != 3 {
		t.Fatalf("squash set %v", ps)
	}
	before := e.head("matches", "derby").ID
	must(p.Apply(ctx))
	if e.head("matches", "derby").ID == before {
		t.Fatal("keep not recorded")
	}
	for n, want := range map[string]string{"derby": "0-1", "cup": "1-1", "semi": "1-0"} {
		if doc := e.doc("matches", n).(map[string]any); doc["score"] != want {
			t.Fatalf("%s: %v", n, doc)
		}
	}
}
