package merge_test

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/sig"
)

// MRG-16, MRG-19: a namespace that keeps its schemas beside its content
// drafts them in its own branch, merging its schema resources in step 1
// and the rest in step 2, two batches with one source. A merge that stops
// after either went in, before it was recorded, resumes by finding that
// step's own batch in the base's log.
func TestV087ReleaseSchemasBesideContent(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.branch("cat-season", "cat-season-r7")
	td := must(w.anna.CreateDoc(ctx, "cat-season-r7", "teamdef", map[string]any{"$schema": dialect, "type": "object"})).ID
	must(w.anna.CreateDoc(ctx, "cat-season-r7", "final", map[string]any{"$schema": "/r/cat-season/teamdef/rev/" + td, "title": "Final"}))
	w.appendTo("cat-season-r7", "season", op("replace", "/title", "Season 2026"))
	w.writeRelease("release-7", map[string]string{"cat-season": "cat-season-r7"})
	o := w.publishOpts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() || !reflect.DeepEqual(stepsOf(rp), []string{"1 cat-season teamdef", "2 cat-season final season", "3 cat-season final"}) {
		t.Fatalf("plan %q %+v", stepsOf(rp), rp.Conflicts)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	stop := errors.New("stop")
	for _, at := range []int{merge.StepSchemas, merge.StepContent} {
		o.AfterSubmit = func(st *merge.ReleaseStep) error {
			if st.Step == at {
				return stop
			}
			return nil
		}
		if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, stop) {
			t.Fatalf("apply stopping after step %d: %v", at, err)
		}
	}
	o.AfterSubmit = nil
	rp = must(merge.ApplyRelease(ctx, w.anna, o))
	want := map[int][]string{merge.StepSchemas: {"teamdef"}, merge.StepContent: {"final", "season"}, merge.StepPublish: {"final"}}
	seen := map[string]bool{}
	for _, st := range rp.Steps {
		if seen[st.Done] {
			t.Fatalf("step %d recorded %s, another step's batch", st.Step, st.Done)
		}
		seen[st.Done] = true
		var got []string
		for _, s := range entryOf(t, w.anna, "cat-season", st.Done).Entries {
			if s.Kind == "head" {
				got = append(got, s.Resource)
			}
		}
		if !reflect.DeepEqual(got, want[st.Step]) {
			t.Fatalf("step %d's batch has %v, want %v", st.Step, got, want[st.Step])
		}
	}
	if d := w.doc("cat-season", "final"); d["published"] != true {
		t.Fatalf("final %v", d)
	}
}

// MRG-17, MRG-18: a document deleted in the base that the release restores
// counts as created: carrying the field set, as it was before its deletion,
// is a conflict; restored without it, step 3 publishes it.
func TestV087ReleaseRestoreCountsAsCreated(t *testing.T) {
	t.Parallel()
	w, _ := publishWorld(t)
	h := must(w.anna.Head(ctx, "matches", "derby")) // published
	tomb := must(w.anna.Delete(ctx, "matches", "derby", h.ID)).ID
	w.branch("matches", "matches-r7")
	restore := must(w.anna.Restore(ctx, "matches-r7", "derby", tomb, ops(op("replace", "/home", "R"), nonce()))).ID
	w.writeRelease("release-7", map[string]string{"matches": "matches-r7"})
	o := w.publishOpts("release-7")
	if got := conflictKinds(must(merge.PlanRelease(ctx, w.anna, o)))[merge.RCPublished]; strings.Join(got, ",") != "matches/derby" {
		t.Fatalf("a restore keeping /published: conflicts %v", got)
	}
	must(w.anna.Append(ctx, "matches-r7", "derby", restore, ops(op("remove", "/published", nil), nonce())))
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() || !reflect.DeepEqual(stepsOf(rp), []string{"2 matches derby", "3 matches derby"}) {
		t.Fatalf("plan %q %+v", stepsOf(rp), rp.Conflicts)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	must(merge.ApplyRelease(ctx, w.anna, o))
	if d := w.doc("matches", "derby"); d["published"] != true || d["home"] != "R" {
		t.Fatalf("derby %v", d)
	}
}

// MRG-17 (§C.3.1): where signatures are required, the merge service signs
// every step it writes, step 3's batch without source included.
func TestV087ReleaseSignedPublish(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	admin := clienttest.NewKey("admin")
	for ns, doc := range map[string]map[string]any{
		"matches":  {"read": "grant", "signatures": "required"},
		"releases": {"read": "grant"},
	} {
		doc["keys"] = []any{admin.Entry("*")}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	k := sig.Key{Kid: "k1", Priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
	g := admin.Grant(t, s.Now(), "user:anna", []string{"matches", "matches-r7", "releases"}, grant.Verbs, map[string]any{"signers": []any{k.Entry()}})
	c := s.Client(t, client.WithBearer(g)).With(client.WithSigner(k))
	must(c.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "Derby"}))
	must(c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	must(c.CreateDoc(ctx, "matches-r7", "final", map[string]any{"title": "Final"}))
	must(release.Write(ctx, c, release.Ref{NS: "releases", Name: "rel"}, "", &release.Doc{Name: "rel", Branches: map[string]release.Branch{"matches": {NS: "matches-r7"}}}))
	o := merge.ReleaseOptions{Release: "/r/releases/rel", Who: "user:anna", Now: s.Now, Signer: &k, Publish: &merge.Publish{Path: "/published"}}
	rp := must(merge.PlanRelease(ctx, c, o))
	noErr(t, merge.SaveReleasePlan(ctx, c, o, rp))
	o.Publish = nil
	must(merge.ApproveRelease(ctx, c, o))
	rp, err := merge.ApplyRelease(ctx, c, o)
	noErr(t, err)
	if rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
	log := must(c.Log(ctx, "matches", "final", rp.Steps[1].IDs["final"], ""))
	if last := log[len(log)-1]; last.Signature == "" || last.Parent != rp.Steps[0].IDs["final"] {
		t.Fatalf("the published revision %+v", last)
	}
	_, d := must2(c.Load(ctx, "matches", "final"))
	if d.Value.(map[string]any)["published"] != true {
		t.Fatalf("final %v", d.Value)
	}
}
