package merge_test

// TOOLS §F.9 on v0.87: releases in three steps, schemas, content and
// publishing; the plan stored and resumed from; releases built on
// another.

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/seal"
)

// notPublisher is the guard of §6.4.4 for /published: writers outside the
// publishers group never write it, and create documents without it.
func publishedRules() []any {
	notPublisher := map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups",
		"schema": map[string]any{"contains": map[string]any{"const": "publishers"}}}}
	return []any{
		map[string]any{
			"if":   []any{notPublisher, map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": sAny("append", "restore")}}},
			"then": []any{map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/published"}}},
		},
		map[string]any{
			"if":   []any{notPublisher, map[string]any{"op": "test", "path": "/action", "value": "create"}},
			"then": []any{map[string]any{"op": "test", "path": "/doc/published", "exists": false}},
		},
	}
}

func nonce() map[string]any { return op("add", "/$nonce", seal.NewNonce()) }

// publishWorld is newRelWorld with matches guarding /published (§6.4.4)
// and requiring nonces (§C.7), as a namespace whose readers' rules test a
// field should (§7.9); derby is published there. bo is an editor outside
// the publishers group, which anna's grant (the merge service's here)
// carries.
func publishWorld(t *testing.T) (*relWorld, *client.Client) {
	w := newRelWorld(t)
	h := must(w.ops.NSHead(ctx, "matches"))
	must(w.ops.PatchConfig(ctx, "matches", h.Config, ops(op("add", "/rules", publishedRules()), op("add", "/nonce", "required"))))
	w.appendTo("matches", "derby", op("add", "/published", true), nonce())
	bo := w.s.Client(t, client.WithBearer(w.idp.Grant(t, w.s.Now(), "user:bo", relNS, []string{"read", "create", "append"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	return w, bo
}

// release7p builds a release of schemas and matches: schemas-r7 drafts
// match T1, matches-r7 creates final (unpublished) on T1 and edits derby.
func (w *relWorld) release7p() (t1 string) {
	w.branch("schemas", "schemas-r7", op("add", "/drafts", map[string]any{"for": sAny("matches-r7")}))
	w.branch("matches", "matches-r7")
	t1 = w.appendTo("schemas-r7", "match", op("add", "/properties/venue", map[string]any{"type": "string"}))
	draft := "/r/schemas/match/rev/" + t1
	must(w.anna.CreateDoc(ctx, "matches-r7", "final", map[string]any{"$schema": draft, "home": "A", "away": "C", "venue": "Wembley", "$nonce": seal.NewNonce()}))
	w.appendTo("matches-r7", "derby", op("replace", "/home", "Z"), nonce())
	w.writeRelease("release-7", map[string]string{"schemas": "schemas-r7", "matches": "matches-r7"})
	return t1
}

func (w *relWorld) publishOpts(rel string) merge.ReleaseOptions {
	o := w.opts(rel)
	o.Publish = &merge.Publish{Path: "/published"}
	return o
}

// MRG-17, MRG-19: the three steps. Step 3 is one batch without source,
// setting /published on the documents step 2 created, each item's
// If-Match the id step 2 left it at; the guard rule refuses the field to
// writers outside the group, not to the merge service's grant. Every
// branch records merged after the last step, at the target's ns_id after
// the last batch into it, and the janitor verifies the claim.
func TestV087ReleasePublish(t *testing.T) {
	t.Parallel()
	w, bo := publishWorld(t)
	// The guard (§6.4.4): an editor outside the group can't publish.
	_, err := bo.CreateDoc(ctx, "matches", "sneak", map[string]any{"home": "x", "away": "y", "published": true, "$nonce": seal.NewNonce()})
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 || ae.Code != "rule" {
		t.Fatalf("create with /published by bo: %v", err)
	}
	h := must(bo.Head(ctx, "matches", "cup"))
	if _, err := bo.Append(ctx, "matches", "cup", h.ID, ops(op("add", "/published", true), nonce())); err == nil {
		t.Fatal("bo published cup")
	}
	must(bo.Append(ctx, "matches", "cup", h.ID, ops(op("add", "/note", "fine"), nonce())))

	w.release7p()
	o := w.publishOpts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() {
		t.Fatalf("conflicts %+v", rp.Conflicts)
	}
	if got := stepsOf(rp); !reflect.DeepEqual(got, []string{"1 schemas match", "2 matches derby final", "3 matches final"}) {
		t.Fatalf("steps %q", got)
	}
	batches := rp.Plan["batches"].([]any)
	if len(batches) != 3 {
		t.Fatalf("plan %v", rp.Plan)
	}
	b3 := batches[2].(map[string]any)
	if _, has := b3["source"]; has || b3["ns"] != "matches" {
		t.Fatalf("step 3's batch %v", b3)
	}
	finalIdx := -1
	for i, it := range batches[1].(map[string]any)["items"].([]any) {
		if it.(map[string]any)["resource"] == "final" {
			finalIdx = i
		}
	}
	if pre := b3["items"].([]any)[0].(map[string]any)["ifMatch"].(map[string]any); pre["batch"] != 1.0 || pre["item"] != float64(finalIdx) {
		t.Fatalf("step 3's precondition %v, want batch 1 item %d", pre, finalIdx)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	// Approve and apply take the stored plan's field.
	must(merge.ApproveRelease(ctx, w.anna, w.opts("release-7")))
	branchFinal := must(w.anna.Head(ctx, "matches-r7", "final")).ID
	rp, err = merge.ApplyRelease(ctx, w.anna, w.opts("release-7"))
	noErr(t, err)
	if rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
	if d := w.doc("matches", "final"); d["published"] != true || d["venue"] != "Wembley" {
		t.Fatalf("final %v", d)
	}
	if d := w.doc("matches", "derby"); d["published"] != true || d["home"] != "Z" {
		t.Fatalf("derby %v", d)
	}
	// final: step 2 fast-forwarded the branch's id, step 3 set the field
	// on it, in a batch without source.
	s2, s3 := rp.Steps[1], rp.Steps[2]
	if s2.IDs["final"] != branchFinal {
		t.Fatalf("step 2 left final at %s, the branch has %s", s2.IDs["final"], branchFinal)
	}
	fl := must(w.anna.Log(ctx, "matches", "final", s3.IDs["final"], ""))
	if last := fl[len(fl)-1]; last.Parent != branchFinal {
		t.Fatalf("published revision's parent %s, want %s", last.Parent, branchFinal)
	}
	if e := entryOf(t, w.anna, "matches", s3.Done); e.Kind != "batch" || e.HasSource {
		t.Fatalf("step 3's entry %+v", e)
	}
	if e := entryOf(t, w.anna, "matches", s2.Done); e.Source["ns"] != "matches-r7" {
		t.Fatalf("step 2's entry %+v", e)
	}
	nd := must(w.anna.NSDoc(ctx, "matches-r7", must(w.anna.NSHead(ctx, "matches-r7")).ID))
	if m, _ := nd.Value["merged"].(map[string]any); m["at"] != s3.Done {
		t.Fatalf("matches-r7 merged %v, want at %s (after step 3)", nd.Value["merged"], s3.Done)
	}
	j := janitor.New(w.anna, janitor.Options{DryRun: true, Now: func() time.Time { return w.s.Now().Add(time.Hour) }})
	for base, br := range map[string]string{"schemas": "schemas-r7", "matches": "matches-r7"} {
		if dec := must(j.Check(ctx, base, br)); dec.Claim != "merged" || dec.Action != janitor.ActionWouldPurge {
			t.Fatalf("janitor on %s: %+v", br, dec)
		}
	}
}

// MRG-18: a change to the published field in steps 1 and 2 is a conflict:
// a document the release creates carrying it set, or one whose value it
// changes. Edits to published documents that leave it alone (derby)
// aren't.
func TestV087ReleasePublishedConflict(t *testing.T) {
	t.Parallel()
	w, _ := publishWorld(t)
	w.release7p()
	// anna is in the group, so the branch's copy of the guard lets her.
	must(w.anna.CreateDoc(ctx, "matches-r7", "early", map[string]any{"home": "E", "away": "F", "published": true, "$nonce": seal.NewNonce()}))
	w.appendTo("matches-r7", "cup", op("add", "/published", false), nonce())
	o := w.publishOpts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	got := conflictKinds(rp)[merge.RCPublished]
	if strings.Join(got, ",") != "matches/cup,matches/early" {
		t.Fatalf("published conflicts %v in %+v", got, rp.Conflicts)
	}
	if len(conflictKinds(rp)) != 1 {
		t.Fatalf("other conflicts %+v", rp.Conflicts)
	}
	// Without a published field there is no step 3 and no such conflict.
	if rp := must(merge.PlanRelease(ctx, w.anna, w.opts("release-7"))); !rp.Clean() || len(rp.Steps) != 2 {
		t.Fatalf("without --publish: %+v %q", rp.Conflicts, stepsOf(rp))
	}
}

// MRG-18 for a replay: the base set the field since the branch started,
// and the branch edits another member, so the replay keeps the base's
// value: no conflict, and the document isn't published again.
func TestV087ReleasePublishedReplay(t *testing.T) {
	t.Parallel()
	w, _ := publishWorld(t)
	w.branch("matches", "matches-r7")
	w.appendTo("matches-r7", "cup", op("add", "/note", "branch"), nonce())
	w.appendTo("matches", "cup", op("add", "/published", true), nonce())
	w.writeRelease("release-7", map[string]string{"matches": "matches-r7"})
	o := w.publishOpts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() || !reflect.DeepEqual(stepsOf(rp), []string{"2 matches cup"}) {
		t.Fatalf("plan %q %+v", stepsOf(rp), rp.Conflicts)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	must(merge.ApplyRelease(ctx, w.anna, o))
	if d := w.doc("matches", "cup"); d["published"] != true || d["note"] != "branch" {
		t.Fatalf("cup %v", d)
	}
}

// MRG-19: the plan is stored before anything is submitted, and a merge
// that stops resumes from it and never reverts: here twice, each time
// after a batch went in and before it was recorded, so the resumed merge
// finds the batch in the target's log rather than submitting it again.
func TestV087ReleaseResumesFromStoredPlan(t *testing.T) {
	t.Parallel()
	for _, stateNS := range []string{"", "schemas-x"} {
		t.Run("state-ns="+stateNS, func(t *testing.T) {
			t.Parallel()
			w, _ := publishWorld(t)
			w.release7p()
			o := w.publishOpts("release-7")
			if stateNS != "" {
				must(w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, stateNS))).CreateNamespace(ctx, stateNS,
					map[string]any{"read": "grant", "nonce": "required", "keys": []any{w.opsKey.Entry("*"), w.idp.Entry("read", "create", "append", "delete", "restore", "config", "branch", "purge-ns", "purge")}}))
				o.StateNS = stateNS
			}
			noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
			approved := must(merge.ApproveRelease(ctx, w.anna, o))
			stored := must(merge.LoadReleasePlan(ctx, w.anna, o))
			if stored.Digest != approved.Digest || merge.PlanDigest(stored.Plan) != stored.Digest {
				t.Fatalf("the stored plan %s doesn't hold its digest %s", merge.PlanDigest(stored.Plan), stored.Digest)
			}
			stop := errors.New("stop")
			for _, at := range []int{merge.StepContent, merge.StepPublish} {
				o.AfterSubmit = func(st *merge.ReleaseStep) error {
					if st.Step == at {
						return stop
					}
					return nil
				}
				if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, stop) {
					t.Fatalf("apply stopping after step %d: %v", at, err)
				}
				rec := must(merge.LoadReleasePlan(ctx, w.anna, o))
				if rec.State != merge.ReleaseMerging || rec.Steps[at-1].Done != "" {
					t.Fatalf("after the stop in step %d: %s %+v", at, rec.State, rec.Steps[at-1])
				}
			}
			o.AfterSubmit = nil
			rp, err := merge.ApplyRelease(ctx, w.anna, o)
			noErr(t, err)
			if rp.State != merge.ReleaseDone {
				t.Fatalf("state %s", rp.State)
			}
			// One batch per step in the base, each recorded: none twice.
			for _, st := range rp.Steps {
				ns := rp.Branch(st.Key).Target
				e := entryOf(t, w.anna, ns, st.Done)
				if e.Kind != "batch" {
					t.Fatalf("step %d recorded %s, a %s", st.Step, st.Done, e.Kind)
				}
				for name, id := range st.IDs {
					found := false
					for _, s := range e.Entries {
						found = found || (s.Resource == name && s.Target == id)
					}
					if !found {
						t.Fatalf("step %d: %s at %s isn't in its batch %+v", st.Step, name, id, e.Entries)
					}
				}
			}
			fl := must(w.anna.Log(ctx, "matches", "final", must(w.anna.Head(ctx, "matches", "final")).ID, ""))
			if len(fl) != 2 {
				t.Fatalf("final's log has %d revisions, want its creation and its publishing", len(fl))
			}
			if d := w.doc("matches", "final"); d["published"] != true {
				t.Fatalf("final %v", d)
			}
		})
	}
}

// MRG-19, MRG-5: after the approval, a document step 2 created that moves
// on before step 3 is a change to the approved plan: the merge stops for a
// new approval, and never reverts what went in.
func TestV087ReleasePublishStopsOnChange(t *testing.T) {
	t.Parallel()
	w, _ := publishWorld(t)
	w.release7p()
	o := w.publishOpts("release-7")
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	must(merge.ApproveRelease(ctx, w.anna, o))
	o.AfterStep = func(st *merge.ReleaseStep) error {
		if st.Step == merge.StepContent {
			// Someone edits final between steps 2 and 3.
			w.appendTo("matches", "final", op("replace", "/venue", "Hampden"), nonce())
		}
		return nil
	}
	_, err := merge.ApplyRelease(ctx, w.anna, o)
	if !errors.Is(err, merge.ErrPlanChanged) || !strings.Contains(err.Error(), "step 3") {
		t.Fatalf("apply: %v", err)
	}
	if d := w.doc("matches", "final"); d["published"] != nil || d["venue"] != "Hampden" {
		t.Fatalf("final %v", d)
	}
}

// MRG-22: a release built on another branches that release's branches and
// names it in on, keyed by the namespaces paths name. Its branches merge
// into the earlier release's, so its documents resolve drafts from both,
// and it has no step 3: what it adds is created in the earlier release's
// branch, whose own step 3 publishes it. Its branches' base must be the
// earlier release's branch for the key.
func TestV087ReleaseBuiltOnAnother(t *testing.T) {
	t.Parallel()
	w, _ := publishWorld(t)
	// release-6: schemas-r6 drafts match T6 for matches-r6.
	w.branch("schemas", "schemas-r6", op("add", "/drafts", map[string]any{"for": sAny("matches-r6")}))
	w.branch("matches", "matches-r6")
	t6 := w.appendTo("schemas-r6", "match", op("add", "/properties/venue", map[string]any{"type": "string"}))
	must(w.anna.CreateDoc(ctx, "matches-r6", "semi", map[string]any{"$schema": "/r/schemas/match/rev/" + t6, "home": "S", "away": "T", "venue": "V", "$nonce": seal.NewNonce()}))
	w.writeRelease("release-6", map[string]string{"schemas": "schemas-r6", "matches": "matches-r6"})
	rel6 := must(release.Load(ctx, w.anna, "/r/releases/release-6"))

	// release-7 on release-6: its branches are branches of release-6's;
	// final resolves release-6's draft T6, and derby release-7's own T7,
	// which drafts the same schema resource on top of T6.
	w.branch("schemas-r6", "schemas-r7", op("add", "/drafts", map[string]any{"for": sAny("matches-r7")}))
	w.branch("matches-r6", "matches-r7")
	t7 := w.appendTo("schemas-r7", "match", op("add", "/properties/coach", map[string]any{"type": "string"}))
	must(w.anna.CreateDoc(ctx, "matches-r7", "final", map[string]any{"$schema": "/r/schemas/match/rev/" + t6, "home": "A", "away": "C", "venue": "W", "$nonce": seal.NewNonce()}))
	w.appendTo("matches-r7", "derby", op("replace", "/$schema", "/r/schemas/match/rev/"+t7), op("add", "/coach", "K"), nonce())
	writeOn := func(name string, branches map[string]string) {
		d := &release.Doc{Name: name, Branches: map[string]release.Branch{}, On: rel6.Ref.String()}
		for k, b := range branches {
			d.Branches[k] = release.Branch{NS: b}
		}
		must(release.Write(ctx, w.anna, release.Ref{NS: "releases", Name: name}, "", d))
	}
	writeOn("release-7", map[string]string{"schemas": "schemas-r7", "matches": "matches-r7"})

	o := w.publishOpts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() {
		t.Fatalf("conflicts %+v", rp.Conflicts)
	}
	for _, b := range rp.Branches {
		if want := map[string]string{"schemas": "schemas-r6", "matches": "matches-r6"}[b.Key]; b.Target != want {
			t.Fatalf("%s merges into %s, want %s", b.NS, b.Target, want)
		}
	}
	if got := stepsOf(rp); !reflect.DeepEqual(got, []string{"1 schemas match", "2 matches derby final"}) {
		t.Fatalf("steps %q (no step 3 into a branch)", got)
	}
	if len(rp.Notes) == 0 || !strings.Contains(rp.Notes[0], "no step 3") {
		t.Fatalf("notes %q", rp.Notes)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	rp, err := merge.ApplyRelease(ctx, w.anna, o)
	noErr(t, err)
	if h := must(w.anna.Head(ctx, "schemas-r6", "match")); h.ID != t7 {
		t.Fatalf("schemas-r6/match %s, want T7 %s fast-forwarded", h.ID, t7)
	}
	if d := w.doc("matches-r6", "final"); d == nil || d["published"] != nil {
		t.Fatalf("matches-r6/final %v", d)
	}

	// Then release-6 merges, and its step 3 publishes what release-7 added.
	o6 := w.publishOpts("release-6")
	rp6 := must(merge.PlanRelease(ctx, w.anna, o6))
	if !rp6.Clean() || !reflect.DeepEqual(stepsOf(rp6), []string{"1 schemas match", "2 matches derby final semi", "3 matches final semi"}) {
		t.Fatalf("release-6: %q %+v", stepsOf(rp6), rp6.Conflicts)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o6, rp6))
	must(merge.ApproveRelease(ctx, w.anna, o6))
	must(merge.ApplyRelease(ctx, w.anna, o6))
	for _, n := range []string{"final", "semi"} {
		if d := w.doc("matches", n); d["published"] != true {
			t.Fatalf("matches/%s %v", n, d)
		}
	}
	if d := w.doc("matches", "derby"); d["$schema"] != "/r/schemas/match/rev/"+t7 || d["coach"] != "K" {
		t.Fatalf("derby %v", d)
	}

	// A release on release-6 whose branch isn't a branch of release-6's.
	w.branch("matches", "matches-x")
	writeOn("release-8", map[string]string{"matches": "matches-x"})
	if got := conflictKinds(must(merge.PlanRelease(ctx, w.anna, w.opts("release-8"))))[merge.RCBaseChain]; len(got) != 1 {
		t.Fatalf("base chain conflicts %v", got)
	}
}
