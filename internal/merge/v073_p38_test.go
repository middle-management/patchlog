package merge

// The plan digest of §F.9 for Addendum I (v0.87: three steps). A content
// branch merges in step 2, creating matches.newbie, and step 3 publishes
// it: the step-3 item's precondition is the step-2 item's result, {
// "batch": 0, "item": i }, and step 3's batch has no source. The steps
// carry fresh $nonce ops and a fresh top-level $nonce in a root
// operation's value, as a namespace that requires nonces gets them
// (§6.4.1), which the digest leaves out. The steps go through the
// planner's own rendering (digestItems, publishItems: digestSteps, the
// batch order) and the plan through PlanObject and PlanDigest. Kept in
// internal/vectors/testdata/plandigest.json (internal/vectors/golden).

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

func TestVectorPlanDigest(t *testing.T) {
	const (
		fresh  = "abcdefghijklmnopqrstuvwxyz" // the fresh form: 26 base32 characters
		fresh2 = "zyxwvutsrqponmlkjihgfedcba"
		// Ids of Addendum I (I.2) stand for the heads and checkpoints.
		headSeason = "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"
		headCup    = "1sywh54kpo3c4ezn2znktvl3avge4zl5d"
		headOld    = "1idx6u2b3z42obqmwsgmlzvrfuutks2bq"
		branchAt   = "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"
		release    = "/r/releases/release-7/rev/1vmctae4vewju6nvxi374rkrkmyzpdrif"
	)
	op := func(o, path string, v any) map[string]any {
		m := map[string]any{"op": o, "path": path}
		if v != nil {
			m["value"] = v
		}
		return m
	}
	branches := []*ReleaseBranch{{Key: "matches", NS: "matches-r7", Target: "matches", At: branchAt}}
	s2 := &ReleaseStep{Step: StepContent, Key: "matches", Resources: []string{"season", "matches.cup", "matches.newbie", "matches.old"}}
	s3 := &ReleaseStep{Step: StepPublish, Key: "matches", Resources: []string{"matches.newbie"}}
	pub := &Publish{Path: "/published", Value: true}
	// The items as the planner holds them, steps as they would be sent.
	sent := []stepItem{
		{"season", map[string]any{"ifMatch": headSeason}, []client.Step{client.PatchStep([]any{
			op("remove", "/note", nil),
			op("add", "/$nonce", fresh)})}},
		{"matches.cup", map[string]any{"ifMatch": headCup}, []client.Step{client.PatchStep([]any{
			op("replace", "/venue", "Wembley"),
			op("replace", "/$nonce", fresh2)})}},
		{"matches.old", map[string]any{"ifMatch": headOld}, []client.Step{client.DeleteStep()}},
		{"matches.newbie", map[string]any{"ifNoneMatch": "*"}, []client.Step{client.PatchStep([]any{
			op("add", "", map[string]any{"$nonce": fresh, "home": "A", "away": "B"})})}},
	}
	publish := []client.Step{client.PatchStep(append(pub.step().Patches.([]any), op("add", "/$nonce", fresh2)))}
	items := map[*ReleaseStep][]any{s2: digestItems(s2, sent), s3: publishItems(s3, pub)}
	plan, err := PlanObject(release, branches, []*ReleaseStep{s2, s3}, items)
	if err != nil {
		t.Fatal(err)
	}
	canon := jsonv.Canonical(jsonv.FromGo(plan))
	digest := PlanDigest(plan)
	if digest != ids.Of(canon).String() {
		t.Fatal("the digest isn't text(trunc160(sha256(canonical(plan))))")
	}
	// Step 3's item names step 2's result, and its batch has no source.
	batches := plan["batches"].([]any)
	first := -1
	for i, it := range batches[0].(map[string]any)["items"].([]any) {
		if it.(map[string]any)["resource"] == "matches.newbie" {
			first = i
		}
	}
	b3 := batches[1].(map[string]any)
	if _, has := b3["source"]; has {
		t.Fatal("step 3's batch has a source")
	}
	pre := b3["items"].([]any)[0].(map[string]any)["ifMatch"]
	if string(jsonv.Canonical(jsonv.FromGo(pre))) != `{"batch":0,"item":`+string(rune('0'+first))+`}` {
		t.Fatalf("step-3 precondition %v, want item %d of batch 0", pre, first)
	}
	// The publish step as sent, with its fresh nonce, digests as planned.
	if got, want := jsonv.Canonical(jsonv.FromGo(digestSteps(publish))), jsonv.Canonical(jsonv.FromGo(b3["items"].([]any)[0].(map[string]any)["steps"])); string(got) != string(want) {
		t.Fatalf("step 3 as sent digests as %s, planned %s", got, want)
	}
	// Fresh nonces don't change the digest; another value of a member
	// that isn't fresh does.
	again := append([]stepItem(nil), sent...)
	again[0] = stepItem{"season", map[string]any{"ifMatch": headSeason}, []client.Step{client.PatchStep([]any{
		op("remove", "/note", nil), op("add", "/$nonce", fresh2)})}}
	p2, _ := PlanObject(release, branches, []*ReleaseStep{s2, s3}, map[*ReleaseStep][]any{s2: digestItems(s2, again), s3: publishItems(s3, pub)})
	if PlanDigest(p2) != digest {
		t.Fatal("another fresh nonce changed the digest")
	}
	p3, _ := PlanObject(release, branches, []*ReleaseStep{s2, s3}, map[*ReleaseStep][]any{s2: digestItems(s2, sent), s3: publishItems(s3, &Publish{Path: "/published", Value: "yes"})})
	if PlanDigest(p3) == digest {
		t.Fatal("another published value kept the digest")
	}

	// The vector as v0.86 kept it, two batches of one branch with one
	// source (now steps 1 and 2, as a branch holding schemas and content
	// merges), the second's precondition { batch, item } on the first's
	// result: its plan and digest are unchanged.
	const oldPlan = `{"batches":[{"items":[{"ifMatch":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"matches.cup","steps":[[{"op":"replace","path":"/parents","value":[{"href":"/r/cat-season/vault"}]}]]},{"ifMatch":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq","resource":"matches.old","steps":["delete"]},{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","resource":"season","steps":[[{"op":"remove","path":"/$access/group:fans"}]]}],"ns":"cat-season","source":{"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"cat-season-r7"}},{"items":[{"ifMatch":{"batch":0,"item":0},"resource":"matches.cup","steps":[[{"op":"replace","path":"/parents","value":[{"href":"/r/cat-season/embargo"}]},{"op":"add","path":"/$nonce","value":"not-fresh"}]]},{"ifNoneMatch":"*","resource":"matches.newbie","steps":[[{"op":"add","path":"","value":{"parents":[{"href":"/r/cat-season/season"}]}}]]}],"ns":"cat-season","source":{"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"cat-season-r7"}}],"release":"/r/releases/release-7/rev/1vmctae4vewju6nvxi374rkrkmyzpdrif"}`
	const oldDigest = "1rvfmashxuxn5rbmma7dupfj55l74r3jb"
	parents := func(p string) []any { return []any{map[string]any{"href": "/r/cat-season/" + p}} }
	ob := []*ReleaseBranch{{Key: "cat-season", NS: "cat-season-r7", Target: "cat-season", At: branchAt}}
	o1 := &ReleaseStep{Step: StepSchemas, Key: "cat-season", Resources: []string{"matches.cup", "matches.old", "season"}}
	o2 := &ReleaseStep{Step: StepContent, Key: "cat-season", Resources: []string{"matches.cup", "matches.newbie"}}
	oldSent := map[*ReleaseStep][]stepItem{
		o1: {
			{"season", map[string]any{"ifMatch": headSeason}, []client.Step{client.PatchStep([]any{
				op("remove", "/$access/group:fans", nil), op("add", "/$nonce", fresh)})}},
			{"matches.cup", map[string]any{"ifMatch": headCup}, []client.Step{client.PatchStep([]any{
				op("replace", "/parents", parents("vault")), op("replace", "/$nonce", fresh2)})}},
			{"matches.old", map[string]any{"ifMatch": headOld}, []client.Step{client.DeleteStep()}},
		},
		o2: {
			{"matches.newbie", map[string]any{"ifNoneMatch": "*"}, []client.Step{client.PatchStep([]any{
				op("add", "", map[string]any{"$nonce": fresh, "parents": parents("season")})})}},
			{"matches.cup", map[string]any{"after": map[string]any{"step": StepSchemas, "key": "cat-season", "item": "matches.cup"}}, []client.Step{client.PatchStep([]any{
				op("replace", "/parents", parents("embargo")), op("add", "/$nonce", "not-fresh")})}},
		},
	}
	op1, err := PlanObject(release, ob, []*ReleaseStep{o1, o2}, map[*ReleaseStep][]any{o1: digestItems(o1, oldSent[o1]), o2: digestItems(o2, oldSent[o2])})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(jsonv.Canonical(jsonv.FromGo(op1))); got != oldPlan || PlanDigest(op1) != oldDigest {
		t.Fatalf("the earlier vector's plan is\n%s\n(digest %s), want\n%s\n(digest %s)", got, PlanDigest(op1), oldPlan, oldDigest)
	}
	var oldJSON []any
	for _, st := range []*ReleaseStep{o1, o2} {
		for _, it := range oldSent[st] {
			oldJSON = append(oldJSON, golden.Obj{{Key: "step", Value: st.Step}, {Key: "resource", Value: it.name},
				{Key: "steps as sent", Value: string(jsonv.Canonical(jsonv.FromGo(StepsJSON(it.steps))))}})
		}
	}

	var sentJSON []any
	for _, it := range sent {
		sentJSON = append(sentJSON, golden.Obj{{Key: "step", Value: StepContent}, {Key: "resource", Value: it.name},
			{Key: "steps as sent", Value: string(jsonv.Canonical(jsonv.FromGo(StepsJSON(it.steps))))}})
	}
	sentJSON = append(sentJSON, golden.Obj{{Key: "step", Value: StepPublish}, {Key: "resource", Value: "matches.newbie"},
		{Key: "steps as sent", Value: string(jsonv.Canonical(jsonv.FromGo(StepsJSON(publish))))}})
	golden.Check(t, "plandigest", golden.Obj{
		{Key: "section", Value: "§F.9"},
		{Key: "about", Value: "a release's plan digest, text(trunc160(sha256(canonical(plan)))), a precondition on an earlier batch's result { batch, item } (items in each batch by resource name, as the reference orders them); fresh $nonce ops, and a fresh top-level $nonce in a root operation's value, are left out of the steps"},
		{Key: "vectors", Value: []any{golden.Obj{
			{Key: "name", Value: "two batches of one branch with one source (steps 1 and 2), the second naming the first's result; the plan and digest of v0.86's vector"},
			{Key: "fn", Value: "merge.digestItems (digestSteps), merge.PlanObject, merge.PlanDigest"},
			{Key: "items", Value: oldJSON},
			{Key: "plan", Value: oldPlan},
			{Key: "digest", Value: oldDigest},
		}, golden.Obj{
			{Key: "name", Value: "content and publishing with nonce'd steps"},
			{Key: "fn", Value: "merge.digestItems, merge.publishItems (digestSteps), merge.PlanObject, merge.PlanDigest"},
			{Key: "items", Value: sentJSON},
			{Key: "plan", Value: string(canon)},
			{Key: "digest", Value: digest},
		}}},
	})
}
