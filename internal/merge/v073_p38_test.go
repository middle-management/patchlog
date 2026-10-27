package merge

// Spec v0.73, package P38 (CIS-38, MF-27): the plan digest of §F.9 for
// Addendum I. A release with a catalog branch whose node matches.cup is
// split, narrowed in step 2 and widened in step 4, so the step-4 item's
// precondition is the step-2 item's result, { "batch": 0, "item": i };
// its steps carry fresh $nonce ops and a fresh top-level $nonce in a root
// operation's value, as a catalog that requires nonces gets them (§6.4.1),
// which the digest leaves out. The steps go through the planner's own
// rendering (digestItems: digestSteps, the batch order) and the plan
// through PlanObject and PlanDigest. Kept in
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
	parents := func(p string) []any { return []any{map[string]any{"href": "/r/cat-season/" + p}} }
	op := func(o, path string, v any) map[string]any {
		m := map[string]any{"op": o, "path": path}
		if v != nil {
			m["value"] = v
		}
		return m
	}
	branches := []*ReleaseBranch{{Key: "cat-season", NS: "cat-season-r7", Target: "cat-season", Catalog: true, At: branchAt}}
	s2 := &ReleaseStep{Step: 2, Key: "cat-season", Resources: []string{"season", "matches.cup", "matches.old"}}
	s4 := &ReleaseStep{Step: 4, Key: "cat-season", Resources: []string{"matches.cup", "matches.newbie"}}
	// The items as the planner holds them, steps as they would be sent.
	sent := map[*ReleaseStep][]stepItem{
		s2: {
			{"season", map[string]any{"ifMatch": headSeason}, []client.Step{client.PatchStep([]any{
				op("remove", "/$access/group:fans", nil),
				op("add", "/$nonce", fresh)})}},
			{"matches.cup", map[string]any{"ifMatch": headCup}, []client.Step{client.PatchStep([]any{
				op("replace", "/parents", parents("vault")),
				op("replace", "/$nonce", fresh2)})}},
			{"matches.old", map[string]any{"ifMatch": headOld}, []client.Step{client.DeleteStep()}},
		},
		s4: {
			{"matches.newbie", map[string]any{"ifNoneMatch": "*"}, []client.Step{client.PatchStep([]any{
				op("add", "", map[string]any{"$nonce": fresh, "parents": parents("season")})})}},
			{"matches.cup", map[string]any{"after": map[string]any{"step": 2, "key": "cat-season", "item": "matches.cup"}}, []client.Step{client.PatchStep([]any{
				op("replace", "/parents", parents("embargo")),
				op("add", "/$nonce", "not-fresh")})}},
		},
	}
	items := map[*ReleaseStep][]any{s2: digestItems(s2, sent[s2]), s4: digestItems(s4, sent[s4])}
	plan, err := PlanObject(release, branches, []*ReleaseStep{s2, s4}, items)
	if err != nil {
		t.Fatal(err)
	}
	canon := jsonv.Canonical(jsonv.FromGo(plan))
	digest := PlanDigest(plan)
	if digest != ids.Of(canon).String() {
		t.Fatal("the digest isn't text(trunc160(sha256(canonical(plan))))")
	}
	// The split node's second half names the first's result.
	at := func(batch int, name string) (int, map[string]any) {
		for i, it := range plan["batches"].([]any)[batch].(map[string]any)["items"].([]any) {
			if m := it.(map[string]any); m["resource"] == name {
				return i, m
			}
		}
		t.Fatalf("no %s in batch %d", name, batch)
		return 0, nil
	}
	first, _ := at(0, "matches.cup")
	_, second := at(1, "matches.cup")
	if pre := second["ifMatch"]; string(jsonv.Canonical(jsonv.FromGo(pre))) != `{"batch":0,"item":`+string(rune('0'+first))+`}` {
		t.Fatalf("step-4 precondition %v, want item %d of batch 0", pre, first)
	}
	// Fresh nonces don't change the digest; another value of a member
	// that isn't fresh does.
	again := map[*ReleaseStep][]stepItem{s2: append([]stepItem(nil), sent[s2]...), s4: sent[s4]}
	again[s2][0] = stepItem{"season", map[string]any{"ifMatch": headSeason}, []client.Step{client.PatchStep([]any{
		op("remove", "/$access/group:fans", nil), op("add", "/$nonce", fresh2)})}}
	p2, _ := PlanObject(release, branches, []*ReleaseStep{s2, s4}, map[*ReleaseStep][]any{s2: digestItems(s2, again[s2]), s4: digestItems(s4, again[s4])})
	if PlanDigest(p2) != digest {
		t.Fatal("another fresh nonce changed the digest")
	}

	var sentJSON []any
	for _, st := range []*ReleaseStep{s2, s4} {
		for _, it := range sent[st] {
			sentJSON = append(sentJSON, golden.Obj{{Key: "step", Value: st.Step}, {Key: "resource", Value: it.name},
				{Key: "steps as sent", Value: string(jsonv.Canonical(jsonv.FromGo(StepsJSON(it.steps))))}})
		}
	}
	golden.Check(t, "plandigest", golden.Obj{
		{Key: "section", Value: "§F.9"},
		{Key: "about", Value: "a release's plan digest, text(trunc160(sha256(canonical(plan)))): two batches of one catalog branch (steps 2 and 4), the split node matches.cup in both, the second half's precondition { batch, item } on the first's result (items in each batch by resource name, as the reference orders them); fresh $nonce ops, and a fresh top-level $nonce in a root operation's value, are left out of the steps"},
		{Key: "vectors", Value: []any{golden.Obj{
			{Key: "name", Value: "two batches with a split node and nonce'd steps"},
			{Key: "fn", Value: "merge.digestItems (digestSteps), merge.PlanObject, merge.PlanDigest"},
			{Key: "items", Value: sentJSON},
			{Key: "plan", Value: string(canon)},
			{Key: "digest", Value: digest},
		}}},
	})
}
