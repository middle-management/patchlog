package ddb

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
)

func sk(a types.TransactWriteItem) string {
	var k map[string]types.AttributeValue
	switch {
	case a.Put != nil:
		k = a.Put.Item
	case a.Update != nil:
		k = a.Update.Key
	case a.ConditionCheck != nil:
		k = a.ConditionCheck.Key
	case a.Delete != nil:
		k = a.Delete.Key
	}
	return k["SK"].(*types.AttributeValueMemberS).Value
}

func cond(a types.TransactWriteItem) string {
	switch {
	case a.Put != nil && a.Put.ConditionExpression != nil:
		return *a.Put.ConditionExpression
	case a.Update != nil && a.Update.ConditionExpression != nil:
		return *a.Update.ConditionExpression
	case a.ConditionCheck != nil:
		return *a.ConditionCheck.ConditionExpression
	}
	return ""
}

var testTip = tip{headPos: 7, headID: ids.Of([]byte("entry7")).String()}

func createCommit(name string) *Commit {
	id := ids.Of([]byte(name)).String()
	return &Commit{
		NS: "demo", Author: "alice", Created: 1000, CfgPos: 1, CfgID: ids.Of([]byte("cfg")).String(),
		Items: []CommitItem{{Name: name, Steps: []CommitStep{{ID: id, Patches: `[]`, Doc: `{}`}}}},
		Entry: map[string]any{"resource": name, "kind": "head", "target": id}, Kind: "head",
	}
}

// A create's transaction: its revision (one child per parent), the head
// (genesis: attribute_not_exists), the document, the history row, the
// entry, the marker — then the tip move pinned on the tip it chained
// over, and the configuration's condition.
func TestBuildCommitCreate(t *testing.T) {
	s := &Store{Table: "tbl"}
	c := createCommit("doc1")
	acts, res, err := s.buildCommits("demo", []*Commit{c}, testTip)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ sk, cond string }{
		{"REV#doc1#" + padPos(1), "attribute_not_exists(PK)"},
		{"RES#doc1", "attribute_not_exists(PK)"},
		{"DOC#doc1#HEAD", ""},
		{"HIST#doc1#" + padPos(8), ""},
		{"LOG#" + padPos(8), "attribute_not_exists(PK)"},
		{"#", "attribute_not_exists(PK)"}, // the marker
		{"#TIP", "headPos = :h AND headId = :i"},
		{"#META", "configPos = :cp AND configId = :ci"},
	}
	if len(acts) != len(want) || len(acts) != c.actions()+txShared {
		t.Fatalf("%d actions, want %d (counted %d)", len(acts), len(want), c.actions()+txShared)
	}
	for i, w := range want {
		if sk(acts[i]) != w.sk || cond(acts[i]) != w.cond {
			t.Errorf("action %d: %s %q, want %s %q", i, sk(acts[i]), cond(acts[i]), w.sk, w.cond)
		}
	}
	// The entry chains over the tip (§3.5), at the next position.
	tid, _ := ids.Parse(testTip.headID)
	body := `{"kind":"head","resource":"doc1","target":"` + c.Items[0].Steps[0].ID + `"}`
	if res[0].Pos != 8 || res[0].NSID != ids.Hash(&tid, []byte(body)).String() {
		t.Fatalf("entry %+v", res[0])
	}
	if v := acts[6].Update.ExpressionAttributeValues; v[":new"].(*types.AttributeValueMemberN).Value != "8" || v[":newi"].(*types.AttributeValueMemberS).Value != res[0].NSID {
		t.Fatalf("tip move %v", v)
	}
}

// A delete's: the tombstone on the head it pins, no document or history
// row; the head records the last live revision.
func TestBuildCommitDelete(t *testing.T) {
	s := &Store{Table: "tbl"}
	live := ids.Of([]byte("live")).String()
	tomb := ids.Tombstone(ids.Of([]byte("live"))).String()
	c := &Commit{
		NS: "demo", Author: "alice", CfgPos: 1, CfgID: "c",
		Items: []CommitItem{{Name: "doc1", HeadPos: 3, HeadID: live, Steps: []CommitStep{{ID: tomb, ParentID: live, Tombstone: true}}}},
		Entry: map[string]any{"resource": "doc1", "kind": "tombstone", "target": tomb}, Kind: "tombstone",
	}
	acts, _, err := s.buildCommits("demo", []*Commit{c}, testTip)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != c.actions()+txShared || len(acts) != 6 {
		t.Fatalf("%d actions (counted %d)", len(acts), c.actions()+txShared)
	}
	res := acts[1].Update
	if sk(acts[1]) != "RES#doc1" || cond(acts[1]) != "headPos = :old AND headId = :oldi" ||
		res.ExpressionAttributeValues[":l"].(*types.AttributeValueMemberS).Value != live ||
		res.ExpressionAttributeValues[":lp"].(*types.AttributeValueMemberN).Value != "3" {
		t.Fatalf("head update %s %q %v", sk(acts[1]), cond(acts[1]), res.ExpressionAttributeValues)
	}
}

// A group: every commit's actions chained in order, one tip move, one
// configuration condition — a transaction may touch an item once.
func TestBuildCommitsGroup(t *testing.T) {
	s := &Store{Table: "tbl"}
	cs := []*Commit{createCommit("a"), createCommit("b"), createCommit("c")}
	acts, res, err := s.buildCommits("demo", cs, testTip)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 3*cs[0].actions()+txShared {
		t.Fatalf("%d actions", len(acts))
	}
	metas := 0
	for _, a := range acts {
		if sk(a) == "#META" {
			metas++
		}
	}
	if metas != 1 {
		t.Fatalf("%d #META actions, want 1", metas)
	}
	prev := testTip
	for i, r := range res {
		pid, _ := ids.Parse(prev.headID)
		if r.Pos != prev.headPos+1 || r.NSID != ids.Hash(&pid, []byte(`{"kind":"head","resource":"`+cs[i].Items[0].Name+`","target":"`+cs[i].Items[0].Steps[0].ID+`"}`)).String() {
			t.Fatalf("commit %d: entry %+v", i, r)
		}
		prev = tip{headPos: r.Pos, headID: r.NSID}
	}
}

// A config change conditions #META with its update: no separate check.
func TestBuildCommitConfig(t *testing.T) {
	s := &Store{Table: "tbl"}
	c := &Commit{
		NS: "demo", Author: "alice", CfgPos: 4, CfgID: "c4",
		Config: &CommitConfig{ID: "c5", Patches: `[]`, Doc: `{}`},
		Entry:  map[string]any{"kind": "config", "target": "c5"}, Kind: "config",
	}
	acts, _, err := s.buildCommits("demo", []*Commit{c}, testTip)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != c.actions()+1 || sk(acts[0]) != "#META" || cond(acts[0]) != "configPos = :old AND configId = :oldi" || sk(acts[1]) != "CFG#"+padPos(5) {
		t.Fatalf("config change: %d actions, %s %q, %s", len(acts), sk(acts[0]), cond(acts[0]), sk(acts[1]))
	}
	if sk(acts[len(acts)-1]) != "#TIP" {
		t.Fatalf("last action %s, want the tip move", sk(acts[len(acts)-1]))
	}
}

// classifyCancel sorts a group's cancellation by the commits' layout: a
// commit's own condition makes it stale, its entry's makes the tip moved,
// the shared configuration condition makes every commit stale.
func TestClassifyCancel(t *testing.T) {
	cs := []*Commit{createCommit("a"), createCommit("b")}
	k := cs[0].actions()
	n := 2*k + txShared
	cancel := func(failed ...int) error {
		rs := make([]types.CancellationReason, n)
		for i := range rs {
			code := "None"
			rs[i].Code = &code
		}
		for _, f := range failed {
			code := "ConditionalCheckFailed"
			rs[f].Code = &code
		}
		return &types.TransactionCanceledException{CancellationReasons: rs}
	}
	for _, c := range []struct {
		name   string
		failed []int
		stale  [2]bool
		tip    bool
	}{
		{"b's head", []int{k + 1}, [2]bool{false, true}, false},
		{"a's entry", []int{k - 2}, [2]bool{}, true},
		{"the tip", []int{n - 2}, [2]bool{}, true},
		{"the configuration", []int{n - 1}, [2]bool{true, true}, false},
	} {
		stale, tipMoved, err := classifyCancel(cancel(c.failed...), cs, n)
		if err != nil || stale[0] != c.stale[0] || stale[1] != c.stale[1] || tipMoved != c.tip {
			t.Errorf("%s: stale %v tip %v %v", c.name, stale, tipMoved, err)
		}
	}
}
