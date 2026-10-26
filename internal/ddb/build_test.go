package ddb

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

var (
	// A create's patch set establishes the root document (§6.2), exactly
	// as on the SQL backends: add of the root value.
	testPatches = jsonv.MustParse([]byte(`[{"op":"add","path":"","value":{"a":1}}]`))
	testMeta    = &nsMeta{configPos: 1, configID: ids.Of([]byte("cfg")).String()}
	testTip     = &tip{headPos: 1, headID: ids.Of([]byte("entry1")).String()}
)

func plan(t *testing.T, head *resRow, headDoc any, ifMatch string) (*writePlan, *Error) {
	t.Helper()
	return planWrite("demo", "doc1", testMeta, testTip, head, headDoc, ifMatch, testPatches, "alice", 1000, applyPatches)
}

func TestPlanWriteGenesis(t *testing.T) {
	p, e := plan(t, nil, nil, "")
	if e != nil {
		t.Fatalf("planWrite: %v", e)
	}
	canon := jsonv.Canonical(testPatches)
	revID := ids.Revision(nil, canon)
	if p.rev.id != revID.String() {
		t.Fatalf("revision id %q, want %q (ids.Revision(nil, canonical patches), §3.3)", p.rev.id, revID)
	}
	if p.rev.pos != 1 || !p.create {
		t.Fatalf("genesis at pos %d, create %v", p.rev.pos, p.create)
	}
	// The entry: pos 2 (after the tip at 1), id chained over the tip
	// (§3.5), body exactly the hashed members.
	wantBody := `{"kind":"head","resource":"doc1","target":"` + revID.String() + `"}`
	if p.entry.body != wantBody {
		t.Fatalf("entry body %q, want %q", p.entry.body, wantBody)
	}
	tipID, _ := ids.Parse(testTip.headID)
	wantEntry := ids.Hash(&tipID, []byte(wantBody))
	if p.entry.pos != 2 || p.entry.prevPos != 1 || p.entry.id != wantEntry.String() {
		t.Fatalf("entry %+v, want pos 2 prev 1 id %q", p.entry, wantEntry)
	}
	// The document is folded with the production patch engine.
	if p.doc != `{"a":1}` {
		t.Fatalf("head document %q", p.doc)
	}
}

func TestPlanWriteAppend(t *testing.T) {
	p0, _ := plan(t, nil, nil, "")
	head := &resRow{headPos: 1, headID: p0.rev.id, entryID: p0.entry.id, state: "live"}
	patches := jsonv.MustParse([]byte(`[{"op":"add","path":"/b","value":2}]`))
	p, e := planWrite("demo", "doc1", testMeta, testTip, head, map[string]any{"a": float64(1)}, p0.rev.id, patches, "alice", 1001, applyPatches)
	if e != nil {
		t.Fatalf("planWrite: %v", e)
	}
	parent, _ := ids.Parse(p0.rev.id)
	if want := ids.Revision(&parent, jsonv.Canonical(patches)).String(); p.rev.id != want {
		t.Fatalf("append id %q, want %q (over parent)", p.rev.id, want)
	}
	if p.rev.pos != 2 || p.rev.parentID != p0.rev.id || p.create {
		t.Fatalf("append at pos %d parent %q create %v", p.rev.pos, p.rev.parentID, p.create)
	}
	if p.doc != `{"a":1,"b":2}` {
		t.Fatalf("folded document %q", p.doc)
	}
}

func TestPlanWriteReplay(t *testing.T) {
	p0, _ := plan(t, nil, nil, "")
	doc := map[string]any{"a": float64(1)}
	// An append pins its parent with ifMatch, commits, and moves the head.
	patches := jsonv.MustParse([]byte(`[{"op":"add","path":"/b","value":2}]`))
	p1, e := planWrite("demo", "doc1", testMeta, testTip, &resRow{headPos: 1, headID: p0.rev.id, state: "live"}, doc, p0.rev.id, patches, "alice", 1001, applyPatches)
	if e != nil {
		t.Fatalf("first append: %v", e)
	}
	// Its retry names the same parent; the head is now the first
	// attempt's own revision. Replay, not 412.
	head2 := &resRow{headPos: 2, headID: p1.rev.id, entryID: p1.entry.id, state: "live"}
	p, e := planWrite("demo", "doc1", testMeta, testTip, head2, map[string]any{"a": float64(1), "b": float64(2)}, p0.rev.id, patches, "alice", 1002, applyPatches)
	if e != nil {
		t.Fatalf("planWrite: %v", e)
	}
	if !p.replay {
		t.Fatal("a retried write did not replay")
	}
	if p.rev.id != p1.rev.id || p.entry.id != p1.entry.id {
		t.Fatalf("replay answers rev %q entry %q, want the committed %q %q", p.rev.id, p.entry.id, p1.rev.id, p1.entry.id)
	}
	// But a retry whose patches differ is not its own write: 412.
	other := jsonv.MustParse([]byte(`[{"op":"add","path":"/c","value":3}]`))
	if _, e := planWrite("demo", "doc1", testMeta, testTip, head2, nil, p0.rev.id, other, "alice", 1003, applyPatches); e == nil || e.Status != 412 {
		t.Fatalf("moved head with different patches: %v", e)
	}
}

func TestPlanWriteStale(t *testing.T) {
	_, e := plan(t, nil, nil, ids.Of([]byte("elsewhere")).String())
	if e == nil || e.Status != 412 {
		t.Fatalf("ifMatch on an absent resource: %v", e)
	}
	p0, _ := plan(t, nil, nil, "")
	head := &resRow{headPos: 1, headID: p0.rev.id, state: "live"}
	_, e = plan(t, head, nil, ids.Of([]byte("elsewhere")).String())
	if e == nil || e.Status != 412 || e.Body["head"] != p0.rev.id {
		t.Fatalf("ifMatch mismatch: %v", e)
	}
}

func TestPlanWriteNamespaceStates(t *testing.T) {
	if _, e := planWrite("demo", "d", nil, testTip, nil, nil, "", testPatches, "a", 0, applyPatches); e == nil || e.Status != 404 {
		t.Fatalf("absent namespace: %v", e)
	}
	if _, e := planWrite("demo", "d", &nsMeta{purged: true}, testTip, nil, nil, "", testPatches, "a", 0, applyPatches); e == nil || e.Status != 410 {
		t.Fatalf("purged namespace: %v", e)
	}
	if _, e := planWrite("demo", "d", &nsMeta{frozen: true}, testTip, nil, nil, "", testPatches, "a", 0, applyPatches); e == nil || e.Status != 409 {
		t.Fatalf("frozen namespace: %v", e)
	}
}

func TestBuildWriteTx(t *testing.T) {
	p, _ := plan(t, nil, nil, "")
	acts := buildWriteTx("tbl", "demo", "doc1", p)
	if len(acts) != numActs {
		t.Fatalf("%d actions, want %d", len(acts), numActs)
	}
	// Keys land where keys.go says.
	if got := acts[actRev].Put.Item["SK"].(*types.AttributeValueMemberS).Value; got != "REV#doc1#"+padPos(1) {
		t.Fatalf("revision at %q", got)
	}
	if got := acts[actLog].Put.Item["SK"].(*types.AttributeValueMemberS).Value; got != "LOG#"+padPos(2) {
		t.Fatalf("entry at %q", got)
	}
	// Conditions: the chain races of §4.
	conds := map[int]string{
		actRev:  "attribute_not_exists(PK)",
		actRes:  "attribute_not_exists(PK)", // genesis
		actLog:  "attribute_not_exists(PK)",
		actTip:  "headPos = :h AND headId = :i",
		actNSID: "attribute_not_exists(PK)",
	}
	for i, want := range conds {
		var got *string
		switch {
		case acts[i].Put != nil:
			got = acts[i].Put.ConditionExpression
		case acts[i].Update != nil:
			got = acts[i].Update.ConditionExpression
		}
		if got == nil || *got != want {
			t.Errorf("action %d condition %v, want %q", i, got, want)
		}
	}
	// The head snapshot and history carry no condition.
	if acts[actDoc].Put.ConditionExpression != nil || acts[actHist].Put.ConditionExpression != nil {
		t.Error("doc/history puts must be unconditional upserts")
	}
	// The tip moves to the entry's position and id, pinned on the old
	// ones. (A spike once set the old values back: the tip never
	// advanced, and every later write collided on the same LOG# item.)
	tipVals := acts[actTip].Update.ExpressionAttributeValues
	if got := tipVals[":new"].(*types.AttributeValueMemberN).Value; got != "2" {
		t.Errorf("tip moves to headPos %q, want the entry's 2", got)
	}
	if got := tipVals[":newi"].(*types.AttributeValueMemberS).Value; got != p.entry.id {
		t.Errorf("tip moves to headId %q, want the entry's %q", got, p.entry.id)
	}
	// The append form conditions on the old head.
	head := &resRow{headPos: 1, headID: p.rev.id, entryID: p.entry.id, state: "live"}
	p2, _ := planWrite("demo", "doc1", testMeta, testTip, head, map[string]any{"a": float64(1)}, "", testPatches, "alice", 1001, applyPatches)
	if p2.replay {
		t.Fatal("unexpected replay")
	}
	acts2 := buildWriteTx("tbl", "demo", "doc1", p2)
	if got := *acts2[actRes].Update.ConditionExpression; got != "headPos = :old" {
		t.Fatalf("append conditions on the old head: %q", got)
	}
	old := acts2[actRes].Update.ExpressionAttributeValues[":old"].(*types.AttributeValueMemberN).Value
	if old != "1" {
		t.Fatalf(":old = %q, want the checked headPos 1", old)
	}
	// Every action names the table (transactions span tables; there is
	// no input-level TableName).
	for i, a := range acts2 {
		var tn *string
		switch {
		case a.Put != nil:
			tn = a.Put.TableName
		case a.Update != nil:
			tn = a.Update.TableName
		}
		if tn == nil || *tn != "tbl" {
			t.Errorf("action %d has no table name", i)
		}
	}
}
