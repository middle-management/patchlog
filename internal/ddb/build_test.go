package ddb

import (
	"strings"
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

// plan plans testPatches on doc1: a create ("", If-None-Match) or an
// append to ifMatch.
func plan(t *testing.T, head *resRow, headDoc any, ifMatch string) (*writePlan, *Error) {
	t.Helper()
	return planWrite("demo", "doc1", testMeta, testTip, head, headDoc, Pre{IfMatch: ifMatch, IfNoneMatch: ifMatch == ""}, testPatches, "", "", "alice", 1000, applyPatches)
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
	p, e := planWrite("demo", "doc1", testMeta, testTip, head, map[string]any{"a": float64(1)}, Pre{IfMatch: p0.rev.id}, patches, "", "", "alice", 1001, applyPatches)
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

// A retried append names the same parent as its first attempt, which
// has since become the head's parent: step 2 refuses it (412), and the
// id the request computes (Pre.expectedID) is the committed revision's —
// what the store's retry lookup finds (Store.replay).
func TestPlanWriteReplay(t *testing.T) {
	p0, _ := plan(t, nil, nil, "")
	doc := map[string]any{"a": float64(1)}
	patches := jsonv.MustParse([]byte(`[{"op":"add","path":"/b","value":2}]`))
	pre := Pre{IfMatch: p0.rev.id}
	p1, e := planWrite("demo", "doc1", testMeta, testTip, &resRow{headPos: 1, headID: p0.rev.id, state: "live"}, doc, pre, patches, "", "", "alice", 1001, applyPatches)
	if e != nil {
		t.Fatalf("first append: %v", e)
	}
	head2 := &resRow{headPos: 2, headID: p1.rev.id, entryID: p1.entry.id, state: "live"}
	if _, e := planWrite("demo", "doc1", testMeta, testTip, head2, nil, pre, patches, "", "", "alice", 1002, applyPatches); e == nil || e.Status != 412 || e.Body["head"] != p1.rev.id {
		t.Fatalf("retry at step 2: %v", e)
	}
	if id, ok := pre.expectedID(false, patches); !ok || id != p1.rev.id {
		t.Fatalf("expected id %q %v, want the committed %q", id, ok, p1.rev.id)
	}
	// A create's is over no parent; a delete's the tombstone of its
	// If-Match; without a precondition there is none.
	if id, _ := (Pre{IfNoneMatch: true}).expectedID(false, testPatches); id != p0.rev.id {
		t.Fatalf("create's expected id %q, want %q", id, p0.rev.id)
	}
	if id, _ := pre.expectedID(true, nil); id != ids.Tombstone(mustParse(p0.rev.id)).String() {
		t.Fatalf("delete's expected id %q", id)
	}
	if _, ok := (Pre{}).expectedID(false, patches); ok {
		t.Fatal("expected id without a precondition")
	}
}

// §7.2's preconditions (precondition of write.go): 428 without one, 400
// with both, 412 naming the head (null when absent), 410 naming the
// tombstone for an If-Match on a deleted resource that isn't its
// tombstone.
func TestPlanWritePreconditions(t *testing.T) {
	p0, _ := plan(t, nil, nil, "")
	live := &resRow{headPos: 1, headID: p0.rev.id, state: "live"}
	tid := ids.Tombstone(mustParse(p0.rev.id)).String()
	tomb := &resRow{headPos: 2, headID: tid, state: "tombstoned", lastID: p0.rev.id, lastPos: 1}
	other := ids.Of([]byte("other")).String()
	for _, c := range []struct {
		name   string
		head   *resRow
		pre    Pre
		status int
		member any
	}{
		{"none", live, Pre{}, 428, nil},
		{"both", live, Pre{IfMatch: p0.rev.id, IfNoneMatch: true}, 400, nil},
		{"create on live", live, Pre{IfNoneMatch: true}, 412, p0.rev.id},
		{"create on tombstone", tomb, Pre{IfNoneMatch: true}, 412, tid},
		{"append to absent", nil, Pre{IfMatch: other}, 412, nil},
		{"append stale", live, Pre{IfMatch: other}, 412, p0.rev.id},
		{"restore stale", tomb, Pre{IfMatch: other}, 410, tid},
	} {
		_, e := planWrite("demo", "doc1", testMeta, testTip, c.head, nil, c.pre, testPatches, "", "", "alice", 1000, applyPatches)
		if e == nil || e.Status != c.status {
			t.Errorf("%s: %v, want %d", c.name, e, c.status)
			continue
		}
		switch c.status {
		case 412:
			if e.Body["head"] != c.member {
				t.Errorf("%s: head %v, want %v", c.name, e.Body["head"], c.member)
			}
		case 410:
			if e.Body["tombstone"] != c.member {
				t.Errorf("%s: tombstone %v, want %v", c.name, e.Body["tombstone"], c.member)
			}
		}
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
	if _, e := planWrite("demo", "d", nil, testTip, nil, nil, Pre{IfNoneMatch: true}, testPatches, "", "", "a", 0, applyPatches); e == nil || e.Status != 404 {
		t.Fatalf("absent namespace: %v", e)
	}
	if _, e := planWrite("demo", "d", &nsMeta{purged: true}, testTip, nil, nil, Pre{IfNoneMatch: true}, testPatches, "", "", "a", 0, applyPatches); e == nil || e.Status != 410 {
		t.Fatalf("purged namespace: %v", e)
	}
	if _, e := planWrite("demo", "d", &nsMeta{frozen: true}, testTip, nil, nil, Pre{IfNoneMatch: true}, testPatches, "", "", "a", 0, applyPatches); e == nil || e.Status != 409 {
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
	p2, e := planWrite("demo", "doc1", testMeta, testTip, head, map[string]any{"a": float64(1)}, Pre{IfMatch: p.rev.id}, jsonv.MustParse([]byte(`[{"op":"add","path":"/b","value":2}]`)), "", "", "alice", 1001, applyPatches)
	if e != nil {
		t.Fatalf("append: %v", e)
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

func TestPlanDelete(t *testing.T) {
	p0, _ := plan(t, nil, nil, "")
	head := &resRow{headPos: 1, headID: p0.rev.id, entryID: p0.entry.id, state: "live"}

	// No If-Match: 428; a stale one: 412 naming the head, null for an
	// absent resource (precondition of write.go).
	if _, e := planDelete("demo", "doc1", testMeta, testTip, head, Pre{}, "", "", "alice", 2000); e == nil || e.Status != 428 {
		t.Fatalf("no If-Match: %v", e)
	}
	if _, e := planDelete("demo", "doc1", testMeta, testTip, nil, Pre{IfMatch: p0.rev.id}, "", "", "alice", 2000); e == nil || e.Status != 412 || e.Body["head"] != nil {
		t.Fatalf("absent: %v", e)
	}
	other := ids.Of([]byte("other")).String()
	if _, e := planDelete("demo", "doc1", testMeta, testTip, head, Pre{IfMatch: other}, "", "", "alice", 2000); e == nil || e.Status != 412 || e.Body["head"] != p0.rev.id {
		t.Fatalf("stale: %v", e)
	}

	p, e := planDelete("demo", "doc1", testMeta, testTip, head, Pre{IfMatch: p0.rev.id}, "g", "", "alice", 2000)
	if e != nil {
		t.Fatalf("planDelete: %v", e)
	}
	// The tombstone id is ids.Tombstone over the deleted head (§3.3), so a
	// retried DELETE recomputes it; the parent is the deleted head.
	parent, _ := ids.Parse(p0.rev.id)
	wantTid := ids.Tombstone(parent)
	if p.rev.id != wantTid.String() || p.rev.kind != "tombstone" || p.rev.parentID != p0.rev.id {
		t.Fatalf("tombstone %+v, want id %q parent %q", p.rev, wantTid, p0.rev.id)
	}
	if !p.del || p.newHead.state != "tombstoned" || p.newHead.lastID != p0.rev.id || p.newHead.lastPos != 1 {
		t.Fatalf("plan %+v", p)
	}
	wantBody := `{"kind":"tombstone","resource":"doc1","target":"` + wantTid.String() + `"}`
	if p.entry.body != wantBody || p.entry.kind != "tombstone" {
		t.Fatalf("entry %+v, want body %q", p.entry, wantBody)
	}
	// Its transaction: five actions, the head pinned on the deleted
	// revision; the document stays, the last live one (a restore's base).
	tx := buildDeleteTx("tbl", "demo", "doc1", p)
	if len(tx) != delNumActs {
		t.Fatalf("%d actions, want %d", len(tx), delNumActs)
	}
	for i, a := range tx {
		if a.Delete != nil {
			t.Fatalf("action %d deletes an item", i)
		}
	}
	res := tx[delActRes].Update
	if *res.ConditionExpression != "headPos = :old AND headId = :oldi" {
		t.Fatalf("RES condition %q", *res.ConditionExpression)
	}

	// A DELETE of a tombstoned resource is 410 naming the tombstone, its
	// own retry included: the store's retry lookup answers that one
	// (Store.replay, by the tombstone id the request computes).
	tomb := &resRow{headPos: 2, headID: p.rev.id, entryID: p.entry.id, state: "tombstoned", lastID: p0.rev.id, lastPos: 1}
	for _, im := range []string{p0.rev.id, other} {
		if _, e := planDelete("demo", "doc1", testMeta, testTip, tomb, Pre{IfMatch: im}, "", "", "alice", 2001); e == nil || e.Status != 410 || e.Body["tombstone"] != p.rev.id {
			t.Fatalf("delete of a tombstone (If-Match %s): %v", im, e)
		}
	}
}

func TestPlanWriteRestore(t *testing.T) {
	p0, _ := plan(t, nil, nil, "")
	tid := ids.Tombstone(mustParse(p0.rev.id)).String()
	tomb := &resRow{headPos: 2, headID: tid, entryID: "e", state: "tombstoned", lastID: p0.rev.id, lastPos: 1}

	// A write naming the tombstone restores (§6.2): the parent is the
	// tombstone id, the patches apply to the last live document (an
	// empty patch set restores it unchanged), and the RES update clears
	// the last-revision markers.
	last := map[string]any{"a": float64(1)}
	p, e := planWrite("demo", "doc1", testMeta, testTip, tomb, last, Pre{IfMatch: tid}, []any{}, "", "", "alice", 3000, applyPatches)
	if e != nil {
		t.Fatalf("planWrite: %v", e)
	}
	if !p.restore || p.create || p.rev.parentID != tid || p.rev.pos != 3 {
		t.Fatalf("restore plan %+v", p)
	}
	if p.doc != `{"a":1}` {
		t.Fatalf("restored document %q", p.doc)
	}
	tx := buildWriteTx("tbl", "demo", "doc1", p)
	if u := *tx[actRes].Update.UpdateExpression; !strings.HasSuffix(u, "REMOVE lastId, lastPos") {
		t.Fatalf("RES update %q", u)
	}
	// Its revision id differs from the pre-delete genesis's, whose parent
	// was nil: chains don't alias across a tombstone.
	if p.rev.id == p0.rev.id {
		t.Fatalf("restore aliases the genesis id %q", p.rev.id)
	}
}

func mustParse(s string) ids.ID {
	id, err := ids.Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}
