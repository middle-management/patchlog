package ddb

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
)

func member(t *testing.T, name string, cfgPos uint64) *groupMember {
	t.Helper()
	p, e := planWrite("demo", name, &nsMeta{configPos: cfgPos, configID: testMeta.configID}, testTip, nil, nil, "", testPatches, "", "", "alice", 1000, applyPatches)
	if e != nil {
		t.Fatal(e)
	}
	return &groupMember{name: name, p: p}
}

// take groups distinct resources under one configuration, within the
// action budget, and keeps the rest queued in order.
func TestGroupTake(t *testing.T) {
	q := &nsQueue{queue: []*groupMember{
		member(t, "a", 1), member(t, "b", 1), member(t, "a", 1), member(t, "c", 2), member(t, "d", 1),
	}}
	group := q.take(32)
	var got, left []string
	for _, w := range group {
		got = append(got, w.name)
	}
	for _, w := range q.queue {
		left = append(left, fmt.Sprintf("%s@%d", w.name, w.p.entry.cfgPos))
	}
	if strings.Join(got, ",") != "a,b,d" || strings.Join(left, ",") != "a@1,c@2" {
		t.Fatalf("took %v, left %v", got, left)
	}

	// The budget: 2 shared + 6 a write, so 16 writes fit 100 actions.
	q.queue = nil
	for i := range 20 {
		q.queue = append(q.queue, member(t, fmt.Sprintf("r%d", i), 1))
	}
	if group := q.take(32); len(group) != 16 || len(q.queue) != 4 {
		t.Fatalf("took %d, left %d; want 16 and 4", len(group), len(q.queue))
	}
	if group := q.take(3); len(group) != 3 || len(q.queue) != 1 {
		t.Fatalf("limit 3: took %d, left %d", len(group), len(q.queue))
	}
}

// chainGroup re-chains entries over the tip at consecutive positions,
// drops each write's own tip move, and ends with one tip move and the
// configuration's condition.
func TestChainGroup(t *testing.T) {
	ws := []*groupMember{member(t, "a", 1), member(t, "b", 1), member(t, "c", 1)}
	s := &Store{Table: "tbl"}
	start := tip{headPos: 7, headID: testTip.headID}
	acts, err := s.chainGroup("demo", ws, start, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 3*(numActs-1)+groupShared || len(acts) > maxTxActions {
		t.Fatalf("%d actions", len(acts))
	}
	prev := start
	for i, w := range ws {
		e := w.p.entry
		pid, _ := ids.Parse(prev.headID)
		if e.pos != prev.headPos+1 || e.prevPos != prev.headPos || e.id != ids.Hash(&pid, []byte(e.body)).String() {
			t.Fatalf("write %d: entry %d after %d, id %s", i, e.pos, e.prevPos, e.id)
		}
		if w.p.newHead.entryID != e.id {
			t.Fatalf("write %d: RES names entry %s, not %s", i, w.p.newHead.entryID, e.id)
		}
		// The write's own actions: its log entry at its new position,
		// its marker last.
		own := acts[i*(numActs-1) : (i+1)*(numActs-1)]
		if got := own[actLog].Put.Item["SK"].(*types.AttributeValueMemberS).Value; got != "LOG#"+padPos(e.pos) {
			t.Fatalf("write %d: entry at %q", i, got)
		}
		if got := own[len(own)-1].Put.Item["PK"].(*types.AttributeValueMemberS).Value; got != keyNSID("demo", e.id).PK {
			t.Fatalf("write %d: last action %q, want the marker", i, got)
		}
		for _, a := range own {
			if a.Update != nil && a.Update.Key["SK"].(*types.AttributeValueMemberS).Value == "#TIP" {
				t.Fatalf("write %d moves the tip itself", i)
			}
		}
		prev = tip{headPos: e.pos, headID: e.id}
	}
	mv := acts[len(acts)-2].Update
	if mv == nil || *mv.ConditionExpression != "headPos = :h AND headId = :i" ||
		mv.ExpressionAttributeValues[":h"].(*types.AttributeValueMemberN).Value != "7" ||
		mv.ExpressionAttributeValues[":new"].(*types.AttributeValueMemberN).Value != "10" ||
		mv.ExpressionAttributeValues[":newi"].(*types.AttributeValueMemberS).Value != prev.headID {
		t.Fatalf("tip move: %+v", mv)
	}
	cc := acts[len(acts)-1].ConditionCheck
	if cc == nil || *cc.ConditionExpression != "configPos = :cp" || cc.Key["SK"].(*types.AttributeValueMemberS).Value != "#META" {
		t.Fatalf("config condition: %+v", cc)
	}
}

// Grouped writes, deletes and appends race batches and a config change,
// which move the tip outside the queue: every write commits (or answers
// its own 412), the chain has no gaps, and every committed write's entry
// is in it.
func TestLocalGroupMixed(t *testing.T) {
	s := newLocalStore(t)
	s.GroupCommit = 32
	ctx := context.Background()
	mustCreateNS(t, s, "demo")
	const n = 24
	pre := make([]*WriteResult, n)
	for i := range n {
		pre[i] = mustWrite(t, s, "demo", fmt.Sprintf("old%d", i), "", `[{"op":"add","path":"","value":{"v":0}}]`)
	}
	g0, w0 := s.GroupStats()

	var wg sync.WaitGroup
	var mu sync.Mutex
	committed := map[string]bool{}
	var errs []error
	record := func(id string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return
		}
		committed[id] = true
	}
	for i := range n {
		wg.Add(3)
		go func() {
			defer wg.Done()
			res, err := s.WriteResource(ctx, "demo", fmt.Sprintf("new%d", i), "",
				patches(fmt.Sprintf(`[{"op":"add","path":"","value":{"n":%d}}]`, i)), "", "", "alice", nil)
			if err == nil {
				record(res.NSID, nil)
			} else {
				record("", fmt.Errorf("new%d: %w", i, err))
			}
		}()
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("old%d", i)
			var res *WriteResult
			var err error
			if i%2 == 0 {
				res, err = s.DeleteResource(ctx, "demo", name, pre[i].ID, "", "", "alice", nil)
			} else {
				res, err = s.WriteResource(ctx, "demo", name, pre[i].ID, patches(`[{"op":"add","path":"/v","value":1}]`), "", "", "alice", nil)
			}
			if err == nil {
				record(res.NSID, nil)
			} else {
				record("", fmt.Errorf("old%d: %w", i, err))
			}
		}()
		go func() {
			defer wg.Done()
			if i%4 == 0 {
				// A config change: the queued writes planned under the
				// old configuration are checked again.
				res, err := s.WriteConfig(ctx, "demo", "alice", patches(fmt.Sprintf(`[{"op":"add","path":"/k%d","value":true}]`, i)),
					func(doc any, exists bool, p any) (any, error) {
						out, _, err := applyPatches(doc, exists, p)
						return out, err
					}, nil)
				if err == nil {
					record(res.NSID, nil)
				} else {
					record("", fmt.Errorf("config%d: %w", i, err))
				}
				return
			}
			res, err := s.WriteBatch(ctx, "demo", "alice", []BatchItem{
				{Name: fmt.Sprintf("bat%da", i), IfNoneMatch: true, Patches: patches(`[{"op":"add","path":"","value":{}}]`)},
				{Name: fmt.Sprintf("bat%db", i), IfNoneMatch: true, Patches: patches(`[{"op":"add","path":"","value":{}}]`)},
			}, nil, nil, nil, nil, false)
			if err == nil {
				record(res.NSID, nil)
			} else {
				record("", fmt.Errorf("batch%d: %w", i, err))
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		t.Errorf("write: %v", err)
	}
	if len(committed) != 3*n {
		t.Fatalf("%d distinct entries committed, want %d", len(committed), 3*n)
	}

	entries, _, err := s.ReadLog(ctx, "demo", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + n + 3*n; len(entries) != want {
		t.Fatalf("%d entries, want %d", len(entries), want)
	}
	prev := entries[0]["id"].(string)
	for i, e := range entries[1:] {
		if e["prev"] != prev {
			t.Fatalf("entry %d prev %v, want %s: a gap in the chain", i+2, e["prev"], prev)
		}
		prev = e["id"].(string)
		delete(committed, prev)
	}
	if len(committed) != 0 {
		t.Fatalf("answered entries missing from the log: %v", committed)
	}
	for i := range n {
		h, err := s.ReadHead(ctx, "demo", fmt.Sprintf("old%d", i))
		if err != nil || h == nil || h.Live != (i%2 == 1) {
			t.Fatalf("old%d: %+v %v", i, h, err)
		}
	}
	g1, w1 := s.GroupStats()
	t.Logf("%d grouped writes in %d groups", w1-w0, g1-g0)
}

// Two grouped stores on one table stand in for two instances: their
// workers race for the tip, and each re-reads it and re-chains its group
// when the other's commit moved it.
func TestLocalGroupTwoInstances(t *testing.T) {
	a := newLocalStore(t)
	a.GroupCommit = 32
	b := &Store{Client: a.Client, Table: a.Table, GroupCommit: 32}
	ctx := context.Background()
	mustCreateNS(t, a, "demo")
	const n = 64
	var wg sync.WaitGroup
	errs := make([]error, n)
	nsids := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			res, err := s.WriteResource(ctx, "demo", fmt.Sprintf("doc%d", i), "",
				patches(fmt.Sprintf(`[{"op":"add","path":"","value":{"n":%d}}]`, i)), "", "", "alice", nil)
			if err == nil {
				nsids[i] = res.NSID
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}
	entries, _, err := a.ReadLog(ctx, "demo", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n+1 {
		t.Fatalf("%d entries, want %d", len(entries), n+1)
	}
	inLog := map[string]bool{}
	prev := entries[0]["id"].(string)
	for i, e := range entries[1:] {
		if e["prev"] != prev {
			t.Fatalf("entry %d prev %v, want %s: a gap in the chain", i+2, e["prev"], prev)
		}
		prev = e["id"].(string)
		inLog[prev] = true
	}
	for i, id := range nsids {
		if !inLog[id] {
			t.Fatalf("writer %d answered entry %s, not in the log", i, id)
		}
	}
	ga, wa := a.GroupStats()
	gb, wb := b.GroupStats()
	t.Logf("a: %d writes in %d groups; b: %d in %d", wa, ga, wb, gb)
}
