package core

import (
	"context"
	"testing"
)

const (
	gestA = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	gestB = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	gestC = "cccccccccccccccccccccccccc"
)

// gestureStep is a patch set step with gestures.
func gestureStep(patches []any, gesture, undoes string) Step {
	return Step{Patches: patches, Gesture: gesture, Undoes: undoes}
}

// §7.2, §7.4 (v0.39), D.8: writes carrying different gestures, appended
// together by one group (insertItemsBy, appendNSMany), each keep their
// own: in their revisions and in their namespace entries, a single
// write's gesture and undoes, and a batch's gestures map.
func TestPGGroupCommitGestures(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	hz, err := put(e, "n", "z", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := groupSizes(e)
	single := func(name, gesture, undoes string) func() (*WriteResult, error) {
		return func() (*WriteResult, error) {
			r := who
			r.NS = "n"
			return e.WriteResource(context.Background(), r, Item{Resource: name, IfNoneMatch: true,
				Steps: []Step{gestureStep([]any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}, gesture, undoes)}})
		}
	}
	res, errs := queueInOrder(t, e, []func() (*WriteResult, error){
		single("x", gestA, ""),
		single("y", gestB, gestA),
		func() (*WriteResult, error) {
			r := who
			r.NS = "n"
			return e.Batch(context.Background(), r, []Item{{Resource: "z", IfMatch: hz, Steps: []Step{
				gestureStep([]any{map[string]any{"op": "replace", "path": "/n", "value": 1.0}}, gestC, gestB),
				{Delete: true},
			}}}, nil, nil, false)
		},
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != 4 {
		t.Fatalf("group attempts %v, want one of 4", got)
	}
	xids := checkChain(t, e, "n")
	if xids[res[0].NSID] != xids[res[1].NSID] || xids[res[1].NSID] != xids[res[2].NSID] {
		t.Fatal("the writes committed apart")
	}
	if res[0].Entry.Gesture != gestA || res[1].Entry.Gesture != gestB || res[1].Entry.Undoes != gestA {
		t.Fatalf("write results %+v %+v", res[0].Entry, res[1].Entry)
	}
	lg, err := e.NamespaceLog(context.Background(), "n", "", "", 0, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, m := range lg.Entries {
		byID[m["id"].(string)] = m
	}
	if m := byID[res[0].NSID]; m["gesture"] != gestA || m["undoes"] != nil {
		t.Fatalf("x's entry %v", m)
	}
	if m := byID[res[1].NSID]; m["gesture"] != gestB || m["undoes"] != gestA {
		t.Fatalf("y's entry %v", m)
	}
	if m := byID[res[3].NSID]; m["gesture"] != nil || m["gestures"] != nil {
		t.Fatalf("the holder's entry %v", m)
	}
	steps, _ := byID[res[2].NSID]["gestures"].(map[string]any)["z"].([]any)
	if len(steps) != 2 || steps[0].(map[string]any)["gesture"] != gestC || steps[0].(map[string]any)["undoes"] != gestB || len(steps[1].(map[string]any)) != 0 {
		t.Fatalf("the batch's gestures %v", byID[res[2].NSID])
	}
	zl, err := e.ResourceLog(context.Background(), "n", "z", res[2].Items[0].IDs[1], hz, 0, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if len(zl.Entries) != 2 || zl.Entries[0]["gesture"] != gestC || zl.Entries[0]["undoes"] != gestB || zl.Entries[1]["gesture"] != nil {
		t.Fatalf("z's log %v", zl.Entries)
	}
	// The listing finds each gesture's rows, across the group's writes.
	page, err := e.Gestures(context.Background(), "n", gestB, "", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || page.Entries[0]["resource"] != "y" || page.Entries[1]["resource"] != "z" ||
		page.Entries[0]["ns_id"] != res[1].NSID || page.Entries[1]["ns_id"] != res[2].NSID {
		t.Fatalf("gesture B %v", page.Entries)
	}
}
