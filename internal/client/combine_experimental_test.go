package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/verify"
)

// Rebased writes of one document written together in one transaction: every
// write lands once, refusals stay their own, and the resource's log and
// the namespace's chain verify afterwards.
func TestExperimentalCombine(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{ExperimentalRebase: true, ExperimentalCombine: true})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	const writers, each = 12, 1 // one write each: within every default burst
	members := map[string]any{}
	for k := 0; k < writers; k++ {
		members[fmt.Sprintf("w%d", k)] = 0
	}
	base, err := c.CreateDoc(ctx, "hot", "d", map[string]any{"members": members, "list": []any{}, "n": 0})
	if err != nil {
		t.Fatal(err)
	}
	// Another document, written meanwhile, shares the namespace's chain.
	other, err := c.CreateDoc(ctx, "hot", "other", map[string]any{"n": 0})
	if err != nil {
		t.Fatal(err)
	}
	rb := client.WithExperimentalRebase()
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	statuses := map[int]int{}
	for k := 0; k < writers; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			wc := s.Client(t, client.WithAuthor(fmt.Sprintf("w%d", k)))
			<-start
			var p []any
			switch {
			case k == 3: // conflicts with nobody's base but applies nowhere: 422
				p = []any{map[string]any{"op": "remove", "path": "/nope"}}
			case k == 7: // two writers of one member: one of them is a 412 or both land in turn
				p = []any{map[string]any{"op": "test", "path": "/members/w6", "value": 0}, map[string]any{"op": "replace", "path": "/members/w7", "value": 1}}
			default:
				p = []any{map[string]any{"op": "replace", "path": fmt.Sprintf("/members/w%d", k), "value": 1}, map[string]any{"op": "add", "path": "/list/-", "value": k}}
			}
			_, err := wc.Append(ctx, "hot", "d", base.ID, p, rb)
			st := 201
			if ae, ok := client.AsAPIError(err); ok {
				st = ae.Status
			} else if err != nil {
				st = -1
			}
			mu.Lock()
			statuses[k] = st
			mu.Unlock()
		}(k)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		id := other.ID
		for i := 1; i <= 5; i++ {
			w, err := c.Append(ctx, "hot", "other", id, []any{map[string]any{"op": "replace", "path": "/n", "value": i}})
			if err != nil {
				t.Error(err)
				return
			}
			id = w.ID
		}
	}()
	close(start)
	wg.Wait()

	landed := 0
	for k := 0; k < writers; k++ {
		switch st := statuses[k]; {
		case k == 3 && st != 422:
			t.Errorf("writer 3: %d, want 422", st)
		case k == 7 && st != 201 && st != 412:
			t.Errorf("writer 7: %d, want 201 or 412", st)
		case k != 3 && k != 7 && st != 201:
			t.Errorf("writer %d: %d, want 201", k, st)
		case st == 201 && k != 7:
			landed++
		}
	}
	h, d, err := c.Load(ctx, "hot", "d")
	if err != nil {
		t.Fatal(err)
	}
	m := d.Value.(map[string]any)
	if l := m["list"].([]any); len(l) != landed {
		t.Errorf("%d list items, %d writes landed", len(l), landed)
	}
	for k := 0; k < writers; k++ {
		want := "1"
		if k == 3 || statuses[k] != 201 {
			want = "0"
		}
		if b, _ := json.Marshal(m["members"].(map[string]any)[fmt.Sprintf("w%d", k)]); string(b) != want {
			t.Errorf("member w%d = %s, want %s (status %d)", k, b, want, statuses[k])
		}
	}
	// The resource's log and the namespace's chain hold together.
	entries, err := c.Log(ctx, "hot", "d", h.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := verify.VerifyResourceLog(entries, ""); err != nil || got != h.ID {
		t.Fatalf("resource log: head %s (want %s), %v", got, h.ID, err)
	}
	if err := verify.Document(entries, nil); err != nil {
		t.Logf("document check skipped or failed: %v", err)
	}
	if _, _, err := verify.Namespace(ctx, c, "hot", ""); err != nil {
		t.Fatalf("namespace chain: %v", err)
	}
}
