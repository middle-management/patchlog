package client_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// AppendLatest retries a lost race on the head the 412 names, so every
// writer of a contended document gets its change in and none is lost.
func TestAppendLatestContended(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	w, err := c.CreateDoc(ctx, "hot", "list", map[string]any{"items": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	const writers, each = 8, 2 // under the default burst of 20 a principal and resource
	var wg sync.WaitGroup
	var retries atomic.Int64
	errs := make(chan error, writers*each)
	for k := 0; k < writers; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			wc := s.Client(t, client.WithAuthor("w"+string(rune('a'+k))))
			for i := 0; i < each; i++ {
				_, err := wc.AppendLatest(ctx, "hot", "list", w.ID, client.Backoff{OnRetry: func(error) { retries.Add(1) }},
					func(string) (any, error) {
						return []any{map[string]any{"op": "add", "path": "/items/-", "value": k*100 + i}}, nil
					})
				if err != nil {
					errs <- err
				}
			}
		}(k)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	_, d, err := c.Load(ctx, "hot", "list")
	if err != nil {
		t.Fatal(err)
	}
	items := d.Value.(map[string]any)["items"].([]any)
	if len(items) != writers*each {
		t.Fatalf("%d items, want %d (%d retries)", len(items), writers*each, retries.Load())
	}
	if retries.Load() == 0 {
		t.Log("no writer lost a race")
	}
}

// An empty head is read first; build's error ends the call; a refusal
// that isn't a lost race is returned as it is.
func TestAppendLatestEdges(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDoc(ctx, "hot", "n", map[string]any{"n": 0}); err != nil {
		t.Fatal(err)
	}
	set := func(v int) func(string) (any, error) {
		return func(string) (any, error) {
			return []any{map[string]any{"op": "replace", "path": "/n", "value": v}}, nil
		}
	}
	if _, err := c.AppendLatest(ctx, "hot", "n", "", client.Backoff{}, set(1)); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if _, err := c.AppendLatest(ctx, "hot", "n", "", client.Backoff{}, func(string) (any, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("build's error: %v", err)
	}
	calls := 0
	_, err := c.AppendLatest(ctx, "hot", "n", "", client.Backoff{}, func(string) (any, error) {
		calls++
		return []any{map[string]any{"op": "test", "path": "/n", "value": 99}}, nil
	})
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 || calls != 1 {
		t.Fatalf("a failing test op: %v after %d calls", err, calls)
	}
	// A stale head given by the caller is corrected from the 412.
	h, err := c.Head(ctx, "hot", "n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(ctx, "hot", "n", h.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 2}}); err != nil {
		t.Fatal(err)
	}
	var seen []string
	if _, err := c.AppendLatest(ctx, "hot", "n", h.ID, client.Backoff{}, func(head string) (any, error) {
		seen = append(seen, head)
		return []any{map[string]any{"op": "replace", "path": "/n", "value": 3}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != h.ID || seen[1] == h.ID {
		t.Fatalf("heads tried: %v", seen)
	}
}
