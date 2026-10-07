package core

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

func replayEngine(tb testing.TB) *Engine {
	tb.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	path := filepath.Join(tb.TempDir(), "replay.db")
	if pgtest.Enabled() {
		path = pgtest.NewDB(tb)
	}
	e, err := Open(Options{Path: path, BlobDir: tb.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, Purger: discardPurger{}})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { e.Close() })
	genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
		tb.Fatal(err)
	}
	return e
}

// batchOf writes a batch of n creates, named after prefix, by author a.
func batchOf(e *Engine, prefix string, n int) (*WriteResult, error) {
	items := make([]Item, n)
	for j := range items {
		items[j] = Item{Resource: fmt.Sprintf("%s_%d", prefix, j), IfNoneMatch: true,
			Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": float64(j)}}}}}}
	}
	return e.Batch(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, items, nil, nil, false)
}

// The idempotent-retry lookup of a batch (§7.5) runs on every batch. It
// must cost the batch's own rows, not one per earlier batch by the same
// author: it once read and parsed every batch entry the author had written
// in the namespace, so batches slowed down as the log grew. Earlier batch
// entries are made unparseable here; a lookup that reads them fails.
func TestBatchReplayIgnoresOtherBatches(t *testing.T) {
	e := replayEngine(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		if _, err := batchOf(e, fmt.Sprint("old", i), 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE ns_log SET body = 'unparseable' WHERE kind = ? AND seq < (SELECT MAX(seq) FROM ns_log)`, nsKindCode("batch"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := batchOf(e, "new", 3)
	if err != nil || r.Status != 201 {
		t.Fatalf("new batch: %v %+v", err, r)
	}
	// Its retry is still recognised, from its own rows.
	again, err := batchOf(e, "new", 3)
	if err != nil || again.Status != 200 || !again.Replayed || again.NSID != r.NSID || len(again.Items) != 3 {
		t.Fatalf("retry: %v %+v (first %+v)", err, again, r)
	}
	// A batch that overlaps it but isn't it is not a retry.
	other, err := batchOf(e, "new", 2)
	if err == nil && other.Status == 200 {
		t.Fatalf("a different batch replayed: %+v", other)
	}
}

// BenchmarkBatchAfterLog writes one-item batches after a log of prior
// batches by the same author; ns/op should not grow with the prior count.
//
//	go test ./internal/core -run '^$' -bench BatchAfterLog
func BenchmarkBatchAfterLog(b *testing.B) {
	for _, prior := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprint("prior=", prior), func(b *testing.B) {
			e := replayEngine(b)
			for i := 0; i < prior; i++ {
				if _, err := batchOf(e, fmt.Sprint("p", i), 1); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := batchOf(e, fmt.Sprint("x", i), 1); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
