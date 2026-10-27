package ddb

// Integration tests against DynamoDB Local. They run only with
// DDB_ENDPOINT set:
//
//	docker run -d --name ddb-local -p 8000:8000 amazon/dynamodb-local
//	DDB_ENDPOINT=http://localhost:8000 go test ./internal/ddb/
//
// Everything hermetic — keys, plans, transaction shapes, id computations —
// is covered by the other test files; these prove that DynamoDB enforces
// the conditions the way docs/DYNAMODB.md §4 needs.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func newLocalStore(t testing.TB) *Store {
	t.Helper()
	endpoint := os.Getenv("DDB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DDB_ENDPOINT not set: skipping DynamoDB Local integration test")
	}
	ctx := context.Background()
	url := fmt.Sprintf("dynamodb://spike-%d?region=us-east-1&endpoint=%s", time.Now().UnixNano(), endpoint)
	if err := CreateTable(ctx, url); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DeleteTable(context.Background(), url) })
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func patches(v string) any { return jsonv.MustParse([]byte(v)) }

func mustCreateNS(t *testing.T, s *Store, ns string) (cfgID, nsID string) {
	t.Helper()
	cfgID, nsID, err := s.CreateNamespace(context.Background(), ns, "test", patches(`[{"op":"add","path":"","value":{}}]`))
	if err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	return cfgID, nsID
}

func mustWrite(t *testing.T, s *Store, ns, name, ifMatch, p string) *WriteResult {
	t.Helper()
	res, err := s.WriteResource(context.Background(), ns, name, Pre{IfMatch: ifMatch, IfNoneMatch: ifMatch == ""}, patches(p), "", "", "alice", nil)
	if err != nil {
		t.Fatalf("WriteResource %s/%s: %v", ns, name, err)
	}
	return res
}

// The design's core risk (docs/DYNAMODB.md §4): concurrent writers of one
// namespace serialize on the #TIP condition and retry, so entries commit
// in chain order with no gaps.
func TestLocalConcurrentNamespace(t *testing.T) {
	t.Run("alone", func(t *testing.T) { testConcurrentNamespace(t, 1, 8) })
	t.Run("grouped", func(t *testing.T) { testConcurrentNamespace(t, 32, 48) })
}

// testConcurrentNamespace races writers of distinct resources of one
// namespace, each write committed alone (group 1) or grouped (group.go).
func testConcurrentNamespace(t *testing.T, group, writers int) {
	s := newLocalStore(t)
	s.GroupCommit = group
	mustCreateNS(t, s, "demo")
	var wg sync.WaitGroup
	errs := make([]error, writers)
	ids := make([]string, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("doc%d", i)
			res, err := s.WriteResource(context.Background(), "demo", name, Pre{IfNoneMatch: true},
				patches(fmt.Sprintf(`[{"op":"add","path":"","value":{"w":%d}}]`, i)), "", "", "alice", nil)
			if err == nil {
				ids[i] = res.NSID
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
	// Every entry committed: positions 2..writers+1, contiguous, unique ids.
	entries, _, err := s.ReadLog(context.Background(), "demo", "", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != writers+1 {
		t.Fatalf("%d entries, want %d", len(entries), writers+1)
	}
	seen := map[string]bool{}
	prev := entries[0]["id"].(string)
	for i, e := range entries[1:] {
		if e["prev"] != prev {
			t.Fatalf("entry %d prev %q, want %q: a gap in the chain", i+2, e["prev"], prev)
		}
		prev = e["id"].(string)
		if seen[prev] {
			t.Fatalf("duplicate entry id %q", prev)
		}
		seen[prev] = true
	}
	if group > 1 {
		groups, appended := s.GroupStats()
		if appended != int64(writers) || groups >= appended {
			t.Fatalf("%d groups appended %d writes; want %d writes in fewer groups", groups, appended, writers)
		}
		t.Logf("%d writes in %d groups", appended, groups)
	}
}

// Two writers of one resource race; exactly one wins each round and the
// other's 412 names the winner's head (D.3's conflict).
func TestLocalConcurrentResource(t *testing.T) {
	t.Run("alone", func(t *testing.T) { testConcurrentResource(t, 1) })
	t.Run("grouped", func(t *testing.T) { testConcurrentResource(t, 32) })
}

func testConcurrentResource(t *testing.T, group int) {
	s := newLocalStore(t)
	s.GroupCommit = group
	mustCreateNS(t, s, "demo")
	w1 := mustWrite(t, s, "demo", "doc1", "", `[{"op":"add","path":"","value":{"a":1}}]`)
	const racers = 6
	var wg sync.WaitGroup
	results := make([]*WriteResult, racers)
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.WriteResource(context.Background(), "demo", "doc1", Pre{IfMatch: w1.ID},
				patches(fmt.Sprintf(`[{"op":"add","path":"/w%d","value":true}]`, i)), "", "", "alice", nil)
			results[i], errs[i] = res, err
		}()
	}
	wg.Wait()
	var won, stale int
	for i := range racers {
		switch {
		case errs[i] == nil:
			won++
		default:
			ae, ok := errs[i].(*Error)
			if !ok || ae.Status != 412 || ae.Body["head"] == "" {
				t.Errorf("racer %d: %v, want 412 with head", i, errs[i])
				continue
			}
			stale++
		}
	}
	if won != 1 || stale != racers-1 {
		t.Fatalf("%d won, %d stale; want 1 and %d", won, stale, racers-1)
	}
}
