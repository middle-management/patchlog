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
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"

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
	res, err := s.WriteResource(context.Background(), ns, name, ifMatch, patches(p), "", "", "alice", nil)
	if err != nil {
		t.Fatalf("WriteResource %s/%s: %v", ns, name, err)
	}
	return res
}

func TestLocalFlow(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	cfgID, nsID := mustCreateNS(t, s, "demo")

	// The log opens with the config genesis.
	entries, next, err := s.ReadLog(ctx, "demo", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0]["kind"] != "config" || entries[0]["target"] != cfgID || entries[0]["id"] != nsID {
		t.Fatalf("genesis entry: %v", entries)
	}
	if next != "" {
		t.Fatalf("next = %q at the end of the log", next)
	}

	// Create a resource, then append to it.
	w1 := mustWrite(t, s, "demo", "doc1", "", `[{"op":"add","path":"","value":{"a":1}}]`)
	w2 := mustWrite(t, s, "demo", "doc1", w1.ID, `[{"op":"add","path":"/b","value":2}]`)

	head, err := s.ReadHead(ctx, "demo", "doc1")
	if err != nil {
		t.Fatal(err)
	}
	if head == nil || head.ID != w2.ID {
		t.Fatalf("head %+v, want %q", head, w2.ID)
	}
	if string(jsonv.Canonical(head.Doc)) != `{"a":1,"b":2}` {
		t.Fatalf("document %s", jsonv.Canonical(head.Doc))
	}

	// The log: three entries, chained by id.
	entries, _, err = s.ReadLog(ctx, "demo", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("%d entries, want 3", len(entries))
	}
	if entries[1]["id"] != w1.NSID || entries[1]["prev"] != nsID || entries[1]["target"] != w1.ID {
		t.Fatalf("entry 2: %v", entries[1])
	}
	if entries[2]["id"] != w2.NSID || entries[2]["prev"] != w1.NSID {
		t.Fatalf("entry 3: %v", entries[2])
	}

	// Paging: one entry per page, by cursor.
	var all []LogEntry
	since := ""
	for {
		page, n, err := s.ReadLog(ctx, "demo", "", since, 1)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page...)
		if n == "" {
			break
		}
		since = n
	}
	if len(all) != 3 || all[0]["id"] != nsID || all[2]["id"] != w2.NSID {
		t.Fatalf("paged log: %v", all)
	}
}

func TestLocalCreateNamespaceTwice(t *testing.T) {
	s := newLocalStore(t)
	cfgID, nsID := mustCreateNS(t, s, "demo")
	// A retried create (same patches) replays: same ids, no error.
	cfg2, ns2, err := s.CreateNamespace(context.Background(), "demo", "test", patches(`[{"op":"add","path":"","value":{}}]`))
	if err != nil {
		t.Fatalf("retried create: %v", err)
	}
	if cfg2 != cfgID || ns2 != nsID {
		t.Fatalf("replay gave %q %q, want %q %q", cfg2, ns2, cfgID, nsID)
	}
	// A create of the taken name with another document is 412 with the
	// current config id (writeConfig's IfNoneMatch path).
	_, _, err = s.CreateNamespace(context.Background(), "demo", "test", patches(`[{"op":"add","path":"","value":{"x":true}}]`))
	ae, ok := err.(*Error)
	if !ok || ae.Status != 412 || ae.Body["config"] != cfgID {
		t.Fatalf("create of a taken name: %v", err)
	}
}

func TestLocalStaleAndReplay(t *testing.T) {
	s := newLocalStore(t)
	mustCreateNS(t, s, "demo")
	w1 := mustWrite(t, s, "demo", "doc1", "", `[{"op":"add","path":"","value":{"a":1}}]`)
	// Two writes pin the same parent; the first commits.
	w2 := mustWrite(t, s, "demo", "doc1", w1.ID, `[{"op":"add","path":"/b","value":2}]`)
	// The second, with different patches, is stale: 412 naming the head.
	_, err := s.WriteResource(context.Background(), "demo", "doc1", w1.ID, patches(`[{"op":"add","path":"/c","value":3}]`), "", "", "alice", nil)
	ae, ok := err.(*Error)
	if !ok || ae.Status != 412 || ae.Body["head"] != w2.ID {
		t.Fatalf("stale write: %v", err)
	}
	// The first's retry, however, replays: its revision is the head.
	res, err := s.WriteResource(context.Background(), "demo", "doc1", w1.ID, patches(`[{"op":"add","path":"/b","value":2}]`), "", "", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Replayed || res.ID != w2.ID || res.NSID != w2.NSID || res.Status != 200 {
		t.Fatalf("replay: %+v, want %+v", res, w2)
	}
	// And the log did not grow.
	entries, _, err := s.ReadLog(context.Background(), "demo", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("a replay appended: %d entries", len(entries))
	}
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
			res, err := s.WriteResource(context.Background(), "demo", name, "",
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
			res, err := s.WriteResource(context.Background(), "demo", "doc1", w1.ID,
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

func TestLocalListHeads(t *testing.T) {
	s := newLocalStore(t)
	mustCreateNS(t, s, "demo")
	for _, name := range []string{"b", "a", "c", "aa"} {
		mustWrite(t, s, "demo", name, "", `[{"op":"add","path":"","value":{}}]`)
	}
	// Byte order of name, one page of two then the rest.
	page, next, err := s.ListHeads(context.Background(), "demo", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].Name != "a" || page[1].Name != "aa" || next == "" {
		t.Fatalf("page 1: %v next %q", page, next)
	}
	page, next, err = s.ListHeads(context.Background(), "demo", next, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].Name != "b" || page[1].Name != "c" || next != "" {
		t.Fatalf("page 2: %v next %q", page, next)
	}
}

// TestLocalDeleteRestore exercises the tombstone path end to end (§7.2,
// §8.1): DELETE, replay, the 410s, and a restore whose chain the fold
// crosses correctly.
func TestLocalDeleteRestore(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	mustCreateNS(t, s, "demo")
	w1 := mustWrite(t, s, "demo", "doc1", "", `[{"op":"add","path":"","value":{"a":1}}]`)
	w2 := mustWrite(t, s, "demo", "doc1", w1.ID, `[{"op":"add","path":"/b","value":2}]`)

	// DELETE without If-Match is 428; with a stale one, 412 naming the
	// head.
	if _, err := s.DeleteResource(ctx, "demo", "doc1", "", "", "", "alice", nil); err == nil || err.(*Error).Status != 428 {
		t.Fatalf("no If-Match: %v", err)
	}
	if _, err := s.DeleteResource(ctx, "demo", "doc1", w1.ID, "", "", "alice", nil); err == nil || err.(*Error).Status != 412 || err.(*Error).Body["head"] != w2.ID {
		t.Fatalf("stale: %v", err)
	}

	// DELETE: 201, the head is the tombstone, the document is gone.
	d, err := s.DeleteResource(ctx, "demo", "doc1", w2.ID, "gaaaaaaaaaaaaaaaaaaaaaaaaa", "", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != 201 || d.NSID == "" {
		t.Fatalf("delete: %+v", d)
	}
	parent, _ := ids.Parse(w2.ID)
	tid := ids.Tombstone(parent).String()
	if d.ID != tid {
		t.Fatalf("tombstone id %q, want %q", d.ID, tid)
	}
	head, err := s.ReadHead(ctx, "demo", "doc1")
	if err != nil {
		t.Fatal(err)
	}
	if head == nil || head.Live || head.ID != tid || head.LastID != w2.ID || head.Doc != nil {
		t.Fatalf("head after delete: %+v", head)
	}

	// A retried DELETE replays; a DELETE of another parent is 410; a
	// write pinning the old head is 412.
	d2, err := s.DeleteResource(ctx, "demo", "doc1", w2.ID, "", "", "alice", nil)
	if err != nil || d2.Status != 200 || !d2.Replayed || d2.ID != tid || d2.NSID != d.NSID {
		t.Fatalf("replay: %+v %v", d2, err)
	}
	if _, err := s.DeleteResource(ctx, "demo", "doc1", w1.ID, "", "", "alice", nil); err == nil || err.(*Error).Status != 410 {
		t.Fatalf("double delete: %v", err)
	}
	if _, err := s.WriteResource(ctx, "demo", "doc1", w2.ID, patches(`[{"op":"add","path":"/c","value":3}]`), "", "", "alice", nil); err == nil || err.(*Error).Status != 412 {
		t.Fatalf("append at the deleted head: %v", err)
	}

	// The revision read of the tombstone ids as one (GSI1); the resource
	// log serves the tombstone with no patches.
	rev, err := s.ReadRevByID(ctx, "demo", tid)
	if err != nil || rev == nil || rev.Kind != "tombstone" || rev.Pos != 3 {
		t.Fatalf("tombstone rev: %+v %v", rev, err)
	}
	entries, more, err := s.ResourceLog(ctx, "demo", "doc1", 0, 3, 0, 0)
	if err != nil || more || len(entries) != 3 || entries[0].Kind != "rev" || entries[2].Kind != "tombstone" || entries[2].Patches != nil || entries[2].Gesture == "" {
		t.Fatalf("resource log: %+v %v", entries, err)
	}

	// /heads: kind tombstone, no metadata.
	heads, _, err := s.ListHeads(ctx, "demo", "", 10)
	if err != nil || len(heads) != 1 || !heads[0].Tombstoned || heads[0].ID != tid || heads[0].Created != 0 {
		t.Fatalf("heads: %+v %v", heads, err)
	}

	// The namespace log's entry is the tombstone's.
	log, _, err := s.ReadLog(ctx, "demo", d.NSID, "", 0)
	if err != nil || len(log) != 4 {
		t.Fatalf("ns log: %v %v", log, err)
	}
	if le := log[len(log)-1]; le["id"] != d.NSID || le["kind"] != "tombstone" || le["target"] != tid || le["resource"] != "doc1" || le["gesture"] == "" {
		t.Fatalf("tombstone entry: %v", le)
	}

	// Restore: the parent is the tombstone id, the fold across the chain
	// boundary is the restored document only.
	w3, err := s.WriteResource(ctx, "demo", "doc1", tid, patches(`[{"op":"add","path":"","value":{"z":1}}]`), "", "", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if w3.Status != 201 {
		t.Fatalf("restore: %+v", w3)
	}
	doc, canon, err := s.FoldResource(ctx, "demo", "doc1", 0)
	if err != nil || string(canon) != `{"z":1}` {
		t.Fatalf("fold after restore: %s %v", canon, err)
	}
	_ = doc
	head, err = s.ReadHead(ctx, "demo", "doc1")
	if err != nil || head == nil || !head.Live || head.ID != w3.ID || head.LastID != "" {
		t.Fatalf("head after restore: %+v %v", head, err)
	}
	// The fold at the deleted revision is still the old document.
	_, canon, err = s.FoldResource(ctx, "demo", "doc1", 2)
	if err != nil || string(canon) != `{"a":1,"b":2}` {
		t.Fatalf("fold at the deleted rev: %s %v", canon, err)
	}
}

// TestLocalBatch exercises WriteBatch (§7.5): mixed items in one
// transaction, the batch entry, replay, per-item failures, the config
// change, and the dry run.
func TestLocalBatch(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	mustCreateNS(t, s, "demo")
	w1 := mustWrite(t, s, "demo", "doc1", "", `[{"op":"add","path":"","value":{"a":1}}]`)
	w2 := mustWrite(t, s, "demo", "doc2", "", `[{"op":"add","path":"","value":{"b":1}}]`)

	items := []BatchItem{
		{Name: "doc1", IfMatch: w1.ID, Patches: patches(`[{"op":"add","path":"/c","value":3}]`)},
		{Name: "doc2", IfMatch: w2.ID, Delete: true},
		{Name: "doc3", IfNoneMatch: true, Patches: patches(`[{"op":"add","path":"","value":{"d":1}}]`)},
	}
	res, err := s.WriteBatch(ctx, "demo", "alice", items, nil, nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 201 || res.NSID == "" || len(res.IDs) != 3 {
		t.Fatalf("batch: %+v", res)
	}

	// The state: doc1 appended, doc2 tombstoned, doc3 created.
	h1, _ := s.ReadHead(ctx, "demo", "doc1")
	h2, _ := s.ReadHead(ctx, "demo", "doc2")
	h3, _ := s.ReadHead(ctx, "demo", "doc3")
	if h1 == nil || !h1.Live || h1.ID != res.IDs["doc1"] {
		t.Fatalf("doc1: %+v", h1)
	}
	if h2 == nil || h2.Live || h2.LastID != w2.ID {
		t.Fatalf("doc2: %+v", h2)
	}
	if h3 == nil || !h3.Live || h3.ID != res.IDs["doc3"] {
		t.Fatalf("doc3: %+v", h3)
	}

	// One batch entry, kind "batch", naming every target.
	log, _, err := s.ReadLog(ctx, "demo", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	le := log[len(log)-1]
	if le["kind"] != "batch" || le["id"] != res.NSID {
		t.Fatalf("batch entry: %v", le)
	}
	ents, _ := le["entries"].([]any)
	if len(ents) != 3 {
		t.Fatalf("batch entry's entries: %v", le["entries"])
	}

	// A replay answers the same ids (every item's id is computable from
	// the request: the creates' and the appends' via their parents, the
	// delete's via its head).
	rep, err := s.WriteBatch(ctx, "demo", "alice", items, nil, nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != 200 || !rep.Replayed || rep.NSID != res.NSID || rep.IDs["doc1"] != res.IDs["doc1"] || rep.IDs["doc3"] != res.IDs["doc3"] {
		t.Fatalf("replay: %+v", rep)
	}

	// A stale item fails the batch, per item (§7.5), and nothing
	// commits: doc1 keeps its head.
	stale := []BatchItem{
		{Name: "doc1", IfMatch: w1.ID, Patches: patches(`[{"op":"add","path":"/x","value":9}]`)},
		{Name: "doc3", IfMatch: h3.ID, Patches: patches(`[{"op":"add","path":"/e","value":5}]`)},
	}
	_, err = s.WriteBatch(ctx, "demo", "alice", stale, nil, nil, nil, nil, false)
	var bf *BatchFailure
	if !errors.As(err, &bf) || len(bf.Items) != 1 || bf.Items[0].Index != 0 || bf.Items[0].Err.Status != 412 {
		t.Fatalf("stale batch: %v", err)
	}
	h1b, _ := s.ReadHead(ctx, "demo", "doc1")
	if h1b.ID != h1.ID {
		t.Fatalf("doc1 moved in a refused batch: %+v", h1b)
	}

	// The gate's failures collect across items.
	gate := []BatchItem{
		{Name: "doc1", IfMatch: h1.ID, Patches: patches(`[{"op":"add","path":"/bad","value":1}]`)},
		{Name: "doc3", IfMatch: h3.ID, Patches: patches(`[{"op":"add","path":"/bad","value":2}]`)},
	}
	check := func(name string, st *WriteState) error {
		if name == "doc1" {
			return apiErr(422, "rule", "rule", 0)
		}
		return nil
	}
	_, err = s.WriteBatch(ctx, "demo", "alice", gate, nil, nil, nil, check, false)
	if !errors.As(err, &bf) || len(bf.Items) != 1 || bf.Items[0].Err.Body["code"] != "rule" {
		t.Fatalf("gate: %v", err)
	}

	// A dry run answers the computed ids and commits nothing.
	dry, err := s.WriteBatch(ctx, "demo", "alice", gate, nil, nil, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Status != 200 || dry.IDs["doc1"] == "" || dry.IDs["doc3"] == "" {
		t.Fatalf("dry run: %+v", dry)
	}
	h1c, _ := s.ReadHead(ctx, "demo", "doc1")
	if h1c.ID != h1.ID {
		t.Fatalf("dry run committed: %+v", h1c)
	}

	// A config change rides the batch: the entry names it first, the
	// configuration moves, and the change's condition guards the batch.
	cc := patches(`[{"op":"add","path":"/frozen","value":true}]`)
	rc, err := s.WriteBatch(ctx, "demo", "alice",
		[]BatchItem{{Name: "doc1", IfMatch: h1.ID, Patches: patches(`[{"op":"add","path":"/c2","value":4}]`)}},
		cc,
		func(doc any, exists bool, p any) (any, error) {
			out, _, err := applyPatches(doc, exists, p)
			return out, err
		},
		func(st *ConfigState) error { st.NewFrozen = true; return nil },
		nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if rc.ConfigID == "" || rc.ConfigID == res.ConfigID {
		t.Fatalf("config batch: %+v", rc)
	}
	info, err := s.ReadNSInfo(ctx, "demo")
	if err != nil || !info.Frozen || info.ConfigID != rc.ConfigID {
		t.Fatalf("ns after config batch: %+v %v", info, err)
	}
	log, _, _ = s.ReadLog(ctx, "demo", "", "", 0)
	le = log[len(log)-1]
	ents, _ = le["entries"].([]any)
	first, _ := ents[0].(map[string]any)
	if le["kind"] != "batch" || first["kind"] != "config" || first["target"] != rc.ConfigID {
		t.Fatalf("config batch entry: %v", le)
	}
}
