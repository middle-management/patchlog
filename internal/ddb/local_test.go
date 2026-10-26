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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

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
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")),
		// DynamoDB Local's responses trip the SDK's checksum validation.
		config.WithResponseChecksumValidation(aws.ResponseChecksumValidationUnset),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})
	table := fmt.Sprintf("spike-%d", time.Now().UnixNano())
	if _, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("G1PK"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName:  aws.String(gsiName),
				KeySchema:  []types.KeySchemaElement{{AttributeName: aws.String("G1PK"), KeyType: types.KeyTypeHash}},
				Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})
	for range 50 {
		out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		if err == nil && out.Table.TableStatus == types.TableStatusActive {
			return &Store{Client: client, Table: table}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("table did not become ACTIVE")
	return nil
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
	s := newLocalStore(t)
	mustCreateNS(t, s, "demo")
	const writers = 8
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
}

// Two writers of one resource race; exactly one wins each round and the
// other's 412 names the winner's head (D.3's conflict).
func TestLocalConcurrentResource(t *testing.T) {
	s := newLocalStore(t)
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
	entries, err := s.ResourceLogEntries(ctx, "demo", "doc1", 0, 0)
	if err != nil || len(entries) != 3 || entries[2].Kind != "tombstone" || entries[2].Patches != nil || entries[2].Gesture == "" {
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
