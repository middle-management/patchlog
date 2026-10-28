package core

// The DynamoDB backend's failure paths, against DynamoDB Local
// (DDB_ENDPOINT; skipped without it), through a client that fails a
// chosen call or runs a hook before one (faultAPI): a commit that finds
// what its checks read moved is checked again; a call that fails leaves
// nothing half-written; a purge, prune or encryption whose content work
// fails after its commit is finished by the sweep. And heads as of an
// entry, across a delete and a restore (ddbstore's headBefore).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/middle-management/patchlog/internal/ddbstore"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// faultAPI is a store's client that fails the next call of an operation
// (fail), or runs a hook before it (before), once each.
type faultAPI struct {
	ddbstore.API
	mu     sync.Mutex
	fails  map[string]func(in any) bool // the calls to fail, once
	before map[string]func()
	calls  map[string]int // the calls made, by operation (takeCalls)
}

// takeCalls returns the calls made since the last take, by operation, and
// their total.
func (f *faultAPI) takeCalls() (map[string]int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out, n := f.calls, 0
	for _, c := range out {
		n += c
	}
	f.calls = map[string]int{}
	return out, n
}

var errInjected = errors.New("injected failure")

// fail makes the next call of op fail with errInjected.
func (f *faultAPI) fail(op string) { f.failWhen(op, func(any) bool { return true }) }

// failWhen makes the next call of op whose input match accepts fail with
// errInjected.
func (f *faultAPI) failWhen(op string, match func(in any) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fails[op] = match
}

// strippingPatches matches the update that removes a revision's patch
// set: a purge's or a prune's content work, after its commit.
func strippingPatches(in any) bool {
	u, ok := in.(*dynamodb.UpdateItemInput)
	return ok && u.UpdateExpression != nil && strings.HasPrefix(*u.UpdateExpression, "REMOVE patches")
}

// hook runs h before the next call of op, outside the client.
func (f *faultAPI) hook(op string, h func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.before[op] = h
}

// call takes op's armed hook, once, and its armed failure, once, if in
// matches it.
func (f *faultAPI) call(op string, in any) error {
	f.mu.Lock()
	f.calls[op]++
	h := f.before[op]
	delete(f.before, op)
	var err error
	if m := f.fails[op]; m != nil && m(in) {
		delete(f.fails, op)
		err = errInjected
	}
	f.mu.Unlock()
	if h != nil {
		h()
	}
	return err
}

func (f *faultAPI) GetItem(ctx context.Context, in *dynamodb.GetItemInput, o ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if err := f.call("GetItem", in); err != nil {
		return nil, err
	}
	return f.API.GetItem(ctx, in, o...)
}

func (f *faultAPI) BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, o ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	if err := f.call("BatchGetItem", in); err != nil {
		return nil, err
	}
	return f.API.BatchGetItem(ctx, in, o...)
}

func (f *faultAPI) Query(ctx context.Context, in *dynamodb.QueryInput, o ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if err := f.call("Query", in); err != nil {
		return nil, err
	}
	return f.API.Query(ctx, in, o...)
}

func (f *faultAPI) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if err := f.call("UpdateItem", in); err != nil {
		return nil, err
	}
	return f.API.UpdateItem(ctx, in, o...)
}

func (f *faultAPI) DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, o ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if err := f.call("DeleteItem", in); err != nil {
		return nil, err
	}
	return f.API.DeleteItem(ctx, in, o...)
}

func (f *faultAPI) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if err := f.call("TransactWriteItems", in); err != nil {
		return nil, err
	}
	return f.API.TransactWriteItems(ctx, in, o...)
}

// ddbTable makes a fresh table of DynamoDB Local and returns its URL.
func ddbTable(t *testing.T) string {
	t.Helper()
	endpoint, _, _ := strings.Cut(os.Getenv("DDB_ENDPOINT"), ",") // the first of a list (testenv)
	if endpoint == "" {
		t.Skip("DDB_ENDPOINT not set: skipping DynamoDB Local integration test")
	}
	url := fmt.Sprintf("dynamodb://coretest-%d?region=us-east-1&endpoint=%s", time.Now().UnixNano(), endpoint)
	if err := ddbstore.CreateTable(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ddbstore.DeleteTable(context.Background(), url) })
	return url
}

// ddbFaultEngine opens an engine on url whose store calls go through a
// faultAPI.
func ddbFaultEngine(t *testing.T, url string, opt Options) (*Engine, *faultAPI, *ddbstore.Store) {
	t.Helper()
	opt.Path, opt.AuthDisabled = url, true
	e, err := Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	s := e.be.(*ddbBackend).store.(*ddbstore.Store)
	f := &faultAPI{API: s.Client, fails: map[string]func(any) bool{}, before: map[string]func(){}, calls: map[string]int{}}
	s.Client = f
	return e, f, s
}

// A commit whose configuration moved after its checks (another instance's
// config change, here a second engine on the table) is stale: the write
// is checked again under the new configuration and commits, after the
// change, and is counted in patchlog.db.conflicts. Not parallel:
// telemetry.Use sets the process's providers.
func TestDDBRaceRechecked(t *testing.T) {
	url := ddbTable(t)
	e, f, _ := ddbFaultEngine(t, url, Options{})
	other, _, _ := ddbFaultEngine(t, url, Options{})
	reader := sdkmetric.NewManualReader()
	t.Cleanup(telemetry.Use(nil, sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))))
	ctx := context.Background()
	ddbCreateNS(t, e, "race", `{"read":"public"}`)
	w := ddbWrite(t, e, "race", "d", "", `[{"op":"add","path":"","value":{"v":1}}]`)

	raced := false
	f.hook("TransactWriteItems", func() {
		raced = true
		c, err := other.WriteConfig(ctx, Request{NS: "race"}, ConfigChange{IfMatch: configOf(t, other, "race"),
			Patches: patches(t, `[{"op":"add","path":"/x-title","value":"moved"}]`)})
		if err != nil || c.Status != 201 {
			t.Errorf("the racing config change: %+v %v", c, err)
		}
	})
	w2 := ddbWrite(t, e, "race", "d", w.Items[0].IDs[0], `[{"op":"replace","path":"/v","value":2}]`)
	if !raced {
		t.Fatal("the hook never ran")
	}
	lg, err := e.NamespaceLog(ctx, "race", "", "", 0, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, en := range lg.Entries {
		kinds = append(kinds, fmt.Sprint(en["kind"]))
	}
	if got := strings.Join(kinds, ","); got != "config,head,config,head" {
		t.Fatalf("log kinds %s, want the config change before the rechecked write", got)
	}
	if last := lg.Entries[len(lg.Entries)-1]; last["id"] != w2.NSID {
		t.Fatalf("the rechecked write isn't the log's last entry: %v", last)
	}
	if n := sumCounter(t, reader, "patchlog.db.conflicts"); n < 1 {
		t.Fatalf("patchlog.db.conflicts %d, want at least 1", n)
	}
}

func sumCounter(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					n += dp.Value
				}
			}
		}
	}
	return n
}

// A DynamoDB call that fails answers the request with an error, and
// leaves nothing half-written: the head and the log stay as they were,
// and the same write then succeeds.
func TestDDBFailedCallsLeaveNothing(t *testing.T) {
	e, f, _ := ddbFaultEngine(t, ddbTable(t), Options{})
	ctx := context.Background()
	ddbCreateNS(t, e, "io", `{"read":"public"}`)
	w := ddbWrite(t, e, "io", "d", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	head := w.Items[0].IDs[0]
	logLen := func() int {
		t.Helper()
		lg, err := e.NamespaceLog(ctx, "io", "", "", 0, Credentials{})
		if err != nil {
			t.Fatal(err)
		}
		return len(lg.Entries)
	}
	n := logLen()
	appendV := func(v int) (*WriteResult, error) {
		return e.WriteResource(ctx, Request{NS: "io"}, Item{Resource: "d", IfMatch: head,
			Steps: []Step{{Patches: patches(t, fmt.Sprintf(`[{"op":"replace","path":"/v","value":%d}]`, v))}}})
	}
	for _, op := range []string{"GetItem", "BatchGetItem", "Query", "TransactWriteItems"} {
		e.FlushCaches()
		f.fail(op)
		if _, err := appendV(2); !errors.Is(err, errInjected) && !strings.Contains(fmt.Sprint(err), errInjected.Error()) {
			t.Fatalf("%s failing: %v, want the injected failure", op, err)
		}
		f.mu.Lock()
		_, unused := f.fails[op]
		f.mu.Unlock()
		if unused {
			t.Fatalf("the write made no %s call", op)
		}
		e.FlushCaches()
		h, err := e.ResourceHead(ctx, "io", "d", Credentials{})
		if err != nil || h.Head != head {
			t.Fatalf("after a failed %s: head %+v %v, want %s", op, h, err, head)
		}
		if got := logLen(); got != n {
			t.Fatalf("after a failed %s: %d log entries, want %d", op, got, n)
		}
	}
	if _, err := appendV(2); err != nil {
		t.Fatalf("the write after the failures: %v", err)
	}
	if got := logLen(); got != n+1 {
		t.Fatalf("%d log entries, want %d", got, n+1)
	}
	// A failed read is an error, not a panic or a partial answer.
	f.fail("Query")
	if _, err := e.NamespaceLog(ctx, "io", "", "", 0, Credentials{}); err == nil {
		t.Fatal("a log read whose query failed answered")
	}
}

// A purge whose content work fails after its commit answers 204 (the
// purge is committed: reads are 410), leaves its marker, and the sweep
// finishes it: the revisions keep no patch set.
func TestDDBSweepFinishesPurge(t *testing.T) {
	e, f, s := ddbFaultEngine(t, ddbTable(t), Options{})
	ctx := context.Background()
	ddbCreateNS(t, e, "pg", `{"read":"public"}`)
	w := ddbWrite(t, e, "pg", "d", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	w = ddbWrite(t, e, "pg", "d", w.Items[0].IDs[0], `[{"op":"replace","path":"/v","value":2}]`)
	f.failWhen("UpdateItem", strippingPatches) // the first revision's patch set stays
	if _, err := e.Purge(ctx, Request{NS: "pg"}, "d", w.Items[0].IDs[0], false); err != nil {
		t.Fatal(err)
	}
	if h, err := e.ResourceHead(ctx, "pg", "d", Credentials{}); err != nil || h.State != Purged {
		t.Fatalf("a purged resource reads %+v %v, want purged", h, err)
	}
	if nss, names, err := s.Purging(ctx); err != nil || len(nss) != 1 || nss[0] != "pg" || names[0] != "d" {
		t.Fatalf("purges left: %v %v %v", nss, names, err)
	}
	if !revKeepsPatches(t, s, "pg", "d", 1) && !revKeepsPatches(t, s, "pg", "d", 2) {
		t.Fatal("the failed content work deleted every patch set")
	}
	if _, err := e.SweepBlobs(ctx); err != nil {
		t.Fatal(err)
	}
	if nss, _, err := s.Purging(ctx); err != nil || len(nss) != 0 {
		t.Fatalf("purges left after the sweep: %v %v", nss, err)
	}
	for pos := uint64(1); pos <= 2; pos++ {
		if revKeepsPatches(t, s, "pg", "d", pos) {
			t.Fatalf("revision %d keeps its patch set after the sweep", pos)
		}
	}
}

// A prune whose content work fails after its commit answers with its
// horizon, leaves its marker, and the sweep finishes it: the revisions
// below the horizon keep no patch set.
func TestDDBSweepFinishesPrune(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	e, f, s := ddbFaultEngine(t, ddbTable(t), Options{Now: clock})
	ctx := context.Background()
	ddbCreateNS(t, e, "pr", `{"read":"public"}`)
	w := ddbWrite(t, e, "pr", "d", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	for v := 2; v <= 3; v++ {
		w = ddbWrite(t, e, "pr", "d", w.Items[0].IDs[0], fmt.Sprintf(`[{"op":"replace","path":"/v","value":%d}]`, v))
	}
	// A prune keeps the patch sets of revisions within the retry window,
	// for idempotent retries (limits.retryWindow): it comes an hour
	// later.
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	f.failWhen("UpdateItem", strippingPatches)
	if _, err := e.Prune(ctx, Request{NS: "pr"}, "d", PruneRequest{Horizon: w.Items[0].IDs[0]}); err != nil {
		t.Fatal(err)
	}
	if nss, names, err := s.Pruning(ctx); err != nil || len(nss) != 1 || nss[0] != "pr" || names[0] != "d" {
		t.Fatalf("prunes left: %v %v %v", nss, names, err)
	}
	if _, err := e.SweepBlobs(ctx); err != nil {
		t.Fatal(err)
	}
	if nss, _, err := s.Pruning(ctx); err != nil || len(nss) != 0 {
		t.Fatalf("prunes left after the sweep: %v %v", nss, err)
	}
	for pos := uint64(1); pos <= 2; pos++ {
		if revKeepsPatches(t, s, "pr", "d", pos) {
			t.Fatalf("revision %d below the horizon keeps its patch set after the sweep", pos)
		}
	}
	if !revKeepsPatches(t, s, "pr", "d", 3) {
		t.Fatal("the horizon lost its patch set")
	}
	h, err := e.ResourceHead(ctx, "pr", "d", Credentials{})
	if err != nil || h.Head != w.Items[0].IDs[0] {
		t.Fatalf("head after the sweep %+v %v", h, err)
	}
}

// A raise to encryption at rest whose content work fails after its
// commit leaves its marker; the sweep encrypts the rest, which reads back.
func TestDDBSweepFinishesEncryption(t *testing.T) {
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	e, f, s := ddbFaultEngine(t, ddbTable(t), Options{KeyStore: ks})
	ctx := context.Background()
	ddbCreateNS(t, e, "enc", `{"read":"public"}`)
	const marker = "plaintext-marker"
	w := ddbWrite(t, e, "enc", "d", "", `[{"op":"add","path":"","value":{"v":"`+marker+`"}}]`)
	f.fail("UpdateItem")
	c, err := e.WriteConfig(ctx, Request{NS: "enc"}, ConfigChange{IfMatch: configOf(t, e, "enc"),
		Patches: patches(t, `[{"op":"add","path":"/encryption","value":{"level":"at-rest"}}]`)})
	if err != nil || c.Status != 201 {
		t.Fatalf("raising: %+v %v", c, err)
	}
	if nss, err := s.Encrypting(ctx); err != nil || len(nss) != 1 || nss[0] != "enc" {
		t.Fatalf("encryptions left: %v %v", nss, err)
	}
	if _, err := e.SweepBlobs(ctx); err != nil {
		t.Fatal(err)
	}
	if nss, err := s.Encrypting(ctx); err != nil || len(nss) != 0 {
		t.Fatalf("encryptions left after the sweep: %v %v", nss, err)
	}
	ri, err := s.RevAt(ctx, "enc", "d", 1)
	if err != nil || ri == nil || strings.Contains(ri.Patches, marker) {
		t.Fatalf("the revision's patch set after the sweep: %+v %v", ri, err)
	}
	e.FlushCaches()
	rev, err := e.ResourceRev(ctx, "enc", "d", w.Items[0].IDs[0], Credentials{})
	if err != nil || !strings.Contains(string(rev.Doc), marker) {
		t.Fatalf("reads back %+v %v", rev, err)
	}
}

// revKeepsPatches reports whether revision pos of ns/name keeps its patch
// set.
func revKeepsPatches(t *testing.T, s *ddbstore.Store, ns, name string, pos uint64) bool {
	t.Helper()
	ri, err := s.RevAt(context.Background(), ns, name, pos)
	if err != nil || ri == nil {
		t.Fatalf("revision %s/%s/%d: %+v %v", ns, name, pos, ri, err)
	}
	return ri.Patches != ""
}

// A resource's head as of each entry, across a delete and a restore:
// /heads at an entry is the head that entry left, a tombstone included,
// whatever was written after it (ddbstore's headBefore and
// loggedTombstone).
func TestDDBHeadsAtEntries(t *testing.T) {
	e := ddbEngine(t)
	ctx := context.Background()
	ddbCreateNS(t, e, "hd", `{"read":"public"}`)
	type step struct{ nsID, kind, target string }
	var steps []step
	at := func(w *WriteResult, kind string) {
		steps = append(steps, step{w.NSID, kind, w.Items[0].IDs[len(w.Items[0].IDs)-1]})
	}
	w := ddbWrite(t, e, "hd", "d", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	at(w, "head")
	w = ddbWrite(t, e, "hd", "d", w.Items[0].IDs[0], `[{"op":"replace","path":"/v","value":2}]`)
	at(w, "head")
	other := ddbWrite(t, e, "hd", "other", "", `[{"op":"add","path":"","value":{}}]`)
	steps = append(steps, step{other.NSID, steps[len(steps)-1].kind, steps[len(steps)-1].target})
	del, err := e.WriteResource(ctx, Request{NS: "hd"}, Item{Resource: "d", IfMatch: w.Items[0].IDs[0], Steps: []Step{{Delete: true}}})
	if err != nil {
		t.Fatal(err)
	}
	at(del, "tombstone")
	other = ddbWrite(t, e, "hd", "other", other.Items[0].IDs[0], `[{"op":"add","path":"/x","value":1}]`)
	steps = append(steps, step{other.NSID, "tombstone", del.Items[0].IDs[0]})
	w = ddbWrite(t, e, "hd", "d", del.Items[0].IDs[0], `[{"op":"replace","path":"","value":{"v":3}}]`)
	at(w, "head")
	w = ddbWrite(t, e, "hd", "d", w.Items[0].IDs[0], `[{"op":"replace","path":"/v","value":4}]`)
	at(w, "head")
	for i, st := range steps {
		e.FlushCaches()
		hp, err := e.NamespaceHeads(ctx, "hd", st.nsID, "", Credentials{})
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		var got map[string]any
		for _, it := range hp.Items {
			if it["resource"] == "d" {
				got = it
			}
		}
		if got == nil || got["kind"] != st.kind || got["target"] != st.target {
			t.Fatalf("step %d: heads at %s list d as %v, want %s %s", i, st.nsID, got, st.kind, st.target)
		}
	}
}

// The DynamoDB calls a request makes, each a round trip it waits on: a
// write's and a read's, bounded so a change that adds round trips shows.
// DynamoDB's latency is per call (docs/DYNAMODB.md §11). A write is four:
// the namespace, its resources and their head documents in one batch
// (prefetch), the head revision, the retry lookup, the commit.
func TestDDBCallsPerRequest(t *testing.T) {
	e, f, _ := ddbFaultEngine(t, ddbTable(t), Options{})
	ctx := context.Background()
	ddbCreateNS(t, e, "calls", `{"read":"public"}`)
	measure := func(what string, max int, do func()) {
		t.Helper()
		e.FlushCaches()
		f.takeCalls()
		do()
		by, n := f.takeCalls()
		t.Logf("%s: %d calls %v", what, n, by)
		if n > max {
			t.Errorf("%s makes %d DynamoDB calls, want at most %d: %v", what, n, max, by)
		}
	}
	var w *WriteResult
	measure("create", 4, func() { w = ddbWrite(t, e, "calls", "d", "", `[{"op":"add","path":"","value":{"v":0}}]`) })
	for i := 1; i <= 2; i++ {
		measure(fmt.Sprintf("append %d", i), 4, func() {
			w = ddbWrite(t, e, "calls", "d", w.Items[0].IDs[0], fmt.Sprintf(`[{"op":"replace","path":"/v","value":%d}]`, i))
		})
	}
	measure("head read", 3, func() {
		if _, err := e.ResourceHead(ctx, "calls", "d", Credentials{}); err != nil {
			t.Fatal(err)
		}
	})
	measure("revision read", 4, func() {
		if _, err := e.ResourceRev(ctx, "calls", "d", w.Items[0].IDs[0], Credentials{}); err != nil {
			t.Fatal(err)
		}
	})
	measure("log read", 2, func() {
		if _, err := e.NamespaceLog(ctx, "calls", "", "", 0, Credentials{}); err != nil {
			t.Fatal(err)
		}
	})
}

// A write whose check read the tip before another write of this instance
// moved it commits in one transaction: it chains over the tip the other
// committed, which the store remembers, not the stale one its check read
// (a transaction cancelled, the tip read, the transaction again). The
// group commit worker of the other write is gone by then, as a namespace
// whose writes come one at a time sees after each.
func TestDDBStaleTipWastesNoCommit(t *testing.T) {
	e, f, _ := ddbFaultEngine(t, ddbTable(t), Options{})
	ddbCreateNS(t, e, "busy", `{"read":"public"}`)
	a := ddbWrite(t, e, "busy", "a", "", `[{"op":"add","path":"","value":{"v":0}}]`)
	b := ddbWrite(t, e, "busy", "b", "", `[{"op":"add","path":"","value":{"v":0}}]`)
	f.takeCalls()
	// b's check reads the tip (its prefetch), then reads b's head
	// revision: before that, a's write commits, moving the tip.
	f.hook("GetItem", func() {
		ddbWrite(t, e, "busy", "a", a.Items[0].IDs[0], `[{"op":"replace","path":"/v","value":1}]`)
	})
	ddbWrite(t, e, "busy", "b", b.Items[0].IDs[0], `[{"op":"replace","path":"/v","value":1}]`)
	by, _ := f.takeCalls()
	if tx := by["TransactWriteItems"]; tx != 2 {
		t.Fatalf("%d commit transactions for 2 writes, want 2: b chained over a stale tip (%v)", tx, by)
	}
}
