package ddbstore

// Integration tests against DynamoDB Local. They run only with
// DDB_ENDPOINT set:
//
//	docker run -d --name ddb-local -p 8000:8000 amazon/dynamodb-local
//	DDB_ENDPOINT=http://localhost:8000 go test ./internal/ddbstore/
//
// What a write means — §6.2's checks, its answers — is core's gate's, and
// the API suites test it on every backend (internal/testenv). These test
// what only the store shows: that DynamoDB enforces the commit's
// conditions as docs/DYNAMODB.md §4 needs, under races and group commit.
// Their commits are built as the gate would build them (testCommit).

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func newLocalStore(t testing.TB) *Store {
	t.Helper()
	endpoint, _, _ := strings.Cut(os.Getenv("DDB_ENDPOINT"), ",") // the first of a list (testenv)
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

func mustCreateNS(t testing.TB, s *Store, ns string) (cfgID, nsID string) {
	t.Helper()
	cfgID, nsID, err := s.CreateNamespace(context.Background(), &ddb.Create{NS: ns, Author: "test", Patches: patches(`[{"op":"add","path":"","value":{}}]`)})
	if err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	return cfgID, nsID
}

// written is a test write's revision and entry.
type written struct{ ID, NSID string }

// testCommit builds the commit core's gate would for one step on name: a
// write of patch set p, or a tombstone when p is "", on the head ifMatch
// names ("" for a create), against the state read now.
func testCommit(t testing.TB, s *Store, ns, name, ifMatch, p string) *ddb.Commit {
	t.Helper()
	ctx := context.Background()
	n, err := s.Namespace(ctx, ns)
	if err != nil || n == nil {
		t.Fatalf("namespace %s: %+v %v", ns, n, err)
	}
	it := ddb.CommitItem{Name: name}
	res, err := s.Resource(ctx, ns, name)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if res != nil {
		it.HeadPos, it.HeadID, it.HeadTombstoned, it.LastID, it.LastPos = res.HeadPos, res.HeadID, res.Tombstoned, res.LastID, res.LastPos
		b, err := s.DocAt(ctx, ns, name, res.HeadPos)
		if err != nil {
			t.Fatal(err)
		}
		doc = jsonv.MustParse(b)
	}
	var parent *ids.ID
	if ifMatch != "" {
		pid, err := ids.Parse(ifMatch)
		if err != nil {
			t.Fatal(err)
		}
		parent = &pid
	}
	st := ddb.CommitStep{ParentID: ifMatch}
	kind := "head"
	if p == "" {
		st.Tombstone, kind = true, "tombstone"
		st.ID = ids.Tombstone(*parent).String()
	} else {
		ps := patches(p)
		canon := jsonv.Canonical(ps)
		out, _, err := applyPatches(doc, parent != nil, ps)
		if err != nil {
			t.Fatal(err)
		}
		st.ID, st.Patches, st.Doc = ids.Revision(parent, canon).String(), string(canon), string(jsonv.Canonical(out))
	}
	it.Steps = []ddb.CommitStep{st}
	return &ddb.Commit{
		NS: ns, Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
		Items: []ddb.CommitItem{it}, Entry: map[string]any{"resource": name, "kind": kind, "target": st.ID}, Kind: kind,
	}
}

func write(t testing.TB, s *Store, ns, name, ifMatch, p string) (*written, error) {
	t.Helper()
	c := testCommit(t, s, ns, name, ifMatch, p)
	res, err := s.Commit(context.Background(), c)
	if err != nil {
		return nil, err
	}
	return &written{ID: c.Items[0].Steps[0].ID, NSID: res.NSID}, nil
}

func mustWrite(t testing.TB, s *Store, ns, name, ifMatch, p string) *written {
	t.Helper()
	w, err := write(t, s, ns, name, ifMatch, p)
	if err != nil {
		t.Fatalf("write %s/%s: %v", ns, name, err)
	}
	return w
}

// checkChain asserts ns's log is one chain with no gaps or repeats, of
// want entries, and returns its ids.
func checkChain(t testing.TB, s *Store, ns string, want int) map[string]bool {
	t.Helper()
	ctx := context.Background()
	n, err := s.Namespace(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	var entries []*ddb.EntryRow
	if err := s.EntriesBetween(ctx, ns, 0, n.TipPos, 0, func(e *ddb.EntryRow) bool {
		entries = append(entries, e)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf("%d entries, want %d", len(entries), want)
	}
	seen := map[string]bool{}
	for i, e := range entries {
		if e.Pos != uint64(i+1) || e.PrevPos != uint64(i) {
			t.Fatalf("entry %d at %d after %d: a gap in the chain", i+1, e.Pos, e.PrevPos)
		}
		if seen[e.ID] {
			t.Fatalf("duplicate entry id %s", e.ID)
		}
		seen[e.ID] = true
	}
	return seen
}

// Concurrent commits of distinct resources of one namespace serialise on
// the #TIP condition, each re-chained over the tip it lost to (alone) or
// queued into groups: entries commit in chain order with no gaps.
func TestLocalConcurrentNamespace(t *testing.T) {
	t.Run("alone", func(t *testing.T) { testConcurrentNamespace(t, 1, 8) })
	t.Run("grouped", func(t *testing.T) { testConcurrentNamespace(t, 32, 48) })
}

func testConcurrentNamespace(t *testing.T, group, writers int) {
	s := newLocalStore(t)
	s.GroupCommit = group
	mustCreateNS(t, s, "demo")
	var wg sync.WaitGroup
	errs := make([]error, writers)
	nsids := make([]string, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := write(t, s, "demo", fmt.Sprintf("doc%d", i), "", fmt.Sprintf(`[{"op":"add","path":"","value":{"w":%d}}]`, i))
			if err == nil {
				nsids[i] = w.NSID
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
	seen := checkChain(t, s, "demo", writers+1)
	for i, id := range nsids {
		if !seen[id] {
			t.Fatalf("writer %d answered entry %s, not in the log", i, id)
		}
	}
	if group > 1 {
		groups, appended := s.GroupStats()
		if appended != int64(writers) || groups >= appended {
			t.Fatalf("%d groups appended %d commits; want %d in fewer groups", groups, appended, writers)
		}
		t.Logf("%d writes in %d groups", appended, groups)
	}
}

// Commits of one resource on the same head race: exactly one wins, the
// rest are ErrStale (their head moved: core checks them again, D.3).
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
	cs := make([]*ddb.Commit, racers)
	for i := range racers {
		cs[i] = testCommit(t, s, "demo", "doc1", w1.ID, fmt.Sprintf(`[{"op":"add","path":"/w%d","value":true}]`, i))
	}
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Commit(context.Background(), cs[i])
		}()
	}
	wg.Wait()
	var won, stale int
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ddb.ErrStale):
			stale++
		default:
			t.Errorf("racer %d: %v", i, err)
		}
	}
	if won != 1 || stale != racers-1 {
		t.Fatalf("%d won, %d stale; want 1 and %d", won, stale, racers-1)
	}
	checkChain(t, s, "demo", 3)
}

// A commit checked under a configuration that has since changed is
// stale, grouped or not: the gate's checks read the configuration.
func TestLocalConfigPinned(t *testing.T) {
	for _, group := range []int{1, 32} {
		s := newLocalStore(t)
		s.GroupCommit = group
		mustCreateNS(t, s, "demo")
		c := testCommit(t, s, "demo", "doc", "", `[{"op":"add","path":"","value":{}}]`)
		n, _ := s.Namespace(context.Background(), "demo")
		cfg := &ddb.Commit{
			NS: "demo", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
			Config: &ddb.CommitConfig{ID: ids.Of([]byte("next")).String(), Patches: `[]`, Doc: `{"x":1}`},
			Entry:  map[string]any{"kind": "config", "target": ids.Of([]byte("next")).String()}, Kind: "config",
		}
		if _, err := s.Commit(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(context.Background(), c); !errors.Is(err, ddb.ErrStale) {
			t.Fatalf("group %d: commit under the old configuration: %v, want ErrStale", group, err)
		}
	}
}

// A commit pinning another namespace's configuration (a schema's, which
// decides whether the writer may read it) is stale once that moves; one
// pinning the configuration in force commits.
func TestLocalPinnedElsewhere(t *testing.T) {
	for _, group := range []int{1, 32} {
		s := newLocalStore(t)
		s.GroupCommit = group
		mustCreateNS(t, s, "demo")
		mustCreateNS(t, s, "schemas")
		ctx := context.Background()
		sn, _ := s.Namespace(ctx, "schemas")
		pin := ddb.NSPin{NS: "schemas", CfgPos: sn.ConfigPos, CfgID: sn.ConfigID}
		ok := testCommit(t, s, "demo", "a", "", `[{"op":"add","path":"","value":{}}]`)
		ok.Pins = []ddb.NSPin{pin}
		if _, err := s.Commit(ctx, ok); err != nil {
			t.Fatalf("group %d: %v", group, err)
		}
		next := ids.Of([]byte("next")).String()
		if _, err := s.Commit(ctx, &ddb.Commit{
			NS: "schemas", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: sn.ConfigPos, CfgID: sn.ConfigID,
			Config: &ddb.CommitConfig{ID: next, Patches: `[]`, Doc: `{"read":"grant"}`},
			Entry:  map[string]any{"kind": "config", "target": next}, Kind: "config",
		}); err != nil {
			t.Fatal(err)
		}
		stale := testCommit(t, s, "demo", "b", "", `[{"op":"add","path":"","value":{}}]`)
		stale.Pins = []ddb.NSPin{pin}
		if _, err := s.Commit(ctx, stale); !errors.Is(err, ddb.ErrStale) {
			t.Fatalf("group %d: commit pinning the old configuration: %v, want ErrStale", group, err)
		}
	}
}

// A purge commits the resource's purged state on the head it read, and a
// write checked against that head before is stale; its content goes
// after (PurgeContent), and a namespace purge refuses every later write.
func TestLocalPurge(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	mustCreateNS(t, s, "p")
	w := mustWrite(t, s, "p", "a", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	late := testCommit(t, s, "p", "a", w.ID, `[{"op":"add","path":"/w","value":2}]`)
	n, _ := s.Namespace(ctx, "p")
	purge := func(c *ddb.Commit) error {
		c.NS, c.Author, c.Created, c.CfgPos, c.CfgID = "p", "alice", time.Now().UnixMilli(), n.ConfigPos, n.ConfigID
		_, err := s.Commit(ctx, c)
		return err
	}
	if err := purge(&ddb.Commit{Purge: &ddb.CommitPurge{Name: "a", HeadPos: 1, HeadID: w.ID},
		Entry: map[string]any{"resource": "a", "kind": "purge", "target": w.ID}, Kind: "purge"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, late); !errors.Is(err, ddb.ErrStale) {
		t.Fatalf("write checked before the purge: %v, want ErrStale", err)
	}
	if r, err := s.Resource(ctx, "p", "a"); err != nil || r == nil || !r.Purged {
		t.Fatalf("resource after the purge: %+v %v", r, err)
	}
	if _, err := s.PurgeContent(ctx, "p", "a"); err != nil {
		t.Fatal(err)
	}
	if ri, err := s.RevAt(ctx, "p", "a", 1); err != nil || ri.Patches != "" {
		t.Fatalf("revision after the content went: %+v %v", ri, err)
	}
	nss, _, err := s.Purging(ctx)
	if err != nil || len(nss) != 0 {
		t.Fatalf("purges left: %v %v", nss, err)
	}

	b := testCommit(t, s, "p", "b", "", `[{"op":"add","path":"","value":{}}]`)
	if err := purge(&ddb.Commit{PurgeNS: true, Entry: map[string]any{"kind": "purge-ns"}, Kind: "purge-ns"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(ctx, b); !errors.Is(err, ddb.ErrStale) {
		t.Fatalf("write to a purged namespace: %v, want ErrStale", err)
	}
	if nr, _ := s.Namespace(ctx, "p"); nr == nil || !nr.Purged {
		t.Fatalf("namespace after its purge: %+v", nr)
	}
}

// Grouped commits race config changes and deletes, and two stores on one
// table stand in for two instances, so groups lose the tip to other
// writers and re-chain: every commit lands, or is stale and committed
// again as core would after checking it again, and the chain has no gaps.
func TestLocalGroupMixed(t *testing.T) {
	a := newLocalStore(t)
	a.GroupCommit = 32
	b := &Store{Client: a.Client, Table: a.Table, GroupCommit: 32}
	ctx := context.Background()
	mustCreateNS(t, a, "demo")
	const n = 24
	pre := make([]*written, n)
	for i := range n {
		pre[i] = mustWrite(t, a, "demo", fmt.Sprintf("old%d", i), "", `[{"op":"add","path":"","value":{"v":0}}]`)
	}
	// retry commits as core does: checked again (rebuilt) while stale.
	retry := func(s *Store, build func() *ddb.Commit) (*ddb.CommitResult, error) {
		for {
			res, err := s.Commit(ctx, build())
			if !errors.Is(err, ddb.ErrStale) {
				return res, err
			}
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	landed := 0
	record := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return
		}
		landed++
	}
	for i := range n {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := retry(s, func() *ddb.Commit {
				return testCommit(t, s, "demo", fmt.Sprintf("new%d", i), "", fmt.Sprintf(`[{"op":"add","path":"","value":{"n":%d}}]`, i))
			})
			record(err)
		}()
		go func() {
			defer wg.Done()
			p := `[{"op":"add","path":"/v","value":1}]`
			if i%2 == 0 {
				p = "" // a delete
			}
			_, err := retry(s, func() *ddb.Commit { return testCommit(t, s, "demo", fmt.Sprintf("old%d", i), pre[i].ID, p) })
			record(err)
		}()
		go func() {
			defer wg.Done()
			if i%4 != 0 {
				record(nil)
				return
			}
			_, err := retry(s, func() *ddb.Commit {
				n, _ := s.Namespace(ctx, "demo")
				id := ids.Of([]byte(fmt.Sprintf("cfg%d-%d", i, n.ConfigPos))).String()
				return &ddb.Commit{
					NS: "demo", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
					Config: &ddb.CommitConfig{ID: id, Patches: `[]`, Doc: `{}`},
					Entry:  map[string]any{"kind": "config", "target": id}, Kind: "config",
				}
			})
			record(err)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		t.Errorf("commit: %v", err)
	}
	configs := n / 4
	checkChain(t, a, "demo", 1+n+n+n+configs) // genesis, the setup, new, old, configs
	for i := range n {
		r, err := a.Resource(ctx, "demo", fmt.Sprintf("old%d", i))
		if err != nil || r == nil || r.Tombstoned != (i%2 == 0) {
			t.Fatalf("old%d: %+v %v", i, r, err)
		}
	}
	ga, wa := a.GroupStats()
	gb, wb := b.GroupStats()
	t.Logf("a: %d commits in %d groups; b: %d in %d", wa, ga, wb, gb)
}

// A prune's reads go by the horizon from its commit on, before
// PruneContent has stripped anything: below it only a kept position's
// snapshot is served, above it folds start from the horizon's. Then
// PruneContent strips the patch sets and drops the snapshots no longer
// kept, idempotently, and the marker stays for DonePruning.
func TestLocalPruneHorizon(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	mustCreateNS(t, s, "p")
	var revs []*written
	prev := ""
	for i := 0; i < 6; i++ {
		p := fmt.Sprintf(`[{"op":"add","path":"/n","value":%d}]`, i)
		if i == 0 {
			p = `[{"op":"add","path":"","value":{"n":0}}]`
		}
		w, err := write(t, s, "p", "doc", prev, p)
		if err != nil {
			t.Fatal(err)
		}
		revs, prev = append(revs, w), w.ID
	}
	docAt := func(pos uint64) (string, error) {
		b, err := s.DocAt(ctx, "p", "doc", pos)
		return string(b), err
	}
	prune := func(horizon uint64, old uint64, kept []uint64, docs map[uint64][]byte) {
		t.Helper()
		if err := s.PutSnapshots(ctx, "p", "doc", docs); err != nil {
			t.Fatal(err)
		}
		res, _ := s.Resource(ctx, "p", "doc")
		n, _ := s.Namespace(ctx, "p")
		c := &ddb.Commit{
			NS: "p", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
			Entry: map[string]any{"resource": "doc", "kind": "prune", "target": revs[horizon-1].ID}, Kind: "prune",
			Prune: &ddb.CommitPrune{Name: "doc", HeadPos: res.HeadPos, HeadID: res.HeadID, OldHorizon: old,
				HorizonPos: horizon, HorizonID: revs[horizon-1].ID, Base: horizon, Keep: "[]", Kept: kept},
		}
		if _, err := s.Commit(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	// Horizon at 4, keeping 2.
	prune(4, 0, []uint64{2, 4}, map[uint64][]byte{2: []byte(`{"n":1}`), 4: []byte(`{"n":3}`)})
	var pe *ddb.PrunedError
	if _, err := docAt(1); !errors.As(err, &pe) || pe.Pos != 1 {
		t.Fatalf("below the horizon: %v", err)
	}
	if d, err := docAt(2); err != nil || d != `{"n":1}` {
		t.Fatalf("kept: %s %v", d, err)
	}
	if d, err := docAt(5); err != nil || d != `{"n":4}` {
		t.Fatalf("above the horizon: %s %v", d, err)
	}
	if pos, err := s.PrunedBelow(ctx, "p", "doc", 0, 6); err != nil || pos != 3 {
		t.Fatalf("PrunedBelow: %d %v", pos, err)
	}
	// A stale commit (the horizon moved) is refused.
	res, _ := s.Resource(ctx, "p", "doc")
	n, _ := s.Namespace(ctx, "p")
	_, err := s.Commit(ctx, &ddb.Commit{NS: "p", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
		Entry: map[string]any{"resource": "doc", "kind": "prune", "target": revs[4].ID}, Kind: "prune",
		Prune: &ddb.CommitPrune{Name: "doc", HeadPos: res.HeadPos, HeadID: res.HeadID, HorizonPos: 5, HorizonID: revs[4].ID, Base: 5, Keep: "[]"}})
	if !errors.Is(err, ddb.ErrStale) {
		t.Fatalf("prune on a moved horizon: %v", err)
	}
	// A later prune keeps nothing below 5: 2's snapshot is no longer
	// served, even before PruneContent deletes it.
	prune(5, 4, []uint64{5}, map[uint64][]byte{5: []byte(`{"n":4}`)})
	if _, err := docAt(2); !errors.As(err, &pe) {
		t.Fatalf("no longer kept: %v", err)
	}
	for i := 0; i < 2; i++ {
		if ok, err := s.PruneContent(ctx, "p", "doc"); err != nil || !ok {
			t.Fatalf("PruneContent: %v %v", ok, err)
		}
	}
	for pos := uint64(1); pos <= 6; pos++ {
		r, _ := s.RevAt(ctx, "p", "doc", pos)
		if r.Pruned != (pos < 5) {
			t.Fatalf("rev %d pruned = %v", pos, r.Pruned)
		}
	}
	if _, ok, _ := s.snapshot(ctx, "p", "doc", 2); ok {
		t.Fatal("2's snapshot survived")
	}
	if d, err := docAt(6); err != nil || d != `{"n":5}` {
		t.Fatalf("head: %s %v", d, err)
	}
	if nss, _, _ := s.Pruning(ctx); len(nss) != 1 {
		t.Fatalf("markers %v", nss)
	}
	if err := s.DonePruning(ctx, "p", "doc"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.PruneContent(ctx, "p", "doc"); err != nil || ok {
		t.Fatalf("PruneContent after done: %v %v", ok, err)
	}
}

// A table records its key layout at start-up when it has no namespace; a
// table of the earlier layout (namespaces, no record) or of another
// version is refused.
func TestLocalLayout(t *testing.T) {
	ctx := context.Background()
	s := newLocalStore(t)
	for i := 0; i < 2; i++ {
		if err := s.CheckLayout(ctx); err != nil {
			t.Fatalf("check %d of a new table: %v", i+1, err)
		}
	}
	mustCreateNS(t, s, "kept")
	if err := s.CheckLayout(ctx); err != nil {
		t.Fatalf("a table of this layout with a namespace: %v", err)
	}
	if err := s.deleteKey(ctx, keyLayout()); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLayout(ctx); err == nil || !strings.Contains(err.Error(), "key layout 1") {
		t.Fatalf("a table of namespaces without a layout record: %v, want refused as layout 1", err)
	}
	if _, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: withKey(keyLayout(), item{"version": avN(9)})}); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLayout(ctx); err == nil || !strings.Contains(err.Error(), "layout 9") {
		t.Fatalf("a table of layout 9: %v, want refused", err)
	}
}

// A write puts its log entry and resource item under the namespace's key
// and its revision, head document and head history under its resource's
// (resPK): the namespace's partition takes ~1,000 write units a second,
// and resources share it only through these.
func TestLocalWritePartitions(t *testing.T) {
	ctx := context.Background()
	s := newLocalStore(t)
	mustCreateNS(t, s, "p")
	w := mustWrite(t, s, "p", "a", "", `[{"op":"add","path":"","value":{"v":0}}]`)
	mustWrite(t, s, "p", "a", w.ID, `[{"op":"replace","path":"/v","value":1}]`)
	mustWrite(t, s, "p", "b", "", `[{"op":"add","path":"","value":{"v":0}}]`)
	types := func(pk string) map[string]int {
		n := map[string]int{}
		if err := s.eachInPartition(ctx, pk, "", func(i item) error {
			typ, _, _ := strings.Cut(strings.TrimPrefix(i.s("SK"), "#"), "#")
			n[typ]++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ns := types(nsPK("p"))
	for typ := range ns {
		switch typ {
		case "META", "TIP", "CFG", "LOG", "RES":
		default:
			t.Errorf("the namespace's partition holds %s items: %v", typ, ns)
		}
	}
	if ns["LOG"] != 4 || ns["RES"] != 2 {
		t.Errorf("the namespace's partition: %v, want 4 log entries (config, 3 writes) and 2 resources", ns)
	}
	if a := types(resPK("p", "a")); a["REV"] != 2 || a["DOC"] != 1 || a["HIST"] != 2 || len(a) != 3 {
		t.Errorf("a's partition: %v, want 2 revisions, its head document, 2 history rows", a)
	}
}
