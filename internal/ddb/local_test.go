package ddb

// Integration tests against DynamoDB Local. They run only with
// DDB_ENDPOINT set:
//
//	docker run -d --name ddb-local -p 8000:8000 amazon/dynamodb-local
//	DDB_ENDPOINT=http://localhost:8000 go test ./internal/ddb/
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

func mustCreateNS(t testing.TB, s *Store, ns string) (cfgID, nsID string) {
	t.Helper()
	cfgID, nsID, err := s.CreateNamespace(context.Background(), &Create{NS: ns, Author: "test", Patches: patches(`[{"op":"add","path":"","value":{}}]`)})
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
func testCommit(t testing.TB, s *Store, ns, name, ifMatch, p string) *Commit {
	t.Helper()
	ctx := context.Background()
	n, err := s.Namespace(ctx, ns)
	if err != nil || n == nil {
		t.Fatalf("namespace %s: %+v %v", ns, n, err)
	}
	it := CommitItem{Name: name}
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
	st := CommitStep{ParentID: ifMatch}
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
	it.Steps = []CommitStep{st}
	return &Commit{
		NS: ns, Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
		Items: []CommitItem{it}, Entry: map[string]any{"resource": name, "kind": kind, "target": st.ID}, Kind: kind,
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
	entries, _, err := s.ReadLog(context.Background(), ns, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf("%d entries, want %d", len(entries), want)
	}
	seen := map[string]bool{}
	prev := entries[0]["id"].(string)
	seen[prev] = true
	for i, e := range entries[1:] {
		if e["prev"] != prev {
			t.Fatalf("entry %d prev %v, want %s: a gap in the chain", i+2, e["prev"], prev)
		}
		prev = e["id"].(string)
		if seen[prev] {
			t.Fatalf("duplicate entry id %s", prev)
		}
		seen[prev] = true
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
	cs := make([]*Commit, racers)
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
		case errors.Is(err, ErrStale):
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
		cfg := &Commit{
			NS: "demo", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
			Config: &CommitConfig{ID: ids.Of([]byte("next")).String(), Patches: `[]`, Doc: `{"x":1}`},
			Entry:  map[string]any{"kind": "config", "target": ids.Of([]byte("next")).String()}, Kind: "config",
		}
		if _, err := s.Commit(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(context.Background(), c); !errors.Is(err, ErrStale) {
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
		pin := NSPin{NS: "schemas", CfgPos: sn.ConfigPos, CfgID: sn.ConfigID}
		ok := testCommit(t, s, "demo", "a", "", `[{"op":"add","path":"","value":{}}]`)
		ok.Pins = []NSPin{pin}
		if _, err := s.Commit(ctx, ok); err != nil {
			t.Fatalf("group %d: %v", group, err)
		}
		next := ids.Of([]byte("next")).String()
		if _, err := s.Commit(ctx, &Commit{
			NS: "schemas", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: sn.ConfigPos, CfgID: sn.ConfigID,
			Config: &CommitConfig{ID: next, Patches: `[]`, Doc: `{"read":"grant"}`},
			Entry:  map[string]any{"kind": "config", "target": next}, Kind: "config",
		}); err != nil {
			t.Fatal(err)
		}
		stale := testCommit(t, s, "demo", "b", "", `[{"op":"add","path":"","value":{}}]`)
		stale.Pins = []NSPin{pin}
		if _, err := s.Commit(ctx, stale); !errors.Is(err, ErrStale) {
			t.Fatalf("group %d: commit pinning the old configuration: %v, want ErrStale", group, err)
		}
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
	retry := func(s *Store, build func() *Commit) (*CommitResult, error) {
		for {
			res, err := s.Commit(ctx, build())
			if !errors.Is(err, ErrStale) {
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
			_, err := retry(s, func() *Commit {
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
			_, err := retry(s, func() *Commit { return testCommit(t, s, "demo", fmt.Sprintf("old%d", i), pre[i].ID, p) })
			record(err)
		}()
		go func() {
			defer wg.Done()
			if i%4 != 0 {
				record(nil)
				return
			}
			_, err := retry(s, func() *Commit {
				n, _ := s.Namespace(ctx, "demo")
				id := ids.Of([]byte(fmt.Sprintf("cfg%d-%d", i, n.ConfigPos))).String()
				return &Commit{
					NS: "demo", Author: "alice", Created: time.Now().UnixMilli(), CfgPos: n.ConfigPos, CfgID: n.ConfigID,
					Config: &CommitConfig{ID: id, Patches: `[]`, Doc: `{}`},
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
