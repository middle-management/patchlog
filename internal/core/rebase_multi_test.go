package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Two instances of one deployment, both with the experimental rebase and
// combine (rebase.go, combine.go, deferred.go, producer.go).

func openRebaseInstance(t *testing.T, url, dir string, hooks func(*Options)) *Engine {
	t.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	o := Options{Path: url, BlobDir: dir, AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: tailEvery, Purger: discardPurger{}, ExperimentalRebase: true, ExperimentalCombine: true}
	if hooks != nil {
		hooks(&o)
	}
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// rebased appends patches to n/name from head as author, asking for a
// rebase, with a producer key if id is set.
func rebased(e *Engine, author, name, head string, patches []any, id string, seq int64) (*WriteResult, error) {
	r := Request{NS: "n", Cred: Credentials{Author: author}}
	it := Item{Resource: name, IfMatch: head, Rebase: true, Steps: []Step{{Patches: patches}}}
	if id != "" {
		it.Producer = &Producer{ID: id, Seq: seq}
	}
	return e.WriteResource(context.Background(), r, it)
}

func docNow(t *testing.T, e *Engine, name string) map[string]any {
	t.Helper()
	var doc any
	if err := e.read(context.Background(), func(t *tx) error {
		n := t.nsByName("n")
		v := t.resolve(n, name, nil)
		d, err := t.docAt(v.head)
		doc = d
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Through JSON, for plain Go values whatever the parser's number type.
	b, _ := json.Marshal(doc)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("document %s: %v", b, err)
	}
	return m
}

func member(k int) string { return fmt.Sprintf("w%d", k) }

func memberDoc(writers int) map[string]any {
	m := map[string]any{}
	for k := 0; k < writers; k++ {
		m[member(k)] = 0
	}
	return map[string]any{"members": m, "list": []any{}}
}

func memberPatch(k, i int) []any {
	return []any{
		map[string]any{"op": "replace", "path": "/members/" + member(k), "value": i},
		map[string]any{"op": "add", "path": "/list/-", "value": k*1000 + i},
	}
}

func createDoc(t *testing.T, e *Engine, name string, doc map[string]any) string {
	t.Helper()
	r := who
	r.NS = "n"
	res, err := e.WriteResource(context.Background(), r, Item{Resource: name, IfNoneMatch: true,
		Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return res.Items[0].IDs[0]
}

// Writers on both instances rebase onto one document, each repeating some
// of its writes on the other instance: every write lands exactly once, a
// repeat is answered with the first attempt's revision whichever instance
// takes it, and the logs hold together.
func TestPGRebaseTwoInstances(t *testing.T) {
	url, dir := pgtest.NewDB(t), t.TempDir()
	a, b := openRebaseInstance(t, url, dir, nil), openRebaseInstance(t, url, dir, nil)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	const writers, each = 8, 15
	base := createDoc(t, a, "d", memberDoc(writers))

	var wg sync.WaitGroup
	var stale, repeats atomic.Int64
	for k := 0; k < writers; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			mine, other := a, b
			if k%2 == 1 {
				mine, other = b, a
			}
			author, head := member(k), base
			for i := 1; i <= each; i++ {
				seq := int64(i - 1)
				var id string
				for attempt := 0; ; attempt++ {
					res, err := rebased(mine, author, "d", head, memberPatch(k, i), author, seq)
					if err == nil {
						id = res.Items[0].IDs[0]
						break
					}
					if status(err) != 412 || attempt > 50 {
						t.Errorf("writer %d write %d: %v", k, i, err)
						return
					}
					stale.Add(1)
					var ae *Error
					errors.As(err, &ae)
					head, _ = ae.Body["head"].(string)
				}
				if i%3 == 0 {
					// The answer was lost, say: the same write again, at the
					// other instance, from the head it was first sent with.
					res, err := rebased(other, author, "d", head, memberPatch(k, i), author, seq)
					if err != nil || !res.Replayed || len(res.Items) != 1 || res.Items[0].IDs[0] != id {
						t.Errorf("writer %d write %d repeated at the other instance: %+v, %v (first made %s)", k, i, res, err, id)
						return
					}
					repeats.Add(1)
				}
				head = id
			}
		}(k)
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	doc := docNow(t, b, "d")
	if l := doc["list"].([]any); len(l) != writers*each {
		t.Fatalf("%d list items, want %d (%d repeats, %d stale answers)", len(l), writers*each, repeats.Load(), stale.Load())
	}
	for k := 0; k < writers; k++ {
		if got := doc["members"].(map[string]any)[member(k)]; got != float64(each) {
			t.Errorf("member %d is %v, want %d", k, got, each)
		}
	}
	lg, err := a.ResourceLog(context.Background(), "n", "d", "", "", 0, who.Cred)
	if err != nil {
		t.Fatal(err)
	}
	if len(lg.Entries) != 1+writers*each {
		t.Fatalf("d's log has %d entries, want %d", len(lg.Entries), 1+writers*each)
	}
	if xids := checkChain(t, a, "n"); len(xids) == 0 {
		t.Fatal("no namespace entries")
	}
	t.Logf("%d writes, %d repeated across instances, %d stale answers", writers*each, repeats.Load(), stale.Load())
}

// The other instance commits a write of the document while a group's rows
// are held back: the group's flush finds the head moved, rolls back, and
// each of its writes then lands on its own, over the other's.
func TestPGRebaseOtherInstanceCommitsMidGroup(t *testing.T) {
	url, dir := pgtest.NewDB(t), t.TempDir()
	var hold atomic.Bool
	inside, release := make(chan struct{}), make(chan struct{})
	var b *Engine
	var midGroup atomic.Int64
	var bErr error
	var head string
	a := openRebaseInstance(t, url, dir, func(o *Options) {
		o.BeforeCommit = func(context.Context) {
			if hold.CompareAndSwap(true, false) {
				close(inside)
				<-release
			}
		}
	})
	b = openRebaseInstance(t, url, dir, nil)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	const writers = 4
	base := createDoc(t, a, "d", memberDoc(writers+1))
	head = base

	// One write holds the document's queue at its commit while the others
	// arrive, so they form one group.
	hold.Store(true)
	var wg sync.WaitGroup
	errs := make([]error, writers)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errs[0] = rebased(a, member(0), "d", base, memberPatch(0, 1), "", 0)
	}()
	<-inside
	a.combineMember = func(i int) {
		// Before the group's second write, with its first held back: the
		// other instance writes the document and commits.
		if i == 1 && midGroup.Add(1) == 1 {
			h := headOf(t, b, "n", "d")
			_, bErr = rebased(b, member(writers), "d", h, memberPatch(writers, 1), "", 0)
		}
	}
	for k := 1; k < writers; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			_, errs[k] = rebased(a, member(k), "d", head, memberPatch(k, 1), "", 0)
		}(k)
	}
	// Let them queue behind the held write, then let it go.
	if !waitFor(5*time.Second, func() bool {
		a.combine.mu.Lock()
		defer a.combine.mu.Unlock()
		q := a.combine.q["n\x00d"]
		return q != nil && len(q.pending) == writers-1
	}) {
		t.Fatal("the writes didn't queue behind the held one")
	}
	close(release)
	wg.Wait()
	for k, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", k, err)
		}
	}
	if midGroup.Load() == 0 {
		t.Fatal("the group's second write never ran: no group formed")
	}
	if bErr != nil {
		t.Fatalf("the other instance's write: %v", bErr)
	}
	doc := docNow(t, b, "d")
	if l := doc["list"].([]any); len(l) != writers+1 {
		t.Fatalf("%d list items, want %d", len(l), writers+1)
	}
	for k := 0; k <= writers; k++ {
		if got := doc["members"].(map[string]any)[member(k)]; got != float64(1) {
			t.Errorf("member %d is %v, want 1", k, got)
		}
	}
	lg, err := b.ResourceLog(context.Background(), "n", "d", "", "", 0, who.Cred)
	if err != nil {
		t.Fatal(err)
	}
	if len(lg.Entries) != 2+writers {
		t.Fatalf("d's log has %d entries, want %d", len(lg.Entries), 2+writers)
	}
	checkChain(t, a, "n")
}

// A producer's record is the deployment's, not an instance's: a repeat is
// recognised at another instance and after a restart, and a gap refused.
func TestPGProducerAcrossInstancesAndRestart(t *testing.T) {
	url, dir := pgtest.NewDB(t), t.TempDir()
	a, b := openRebaseInstance(t, url, dir, nil), openRebaseInstance(t, url, dir, nil)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	base := createDoc(t, a, "d", memberDoc(1))
	first, err := rebased(a, "w", "d", base, memberPatch(0, 1), "p", 0)
	if err != nil {
		t.Fatal(err)
	}
	id := first.Items[0].IDs[0]
	// Someone else moves the head, so the repeat isn't §7.2's own retry.
	if _, err := rebased(a, "x", "d", id, []any{map[string]any{"op": "add", "path": "/other", "value": 1}}, "", 0); err != nil {
		t.Fatal(err)
	}
	again := func(e *Engine, where string) {
		t.Helper()
		res, err := rebased(e, "w", "d", base, memberPatch(0, 1), "p", 0)
		if err != nil || !res.Replayed || len(res.Items) != 1 || res.Items[0].IDs[0] != id {
			t.Fatalf("the repeat %s: %+v, %v", where, res, err)
		}
	}
	again(b, "at the other instance")
	if _, err := rebased(b, "w", "d", base, memberPatch(0, 3), "p", 2); status(err) != 409 {
		t.Fatalf("a gap at the other instance: %v, want 409", err)
	}
	// Another author's producer of the same name is its own.
	if _, err := rebased(b, "v", "d", base, []any{map[string]any{"op": "add", "path": "/v", "value": 1}}, "p", 0); err != nil {
		t.Fatalf("another author's producer p: %v", err)
	}
	a.Close()
	again(openRebaseInstance(t, url, dir, nil), "after a restart")
	if _, err := rebased(b, "w", "d", headOf(t, b, "n", "d"), memberPatch(0, 2), "p", 1); err != nil {
		t.Fatalf("the next seq: %v", err)
	}
	if l := docNow(t, b, "d")["list"].([]any); len(l) != 2 {
		t.Fatalf("list %v, want the two writes of w once each", l)
	}
}
