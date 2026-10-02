package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// Group commit per namespace (D.8, groupcommit.go). These tests run only
// with PATCHLOG_TEST_PG set.

// groupEngine opens an engine whose writes always queue (no write on its
// own) and whose groups wait long for writes still in their check phase,
// so writes held at BeforeWriteLock until all have arrived form one group.
func groupEngine(t *testing.T) *Engine {
	t.Helper()
	e := openInstance(t, pgtest.NewDB(t), t.TempDir())
	e.noSolo = true
	e.opt.GroupCommitWait = 5 * time.Second
	return e
}

// holdChecked makes the first n writes past their check phase wait for each
// other at BeforeWriteLock, so they queue together; fn, if set, runs once
// all have arrived, before they go on.
func holdChecked(t *testing.T, e *Engine, n int, fn func()) {
	var mu sync.Mutex
	arrived := make(chan struct{})
	e.opt.BeforeWriteLock = func() {
		mu.Lock()
		if n == 0 {
			mu.Unlock()
			return
		}
		if n--; n == 0 {
			if fn != nil {
				fn()
			}
			close(arrived)
		}
		mu.Unlock()
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Error("the writes didn't all finish their checks")
		}
	}
}

// groupSizes records the size of every group transaction attempt (each
// whole-group retry counts again).
func groupSizes(e *Engine) func() []int {
	var mu sync.Mutex
	var sizes []int
	e.groupStart = func(t *tx, size int) {
		mu.Lock()
		sizes = append(sizes, size)
		mu.Unlock()
	}
	return func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), sizes...)
	}
}

// concurrently runs fn(i) for i < n at once and collects the results.
func concurrently(n int, fn func(i int) (*WriteResult, error)) ([]*WriteResult, []error) {
	res, errs := make([]*WriteResult, n), make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = fn(i)
		}()
	}
	wg.Wait()
	return res, errs
}

// write puts {"n": n} to ns/name as put does, returning the whole result.
func write(e *Engine, ns, name, ifMatch string, n int) (*WriteResult, error) {
	r := who
	r.NS = ns
	it := Item{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == ""}
	op := "replace"
	if ifMatch == "" {
		op = "add"
	}
	it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(n)}}}}}
	return e.WriteResource(context.Background(), r, it)
}

// checkChain verifies ns's whole chain in storage: every entry follows the
// one before it by seq, and its id is the hash of the previous id and its
// body (§3.5). It returns the transaction id of each entry, by entry id.
func checkChain(t *testing.T, e *Engine, ns string) map[string]string {
	t.Helper()
	rows, err := e.db.QueryContext(context.Background(), `SELECT seq, id, prev_seq, body, xid::text FROM ns_log
		WHERE ns = (SELECT ns FROM namespaces WHERE name = $1) ORDER BY seq`, ns)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	xids := map[string]string{}
	var prev *ids.ID
	var prevSeq int64
	for rows.Next() {
		var seq int64
		var id []byte
		var ps *int64
		var body, xid string
		if err := rows.Scan(&seq, &id, &ps, &body, &xid); err != nil {
			t.Fatal(err)
		}
		if (prev == nil) != (ps == nil) || ps != nil && *ps != prevSeq {
			t.Fatalf("entry %d follows %v, want %d", seq, ps, prevSeq)
		}
		if want := ids.Hash(prev, []byte(body)); want != ids.FromBytes(id) {
			t.Fatalf("entry %d's id is %s, want %s", seq, ids.FromBytes(id), want)
		}
		p := ids.FromBytes(id)
		prev, prevSeq = &p, seq
		xids[p.String()] = xid
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var headID []byte
	if err := e.db.QueryRow(`SELECT head_id FROM namespaces WHERE name = $1`, ns).Scan(&headID); err != nil {
		t.Fatal(err)
	}
	if prev == nil || ids.FromBytes(headID) != *prev {
		t.Fatalf("the namespace's head is %x, its last entry %v", headID, prev)
	}
	return xids
}

// Concurrent writes to one namespace are appended in one transaction, with
// a correct chain, each answered with its own entry.
func TestPGGroupCommit(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	heads := map[string]string{}
	for i := 0; i < 3; i++ {
		h, err := put(e, "n", fmt.Sprint("r", i), "", i)
		if err != nil {
			t.Fatal(err)
		}
		heads[fmt.Sprint("r", i)] = h
	}
	const n = 6
	sizes := groupSizes(e)
	before := e.groups.committed.Load()
	holdChecked(t, e, n, nil)
	res, errs := concurrently(n, func(i int) (*WriteResult, error) {
		// Appends to r0–r2, creates of c3 and c4, and a batch creating
		// c5 and d5.
		if i < 3 {
			return write(e, "n", fmt.Sprint("r", i), heads[fmt.Sprint("r", i)], 10+i)
		}
		if i == n-1 {
			r := who
			r.NS = "n"
			mk := func(name string) Item {
				return Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"name": name}}}}}}
			}
			return e.Batch(context.Background(), r, []Item{mk(fmt.Sprint("c", i)), mk(fmt.Sprint("d", i))}, nil, nil, false)
		}
		return write(e, "n", fmt.Sprint("c", i), "", i)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != n {
		t.Fatalf("group sizes %v, want one of %d", got, n)
	}
	if got := e.groups.committed.Load() - before; got != 1 {
		t.Fatalf("%d groups committed, want 1", got)
	}
	xids := checkChain(t, e, "n")
	xid := ""
	seen := map[string]bool{}
	for i, r := range res {
		if r.Status != 201 || r.Replayed || (r.Entry == nil) != (i == n-1) {
			t.Fatalf("write %d: %+v", i, r)
		}
		if seen[r.NSID] {
			t.Fatalf("write %d answered with entry %s twice", i, r.NSID)
		}
		seen[r.NSID] = true
		x, ok := xids[r.NSID]
		if !ok {
			t.Fatalf("write %d's entry %s isn't in the chain", i, r.NSID)
		}
		if xid != "" && x != xid {
			t.Fatalf("write %d committed in transaction %s, the others in %s", i, x, xid)
		}
		xid = x
		for _, it := range r.Items {
			hd, err := e.ResourceHead(context.Background(), "n", it.Resource, who.Cred)
			if err != nil || hd.Head != it.IDs[0] {
				t.Fatalf("%s: head %+v %v, want %s", it.Resource, hd, err, it.IDs[0])
			}
		}
	}
	log, err := e.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + 3 + n; len(log.Entries) != want {
		t.Fatalf("%d entries, want %d", len(log.Entries), want)
	}
}

// A write of a group whose resource's head moved, here by an earlier write
// of the same group, rolls back to its savepoint and is answered 412 with
// the new head; the rest of the group commits.
func TestPGGroupCommitMovedHead(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	h, err := put(e, "n", "s", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := groupSizes(e)
	alone := e.groups.alone.Load()
	holdChecked(t, e, 4, nil)
	res, errs := concurrently(4, func(i int) (*WriteResult, error) {
		if i < 2 {
			return write(e, "n", "s", h, 100+i) // the same head, different content
		}
		return write(e, "n", fmt.Sprint("c", i), "", i)
	})
	if got := sizes(); len(got) != 1 || got[0] != 4 {
		t.Fatalf("group sizes %v, want one of 4", got)
	}
	win := 0
	if errs[0] != nil {
		win = 1
	}
	if errs[win] != nil || status(errs[1-win]) != 412 {
		t.Fatalf("the writes of s: %v, %v", errs[0], errs[1])
	}
	var ae *Error
	errors.As(errs[1-win], &ae)
	if ae.Body["head"] != res[win].Items[0].IDs[0] {
		t.Fatalf("412 names %v, the winner is %s", ae.Body["head"], res[win].Items[0].IDs[0])
	}
	if errs[2] != nil || errs[3] != nil {
		t.Fatalf("the other writes: %v, %v", errs[2], errs[3])
	}
	if got := e.groups.alone.Load() - alone; got != 1 {
		t.Fatalf("%d writes answered alone, want 1", got)
	}
	xids := checkChain(t, e, "n")
	if x := xids[res[win].NSID]; x == "" || x != xids[res[2].NSID] || x != xids[res[3].NSID] {
		t.Fatalf("the group's writes committed apart: %v", xids)
	}
	log, err := e.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
	if err != nil || len(log.Entries) != 1+1+3 {
		t.Fatalf("log: %v %v", log, err)
	}
}

// The same write twice in one group: the second finds the first, which
// committed with the group, and is answered as its idempotent retry
// (§7.2).
func TestPGGroupCommitIdempotentRetry(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	h, err := put(e, "n", "s", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := groupSizes(e)
	holdChecked(t, e, 3, nil)
	res, errs := concurrently(3, func(i int) (*WriteResult, error) {
		if i < 2 {
			return write(e, "n", "s", h, 7) // the same write
		}
		return write(e, "n", "c", "", 1)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != 3 {
		t.Fatalf("group sizes %v, want one of 3", got)
	}
	first, retry := res[0], res[1]
	if first.Replayed {
		first, retry = retry, first
	}
	if first.Replayed || first.Status != 201 || !retry.Replayed || retry.Status != 200 {
		t.Fatalf("want one write and its retry: %+v, %+v", res[0], res[1])
	}
	if retry.Items[0].IDs[0] != first.Items[0].IDs[0] || retry.NSID != first.NSID {
		t.Fatalf("the retry answers %v %s, the write %v %s", retry.Items[0].IDs, retry.NSID, first.Items[0].IDs, first.NSID)
	}
	xids := checkChain(t, e, "n")
	if xids[first.NSID] != xids[res[2].NSID] {
		t.Fatalf("the group's writes committed apart: %v", xids)
	}
	log, err := e.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
	if err != nil || len(log.Entries) != 1+1+2 {
		t.Fatalf("log: %v %v", log, err)
	}
}

// A config change that commits between a group's checks and its
// transaction: every write's re-check fails, and each is checked again
// against the new configuration (D.3), which here allows it, and there
// refuses it.
func TestPGGroupCommitConfigRace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change map[string]any
		status int // 0: the writes succeed
	}{
		{"allowed", map[string]any{"op": "add", "path": "/limits", "value": map[string]any{"documentSize": float64(1 << 20)}}, 0},
		{"refused", map[string]any{"op": "add", "path": "/frozen", "value": true}, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := groupEngine(t)
			cfg := mkNS(t, e, "n", map[string]any{"read": "public"})
			sizes := groupSizes(e)
			alone := e.groups.alone.Load()
			holdChecked(t, e, 3, func() {
				r := who
				r.NS = "n"
				if _, err := e.WriteConfig(context.Background(), r, ConfigChange{IfMatch: cfg, Patches: []any{tc.change}}); err != nil {
					t.Error(err)
				}
			})
			_, errs := concurrently(3, func(i int) (*WriteResult, error) { return write(e, "n", fmt.Sprint("c", i), "", i) })
			for i, err := range errs {
				if status(err) != tc.status && !(tc.status == 0 && err == nil) {
					t.Fatalf("write %d: %v, want status %d", i, err, tc.status)
				}
			}
			if got := sizes(); len(got) != 1 || got[0] != 3 {
				t.Fatalf("group sizes %v, want one of 3", got)
			}
			if got := e.groups.alone.Load() - alone; got != 3 {
				t.Fatalf("%d writes answered alone, want 3", got)
			}
			checkChain(t, e, "n")
			log, err := e.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
			want := 2 + 3
			if tc.status != 0 {
				want = 2
			}
			if err != nil || len(log.Entries) != want {
				t.Fatalf("log: %d entries (%v), want %d", len(log.Entries), err, want)
			}
		})
	}
}

// An error that aborts the group's transaction (here a deadlock, raised
// after two of its writes were appended) retries the whole group, which
// then commits once, every write with its single entry.
func TestPGGroupCommitRetriesAbortedGroup(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	var injected atomic.Bool
	e.groupMember = func(t *tx, i int) {
		if i == 2 && injected.CompareAndSwap(false, true) {
			_, err := t.Exec(`DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40P01'; END $$`)
			t.must(err)
		}
	}
	sizes := groupSizes(e)
	before := e.groups.committed.Load()
	alone := e.groups.alone.Load()
	const n = 4
	holdChecked(t, e, n, nil)
	res, errs := concurrently(n, func(i int) (*WriteResult, error) { return write(e, "n", fmt.Sprint("c", i), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if !injected.Load() {
		t.Fatal("no abort was injected")
	}
	if got := sizes(); len(got) != 2 || got[0] != n || got[1] != n {
		t.Fatalf("group attempts %v, want two of %d", got, n)
	}
	if got := e.groups.committed.Load() - before; got != 1 {
		t.Fatalf("%d groups committed, want 1", got)
	}
	if got := e.groups.alone.Load() - alone; got != 0 {
		t.Fatalf("%d writes answered alone, want none", got)
	}
	xids := checkChain(t, e, "n")
	for i, r := range res {
		if r.Status != 201 || xids[r.NSID] != xids[res[0].NSID] {
			t.Fatalf("write %d: %+v (transactions %v)", i, r, xids)
		}
	}
	log, err := e.NamespaceLog(context.Background(), "n", "", "", 0, who.Cred)
	if err != nil || len(log.Entries) != 1+n {
		t.Fatalf("log: %v %v", log, err)
	}
}

// Writes inserted together that lose a race to insert (here a unique
// violation of a revision, as when another instance moved a head between
// the re-checks and the insert) are appended again one by one, each under
// its own savepoint, in a transaction run again; all commit together.
func TestPGGroupCommitLostRaceAppendsApart(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	var injected atomic.Bool
	e.groupMember = func(t *tx, i int) {
		if injected.CompareAndSwap(false, true) {
			_, err := t.Exec(`DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '23505', TABLE = 'revisions'; END $$`)
			t.must(err)
		}
	}
	sizes := groupSizes(e)
	before := e.groups.committed.Load()
	alone := e.groups.alone.Load()
	const n = 4
	holdChecked(t, e, n, nil)
	res, errs := concurrently(n, func(i int) (*WriteResult, error) { return write(e, "n", fmt.Sprint("c", i), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if !injected.Load() {
		t.Fatal("no race was injected")
	}
	if got := sizes(); len(got) != 2 || got[0] != n || got[1] != n {
		t.Fatalf("group attempts %v, want two of %d", got, n)
	}
	if got := e.groups.committed.Load() - before; got != 1 {
		t.Fatalf("%d groups committed, want 1", got)
	}
	if got := e.groups.alone.Load() - alone; got != 0 {
		t.Fatalf("%d writes answered alone, want none", got)
	}
	xids := checkChain(t, e, "n")
	for i, r := range res {
		if r.Status != 201 || xids[r.NSID] != xids[res[0].NSID] {
			t.Fatalf("write %d: %+v (transactions %v)", i, r, xids)
		}
	}
	if len(xids) != 1+n {
		t.Fatalf("%d entries, want %d", len(xids), 1+n)
	}
}

// Group commit on and off (GroupCommit 1), many writers of one namespace,
// some racing for the same resources: every success is in the chain once,
// every loser is answered 412, and every resource's chain is linear.
func TestPGGroupCommitStress(t *testing.T) {
	for _, size := range []int{1, 4, 32} {
		t.Run(fmt.Sprint("group=", size), func(t *testing.T) {
			a, b := twoInstances(t)
			for _, e := range []*Engine{a, b} {
				e.opt.GroupCommit = size
			}
			mkNS(t, a, "n", map[string]any{"read": "public"})
			const writers, rounds, resources = 12, 15, 4
			var mu sync.Mutex
			heads := map[string]string{}
			wins := 0
			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					e := []*Engine{a, b}[w%2]
					for r := 0; r < rounds; r++ {
						name := fmt.Sprint("r", (w+r)%resources)
						mu.Lock()
						h := heads[name]
						mu.Unlock()
						id, err := put(e, "n", name, h, w*1000+r)
						switch {
						case err == nil:
							mu.Lock()
							wins++
							heads[name] = id
							mu.Unlock()
						case status(err) != 412:
							t.Errorf("writer %d: %v", w, err)
							return
						default:
							var ae *Error
							errors.As(err, &ae)
							mu.Lock()
							if hd, _ := ae.Body["head"].(string); hd != "" {
								heads[name] = hd
							}
							mu.Unlock()
						}
					}
				}()
			}
			wg.Wait()
			if xids := checkChain(t, a, "n"); len(xids) != 1+wins {
				t.Fatalf("%d entries for %d successes", len(xids), wins)
			}
			// Every resource's revisions form one linear chain.
			var forks int
			if err := a.db.QueryRow(`SELECT COUNT(*) FROM revisions r
				WHERE r.first = 0 AND r.parent_seq IS NULL`).Scan(&forks); err != nil || forks != 0 {
				t.Fatalf("%d revisions without a parent (%v)", forks, err)
			}
			var revs int
			if err := a.db.QueryRow(`SELECT COUNT(*) FROM revisions`).Scan(&revs); err != nil || revs != wins {
				t.Fatalf("%d revisions for %d successes (%v)", revs, wins, err)
			}
		})
	}
}
