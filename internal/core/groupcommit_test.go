package core

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
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
	// Authentication is disabled: entries appended together record
	// "grant": null like the others (§1, §7.4).
	for i, m := range log.Entries {
		if g, has := m["grant"]; !has || g != nil {
			t.Fatalf("entry %d: %v", i, m)
		}
	}
}

// A write of a group whose resource an earlier write of the same group
// writes is left out and answered alone, here 412 with the new head; the
// rest of the group commits.
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

// An error that aborts the group's transaction (a deadlock or a
// serialization failure, raised after every write's rows were inserted and
// before any entry was appended, or locks needed out of order) retries the
// whole group, which then commits once, every write with its single entry.
func TestPGGroupCommitRetriesAbortedGroup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(t *tx)
		atEnd  bool // injected after the inserts, else at the group's start
	}{
		{"deadlock", func(t *tx) {
			_, err := t.Exec(`DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40P01'; END $$`)
			t.must(err)
		}, true},
		{"serialization", func(t *tx) {
			_, err := t.Exec(`DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40001'; END $$`)
			t.must(err)
		}, true},
		{"relock", func(t *tx) {
			panic(&errRelock{want: maps.Clone(t.locks)})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := groupEngine(t)
			mkNS(t, e, "n", map[string]any{"read": "public"})
			var injected atomic.Bool
			inject := func(t *tx) {
				if injected.CompareAndSwap(false, true) {
					tc.inject(t)
				}
			}
			e.groupMember = func(t *tx, i int) {
				if tc.atEnd && i == 2 {
					inject(t)
				}
			}
			sizes := groupSizes(e)
			if !tc.atEnd {
				record := e.groupStart
				e.groupStart = func(t *tx, size int) {
					record(t, size)
					inject(t)
				}
			}
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
		})
	}
}

// Writes inserted together that lose a race to insert (here a unique
// violation of a revision, as when another instance moved a head between
// the re-checks and the insert) are re-checked and inserted again in a
// transaction run again, without savepoints; all commit together.
func TestPGGroupCommitLostRaceRunsAgain(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	const n = 4
	// Postgres 16 reports a backend's subtransactions: the group uses none,
	// so a large group doesn't overflow their cache.
	var version int
	if err := e.db.QueryRow(`SELECT current_setting('server_version_num')::int`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	subxacts := -1
	var injected atomic.Bool
	e.groupMember = func(t *tx, i int) {
		if injected.CompareAndSwap(false, true) {
			_, err := t.Exec(`DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '23505', TABLE = 'revisions'; END $$`)
			t.must(err)
		}
		if i == n-1 && version >= 160000 {
			t.must(t.QueryRow(`SELECT (pg_stat_get_backend_subxact(b)).subxact_count FROM pg_stat_get_backend_idset() AS b
				WHERE pg_stat_get_backend_pid(b) = pg_backend_pid()`).Scan(&subxacts))
		}
	}
	sizes := groupSizes(e)
	before := e.groups.committed.Load()
	alone := e.groups.alone.Load()
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
	if version >= 160000 && subxacts != 0 {
		t.Fatalf("the group's transaction has %d subtransactions, want none", subxacts)
	}
}

// deadlockWait is how long Postgres waits before detecting a deadlock in
// the databases of slowDeadlockDB: long enough that a write delayed by one
// stands out from a slow write.
const deadlockWait = 5 * time.Second

// slowDeadlockDB is pgtest.NewDB with deadlock_timeout set to deadlockWait
// on every connection.
func slowDeadlockDB(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(pgtest.NewDB(t))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("deadlock_timeout", deadlockWait.String())
	u.RawQuery = q.Encode()
	return u.String()
}

// twoInstancesAt opens two engines on url, sharing a blob directory.
func twoInstancesAt(t *testing.T, url string) (*Engine, *Engine) {
	dir := t.TempDir()
	return openInstance(t, url, dir), openInstance(t, url, dir)
}

// waiting counts the lock requests of the database's transactions that
// are not granted.
func waiting(e *Engine) int {
	var n int
	e.db.QueryRow(`SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE NOT l.granted AND a.datname = current_database()`).Scan(&n)
	return n
}

// waitFor polls cond until it holds or d passes, and reports whether it
// held. Unlike within it may run outside the test's goroutine.
func waitFor(d time.Duration, cond func() bool) bool {
	for start := time.Now(); !cond(); time.Sleep(2 * time.Millisecond) {
		if time.Since(start) > d {
			return false
		}
	}
	return true
}

// idle reports whether the engine has no group-commit state left.
func idle(e *Engine) bool {
	e.groups.mu.Lock()
	defer e.groups.mu.Unlock()
	return len(e.groups.ns) == 0
}

// queued is how many writes of ns are queued.
func queued(e *Engine, ns string) int {
	e.groups.mu.Lock()
	defer e.groups.mu.Unlock()
	if s := e.groups.ns[ns]; s != nil {
		return len(s.queue)
	}
	return 0
}

// writeCtx is write with a context.
func writeCtx(ctx context.Context, e *Engine, ns, name string, n int) (*WriteResult, error) {
	r := who
	r.NS = ns
	it := Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": float64(n)}}}}}}
	return e.WriteResource(ctx, r, it)
}

func nsIDOf(t *testing.T, e *Engine, ns string) int64 {
	t.Helper()
	var id int64
	if err := e.db.QueryRow(`SELECT ns FROM namespaces WHERE name = $1`, ns).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// holdLock holds an advisory lock of class on a connection of its own,
// exclusively, until the returned func is called.
func holdLock(t *testing.T, e *Engine, class int, key int32) func() {
	t.Helper()
	tx, err := e.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1, $2)`, class, key); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { tx.Rollback() }) }
	t.Cleanup(release)
	return release
}

// Group commit on and off (GroupCommit 1), many writers of one namespace on
// two instances, writing single resources and batches of two in either
// order, some racing for the same resources: every success is in the chain
// once, every loser is answered 412, every resource's chain is linear, and
// no write waits for a deadlock to be detected. (A group inserts its rows in
// resource order and only then takes the log lock, so it deadlocks neither
// with single writes nor with batches or other groups.)
func TestPGGroupCommitStress(t *testing.T) {
	for _, size := range []int{1, 4, 32} {
		t.Run(fmt.Sprint("group=", size), func(t *testing.T) {
			a, b := twoInstancesAt(t, slowDeadlockDB(t))
			for _, e := range []*Engine{a, b} {
				e.opt.GroupCommit = size
			}
			mkNS(t, a, "n", map[string]any{"read": "public"})
			const writers, rounds, resources = 24, 20, 6
			var mu sync.Mutex
			heads := map[string]string{}
			entries, revs := 0, 0
			var slowest time.Duration
			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					e := []*Engine{a, b}[w%2]
					for r := 0; r < rounds; r++ {
						names := []string{fmt.Sprint("r", (w+r)%resources)}
						if r%3 == 2 {
							// A batch of two, in either order.
							other := fmt.Sprint("r", (w+r+1+w%3)%resources)
							if w%2 == 0 {
								names = append(names, other)
							} else {
								names = append([]string{other}, names...)
							}
						}
						var items []Item
						mu.Lock()
						for _, nm := range names {
							h := heads[nm]
							it := Item{Resource: nm, IfMatch: h, IfNoneMatch: h == ""}
							op := "replace"
							if h == "" {
								op = "add"
							}
							it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(w*1000 + r)}}}}}
							items = append(items, it)
						}
						mu.Unlock()
						req := who
						req.NS = "n"
						start := time.Now()
						var res *WriteResult
						var err error
						if len(items) == 1 {
							res, err = e.WriteResource(context.Background(), req, items[0])
						} else {
							res, err = e.Batch(context.Background(), req, items, nil, nil, false)
						}
						took := time.Since(start)
						mu.Lock()
						slowest = max(slowest, took)
						if err == nil {
							entries++
							revs += len(items)
							for _, it := range res.Items {
								heads[it.Resource] = it.IDs[0]
							}
						}
						mu.Unlock()
						if err != nil && status(err) != 412 {
							t.Errorf("writer %d: %v", w, err)
							return
						}
						if err != nil {
							// Learn the heads that moved.
							for _, nm := range names {
								hd, herr := e.ResourceHead(context.Background(), "n", nm, who.Cred)
								mu.Lock()
								if herr == nil {
									heads[nm] = hd.Head
								}
								mu.Unlock()
							}
						}
					}
				}()
			}
			wg.Wait()
			var deadlocks int64
			a.db.QueryRow(`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&deadlocks)
			t.Logf("%d entries, slowest write %v, groups %d+%d (alone %d+%d), deadlocks reported so far %d", entries, slowest,
				a.groups.committed.Load(), b.groups.committed.Load(), a.groups.alone.Load(), b.groups.alone.Load(), deadlocks)
			if slowest >= deadlockWait/2 {
				t.Errorf("a write took %v: it waited for a deadlock to be detected", slowest)
			}
			if size > 1 && a.groups.committed.Load()+b.groups.committed.Load() == 0 {
				t.Errorf("no group committed")
			}
			if xids := checkChain(t, a, "n"); len(xids) != 1+entries {
				t.Fatalf("%d entries for %d successes", len(xids), entries)
			}
			// Every resource's revisions form one linear chain.
			var forks int
			if err := a.db.QueryRow(`SELECT COUNT(*) FROM revisions r
				WHERE r.first = 0 AND r.parent_seq IS NULL`).Scan(&forks); err != nil || forks != 0 {
				t.Fatalf("%d revisions without a parent (%v)", forks, err)
			}
			var n int
			if err := a.db.QueryRow(`SELECT COUNT(*) FROM revisions`).Scan(&n); err != nil || n != revs {
				t.Fatalf("%d revisions for %d written (%v)", n, revs, err)
			}
		})
	}
}

// A group waits for another writer's rows only before it takes the log
// lock. Here, once the group has inserted its rows, a single write of one of
// its resources on another instance waits for the group's row; the group
// takes the log lock, appends and commits, and the single write is answered
// 412. (Had the group inserted a write's rows after taking the log lock,
// the single write would have inserted first and waited for that lock: a
// deadlock.) A write that attaches a blob goes in with the others.
func TestPGGroupCommitNoDeadlockWithSingleWrite(t *testing.T) {
	a, b := twoInstancesAt(t, slowDeadlockDB(t))
	a.noSolo = true
	a.opt.GroupCommitWait = 5 * time.Second
	b.opt.GroupCommit = 1
	mkNS(t, a, "n", map[string]any{"read": "public"})
	h, err := put(a, "n", "x", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("blob for x")
	bid := uploadBlob(t, a, "n", "x", data)
	single := make(chan error, 1)
	var fired atomic.Bool
	a.groupMember = func(tx *tx, i int) {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		if len(tx.logLocks) > 0 {
			t.Error("the group holds the log lock before appending")
		}
		go func() {
			_, err := put(b, "n", "x", h, 99)
			single <- err
		}()
		if !waitFor(5*time.Second, func() bool { return waiting(a) > 0 }) {
			t.Error("the single write didn't wait for the group's row")
		}
	}
	sizes := groupSizes(a)
	holdChecked(t, a, 2, nil)
	start := time.Now()
	res, errs := concurrently(2, func(i int) (*WriteResult, error) {
		if i == 0 {
			return write(a, "n", "p", "", 1)
		}
		r := who
		r.NS = "n"
		doc := map[string]any{"b": map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}}
		it := Item{Resource: "x", IfMatch: h, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "", "value": doc}}}}}
		return a.WriteResource(context.Background(), r, it)
	})
	serr := <-single
	if took := time.Since(start); took >= deadlockWait/2 {
		t.Fatalf("took %v: a deadlock", took)
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("group write %d: %v", i, err)
		}
	}
	if status(serr) != 412 {
		t.Fatalf("the single write: %v, want 412", serr)
	}
	if got := sizes(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("group attempts %v, want one of 2", got)
	}
	xids := checkChain(t, a, "n")
	if xids[res[0].NSID] != xids[res[1].NSID] {
		t.Fatalf("the group's writes committed apart")
	}
	var refs int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM blob_refs WHERE to_seq IS NULL`).Scan(&refs); err != nil || refs != 1 {
		t.Fatalf("%d blob_refs (%v), want 1", refs, err)
	}
}

// A group that loses a real race to insert: a single write of x on another
// instance has inserted its row and waits for the log lock (held here by a
// stand-in appender) when the group inserts its own write of x, from the
// same head. Once the single write commits, the group's insert fails, its
// transaction runs again, and the re-check leaves x's write out, to be
// answered 412 alone; the others commit together.
func TestPGGroupCommitLostRaceLeavesLoserOut(t *testing.T) {
	a, b := twoInstancesAt(t, slowDeadlockDB(t))
	a.noSolo = true
	a.opt.GroupCommitWait = 5 * time.Second
	b.opt.GroupCommit = 1
	mkNS(t, a, "n", map[string]any{"read": "public"})
	h, err := put(a, "n", "x", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	release := holdLock(t, a, logClass, lockKey(nsIDOf(t, a, "n")))
	type outcome struct {
		res *WriteResult
		err error
	}
	single := make(chan outcome, 1)
	go func() {
		r, err := write(b, "n", "x", h, 99)
		single <- outcome{r, err}
	}()
	within(t, 5*time.Second, "the single write waits for the log lock", func() bool { return waiting(a) == 1 })
	sizes := groupSizes(a)
	alone := a.groups.alone.Load()
	holdChecked(t, a, 3, nil)
	go func() {
		// Once the group waits for the single write's row, the single write
		// may append.
		if !waitFor(5*time.Second, func() bool { return waiting(a) == 2 }) {
			t.Error("the group didn't wait for the single write's row")
		}
		release()
	}()
	start := time.Now()
	res, errs := concurrently(3, func(i int) (*WriteResult, error) {
		if i == 0 {
			return write(a, "n", "x", h, 7)
		}
		return write(a, "n", fmt.Sprint("c", i), "", i)
	})
	if took := time.Since(start); took >= deadlockWait/2 {
		t.Fatalf("took %v: a deadlock", took)
	}
	s := <-single
	if s.err != nil {
		t.Fatalf("the single write: %v", s.err)
	}
	var ae *Error
	if !errors.As(errs[0], &ae) || ae.Status != 412 || ae.Body["head"] != s.res.Items[0].IDs[0] {
		t.Fatalf("the group's write of x: %v, want 412 naming %s", errs[0], s.res.Items[0].IDs[0])
	}
	if errs[1] != nil || errs[2] != nil {
		t.Fatalf("the other writes: %v, %v", errs[1], errs[2])
	}
	if got := sizes(); len(got) != 2 || got[0] != 3 || got[1] != 3 {
		t.Fatalf("group attempts %v, want two of 3", got)
	}
	if got := a.groups.alone.Load() - alone; got != 1 {
		t.Fatalf("%d writes answered alone, want 1", got)
	}
	xids := checkChain(t, a, "n")
	if xids[res[1].NSID] != xids[res[2].NSID] {
		t.Fatalf("the group's writes committed apart")
	}
}

// queueInOrder runs writes so that they queue in the order given and form
// one group: a holder write stays in its check phase, keeping the worker
// waiting, while each write is queued in turn, then queues last itself.
// It returns the results, the holder's last.
func queueInOrder(t *testing.T, e *Engine, writes []func() (*WriteResult, error)) ([]*WriteResult, []error) {
	t.Helper()
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	e.opt.BeforeWriteLock = func() {
		mu.Lock()
		calls++
		c := calls
		mu.Unlock()
		if c == 1 {
			<-release
		}
	}
	n := len(writes)
	res, errs := make([]*WriteResult, n+1), make([]error, n+1)
	var wg sync.WaitGroup
	wg.Add(n + 1)
	go func() {
		defer wg.Done()
		res[n], errs[n] = write(e, "n", "holder", "", 0)
	}()
	within(t, 5*time.Second, "the holder checks", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls == 1
	})
	for i, w := range writes {
		go func() {
			defer wg.Done()
			res[i], errs[i] = w()
		}()
		within(t, 5*time.Second, fmt.Sprint("write ", i, " queued"), func() bool { return queued(e, "n") == i+1 })
	}
	close(release)
	wg.Wait()
	return res, errs
}

// Writes of a group that write a resource an earlier write of the group
// writes are left out and answered alone; the others commit together, their
// entries in queue order. Here B1 writes y, B2 y and z, B3 z: B1 and B3
// commit, and B2 is answered 412.
func TestPGGroupCommitSharedResources(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	hy, err := put(e, "n", "y", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	hz, err := put(e, "n", "z", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := groupSizes(e)
	alone := e.groups.alone.Load()
	res, errs := queueInOrder(t, e, []func() (*WriteResult, error){
		func() (*WriteResult, error) { return write(e, "n", "y", hy, 1) },
		func() (*WriteResult, error) {
			r := who
			r.NS = "n"
			step := []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}}}}
			return e.Batch(context.Background(), r, []Item{{Resource: "y", IfMatch: hy, Steps: step}, {Resource: "z", IfMatch: hz, Steps: step}}, nil, nil, false)
		},
		func() (*WriteResult, error) { return write(e, "n", "z", hz, 3) },
	})
	if errs[0] != nil || errs[2] != nil || errs[3] != nil {
		t.Fatalf("writes: %v", errs)
	}
	if status(errs[1]) != 412 {
		t.Fatalf("B2: %v, want 412", errs[1])
	}
	if got := sizes(); len(got) != 1 || got[0] != 4 {
		t.Fatalf("group attempts %v, want one of 4", got)
	}
	if got := e.groups.alone.Load() - alone; got != 1 {
		t.Fatalf("%d writes answered alone, want 1", got)
	}
	xids := checkChain(t, e, "n")
	if xids[res[0].NSID] != xids[res[2].NSID] {
		t.Fatalf("B1 and B3 committed apart")
	}
	var s1, s3 int64
	for _, q := range []struct {
		id  string
		seq *int64
	}{{res[0].NSID, &s1}, {res[2].NSID, &s3}} {
		id, _ := ids.Parse(q.id)
		if err := e.db.QueryRow(`SELECT seq FROM ns_log WHERE id = $1`, id[:]).Scan(q.seq); err != nil {
			t.Fatal(err)
		}
	}
	if s1 >= s3 {
		t.Fatalf("B1's entry at %d, B3's at %d: not in queue order", s1, s3)
	}
}

// Two writes of one principal (root sub) under grants signed by different
// namespace keys, appended together: each entry records its own grant
// (§7.4), whose root kid merge tools and the janitor match against
// merge.authors (§F.3).
func TestPGGroupCommitKidPerWrite(t *testing.T) {
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.NewDB(t), BlobDir: t.TempDir(), OperatorKeys: ops, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: tailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	e.noSolo = true
	e.opt.GroupCommitWait = 5 * time.Second
	exp := time.Now().Add(time.Hour).Format(time.RFC3339)
	mint := func(priv ed25519.PrivateKey, root map[string]any) string {
		g, err := grant.Mint(root, priv)
		if err != nil {
			t.Fatal(err)
		}
		return g.Encode()
	}
	pub1, priv1 := grant.GenerateKey()
	pub2, priv2 := grant.GenerateKey()
	opG := mint(opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}, "exp": exp})
	can := []any{"read", "create", "append"}
	doc := map[string]any{"read": "public", "keys": []any{
		map[string]any{"kid": "k1", "alg": "ed25519", "pub": pub1, "can": can},
		map[string]any{"kid": "k2", "alg": "ed25519", "pub": pub2, "can": can},
	}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "n", Cred: Credentials{Bearer: opG}}, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
		t.Fatal(err)
	}
	grants := []string{
		mint(priv1, map[string]any{"kid": "k1", "sub": "svc:merge", "ns": []any{"n"}, "can": can, "exp": exp}),
		mint(priv2, map[string]any{"kid": "k2", "sub": "svc:merge", "ns": []any{"n"}, "can": can, "exp": exp}),
	}
	sizes := groupSizes(e)
	holdChecked(t, e, 2, nil)
	res, errs := concurrently(2, func(i int) (*WriteResult, error) {
		it := Item{Resource: fmt.Sprint("c", i), IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": float64(i)}}}}}}
		return e.WriteResource(context.Background(), Request{NS: "n", Cred: Credentials{Bearer: grants[i]}}, it)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("group attempts %v, want one of 2", got)
	}
	xids := checkChain(t, e, "n")
	if xids[res[0].NSID] != xids[res[1].NSID] {
		t.Fatalf("the writes committed apart")
	}
	for i, r := range res {
		var kid string
		id, _ := ids.Parse(r.NSID)
		if err := e.db.QueryRow(`SELECT g.root_kid FROM ns_log l JOIN grants g ON g.id = l.grant_id WHERE l.id = $1`, id[:]).Scan(&kid); err != nil {
			t.Fatal(err)
		}
		if want := []string{"k1", "k2"}[i]; kid != want {
			t.Errorf("write %d under a grant of %s recorded kid %s", i, want, kid)
		}
	}
}

// Writes that attach blobs (§7.8) are inserted with the group's others.
func TestPGGroupCommitBlobWrites(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	data := [][]byte{[]byte("hello blob"), []byte("hello blob 2")}
	bids := []string{uploadBlob(t, e, "n", "b0", data[0]), uploadBlob(t, e, "n", "b1", data[1])}
	sizes := groupSizes(e)
	alone := e.groups.alone.Load()
	holdChecked(t, e, 4, nil)
	res, errs := concurrently(4, func(i int) (*WriteResult, error) {
		if i < 2 {
			r := who
			r.NS = "n"
			doc := map[string]any{"b": map[string]any{"$blob": bids[i], "type": "text/plain", "size": float64(len(data[i]))}}
			it := Item{Resource: fmt.Sprint("b", i), IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}}}
			return e.WriteResource(context.Background(), r, it)
		}
		return write(e, "n", fmt.Sprint("c", i), "", i)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != 4 {
		t.Fatalf("group attempts %v, want one of 4", got)
	}
	if got := e.groups.alone.Load() - alone; got != 0 {
		t.Fatalf("%d writes answered alone, want none", got)
	}
	xids := checkChain(t, e, "n")
	for i, r := range res {
		if xids[r.NSID] != xids[res[0].NSID] {
			t.Fatalf("write %d committed apart", i)
		}
	}
	var refs, pending int
	if err := e.db.QueryRow(`SELECT (SELECT COUNT(*) FROM blob_refs WHERE to_seq IS NULL), (SELECT COUNT(*) FROM blob_pending)`).Scan(&refs, &pending); err != nil {
		t.Fatal(err)
	}
	if refs != 2 || pending != 0 {
		t.Fatalf("%d blob_refs and %d pending blobs, want 2 and 0", refs, pending)
	}
}

// A config change of a branch's base between a group's checks and its
// transaction: the branch writes' re-checks read the base, so each is
// answered alone, checked again against the new configuration (D.3).
func TestPGGroupCommitBaseConfigRace(t *testing.T) {
	e := groupEngine(t)
	cfg := mkNS(t, e, "n", map[string]any{"read": "public"})
	r := who
	r.NS = "n"
	if _, err := e.CreateBranch(context.Background(), r, BranchRequest{Name: "b"}); err != nil {
		t.Fatal(err)
	}
	sizes := groupSizes(e)
	alone := e.groups.alone.Load()
	holdChecked(t, e, 3, func() {
		change := map[string]any{"op": "add", "path": "/limits", "value": map[string]any{"documentSize": float64(1 << 20)}}
		if _, err := e.WriteConfig(context.Background(), r, ConfigChange{IfMatch: cfg, Patches: []any{change}}); err != nil {
			t.Error(err)
		}
	})
	_, errs := concurrently(3, func(i int) (*WriteResult, error) { return write(e, "b", fmt.Sprint("c", i), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != 3 {
		t.Fatalf("group attempts %v, want one of 3", got)
	}
	if got := e.groups.alone.Load() - alone; got != 3 {
		t.Fatalf("%d writes answered alone, want 3", got)
	}
	checkChain(t, e, "b")
}

// A write of a group answered alone doesn't draw its rate-limit tokens
// again: here each resource allows one write, and a config change between
// the checks and the group sends every write down its own path.
func TestPGGroupCommitAloneDrawsTokensOnce(t *testing.T) {
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast
	lim.RatePerResource = Rate{1e-9, 1}
	e, err := Open(Options{Path: pgtest.NewDB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: tailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	e.noSolo = true
	e.opt.GroupCommitWait = 5 * time.Second
	cfg := mkNS(t, e, "n", map[string]any{"read": "public"})
	alone := e.groups.alone.Load()
	holdChecked(t, e, 3, func() {
		r := who
		r.NS = "n"
		change := map[string]any{"op": "add", "path": "/limits", "value": map[string]any{"documentSize": float64(1 << 20)}}
		if _, err := e.WriteConfig(context.Background(), r, ConfigChange{IfMatch: cfg, Patches: []any{change}}); err != nil {
			t.Error(err)
		}
	})
	_, errs := concurrently(3, func(i int) (*WriteResult, error) { return write(e, "n", fmt.Sprint("c", i), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := e.groups.alone.Load() - alone; got != 3 {
		t.Fatalf("%d writes answered alone, want 3", got)
	}
	// The bucket is empty now.
	if _, err := write(e, "n", "c0", "", 9); status(err) != 429 {
		t.Fatalf("a second write of c0: %v, want 429", err)
	}
}

// A write cancelled while queued is never written, and its namespace's
// state is dropped once idle.
func TestPGGroupCommitCancelQueued(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	e.opt.BeforeWriteLock = func() {
		mu.Lock()
		calls++
		c := calls
		mu.Unlock()
		if c == 1 {
			<-release
		}
	}
	holder := make(chan error, 1)
	go func() {
		_, err := put(e, "n", "b", "", 2)
		holder <- err
	}()
	within(t, 5*time.Second, "the holder checks", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls == 1
	})
	ctx, cancel := context.WithCancel(context.Background())
	queuedErr := make(chan error, 1)
	go func() {
		_, err := writeCtx(ctx, e, "n", "a", 1)
		queuedErr <- err
	}()
	within(t, 5*time.Second, "the write queues", func() bool { return queued(e, "n") == 1 })
	cancel()
	if err := <-queuedErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled write: %v", err)
	}
	close(release)
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if xids := checkChain(t, e, "n"); len(xids) != 2 {
		t.Fatalf("%d entries, want 2", len(xids))
	}
	within(t, 5*time.Second, "the namespace's state is dropped", func() bool { return idle(e) })
}

// A group's transaction waiting for a lock (here its namespace's, held
// exclusively elsewhere) goes on while some of its requests are cancelled,
// and stops waiting once all are: nothing is written, every request returns
// its cancellation, and the namespace's state is dropped.
func TestPGGroupCommitCancelBlockedGroup(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	release := holdLock(t, e, lockClass, lockKey(nsIDOf(t, e, "n")))
	const n = 3
	ctxs, cancels := make([]context.Context, n), make([]context.CancelFunc, n)
	errs := make([]chan error, n)
	sizes := groupSizes(e)
	holdChecked(t, e, n, nil)
	for i := range n {
		ctxs[i], cancels[i] = context.WithCancel(context.Background())
		errs[i] = make(chan error, 1)
		go func() {
			_, err := writeCtx(ctxs[i], e, "n", fmt.Sprint("c", i), i)
			errs[i] <- err
		}()
	}
	within(t, 5*time.Second, "the group waits for the lock", func() bool { return waiting(e) > 0 })
	cancels[0]()
	cancels[1]()
	select {
	case err := <-errs[0]:
		t.Fatalf("a write of the group returned before the group did: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancels[2]()
	for i := range n {
		select {
		case err := <-errs[i]:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("write %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("write %d still waits for the lock after every request was cancelled", i)
		}
	}
	release()
	if got := sizes(); len(got) != 0 {
		t.Fatalf("group attempts %v, want none past the lock", got)
	}
	if xids := checkChain(t, e, "n"); len(xids) != 1 {
		t.Fatalf("%d entries, want 1 (nothing written)", len(xids))
	}
	within(t, 5*time.Second, "the namespace's state is dropped", func() bool { return idle(e) })
}

// A request cancelled after its group formed still gets the group's
// outcome: the group isn't cancelled while another of its requests isn't.
func TestPGGroupCommitCancelOneOfGroup(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	release := holdLock(t, e, lockClass, lockKey(nsIDOf(t, e, "n")))
	ctx, cancel := context.WithCancel(context.Background())
	holdChecked(t, e, 2, nil)
	res, errs := make([]*WriteResult, 2), make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := context.Background()
			if i == 0 {
				c = ctx
			}
			res[i], errs[i] = writeCtx(c, e, "n", fmt.Sprint("c", i), i)
		}()
	}
	within(t, 5*time.Second, "the group waits for the lock", func() bool { return waiting(e) > 0 })
	cancel()
	time.Sleep(100 * time.Millisecond)
	release()
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	xids := checkChain(t, e, "n")
	if len(xids) != 3 || xids[res[0].NSID] != xids[res[1].NSID] {
		t.Fatalf("entries %v: want both writes in one transaction", xids)
	}
}

// A group whose COMMIT fails (a deferred trigger raising once): every write
// is answered alone and commits once.
func TestPGGroupCommitFailedCommit(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	for _, q := range []string{
		`CREATE SEQUENCE failseq`,
		`CREATE FUNCTION failonce() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('failseq') = 1 THEN RAISE EXCEPTION 'injected commit failure'; END IF; RETURN NULL; END $$`,
		`CREATE CONSTRAINT TRIGGER failonce AFTER INSERT ON ns_log DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION failonce()`,
	} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	alone := e.groups.alone.Load()
	const n = 4
	holdChecked(t, e, n, nil)
	res, errs := concurrently(n, func(i int) (*WriteResult, error) { return write(e, "n", fmt.Sprint("c", i), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if res[i].Status != 201 {
			t.Fatalf("write %d: %+v", i, res[i])
		}
	}
	if got := e.groups.alone.Load() - alone; got != n {
		t.Fatalf("%d writes answered alone, want %d", got, n)
	}
	if xids := checkChain(t, e, "n"); len(xids) != 1+n {
		t.Fatalf("%d entries, want %d", len(xids), 1+n)
	}
}

// A panic (not an error) inside the group's transaction doesn't stop the
// worker: every write is answered alone, and the state is dropped after.
func TestPGGroupCommitPanicInGroup(t *testing.T) {
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	var once sync.Once
	e.groupStart = func(t *tx, size int) {
		once.Do(func() { panic("injected") })
	}
	alone := e.groups.alone.Load()
	const n = 3
	holdChecked(t, e, n, nil)
	_, errs := concurrently(n, func(i int) (*WriteResult, error) { return write(e, "n", fmt.Sprint("c", i), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := e.groups.alone.Load() - alone; got != n {
		t.Fatalf("%d writes answered alone, want %d", got, n)
	}
	if xids := checkChain(t, e, "n"); len(xids) != 1+n {
		t.Fatalf("%d entries, want %d", len(xids), 1+n)
	}
	within(t, 5*time.Second, "the namespace's state is dropped", func() bool { return idle(e) })
}

// A BeforeWriteLock hook that panics, on a write in its check phase or on
// one on its own, leaves no namespace counted busy.
func TestPGGroupCommitHookPanic(t *testing.T) {
	for _, solo := range []bool{false, true} {
		t.Run(fmt.Sprint("solo=", solo), func(t *testing.T) {
			e := groupEngine(t)
			e.noSolo = !solo
			e.opt.LockedCheckBytes = -1 // a write on its own checks outside the lock, and calls the hook
			mkNS(t, e, "n", map[string]any{"read": "public"})
			e.opt.BeforeWriteLock = func() { panic("injected") }
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("the hook didn't panic")
					}
				}()
				write(e, "n", "c", "", 1)
			}()
			if !idle(e) {
				t.Fatal("the namespace is still counted busy")
			}
			e.opt.BeforeWriteLock = nil
			if _, err := write(e, "n", "c", "", 1); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Writes taken from a namespace's queue, or removed from it, leave its
// array too, so they aren't kept reachable once answered.
func TestGroupQueueReleasesWrites(t *testing.T) {
	s := &nsGroup{}
	ws := make([]*groupWrite, 5)
	for i := range ws {
		ws[i] = &groupWrite{}
		s.queue = append(s.queue, ws[i])
	}
	if got := s.take(2); len(got) != 2 || got[0] != ws[0] || got[1] != ws[1] {
		t.Fatalf("took %v", got)
	}
	if !s.remove(ws[3]) || s.remove(ws[3]) {
		t.Fatal("remove")
	}
	if len(s.queue) != 2 || s.queue[0] != ws[2] || s.queue[1] != ws[4] {
		t.Fatalf("queue %v", s.queue)
	}
	for i, w := range s.queue[len(s.queue):cap(s.queue)] {
		if w != nil {
			t.Fatalf("the queue's array still holds a write past its end, at %d", len(s.queue)+i)
		}
	}
}
