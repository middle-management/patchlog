package core

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"
)

// Group commit per namespace (Addendum D.8, "Contention"), on Postgres.
//
// A namespace's entries are appended one at a time under its log lock,
// held through commit (pglock.go), so a namespace takes about one write
// per log append and WAL flush, and writers queueing on the lock add a
// hand-over each. Instead an instance queues the checked resource writes
// and batches (without a config change) of each namespace, and one
// transaction appends several of them, then commits once:
//
//   - Each write runs steps 1–6 of §6.2 first, on its own, in a read
//     transaction outside any lock (D.3, recheck.go), and is queued with
//     its plan and what the check read (writeDeps). Config writes, purges,
//     prunes, branch writes and batches that change the configuration
//     never take this path.
//   - A worker per namespace with a queue takes up to GroupCommit queued
//     writes, waiting at most GroupCommitWait for writes of the namespace
//     still in their check phase. Its transaction takes, in ascending
//     order and all shared, the namespace locks of everything the group's
//     checks read, then appends the writes in queue order, as if each were
//     under a savepoint of its own: the D.3 re-check, the insert and the
//     namespace entry. An entry is computed from the one before it, at the
//     chain's head as of the log lock, since its id covers the entry
//     before it (§3.5). The log lock is taken at the first append and held
//     through the commit, which flushes once for the whole group.
//   - Appending them literally one by one costs a dozen statements a write,
//     one after another in one transaction, which on a fast disk costs
//     more than the flushes saved. So the writes of distinct resources are
//     re-checked first and appended together, with one statement per table
//     (appendGroup), which has the same outcome; the others, and all of
//     them if that loses a race to insert, are appended one by one, each
//     under its savepoint (appendGrouped).
//   - A write whose re-check fails, because its resource's head moved (an
//     earlier write of the group, another instance) or because the
//     configuration or anything else its check read changed, or that loses
//     a race to insert (isConflict), rolls back to its savepoint and is
//     answered alone once the group has committed: on the path a write
//     takes without group commit, with its rate-limit tokens already
//     drawn, so it finds the idempotent retry (§7.2) if the same write
//     committed, answers 412 with the new head, or is checked again against
//     the new configuration (D.3). The other writes are unaffected.
//   - An error that aborts the whole transaction (a deadlock, 40P01, a
//     serialization failure, locks needed out of order) retries the whole
//     group (update1). One that persists, or any other, sends every write
//     of the group down the path it takes alone, so no write is refused
//     for another's failure.
//   - Every write is answered after the group's commit, and caches, live
//     readers and CDN purges learn of the group's writes only then, as of
//     any commit (updateOnce).
//
// While no group of a namespace is queued or committing on this instance,
// up to soloWrites of its writes take the path they take without group
// commit, checked inside the namespace's lock, which costs fewer round
// trips; writes beyond those queue. So a few writers see no difference,
// groups form only once writers contend, and GroupCommit 1 turns group
// commit off.

// Group commit defaults (Options.GroupCommit, GroupCommitWait).
const (
	defaultGroupCommit     = 32
	defaultGroupCommitWait = 200 * time.Microsecond
	// soloWrites is how many writes of a namespace may run on their own
	// at once on this instance, while no group is queued or committing.
	soloWrites = 4
)

// groupWrite is a checked write waiting in its namespace's queue.
type groupWrite struct {
	ctx     context.Context
	req     Request
	items   []Item
	source  any
	isBatch bool
	plan    *writePlan
	deps    *writeDeps
	// Set by the worker before done is closed: the write's result, or
	// alone if it must be answered on its own (above).
	res   *WriteResult
	alone bool
	done  chan struct{}
}

// nsGroup is a namespace's group-commit state on this instance.
type nsGroup struct {
	// worker: a worker runs. solo counts writes that found the namespace
	// idle and run on their own, checking those in their check phase; a
	// worker waits a little for either.
	worker         bool
	solo, checking int
	queue          []*groupWrite
	wake           chan struct{} // nudges a waiting worker
}

// groups is the engine's group-commit state, per namespace name.
type groups struct {
	mu sync.Mutex
	ns map[string]*nsGroup
	// Counters (tests, benchmarks): groups committed, writes appended in
	// them, and writes answered alone after their group.
	committed, appended, alone atomic.Int64
}

// grouping reports whether resource writes and batches use group commit.
func (e *Engine) grouping() bool { return e.pg && e.opt.GroupCommit > 1 }

// get returns ns's state, creating it. Callers hold g.mu.
func (g *groups) get(ns string) *nsGroup {
	if g.ns == nil {
		g.ns = map[string]*nsGroup{}
	}
	s := g.ns[ns]
	if s == nil {
		s = &nsGroup{wake: make(chan struct{}, 1)}
		g.ns[ns] = s
	}
	return s
}

// tidy forgets an idle namespace's state. Callers hold g.mu.
func (g *groups) tidy(ns string, s *nsGroup) {
	if !s.worker && s.solo == 0 && s.checking == 0 && len(s.queue) == 0 {
		delete(g.ns, ns)
	}
}

func (s *nsGroup) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// writeGrouped is writeOptimistic with group commit.
func (e *Engine) writeGrouped(ctx context.Context, req Request, items []Item, source any, isBatch bool) (*WriteResult, error) {
	g := &e.groups
	g.mu.Lock()
	s := g.get(req.NS)
	if !s.worker && s.solo < soloWrites && len(s.queue) == 0 && !e.noSolo {
		// No group of the namespace here: the path without group commit.
		// Writes beyond soloWrites queue, and their worker doesn't wait for
		// this one longer than GroupCommitWait (a BeforeWriteLock hook may
		// write to the namespace itself).
		s.solo++
		g.mu.Unlock()
		res, err := e.writeAlone(ctx, req, items, source, isBatch, false, 0)
		g.mu.Lock()
		s.solo--
		s.nudge()
		g.tidy(req.NS, s)
		g.mu.Unlock()
		return res, err
	}
	s.checking++
	g.mu.Unlock()

	plan, deps, res, err := e.checkOutside(ctx, req, items, source, isBatch, false)
	if err != nil || res != nil {
		g.mu.Lock()
		s.checking--
		s.nudge()
		g.tidy(req.NS, s)
		g.mu.Unlock()
		return res, err
	}
	if h := e.opt.BeforeWriteLock; h != nil {
		h()
	}
	w := &groupWrite{ctx: ctx, req: req, items: items, source: source, isBatch: isBatch, plan: plan, deps: deps, done: make(chan struct{})}
	g.mu.Lock()
	s.checking--
	s.queue = append(s.queue, w)
	s.nudge()
	e.startWorker(req.NS, s)
	g.mu.Unlock()

	select {
	case <-w.done:
	case <-ctx.Done():
		g.mu.Lock()
		for i, q := range s.queue {
			if q == w {
				// Not taken into a group yet: never written.
				s.queue = append(s.queue[:i], s.queue[i+1:]...)
				g.tidy(req.NS, s)
				g.mu.Unlock()
				return nil, ctx.Err()
			}
		}
		g.mu.Unlock()
		// In a group already: it commits or not, and is cancelled once all
		// of its writes are. Its outcome is this write's.
		<-w.done
	}
	if w.alone {
		g.alone.Add(1)
		return e.writeAlone(ctx, req, items, source, isBatch, true, 1)
	}
	return w.res, nil
}

// startWorker starts ns's worker if writes are queued and none runs.
// Callers hold g.mu.
func (e *Engine) startWorker(ns string, s *nsGroup) {
	if s.worker || len(s.queue) == 0 {
		return
	}
	s.worker = true
	go e.groupWorker(ns, s)
}

// groupWorker commits ns's queued writes, group after group, until the
// queue is empty.
func (e *Engine) groupWorker(ns string, s *nsGroup) {
	g := &e.groups
	limit, wait := e.opt.GroupCommit, e.opt.GroupCommitWait
	for {
		g.mu.Lock()
		if len(s.queue) == 0 {
			s.worker = false
			g.tidy(ns, s)
			g.mu.Unlock()
			return
		}
		// Writes still in their check phase join this group if they are
		// done within the wait, and a write on its own may commit first.
		if wait > 0 && len(s.queue) < limit && s.checking+s.solo > 0 {
			timer := time.NewTimer(wait)
			for waiting := true; waiting && len(s.queue) < limit && s.checking+s.solo > 0; {
				g.mu.Unlock()
				select {
				case <-s.wake:
				case <-timer.C:
					waiting = false
				}
				g.mu.Lock()
			}
			timer.Stop()
		}
		n := min(len(s.queue), limit)
		if n == 0 {
			// Its writes were cancelled while it waited.
			g.mu.Unlock()
			continue
		}
		group := append([]*groupWrite(nil), s.queue[:n]...)
		s.queue = append(s.queue[:0], s.queue[n:]...)
		g.mu.Unlock()
		e.commitGroup(ns, group)
		for _, w := range group {
			close(w.done)
		}
	}
}

// commitGroup appends a group of checked writes in one transaction
// (above). On return each write has its result, or is marked alone.
func (e *Engine) commitGroup(ns string, group []*groupWrite) {
	// No single request's cancellation aborts the group, but once every
	// one of its requests is cancelled (a shutdown timeout), so is it.
	ctx, cancel := context.WithCancel(context.WithoutCancel(group[0].ctx))
	defer cancel()
	var left atomic.Int64
	left.Store(int64(len(group)))
	for _, w := range group {
		stop := context.AfterFunc(w.ctx, func() {
			if left.Add(-1) == 0 {
				cancel()
			}
		})
		defer stop()
	}
	together := true
	f := func(t *tx) error {
		// A whole-group retry starts over.
		for _, w := range group {
			w.res, w.alone = nil, false
		}
		t.logHeads = map[int64]logHead{}
		want := map[int32]lockMode{}
		for _, w := range group {
			want[lockKey(w.plan.n.id)] = lockShared
			for id := range w.deps.ns {
				want[lockKey(id)] = lockShared
			}
		}
		t.lockAll(want)
		if t.locking() {
			t.sharedNS = group[0].plan.n.id
		}
		if h := e.afterWriteLock; h != nil {
			h(ns)
		}
		if h := e.groupStart; h != nil {
			h(t, len(group))
		}
		if len(group) == 1 {
			// No savepoint: a write that must be answered alone rolls the
			// whole transaction back.
			t.appendGrouped(group[0], 0, false, nil)
			return nil
		}
		t.appendGroup(group, together)
		return nil
	}
	err := e.update(ctx, f)
	if errors.Is(err, errApart) {
		together = false
		err = e.update(ctx, f)
	}
	if err != nil {
		// Not committed, or not known to be: every write is answered
		// alone, which finds the ones that did commit (§7.2).
		for _, w := range group {
			w.res, w.alone = nil, true
		}
		return
	}
	n := int64(0)
	for _, w := range group {
		if !w.alone {
			n++
		}
	}
	if n > 0 {
		e.groups.committed.Add(1)
		e.groups.appended.Add(n)
	}
}

// appendGroup appends the writes of a group of several, in the group's
// transaction with its locks held.
//
// Writing them one by one, each re-checked and inserted under a savepoint
// of its own (appendGrouped), costs a dozen statements a write, one after
// another in one transaction. So the writes are re-checked first, sharing
// what they read, and those that pass and write resources no other write
// of the group writes are inserted together, with one statement per table
// as a batch's items are (insertItemsBy); then their entries are appended
// in queue order, each computed from the one before it (appendNSMany).
// That has the outcome of appending them one by one: writes of distinct
// resources don't change what each other's re-checks read, and rows go in
// resource order whatever write they belong to (insertItems). If that
// fails, as when another instance moved one of the heads, the whole
// transaction runs again with together unset, appending every write one
// by one. The writes left (sharing a resource with an earlier one, or
// referencing blobs, whose rows writes may share) are appended one by one
// after them.
func (t *tx) appendGroup(group []*groupWrite, together bool) {
	target := group[0].plan.n.id
	var names []string
	for _, w := range group {
		if w.plan.n.id == target {
			for _, s := range w.plan.st {
				names = append(names, s.Resource)
			}
		}
	}
	t.prefetchResources(target, names)
	// The heads the checks found: revision rows don't change, and a
	// re-check compares only which one is the head (sameView).
	if t.memo.rev == nil {
		t.memo.rev = map[int64]revRow{}
	}
	for _, w := range group {
		for _, s := range w.plan.st {
			if h := s.view.head; h != nil {
				t.memo.rev[h.seq] = *h
				t.knowRevID(h.seq, h.id)
			}
		}
	}
	nss := map[int64]*nsRow{}
	var joint, apart []*groupWrite
	taken := map[string]bool{}
	for _, w := range group {
		n, ok := t.recheckIn(w.plan, w.deps, nss)
		if !ok {
			w.alone = true
			continue
		}
		w.plan.n = n
		if !together || n.id != target || !distinct(w, taken) || referencesBlobs(w) {
			apart = append(apart, w)
			continue
		}
		joint = append(joint, w)
	}
	if len(joint) > 0 {
		t.appendTogether(joint)
	}
	for i, w := range apart {
		if !t.appendGrouped(w, i, true, nss) {
			w.alone = true
		}
	}
}

// distinct reports whether none of w's resources is in taken, and if so
// adds them.
func distinct(w *groupWrite, taken map[string]bool) bool {
	for _, s := range w.plan.st {
		if taken[s.Resource] {
			return false
		}
	}
	for _, s := range w.plan.st {
		taken[s.Resource] = true
	}
	return true
}

// referencesBlobs reports whether a write attaches blobs (§7.8).
func referencesBlobs(w *groupWrite) bool {
	for _, s := range w.plan.st {
		for _, step := range s.steps {
			if len(step.blobs) > 0 || len(step.declared) > 0 || step.keepsList {
				return true
			}
		}
	}
	return false
}

// errApart rolls back a group's transaction whose writes, inserted
// together, lost a race to insert: it runs again appending them one by one
// (appendGroup).
var errApart = errors.New("group commit: a write lost a race to insert; appending one by one")

// appendTogether inserts re-checked writes of distinct resources of one
// namespace together, then appends their entries in order (appendGroup).
func (t *tx) appendTogether(ws []*groupWrite) {
	defer func() {
		if p := recover(); p != nil {
			if err, _ := p.(error); err != nil && isConflict(err) {
				panic(errApart)
			}
			panic(p)
		}
	}()
	n := ws[0].plan.n
	authors := make([]int64, len(ws))
	var st []*itemState
	var by []writer
	stored := map[string]bool{}
	for i, w := range ws {
		a := w.plan.a
		authors[i] = t.actorID(a)
		var grantID []byte
		if a.grant != nil {
			// Each grant once.
			id := a.grant.ID()
			if grantID = id[:]; !stored[string(grantID)] {
				stored[string(grantID)] = true
				t.storeGrant(n, a)
			}
		}
		wr := writtenBy(a, authors[i], grantID, w.req.Signature)
		for _, s := range w.plan.st {
			st, by = append(st, s), append(by, wr)
		}
	}
	inserted := t.insertItemsBy(n, st, by)
	as := make([]nsAppend, len(ws))
	for i, w := range ws {
		if h := t.e.groupMember; h != nil {
			h(t, i)
		}
		k := len(w.plan.st)
		as[i] = t.planEntry(w.plan, authors[i], nil, inserted[:k])
		inserted = inserted[k:]
	}
	nsIDs := t.appendNSMany(n, n.configSeq, as)
	for i, w := range ws {
		w.plan.result.NSID = nsIDs[i].String()
		w.res = w.plan.result
	}
}

// appendGrouped re-checks and inserts one write of a group, under a
// savepoint if savepoint is set, and reports false if it rolled back to
// it: the write must be answered alone. Without a savepoint, such a write
// fails the whole transaction instead. An error that aborts the whole
// transaction panics on, to retry or fail the group. nss is as in
// recheckIn.
func (t *tx) appendGrouped(w *groupWrite, i int, savepoint bool, nss map[int64]*nsRow) (ok bool) {
	sp := fmt.Sprintf("g%d", i)
	var m txMark
	if savepoint {
		m = t.mark()
		_, err := t.Tx.Exec(`SAVEPOINT ` + sp)
		t.must(err)
	}
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		err, _ := p.(error)
		if err == nil || !savepoint || !(errors.Is(err, errRecheck) || isConflict(err)) {
			panic(p)
		}
		_, rerr := t.Tx.Exec(`ROLLBACK TO SAVEPOINT ` + sp)
		t.must(rerr)
		t.undo(m)
		ok = false
	}()
	if h := t.e.groupMember; h != nil {
		h(t, i)
	}
	n, good := t.recheckIn(w.plan, w.deps, nss)
	if !good {
		panic(errRecheck)
	}
	w.plan.n = n
	res := t.insertPlan(w.req, w.plan)
	if savepoint {
		_, err := t.Tx.Exec(`RELEASE SAVEPOINT ` + sp)
		t.must(err)
	}
	w.res = res
	return true
}

// txMark is what a transaction has done in memory up to a savepoint, so
// rolling back to it forgets what came after (appendGrouped).
type txMark struct {
	notify                    map[string]bool
	tags, docPuts, rotate     int
	newFiles, dropFiles       int
	lastNS                    int64
	flushDocs, metaChanged    bool
	flushDEKs, flushEpochKeys bool
	ownRevs                   map[int64]revRow
	kids                      map[int64]string
	newDEKs                   map[int64][]byte
	resLevels                 map[int64]int
	shadowLevels              map[string]int
	newEpochKeys              map[epochRef][]byte
	locks                     map[int32]lockMode
	maxKey, maxLogKey         int32
	logLocks, logPlan         map[int32]bool
	logHeads                  map[int64]logHead
	sharedNS                  int64
}

func (t *tx) mark() txMark {
	return txMark{
		notify: maps.Clone(t.notify), tags: len(t.tags), docPuts: len(t.docPuts), rotate: len(t.rotate),
		newFiles: len(t.newFiles), dropFiles: len(t.dropFiles), lastNS: t.lastNS,
		flushDocs: t.flushDocs, metaChanged: t.metaChanged, flushDEKs: t.flushDEKs, flushEpochKeys: t.flushEpochKeys,
		ownRevs: maps.Clone(t.ownRevs), kids: maps.Clone(t.kids), newDEKs: maps.Clone(t.newDEKs),
		resLevels: maps.Clone(t.resLevels), shadowLevels: maps.Clone(t.shadowLevels), newEpochKeys: maps.Clone(t.newEpochKeys),
		locks: maps.Clone(t.locks), maxKey: t.maxKey, maxLogKey: t.maxLogKey,
		logLocks: maps.Clone(t.logLocks), logPlan: maps.Clone(t.logPlan), logHeads: maps.Clone(t.logHeads), sharedNS: t.sharedNS,
	}
}

// undo returns a transaction to a mark after ROLLBACK TO SAVEPOINT, which
// also released the advisory locks taken since (they are held again, or
// tried, when next needed).
func (t *tx) undo(m txMark) {
	t.notify = m.notify
	if t.notify == nil {
		t.notify = map[string]bool{}
	}
	t.tags, t.docPuts, t.rotate = t.tags[:m.tags], t.docPuts[:m.docPuts], t.rotate[:m.rotate]
	t.e.removeFiles(t.newFiles[m.newFiles:])
	t.newFiles, t.dropFiles = t.newFiles[:m.newFiles], t.dropFiles[:m.dropFiles]
	t.lastNS = m.lastNS
	t.flushDocs, t.metaChanged, t.flushDEKs, t.flushEpochKeys = m.flushDocs, m.metaChanged, m.flushDEKs, m.flushEpochKeys
	t.ownRevs, t.kids, t.newDEKs = m.ownRevs, m.kids, m.newDEKs
	t.resLevels, t.shadowLevels, t.newEpochKeys = m.resLevels, m.shadowLevels, m.newEpochKeys
	t.locks, t.maxKey, t.maxLogKey = m.locks, m.maxKey, m.maxLogKey
	t.logLocks, t.logPlan, t.logHeads, t.sharedNS = m.logLocks, m.logPlan, m.logHeads, m.sharedNS
	// Rows read since may be ones the savepoint took back.
	t.revIDs = nil
	t.forget()
}
