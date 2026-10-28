package ddbstore

// Group commit per namespace (docs/DYNAMODB.md §4, §11): the DynamoDB
// counterpart of internal/core's groupcommit.go.
//
// Concurrent writers of one namespace all condition their transaction on
// the namespace's #TIP, so ungrouped they collide and retry, and the
// collisions degenerate as writers are added (§11: 167/s at 8 writers,
// 82/s at 32). Postgres queues writers on its log lock instead; here an
// instance queues them itself, and one transaction appends several:
//
//   - Each write is checked on its own, outside any queue (core's gate),
//     and its decision, a Commit, is queued. Commits with a config change
//     don't queue: they take the namespace's commit lock instead, which
//     the worker holds through each group's commit. With GroupCommit ≤ 1
//     every write commits on its own.
//   - A worker per namespace with a queue takes the queued commits that
//     fit one transaction: at most GroupCommit of them, within the 100
//     actions and a byte budget under the 4 MB transaction cap, of
//     resources no earlier commit of the group writes, checked under the
//     same configuration as the group's first. The others stay queued, in
//     order, for the next group.
//   - The worker chains the group's entries over the tip it knows (an
//     entry's id covers the entry before it, §3.5, but nothing a check
//     read), at consecutive positions, and commits every commit's actions
//     — each pinning its heads and the configuration, as on its own — and
//     one tip move.
//   - A cancelled group sorts its failures: a commit whose own conditions
//     failed (a head or the configuration moved) is answered ErrStale, to
//     be checked again (D.3), and the rest commit again without it; a
//     moved tip (another instance) is re-read and the group re-chained; a
//     failure that isn't a cancellation is every commit's answer.
//
// The worker starts with the first queued commit and takes, after each
// group, whatever queued meanwhile: one writer waits only for a goroutine
// hand-off, and groups form as writers contend.

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/middle-management/patchlog/internal/ddb"
)

// groupBytes bounds a group's bytes (documents and patch sets), under
// DynamoDB's 4 MB aggregate per transaction. A group's first commit is
// always taken: one that doesn't fit fails as it would on its own.
const groupBytes = 3 << 20

// groupMember is a commit waiting in its namespace's queue.
type groupMember struct {
	ctx context.Context
	c   *ddb.Commit
	// Set by the worker before done is closed.
	res  *ddb.CommitResult
	err  error
	done chan struct{}
}

func (w *groupMember) names() []string {
	out := make([]string, len(w.c.Items))
	for i, it := range w.c.Items {
		out[i] = it.Name
	}
	return out
}

// nsLock is a namespace's commit lock on this instance: its group worker
// holds it through each group's commit, and commits that don't queue (a
// config change's) through theirs, so they don't race the worker for the
// tip.
type nsLock struct {
	mu   sync.Mutex
	refs int
}

// serialize takes ns's commit lock and returns its release; when not
// grouping there is none to take.
func (s *Store) serialize(ns string) func() {
	if !s.grouping() {
		return nil
	}
	g := &s.g
	g.mu.Lock()
	if g.locks == nil {
		g.locks = map[string]*nsLock{}
	}
	l := g.locks[ns]
	if l == nil {
		l = &nsLock{}
		g.locks[ns] = l
	}
	l.refs++
	g.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		g.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(g.locks, ns)
		}
		g.mu.Unlock()
	}
}

func release(unlock func()) {
	if unlock != nil {
		unlock()
	}
}

// nsQueue is a namespace's group-commit state on this instance.
type nsQueue struct {
	worker bool
	queue  []*groupMember
	tip    *tip // the tip as of this worker's last commit
}

// groups is a Store's group-commit state, per namespace.
type groups struct {
	mu    sync.Mutex
	ns    map[string]*nsQueue
	locks map[string]*nsLock
	// Counters (tests, benchmarks): groups committed and commits appended
	// in them.
	committed, appended atomic.Int64
	// tips are the tips this instance last committed, by namespace
	// (startTip): a namespace's next commit chains over them first.
	tipMu sync.Mutex
	tips  map[string]tip
}

// committedTip remembers t as ns's tip after a commit of this instance.
func (s *Store) committedTip(ns string, t tip) {
	g := &s.g
	g.tipMu.Lock()
	defer g.tipMu.Unlock()
	if g.tips == nil || len(g.tips) >= 4096 {
		g.tips = map[string]tip{}
	}
	if cur, ok := g.tips[ns]; !ok || t.headPos > cur.headPos {
		g.tips[ns] = t
	}
}

// startTip is the tip a commit of ns chains over first: the newest of
// the one this instance last committed and those its commits' checks
// read (Commit.TipPos), nil if neither is known. A check reads the tip
// before it commits, and another write of this instance may have
// committed since: chaining over the check's then cancels the
// transaction, the tip is read and it runs again. The tip's condition
// decides either way; another instance's commit is found by it.
func (s *Store) startTip(ns string, cs ...*ddb.Commit) *tip {
	var t *tip
	s.g.tipMu.Lock()
	if cur, ok := s.g.tips[ns]; ok {
		t = &cur
	}
	s.g.tipMu.Unlock()
	for _, c := range cs {
		if h := hintedTip(c); h != nil && (t == nil || h.headPos > t.headPos) {
			t = h
		}
	}
	return t
}

// GroupStats reports how many groups committed and how many commits they
// appended.
func (s *Store) GroupStats() (groups, writes int64) {
	return s.g.committed.Load(), s.g.appended.Load()
}

func (s *Store) grouping() bool { return s.GroupCommit > 1 }

// commitGrouped queues a commit and waits for its group.
func (s *Store) commitGrouped(ctx context.Context, c *ddb.Commit) (*ddb.CommitResult, error) {
	w := &groupMember{ctx: ctx, c: c, done: make(chan struct{})}
	g := &s.g
	g.mu.Lock()
	if g.ns == nil {
		g.ns = map[string]*nsQueue{}
	}
	q := g.ns[c.NS]
	if q == nil {
		q = &nsQueue{}
		g.ns[c.NS] = q
	}
	q.queue = append(q.queue, w)
	if !q.worker {
		q.worker = true
		go s.groupWorker(c.NS, q)
	}
	g.mu.Unlock()

	select {
	case <-w.done:
	case <-ctx.Done():
		g.mu.Lock()
		if i := slices.Index(q.queue, w); i >= 0 {
			// Not taken into a group yet: never written.
			q.queue = slices.Delete(q.queue, i, i+1)
			g.mu.Unlock()
			return nil, ctx.Err()
		}
		g.mu.Unlock()
		// In a group already: its outcome is this commit's.
		<-w.done
	}
	return w.res, w.err
}

// groupWorker commits ns's queued commits, group after group, until the
// queue is empty.
func (s *Store) groupWorker(ns string, q *nsQueue) {
	g := &s.g
	for {
		g.mu.Lock()
		if len(q.queue) == 0 {
			q.worker = false
			delete(g.ns, ns)
			g.mu.Unlock()
			return
		}
		group := q.take(s.GroupCommit)
		g.mu.Unlock()
		unlock := s.serialize(ns)
		q.tip = s.commitGroup(ns, group, q.tip)
		unlock()
		for _, w := range group {
			close(w.done)
		}
	}
}

// take removes the queued commits that fit one group (above) and returns
// them; the others keep their order. Callers hold the groups' lock.
func (q *nsQueue) take(limit int) []*groupMember {
	first := q.queue[0]
	group := []*groupMember{first}
	acts, size := txShared+commitTxActions(first.c), commitBytes(first.c)
	names := map[string]bool{}
	for _, n := range first.names() {
		names[n] = true
	}
	pins := map[string]ddb.NSPin{}
	for _, p := range first.c.Pins {
		pins[p.NS] = p
	}
	rest := q.queue[:0:0]
	for _, w := range q.queue[1:] {
		fits := len(group) < limit && w.c.CfgPos == first.c.CfgPos &&
			acts+commitTxActions(w.c) <= maxTxActions && size+commitBytes(w.c) <= groupBytes &&
			pinsAgree(pins, w.c.Pins)
		for _, n := range w.names() {
			fits = fits && !names[n]
		}
		if fits {
			for _, p := range w.c.Pins {
				pins[p.NS] = p
			}
			group = append(group, w)
			acts, size = acts+commitTxActions(w.c), size+commitBytes(w.c)
			for _, n := range w.names() {
				names[n] = true
			}
			continue
		}
		rest = append(rest, w)
	}
	// A fresh array, so answered commits aren't kept reachable.
	q.queue = rest
	return group
}

// commitGroup commits a group in one transaction (above), and returns the
// tip it leaves (nil if unknown). On return each member has its result
// or error. known is the tip as of the worker's last commit, if any.
func (s *Store) commitGroup(ns string, group []*groupMember, known *tip) *tip {
	// No single request's cancellation aborts the group.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(group[0].ctx), 30*time.Second)
	defer cancel()

	fail := func(ws []*groupMember, err error) *tip {
		for _, w := range ws {
			w.err = err
		}
		return nil
	}
	live := group
	t := known
	if t == nil {
		cs := make([]*ddb.Commit, len(group))
		for i, w := range group {
			cs[i] = w.c
		}
		t = s.startTip(ns, cs...)
	}
	for attempt := 0; len(live) > 0; attempt++ {
		if attempt >= maxWriteAttempts {
			return fail(live, apiErr(409, "conflict", "detail", "log tip contention"))
		}
		if t == nil {
			cur, err := s.getTip(ctx, ns)
			if err != nil {
				return fail(live, err)
			}
			if cur == nil {
				return fail(live, ddb.ErrStale)
			}
			t = cur
		}
		cs := make([]*ddb.Commit, len(live))
		for i, w := range live {
			cs[i] = w.c
		}
		acts, res, err := s.buildCommits(ns, cs, *t)
		if err != nil {
			return fail(live, err)
		}
		_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: acts})
		if err == nil {
			for i, w := range live {
				w.res = res[i]
			}
			s.g.committed.Add(1)
			s.g.appended.Add(int64(len(live)))
			if s.OnGroup != nil {
				s.OnGroup(len(live))
			}
			last := res[len(res)-1]
			s.committedTip(ns, tip{headPos: last.Pos, headID: last.NSID})
			return &tip{headPos: last.Pos, headID: last.NSID}
		}
		stale, tipMoved, cerr := classifyCancel(err, cs, len(acts))
		if cerr != nil {
			// Not a cancellation (throughput, the network): committed or
			// not, unknown. A retried request finds out (its retry lookup).
			return fail(live, cerr)
		}
		var keep []*groupMember
		for i, w := range live {
			if stale[i] {
				w.err = ddb.ErrStale
			} else {
				keep = append(keep, w)
			}
		}
		dropped := len(keep) < len(live)
		live = keep
		if tipMoved {
			t = nil
			continue
		}
		if dropped {
			continue // the stale ones out: commit the rest
		}
		// A conflict with another transaction in flight: back off.
		select {
		case <-ctx.Done():
			return fail(live, ctx.Err())
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
	return nil
}

// pinsAgree reports whether a commit's pins agree with a group's: the
// group checks each namespace's configuration once.
func pinsAgree(group map[string]ddb.NSPin, pins []ddb.NSPin) bool {
	for _, p := range pins {
		if g, ok := group[p.NS]; ok && g != p {
			return false
		}
	}
	return true
}
