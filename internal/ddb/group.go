package ddb

// Group commit per namespace (docs/DYNAMODB.md §4, §11): the DynamoDB
// counterpart of internal/core's groupcommit.go.
//
// Concurrent writers of one namespace all condition their transaction on
// the namespace's #TIP, so ungrouped they collide and retry, and the
// collisions degenerate as writers are added (§11: 167/s at 8 writers,
// 82/s at 32). Postgres queues writers on its log lock instead; here an
// instance queues them itself, and one transaction appends several:
//
//   - Each write runs its check phase on its own, outside any queue (the
//     batch read, the plan, the caller's gate), and is queued with its
//     plan. Batches and config writes don't queue; they keep the
//     optimistic tip condition, as does every write when GroupCommit ≤ 1.
//   - A worker per namespace with a queue takes the queued writes that
//     fit one transaction: at most GroupCommit of them, within the 100
//     actions (six a write, five a delete, two shared) and a byte budget
//     under the 4 MB transaction cap, of resources no earlier write of
//     the group writes, planned under the same configuration as the
//     group's first. The others stay queued, in order, for the next group.
//   - The worker re-chains the group's entries over the tip it knows (an
//     entry's id covers the entry before it, §3.5, but nothing a write's
//     check read), at consecutive positions, and commits every write's
//     actions, one tip move, and a condition on #META that the
//     configuration is still the one the writes were checked under — so
//     a write's gate holds at commit even though the tip it read has
//     moved on: the gate reads the configuration and the resource's head,
//     and each write's own actions pin its head as they do ungrouped.
//   - A cancelled group sorts its failures as a write's own transaction
//     does: a write whose head moved is answered on its own (412 with the
//     new head, or its replay if the winner was itself), and the rest
//     commit again without it; a moved tip (a batch, a config write,
//     another instance) is re-read and the group re-chained; a changed
//     configuration, or an error that isn't a condition, sends every
//     write back to its own loop, which re-reads, re-plans and re-checks
//     it (D.3) — so no write is refused for another's failure, and one
//     whose outcome is unknown finds its replay there.
//
// The worker starts with the first queued write and takes, after each
// commit, whatever queued meanwhile: one writer waits only for a goroutine
// hand-off, and groups form as writers contend.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
)

// groupBytes bounds a group's planned bytes (documents and patch sets),
// under DynamoDB's 4 MB aggregate per transaction. A group's first write
// is always taken: one that doesn't fit fails as it would on its own.
const groupBytes = 3 << 20

// groupShared is a group's actions beyond its writes': the tip move and
// the configuration's condition.
const groupShared = 2

// groupMember is a checked write waiting in its namespace's queue.
type groupMember struct {
	ctx  context.Context
	name string
	p    *writePlan
	// Set by the worker before done is closed: the write's result or
	// error, or retry when the write must go round its own loop again.
	res   *WriteResult
	err   error
	retry bool
	done  chan struct{}
}

func (w *groupMember) acts() int {
	if w.p.del {
		return delNumActs - 1
	}
	return numActs - 1
}

func (w *groupMember) bytes() int { return len(w.p.doc) + len(w.p.rev.patches) }

// nsLock is a namespace's commit lock on this instance: its group worker
// holds it through each group's commit, and the writes that don't queue
// (batches, config writes) through each attempt, from their reads to
// their commit. They would otherwise lose the tip to the worker's groups
// attempt after attempt, since it moves it as often as writers queue.
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
	// Counters (tests, benchmarks): groups committed and writes appended
	// in them.
	committed, appended atomic.Int64
}

// GroupStats reports how many groups committed and how many writes they
// appended.
func (s *Store) GroupStats() (groups, writes int64) {
	return s.g.committed.Load(), s.g.appended.Load()
}

func (s *Store) grouping() bool { return s.GroupCommit > 1 }

// commitGrouped queues a checked write and waits for its group: the
// write's result, or retry (its loop re-reads and re-plans it).
func (s *Store) commitGrouped(ctx context.Context, ns, name string, p *writePlan) (*WriteResult, bool, error) {
	w := &groupMember{ctx: ctx, name: name, p: p, done: make(chan struct{})}
	g := &s.g
	g.mu.Lock()
	if g.ns == nil {
		g.ns = map[string]*nsQueue{}
	}
	q := g.ns[ns]
	if q == nil {
		q = &nsQueue{}
		g.ns[ns] = q
	}
	q.queue = append(q.queue, w)
	if !q.worker {
		q.worker = true
		go s.groupWorker(ns, q)
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
			return nil, false, ctx.Err()
		}
		g.mu.Unlock()
		// In a group already: its outcome is this write's.
		<-w.done
	}
	return w.res, w.retry, w.err
}

// groupWorker commits ns's queued writes, group after group, until the
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

// take removes the queued writes that fit one group (above) and returns
// them; the others keep their order. Callers hold the groups' lock.
func (q *nsQueue) take(limit int) []*groupMember {
	first := q.queue[0]
	group := []*groupMember{first}
	acts, size := groupShared+first.acts(), first.bytes()
	names := map[string]bool{first.name: true}
	rest := q.queue[:0:0]
	for _, w := range q.queue[1:] {
		if len(group) < limit && !names[w.name] && w.p.entry.cfgPos == first.p.entry.cfgPos &&
			acts+w.acts() <= maxTxActions && size+w.bytes() <= groupBytes {
			group = append(group, w)
			acts, size = acts+w.acts(), size+w.bytes()
			names[w.name] = true
			continue
		}
		rest = append(rest, w)
	}
	// A fresh array, so answered writes aren't kept reachable.
	q.queue = rest
	return group
}

// commitGroup appends a group of checked writes in one transaction
// (above), and returns the tip it leaves (nil if unknown). On return each
// write has its result or error, or is marked retry. known is the tip as
// of the worker's last commit, if any.
func (s *Store) commitGroup(ns string, group []*groupMember, known *tip) *tip {
	// No single request's cancellation aborts the group.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(group[0].ctx), 30*time.Second)
	defer cancel()

	// The tip to chain over: the newest any write's check read, or this
	// worker's own last commit, whichever is further along. A stale guess
	// costs one cancelled transaction and a re-read.
	t := group[0].p.tip
	for _, w := range group[1:] {
		if w.p.tip.headPos > t.headPos {
			t = w.p.tip
		}
	}
	if known != nil && known.headPos > t.headPos {
		t = *known
	}
	cfgPos := group[0].p.entry.cfgPos

	retryAll := func(ws []*groupMember) *tip {
		for _, w := range ws {
			w.retry = true
		}
		return nil
	}
	live := group
	for attempt := 0; len(live) > 0; attempt++ {
		if attempt >= maxWriteAttempts {
			return retryAll(live)
		}
		acts, err := s.chainGroup(ns, live, t, cfgPos)
		if err != nil {
			for _, w := range live {
				w.err = err
			}
			return nil
		}
		_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: acts})
		if err == nil {
			last := live[len(live)-1].p.entry
			for _, w := range live {
				w.res = &WriteResult{Status: 201, ID: w.p.rev.id, NSID: w.p.entry.id, Created: w.p.entry.created}
			}
			s.g.committed.Add(1)
			s.g.appended.Add(int64(len(live)))
			return &tip{headPos: last.pos, headID: last.id}
		}

		var xe *types.TransactionConflictException
		var ce *types.TransactionCanceledException
		switch {
		case errors.As(err, &xe):
			// Another transaction holds one of the items: run again.
		case errors.As(err, &ce):
			reasons := ce.CancellationReasons
			failed := func(i int) bool {
				return i < len(reasons) && reasons[i].Code != nil && *reasons[i].Code == "ConditionalCheckFailed"
			}
			n := len(acts)
			if failed(n - 1) {
				// The configuration changed: every write is checked again.
				return retryAll(live)
			}
			// Each write's actions, in order: the write's own conditions
			// answer it alone; the others commit again without it.
			var keep []*groupMember
			off, hits := 0, 0
			for _, w := range live {
				k := w.acts()
				// The entry's put fails with the tip (another writer
				// took its position): not the write's own condition.
				logAt := off + actLog
				if w.p.del {
					logAt = off + delActLog
				}
				var hit, marker bool
				for a := off; a < off+k; a++ {
					if failed(a) && a != logAt {
						hit = true
						marker = marker || a == off+k-1
					}
				}
				off += k
				if hit {
					hits++
				}
				switch {
				case !hit:
					keep = append(keep, w)
				case marker:
					// The entry's marker exists: not this write's (its id
					// chains over the group's tip); its own loop sorts it.
					w.retry = true
				case w.p.del:
					w.res, w.retry, w.err = s.deleteConflict(ctx, ns, w.name, w.p)
				default:
					w.res, w.retry, w.err = s.writeConflict(ctx, ns, w.name, w.p)
				}
			}
			live = keep
			if failed(n - 2) {
				// The tip moved under the group: re-read it.
				cur, gerr := s.getTip(ctx, ns)
				if gerr != nil || cur == nil {
					return retryAll(live)
				}
				t = *cur
				continue
			}
			if hits > 0 {
				continue
			}
			// Cancelled for no condition (a conflict reported per
			// action): back off and run again.
		default:
			// Not a cancellation (throughput, the network): committed or
			// not, each write's own loop finds out (its replay).
			return retryAll(live)
		}
		select {
		case <-ctx.Done():
			return retryAll(live)
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
	return nil
}

// chainGroup re-chains a group's entries over t, at consecutive positions,
// and builds its transaction: every write's actions without its own tip
// move (buildWriteTx's, buildDeleteTx's), then the tip move from t to the
// last entry, then the condition that the configuration is still cfgPos.
func (s *Store) chainGroup(ns string, group []*groupMember, t tip, cfgPos uint64) ([]types.TransactWriteItem, error) {
	var out []types.TransactWriteItem
	prev := t
	for _, w := range group {
		var prevID *ids.ID
		if prev.headID != "" {
			p, err := ids.Parse(prev.headID)
			if err != nil {
				return nil, apiErr(500, "stored_tip", "namespace", ns)
			}
			prevID = &p
		}
		p := w.p
		p.tip = prev
		p.entry.pos, p.entry.prevPos = prev.headPos+1, prev.headPos
		p.entry.id = ids.Hash(prevID, []byte(p.entry.body)).String()
		p.newHead.entryID = p.entry.id
		if p.del {
			acts := buildDeleteTx(s.Table, ns, w.name, p)
			out = append(out, slices.Delete(acts, delActTip, delActTip+1)...)
		} else {
			acts := buildWriteTx(s.Table, ns, w.name, p)
			out = append(out, slices.Delete(acts, actTip, actTip+1)...)
		}
		prev = tip{headPos: p.entry.pos, headID: p.entry.id}
	}
	tipK, metaK := keyTip(ns), keyMeta(ns)
	out = append(out,
		types.TransactWriteItem{Update: &types.Update{
			TableName:           &s.Table,
			Key:                 keyAV(tipK),
			UpdateExpression:    strptr("SET headPos = :new, headId = :newi"),
			ConditionExpression: strptr("headPos = :h AND headId = :i"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":new": avN(prev.headPos), ":newi": avS(prev.headID),
				":h": avN(t.headPos), ":i": avS(t.headID),
			},
		}},
		types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:                 &s.Table,
			Key:                       keyAV(metaK),
			ConditionExpression:       strptr("configPos = :cp"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":cp": avN(cfgPos)},
		}},
	)
	return out, nil
}
