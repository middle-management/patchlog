package core

import (
	"context"
	"errors"
	"os"
	"sync"
)

// EXPERIMENTAL, with rebase.go (docs/SPEC-FEEDBACK.md, v0.82 Open 91):
// rebased writes of one document that are waiting together are written in
// one transaction, each applied on the result of the one before it, and
// committed once.
//
// Without it every write to a document is a transaction of its own: on
// Postgres group commit leaves a second write of a resource out of a
// group (groupcommit.go), since without a rebase it would be stale. Here
// the writes of one resource queue, and whoever finds no transaction
// running takes up to combineMax of them and runs each through the whole
// gate of §6.2 (writeItems) in turn, inside one transaction. A write the
// gate refuses (412, 422, 403, 429 …) is answered with its refusal and
// writes nothing; the others are unaffected. Any other error rolls the
// transaction back, and every write of it then runs alone.
const combineMax = 64

// combineAll, for tests (PATCHLOG_TEST_COMBINE_ALL=1), sends every single
// resource write through the combined transaction, a group of one
// included, whether or not it asks for a rebase: the whole test suite then
// exercises several writes per transaction with their ordinary meaning.
var combineAll = os.Getenv("PATCHLOG_TEST_COMBINE_ALL") == "1"

type combiner struct {
	mu sync.Mutex
	q  map[string]*combineQueue
}

type combineQueue struct {
	running bool
	pending []*combined
}

type combined struct {
	ctx  context.Context
	req  Request
	item Item
	res  *WriteResult
	// nsEntry is the number of the namespace entry the write deferred
	// (deferred.go), or -1.
	nsEntry int
	err     error
	done    chan struct{}
}

// writeCombined is WriteResource for a rebased single write.
func (e *Engine) writeCombined(ctx context.Context, req Request, item Item) (*WriteResult, error) {
	p := &combined{ctx: ctx, req: req, item: item, done: make(chan struct{})}
	key := req.NS + "\x00" + item.Resource
	c := &e.combine
	c.mu.Lock()
	if c.q == nil {
		c.q = map[string]*combineQueue{}
	}
	q := c.q[key]
	if q == nil {
		q = &combineQueue{}
		c.q[key] = q
	}
	q.pending = append(q.pending, p)
	if !q.running {
		q.running = true
		go e.drainCombined(key, q)
	}
	c.mu.Unlock()
	<-p.done
	return p.res, p.err
}

func (e *Engine) drainCombined(key string, q *combineQueue) {
	c := &e.combine
	for {
		c.mu.Lock()
		n := min(len(q.pending), combineMax)
		if n == 0 {
			q.running = false
			delete(c.q, key)
			c.mu.Unlock()
			return
		}
		group := append([]*combined(nil), q.pending[:n]...)
		q.pending = q.pending[n:]
		c.mu.Unlock()
		e.runCombined(group)
		for _, p := range group {
			close(p.done)
		}
	}
}

func (e *Engine) runCombined(group []*combined) {
	alone := func(p *combined) {
		p.res, p.err = e.writeOptimistic(p.ctx, p.req, []Item{p.item}, nil, false)
	}
	if len(group) == 1 && !combineAll {
		alone(group[0])
		return
	}
	// A group's transaction outlives any one of its requests; a write
	// whose request is cancelled before its turn is skipped. A write on
	// its own runs under its request, so cancelling it rolls it back.
	ctx := group[0].ctx
	if len(group) > 1 {
		ctx = context.WithoutCancel(ctx)
	}
	err := e.update(ctx, func(t *tx) error {
		// A transaction run again starts over.
		t.combining, t.movedRes, t.ownDocs = true, nil, nil
		t.def = nil
		if t.e.pg && (len(group) > 1 || combineAll) {
			// Step 7's rows of the group are written together (deferred.go).
			t.def = &deferred{want: len(group)}
		}
		if t.logHeads == nil {
			// The chain's head, once this transaction holds its log lock,
			// is the entry it appended last (appendNS).
			t.logHeads = map[int64]logHead{}
		}
		for _, p := range group {
			p.res, p.err, p.nsEntry = nil, nil, -1 // a transaction run again starts over
			if len(group) > 1 && p.ctx.Err() != nil {
				p.err = p.ctx.Err()
				continue
			}
			// The whole gate of §6.2, as writeItems, with the plan's patch
			// sets compressed before the insert as on every other path.
			before := 0
			if t.def != nil {
				before = t.def.total
			}
			plan, res, err := t.checkItems(p.req, []Item{p.item}, nil, nil, false, false, false)
			if err == nil && res == nil {
				t.e.packPlan(plan)
				res = t.insertPlan(p.req, plan)
			}
			if err != nil {
				var ae *Error
				if !errors.As(err, &ae) {
					return err
				}
				p.err = err
				continue
			}
			p.res = res
			if t.def != nil && t.def.total == before+1 {
				p.nsEntry = before
			}
		}
		t.flushDeferred()
		for _, p := range group {
			// The ids of the entries held back, known since the flush.
			if p.res != nil && p.nsEntry >= 0 {
				p.res.NSID = t.def.done[p.nsEntry].String()
			}
		}
		return nil
	})
	if err != nil {
		if len(group) == 1 && group[0].ctx.Err() != nil {
			// Its own transaction, under its own request, which was
			// cancelled: that is its answer.
			group[0].res, group[0].err = nil, err
			return
		}
		// Anything else, such as losing a race to insert to a writer on
		// another instance (a unique violation), is settled on the path a
		// write takes alone, which re-checks and answers 412.
		for _, p := range group {
			alone(p)
		}
	}
}
