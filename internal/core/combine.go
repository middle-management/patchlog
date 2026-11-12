package core

import (
	"context"
	"errors"
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
	err  error
	done chan struct{}
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
	if len(group) == 1 {
		alone(group[0])
		return
	}
	// The transaction outlives any one request of the group.
	ctx := context.WithoutCancel(group[0].ctx)
	err := e.update(ctx, func(t *tx) error {
		for _, p := range group {
			p.res, p.err = nil, nil // a transaction run again starts over
			res, err := t.writeItems(p.req, []Item{p.item}, nil, nil, false, false, false)
			if err != nil {
				var ae *Error
				if !errors.As(err, &ae) {
					return err
				}
				p.err = err
				continue
			}
			p.res = res
		}
		return nil
	})
	if err != nil {
		for _, p := range group {
			alone(p)
		}
	}
}
