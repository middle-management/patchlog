package core

import (
	"context"
	"database/sql"
	"errors"

	"github.com/middle-management/patchlog/internal/schema"
)

// The write path of D.3 for resource writes and batches.
//
// Steps 1–6 of §6.2 run in a read transaction, without the write lock. They
// record what they read that a concurrent write could change (writeDeps).
// Then the write lock is taken (in SQLite the engine mutex and BEGIN
// IMMEDIATE, which also serialises other processes; on Postgres the
// advisory locks of every namespace the check read, all shared, the
// target's included: writers of its other resources run alongside,
// pglock.go), and the re-check confirms, inside that transaction and after
// the locks, that all of it is unchanged:
//
//   - every namespace the check read: the target, every base whose keys and
//     revocations applied (§C.4), the namespaces of resolved schemas, of a
//     requireAt and of a batch source. Their config_seq (rules, keys,
//     revocations, roles, limits, allowances, frozen), frozen and purged
//     flags and base must be the same. A namespace's head may move: that is
//     another resource's write.
//   - every item's resource as the namespace sees it: its state and head
//     (or its absence), read through bases in a branch. This also covers
//     the idempotent-retry lookup: an entry this request would match can
//     only have been added by moving the item's head.
//   - every schema revision the check resolved outside the batch: it must
//     still be available to the writer (§6.1). A schema referenced only by
//     the pending write isn't "referenced" yet, so it can be purged between
//     check and insert.
//
// If all of it is unchanged, the decision is exactly the one steps 1–6 would
// reach inside the lock, and the write is inserted (on Postgres, a writer of
// the same resource that re-checked alongside may still insert first: the
// loser's insert conflicts, isConflict, and it redoes the check as below). Otherwise the whole check
// is redone, outside the lock again; a moved head then fails its
// precondition (412, with the new head) in the redo. Rate-limit tokens are
// drawn once, by the first attempt that passes step 1. After
// optimisticAttempts rounds the gate runs entirely inside the write lock, so
// a write always terminates.

// optimisticAttempts is how many check-then-re-check rounds a write makes
// before it runs its whole gate inside the write lock.
const optimisticAttempts = 3

// errRecheck rolls back a write transaction whose re-check failed.
var errRecheck = errors.New("write re-check failed")

// writeDeps is what a write's check phase read that a concurrent write can
// change.
type writeDeps struct {
	ns      map[int64]*nsRow
	order   []int64
	schemas []schema.Ref
	seen    map[string]bool
}

func newWriteDeps() *writeDeps {
	return &writeDeps{ns: map[int64]*nsRow{}, seen: map[string]bool{}}
}

// addNS records a namespace row as first read.
func (d *writeDeps) addNS(n *nsRow) {
	if d == nil || n == nil {
		return
	}
	if _, ok := d.ns[n.id]; ok {
		return
	}
	c := *n
	d.ns[n.id] = &c
	d.order = append(d.order, n.id)
}

// addSchema records a schema revision resolved from storage.
func (d *writeDeps) addSchema(r schema.Ref) {
	if d == nil || d.seen[r.Path()] {
		return
	}
	d.seen[r.Path()] = true
	d.schemas = append(d.schemas, r)
}

// sameNS reports whether a namespace row is unchanged in everything but its
// head.
func sameNS(a, b *nsRow) bool {
	return a.name == b.name && a.configSeq == b.configSeq && a.frozen == b.frozen && a.purged == b.purged &&
		a.base == b.base && a.baseAt == b.baseAt && a.baseConfigSeq == b.baseConfigSeq
}

// sameView reports whether a resource resolves to the same state and head.
func sameView(a, b *view) bool {
	if a.state != b.state || (a.head == nil) != (b.head == nil) {
		return false
	}
	return a.head == nil || a.head.seq == b.head.seq
}

// recheck confirms, inside the write transaction, that what a plan's check
// phase depended on is unchanged. It returns the target namespace as of
// this transaction (its head moves with other resources' writes).
func (t *tx) recheck(p *writePlan, d *writeDeps) (*nsRow, bool) {
	return t.recheckIn(p, d, nil)
}

// recheckIn is recheck sharing the namespace rows it reads through nss,
// for writes re-checked together under the same locks (group commit): what
// sameNS compares can't change while they are held, and a row's head is
// read again where it matters (appendNS).
func (t *tx) recheckIn(p *writePlan, d *writeDeps, nss map[int64]*nsRow) (*nsRow, bool) {
	var target *nsRow
	for _, id := range d.order {
		cur := nss[id]
		if cur == nil {
			var err error
			cur, err = scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE ns = ?`, id))
			if errors.Is(err, sql.ErrNoRows) {
				return nil, false
			}
			t.must(err)
			if nss != nil {
				nss[id] = cur
			}
		}
		if !sameNS(d.ns[id], cur) {
			return nil, false
		}
		if id == p.n.id {
			c := *cur
			target = &c
		}
	}
	if target == nil {
		return nil, false
	}
	for _, s := range p.st {
		v := t.resolve(target, s.Resource, nil)
		if !sameView(s.view, v) {
			return nil, false
		}
		// The same head, but the resource row may have appeared since (a
		// pending blob's, blobs.go).
		s.view = v
	}
	// Every blob a step references is still available: attached, pending
	// for the writer, or readable through a base or the batch's source
	// (D.2). This also records where step 7 takes each from.
	var bs *batchSource
	if p.isBatch && p.source != nil {
		var err *Error
		if _, bs, err = t.checkSource(p.req, p.source); err != nil {
			return nil, false
		}
	}
	for _, s := range p.st {
		if t.checkBlobs(target, s, p.a, bs) != nil {
			return nil, false
		}
	}
	sc := &schemaCtx{a: p.a, target: target, creds: p.req.anyCreds()}
	t.prefetchSchemas(d.schemas)
	for _, ref := range d.schemas {
		if _, err := t.loadSchema(ref, sc, nil); err != nil {
			return nil, false
		}
	}
	return target, true
}

// writeOptimistic runs a resource write or a batch without a config change
// on the D.3 write path: check outside the lock, re-check and insert inside,
// on Postgres in a group of the namespace's writes (groupcommit.go).
func (e *Engine) writeOptimistic(ctx context.Context, req Request, items []Item, source any, isBatch bool) (*WriteResult, error) {
	if e.grouping() {
		return e.writeGrouped(ctx, req, items, source, isBatch)
	}
	return e.writeAlone(ctx, req, items, source, isBatch, false, 0)
}

// checkOutside runs steps 1–6 of a resource write or batch in a read
// transaction, outside any lock (D.3), recording what it read (writeDeps).
// It returns a plan to re-check and insert, or a final result or error.
func (e *Engine) checkOutside(ctx context.Context, req Request, items []Item, source any, isBatch, rateDrawn bool) (*writePlan, *writeDeps, *WriteResult, error) {
	var plan *writePlan
	var deps *writeDeps
	var res *WriteResult
	// The read transaction is closed before the write lock is taken, so
	// the single connection of :memory: is never held while waiting.
	err := e.read(ctx, func(t *tx) error {
		t.deps = newWriteDeps()
		deps = t.deps
		p, r, err := t.checkItems(req, items, nil, source, isBatch, false, rateDrawn)
		plan, res = p, r
		return err
	})
	if err == nil {
		// After the read transaction too: compressing is CPU only.
		e.packPlan(plan)
	}
	return plan, deps, res, err
}

// writeAlone is writeOptimistic for a write on its own. rateDrawn skips
// the rate-limit draw, for a write whose tokens were already drawn (a
// write of a group answered alone, groupcommit.go), and rounds counts the
// check-then-re-check rounds it already made (its group's).
func (e *Engine) writeAlone(ctx context.Context, req Request, items []Item, source any, isBatch, rateDrawn bool, rounds int) (*WriteResult, error) {
	if e.pg && (e.opt.LockedCheckBytes == 0 || e.opt.LockedCheckBytes > 0 && smallWrite(items, e.opt.LockedCheckBytes)) {
		// On Postgres the write lock is the namespace's, held shared by
		// writers of its resources (pglock.go), and the check's own
		// transaction and the re-check cost a dozen round trips: check
		// inside the lock, where only the namespace's config writes,
		// purges and the like wait for it.
		return e.writeLocked(ctx, req, items, source, isBatch, rateDrawn)
	}
	for attempt := rounds; attempt < optimisticAttempts; attempt++ {
		plan, deps, res, err := e.checkOutside(ctx, req, items, source, isBatch, rateDrawn)
		if err != nil || res != nil {
			// Refused, or answered (an idempotent retry), as of a consistent
			// snapshot: nothing to insert.
			return res, err
		}
		// The plan passed step 1, rate limits included: its tokens are
		// drawn and are not drawn again by a redo.
		rateDrawn = true
		if h := e.opt.BeforeWriteLock; h != nil {
			h()
		}
		err = e.update(ctx, func(t *tx) error {
			// On Postgres, the locks of every namespace the check read,
			// before re-reading any (pglock.go).
			t.lockDeps(plan.n.id, deps)
			if h := e.afterWriteLock; h != nil {
				h(plan.n.name)
			}
			n, ok := t.recheck(plan, deps)
			if !ok {
				return errRecheck
			}
			plan.n = n
			res = t.insertPlan(req, plan)
			return nil
		})
		switch {
		case err == nil:
			return res, nil
		case errors.Is(err, errRecheck), isConflict(err):
			continue // redo steps 1–6 against the new state
		default:
			return nil, err
		}
	}
	// Still contended: run the whole gate inside the write lock.
	return e.writeLocked(ctx, req, items, source, isBatch, rateDrawn)
}

// writeLocked runs a write's whole gate inside the write lock.
//
// On Postgres that lock is the namespace's shared one, and a concurrent
// writer of the same resource can still win the race to insert
// (isConflict): the check, redone, then answers with the precondition that
// now fails (412 and the new head) or the idempotent retry. If it passes
// again the write runs again, the last time with the namespace's lock
// exclusive, which no writer of its resources shares, so a write always
// terminates.
func (e *Engine) writeLocked(ctx context.Context, req Request, items []Item, source any, isBatch, rateDrawn bool) (*WriteResult, error) {
	for attempt := 0; ; attempt++ {
		exclusive := attempt == lockedAttempts-1
		var res *WriteResult
		err := e.update(ctx, func(t *tx) error {
			// A transaction that runs again (Postgres, pglock.go) doesn't draw
			// its rate-limit tokens again.
			t.rateDrawn = &rateDrawn
			t.exclusive = exclusive
			r, err := t.writeItems(req, items, nil, source, isBatch, false, rateDrawn)
			res = r
			return err
		})
		if err == nil || !isConflict(err) || exclusive {
			return res, err
		}
		var r *WriteResult
		rerr := e.read(ctx, func(t *tx) error {
			_, rr, err := t.checkItems(req, items, nil, source, isBatch, false, true)
			r = rr
			return err
		})
		if rerr != nil || r != nil {
			return r, rerr
		}
	}
}

// lockedAttempts bounds how often writeLocked runs a write that lost a
// race to insert but whose check passes again.
const lockedAttempts = 3

// smallWrite reports whether a write's patches are smaller than max,
// judged by a rough size of their JSON. (The document they apply to may
// still be large; checking it holds only its namespace's lock.)
func smallWrite(items []Item, max int) bool {
	n := 0
	for _, it := range items {
		for _, s := range it.Steps {
			if n += approxSize(s.Patches, max-n); n >= max {
				return false
			}
		}
	}
	return true
}

// approxSize approximates the length of v as JSON, stopping past max.
func approxSize(v any, max int) int {
	switch v := v.(type) {
	case string:
		return len(v) + 2
	case map[string]any:
		n := 2
		for k, x := range v {
			if n += len(k) + 4 + approxSize(x, max-n); n > max {
				break
			}
		}
		return n
	case []any:
		n := 2
		for _, x := range v {
			if n += 1 + approxSize(x, max-n); n > max {
				break
			}
		}
		return n
	default:
		return 8
	}
}
