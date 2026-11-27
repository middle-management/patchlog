package core

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
)

// Reads of one statement, without a transaction (Postgres).
//
// A read transaction costs two round trips of its own on Postgres, its
// begin and its rollback, and pgx's work for each. A write's check outside
// the lock (checkOutside, D.3) of one item, and a revision read
// (resourceRev), are usually a single statement (lookupResource): three
// round trips, two of them the transaction's. readOne runs such a read
// without one: its first statement runs on its own, which sees one
// snapshot as a statement always does, so the read is as consistent as in
// a transaction of REPEATABLE READ. If the read needs a second statement
// (a branch's bases, a schema not yet cached, a grant to look up, …), that
// statement doesn't run: the read is abandoned (errNeedsTx) and runs again
// from the start in a read transaction (read), which sees a snapshot of
// its own. Nothing an abandoned read did is kept, but the rate-limit
// tokens a write's check drew from the engine's own buckets, which
// checkOutside carries over (rateDrawn).
//
// A namespace whose reads were abandoned reads in a transaction for its
// next few (loneGate): one after a first abandoned read, as after a
// document the cache no longer held, then twice as many after each further
// one in a row, up to loneBackoff, so a namespace whose reads always need
// more (a branch's, which read its bases) pays for an attempt rarely. A
// read without a transaction that needed none starts it over.

// errNeedsTx abandons a read without a transaction at its second
// statement.
var errNeedsTx = errors.New("read needs a transaction")

// loneBackoff is the most reads of a namespace that run in a transaction
// after one without was abandoned.
const loneBackoff = 64

// loneGate is, per namespace name, its reads' backing off.
type loneGate struct{ m sync.Map } // string -> *loneState

type loneState struct {
	// skip is the reads still to run in a transaction, streak how many it
	// was set to last (0 once a read without one went through).
	skip, streak atomic.Int32
}

// try reports whether a read of ns runs without a transaction.
func (g *loneGate) try(ns string) bool {
	v, ok := g.m.Load(ns)
	if !ok {
		return true
	}
	c := &v.(*loneState).skip
	for {
		n := c.Load()
		if n <= 0 {
			return true
		}
		if c.CompareAndSwap(n, n-1) {
			return false
		}
	}
}

// missed records a read of ns abandoned.
func (g *loneGate) missed(ns string) {
	v, _ := g.m.LoadOrStore(ns, new(loneState))
	s := v.(*loneState)
	n := min(max(2*s.streak.Load(), 1), loneBackoff)
	s.streak.Store(n)
	s.skip.Store(n)
}

// went records a read of ns that ran without a transaction.
func (g *loneGate) went(ns string) {
	if v, ok := g.m.Load(ns); ok {
		if s := v.(*loneState); s.streak.Load() != 0 {
			s.streak.Store(0)
		}
	}
}

// readOne is read for a read that is usually a single statement, which on
// Postgres runs without a transaction (above). f may run twice, so it
// sets everything it hands out afresh.
func (e *Engine) readOne(ctx context.Context, ns string, f func(t *tx) error) (err error) {
	defer func() { err = asUnavailable(err) }()
	if testStorageFault != nil {
		return e.read(ctx, f)
	}
	if !e.pg || e.noLone || !e.lone.try(ns) {
		return e.read(ctx, f)
	}
	var judged []judgedRow
	err = e.readAlone(ctx, func(t *tx) error {
		defer func() { judged = t.judged }()
		return f(t)
	})
	if errors.Is(err, errNeedsTx) && ctx.Err() == nil {
		e.lone.missed(ns)
		return e.read(ctx, f)
	}
	e.lone.went(ns)
	e.flushJudged(ctx, judged)
	return err
}

// readAlone runs f with a tx that has no transaction and runs at most one
// statement.
func (e *Engine) readAlone(ctx context.Context, f func(t *tx) error) (err error) {
	ctx, span := e.dbSpan(ctx, "core.db.read")
	defer func() {
		if errors.Is(err, errNeedsTx) {
			// Not a failure: the read runs again in a transaction.
			endDBSpan(span, nil)
			return
		}
		endDBSpan(span, err)
	}()
	t := &tx{ctx: ctx, e: e, now: e.now(), solo: true, trimGen: e.trims.Load()}
	defer func() {
		if p := recover(); p != nil {
			err = panicErr(p)
		}
		if t.soloRows != nil {
			// Left open by a read abandoned while it iterated them.
			t.soloRows.Close()
		}
		err = ctxErr(ctx, err)
	}()
	return f(t)
}

// soloStmt admits a read's one statement without a transaction, or
// abandons the read.
func (t *tx) soloStmt(q string, args []any) {
	if t.soloUsed {
		panic(errNeedsTx)
	}
	t.soloUsed = true
	if h := t.e.onStatement; h != nil && t.oracle == 0 {
		h(q, args)
	}
}

func (t *tx) soloQueryRow(q string, args []any) *sql.Row {
	t.soloStmt(q, args)
	return t.e.db.QueryRowContext(t.ctx, rebind(q), pgArgs(args)...)
}

func (t *tx) soloQuery(q string, args []any) (*sql.Rows, error) {
	t.soloStmt(q, args)
	rows, err := t.e.db.QueryContext(t.ctx, rebind(q), pgArgs(args)...)
	t.soloRows = rows
	return rows, err
}
