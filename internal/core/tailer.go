package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"time"
)

// The tailer (Postgres, Addendum D.8): how an instance learns of the
// commits of every instance, its own included.
//
// Every TailInterval it reads, in one REPEATABLE READ snapshot:
//
//   - the ns_log rows of transactions it hasn't seen, by transaction id:
//     xid >= from AND xid < pg_snapshot_xmin(pg_current_snapshot()), then
//     from = that xmin. Every transaction below xmin has committed or
//     aborted, so none is skipped however long it ran (ids are assigned
//     before commit, so sequence numbers would be). For each namespace in
//     them it wakes the live readers (long-polls and SSE, §7.7): those of
//     the namespace, and those of the resources its entries name, or all
//     of its resource readers for an entry that names none (as a local
//     commit does, entryResources); and it moves
//     the read cache's counter of that namespace; entries that change what
//     reads may return (config, purge, purge-ns, prune, branch) also count
//     as below;
//   - cache_gen, which every commit that changes what reads may return
//     beyond a namespace's log (configuration, purges, prunes, restores,
//     key destruction: tx.invalidation().meta) increments. A change moves
//     the read cache's meta counter and flushes the document, data key and
//     epoch key caches, as the local commit path does (Engine.invalidate).
//     cache_gen is read as committed, not by xid, so a long transaction
//     holding back xmin doesn't delay it.
//
// A wake-up is a hint: waiters re-read from their own since, so a late one
// delays and never loses anything. The read cache serves nothing unless a
// poll succeeded recently (readcache.go), which bounds how long another
// instance's purge, revocation or configuration change can be served from
// this instance's memory: freshFor after it commits.

// On Spanner (spanner.go) there are no transaction ids: every ns_log row
// records its transaction's commit timestamp (committed, Spanner's
// pending_commit_timestamp()), and a poll reads, in one read-only
// transaction, the rows committed after from, then sets from to that
// transaction's read timestamp. Spanner's commits are externally
// consistent: a read sees every transaction that committed at or before
// its timestamp and none after, and a transaction that commits later
// gets a later timestamp, however long it ran. So the window of a poll
// is exactly the commits after the last one's read and up to its own,
// and nothing is skipped, as below xmin on Postgres. (Commit timestamps
// are read in microseconds, Spanner's nanoseconds truncated, so a poll
// may see the last poll's last commits again: a wake-up is a hint.)

// tailState is the tailer's position.
type tailState struct {
	from uint64 // the next xid to read; on Spanner, the commit timestamp read up to (Unix µs)
	gen  int64  // cache_gen as last read
}

// tailStart reads the position to tail from: what is committed now has
// been seen, by construction of the caches (empty) and the hub (no waiter).
func (e *Engine) tailStart(ctx context.Context) (tailState, error) {
	if e.spanner {
		return e.tailStartSpanner(ctx)
	}
	var s tailState
	var xmin string
	err := e.db.QueryRowContext(ctx, `SELECT pg_snapshot_xmin(pg_current_snapshot())::text, (SELECT gen FROM cache_gen WHERE id = 1)`).Scan(&xmin, &s.gen)
	if err != nil {
		return s, err
	}
	s.from, err = strconv.ParseUint(xmin, 10, 64)
	if err == nil {
		e.tailFrom.Store(s.from)
	}
	return s, err
}

// metaKinds are the ns_log kinds that change what reads may return beyond
// the namespace's log (nsKindNames: purge, config, purge-ns, branch, prune).
// A batch with a config change is caught by cache_gen.
const metaKinds = `2, 3, 5, 6, 7`

// resourceKinds are the ns_log kinds that name one resource, by res (head,
// tombstone, purge, prune); batchKind names its items in its body.
const (
	resourceKinds = `0, 1, 2, 7`
	batchKind     = `4`
)

// tailPoll reads what committed since s and applies it.
func (e *Engine) tailPoll(ctx context.Context, s *tailState) error {
	if e.spanner {
		return e.tailPollSpanner(ctx, s)
	}
	tx, err := e.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var xmin string
	var gen int64
	if err := tx.QueryRow(`SELECT pg_snapshot_xmin(pg_current_snapshot())::text, (SELECT gen FROM cache_gen WHERE id = 1)`).Scan(&xmin, &gen); err != nil {
		return err
	}
	to, err := strconv.ParseUint(xmin, 10, 64)
	if err != nil {
		return err
	}
	inv := invalidation{}
	if to > s.from {
		// One row per entry, or per item of a batch: its namespace, whether
		// it changes what reads return beyond the log, and the resource it
		// names, or NULL for an entry that concerns the whole namespace
		// (entryResources): a write, purge or prune names its resource by
		// res; a batch's items by name in its body, its only entries whose
		// body is read here.
		rows, err := tx.Query(`SELECT n.name, l.kind IN (`+metaKinds+`),
				CASE WHEN l.kind IN (`+resourceKinds+`) THEN r.name
					WHEN l.kind = `+batchKind+` AND e->>'kind' IN ('head', 'tombstone') THEN e->>'resource' END
			FROM ns_log l JOIN namespaces n ON n.ns = l.ns
			LEFT JOIN resources r ON r.res = l.res
			LEFT JOIN LATERAL jsonb_array_elements(CASE WHEN l.kind = `+batchKind+` THEN l.body::jsonb->'entries' END) e ON true
			WHERE l.xid >= $1::text::xid8 AND l.xid < $2::text::xid8`,
			strconv.FormatUint(s.from, 10), xmin)
		if err != nil {
			return err
		}
		w := tailWake{}
		for rows.Next() {
			var name string
			var meta bool
			var res sql.NullString
			if err := rows.Scan(&name, &meta, &res); err != nil {
				rows.Close()
				return err
			}
			w.add(&inv, name, meta, res)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		w.into(&inv)
	}
	e.tailApply(s, inv, max(s.from, to), gen)
	return nil
}

// tailWake gathers a poll's live readers to wake, as tx.wake: per
// namespace, the resources named, or nil for all of them.
type tailWake map[string]map[string]bool

// add records an entry, or an item of a batch, of namespace name: whether
// it changes what reads return beyond the log (meta), and the resource it
// names, if any.
func (w tailWake) add(inv *invalidation, name string, meta bool, res sql.NullString) {
	inv.meta = inv.meta || meta
	cur, seen := w[name]
	if !seen {
		inv.nss = append(inv.nss, name)
	}
	switch {
	case !res.Valid:
		w[name] = nil
	case seen && cur == nil:
	case cur == nil:
		w[name] = map[string]bool{res.String: true}
	default:
		cur[res.String] = true
	}
}

// into records the resources to wake in inv.
func (w tailWake) into(inv *invalidation) {
	for ns, names := range w {
		if names == nil {
			continue
		}
		if inv.res == nil {
			inv.res = map[string][]string{}
		}
		for name := range names {
			inv.res[ns] = append(inv.res[ns], name)
		}
	}
}

// tailApply applies a poll's invalidation and moves the tailer to from,
// with cache_gen as read, gen.
func (e *Engine) tailApply(s *tailState, inv invalidation, from uint64, gen int64) {
	if gen != s.gen {
		inv.meta = true
	}
	if inv.meta {
		inv.flushDocs, inv.flushDEKs, inv.flushEpochKeys = true, true, true
	}
	if inv.meta || len(inv.nss) > 0 {
		e.invalidate(inv, true)
	}
	s.from, s.gen = from, gen
	e.tailFrom.Store(s.from)
}

// tailStartSpanner is tailStart on Spanner: from the read timestamp of
// the read of cache_gen.
func (e *Engine) tailStartSpanner(ctx context.Context) (tailState, error) {
	var s tailState
	c, err := e.db.Conn(ctx)
	if err != nil {
		return s, err
	}
	defer c.Close()
	if err := c.QueryRowContext(ctx, `SELECT gen FROM cache_gen WHERE id = 1`).Scan(&s.gen); err != nil {
		return s, err
	}
	ts, err := spReadTimestamp(ctx, c)
	if err != nil {
		return s, err
	}
	s.from = uint64(ts)
	e.tailFrom.Store(s.from)
	return s, nil
}

// tailPollSpanner is tailPoll on Spanner: the entries committed after
// s.from, up to the read timestamp of a read-only transaction. Spanner
// has no LATERAL nor jsonb_array_elements: a batch's body is read whole
// and its items found here.
func (e *Engine) tailPollSpanner(ctx context.Context, s *tailState) error {
	c, err := e.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	tx, err := c.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var gen int64
	if err := tx.QueryRow(`SELECT gen FROM cache_gen WHERE id = 1`).Scan(&gen); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT n.name, l.kind IN (`+metaKinds+`),
			CASE WHEN l.kind IN (`+resourceKinds+`) THEN r.name END,
			CASE WHEN l.kind = `+batchKind+` THEN l.body END
		FROM ns_log l JOIN namespaces n ON n.ns = l.ns
		LEFT JOIN resources r ON r.res = l.res
		WHERE l.committed > $1`, time.UnixMicro(int64(s.from)).UTC())
	if err != nil {
		return err
	}
	inv := invalidation{}
	w := tailWake{}
	for rows.Next() {
		var name string
		var meta bool
		var res, body sql.NullString
		if err := rows.Scan(&name, &meta, &res, &body); err != nil {
			rows.Close()
			return err
		}
		if !body.Valid {
			w.add(&inv, name, meta, res)
			continue
		}
		var b struct {
			Entries []struct{ Kind, Resource string }
		}
		if err := json.Unmarshal([]byte(body.String), &b); err != nil {
			rows.Close()
			return err
		}
		if len(b.Entries) == 0 {
			// As the join with no items: one row, naming no resource.
			w.add(&inv, name, meta, sql.NullString{})
		}
		for _, it := range b.Entries {
			r := sql.NullString{String: it.Resource, Valid: it.Kind == "head" || it.Kind == "tombstone"}
			w.add(&inv, name, meta, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	to, err := spReadTimestamp(ctx, c)
	if err != nil {
		return err
	}
	w.into(&inv)
	e.tailApply(s, inv, max(s.from, uint64(to)), gen)
	return nil
}

// syncTailSpanner is SyncTail on Spanner: every transaction committed
// before the call committed before the read timestamp of a strong read
// made now, which the tailer must reach.
func (e *Engine) syncTailSpanner(ctx context.Context) error {
	c, err := e.db.Conn(ctx)
	if err != nil {
		return err
	}
	var gen int64
	err = c.QueryRowContext(ctx, `SELECT gen FROM cache_gen WHERE id = 1`).Scan(&gen)
	var want int64
	if err == nil {
		want, err = spReadTimestamp(ctx, c)
	}
	c.Close()
	if err != nil {
		return err
	}
	for e.tailFrom.Load() < uint64(want) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.opt.TailInterval / 4):
		}
	}
	return nil
}

// SyncTail waits until the tailer has read every transaction committed
// before the call, so the wake-ups and cache invalidations for them have
// been applied, or ctx ends. The tailer reads up to the oldest transaction
// still running anywhere in the cluster (tailPoll), so a long one, in any
// database, delays it. Without a tailer (SQLite) it returns at once.
func (e *Engine) SyncTail(ctx context.Context) error {
	if !e.pg {
		return nil
	}
	if e.spanner {
		return e.syncTailSpanner(ctx)
	}
	var xmax string
	if err := e.db.QueryRowContext(ctx, `SELECT pg_snapshot_xmax(pg_current_snapshot())::text`).Scan(&xmax); err != nil {
		return err
	}
	want, err := strconv.ParseUint(xmax, 10, 64)
	if err != nil {
		return err
	}
	for e.tailFrom.Load() < want {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.opt.TailInterval / 4):
		}
	}
	return nil
}

// tailLoop runs the tailer until Close.
func (e *Engine) tailLoop(s tailState) {
	defer e.bg.Done()
	tk := time.NewTicker(e.opt.TailInterval)
	defer tk.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-e.stop
		cancel()
	}()
	var failing time.Time
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			start := time.Now()
			if err := e.tailPoll(ctx, &s); err != nil {
				if ctx.Err() != nil {
					return
				}
				// Logged once a minute at most; the read cache stops
				// serving meanwhile (fresh).
				if time.Since(failing) > time.Minute {
					log.Printf("tailer: %v", err)
					failing = time.Now()
				}
				continue
			}
			e.lastPoll.Store(int64(start.Sub(e.epoch)) + 1)
		}
	}
}

// fresh reports whether the tailer's last successful poll started within
// freshFor (readcache.go).
func (e *Engine) fresh() bool { return e.tailedWithin(e.freshFor()) }

// tailedWithin reports whether the tailer's last successful poll started
// within d.
func (e *Engine) tailedWithin(d time.Duration) bool {
	last := e.lastPoll.Load()
	return last != 0 && time.Since(e.epoch)-time.Duration(last-1) < d
}

// freshFor is how long after a poll started the read cache keeps serving
// on Postgres: a few intervals, so one slow poll doesn't turn it off.
func (e *Engine) freshFor() time.Duration { return 3 * e.opt.TailInterval }
