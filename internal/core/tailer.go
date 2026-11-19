package core

import (
	"context"
	"database/sql"
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

// tailState is the tailer's position.
type tailState struct {
	from uint64 // the next xid to read
	gen  int64  // cache_gen as last read
}

// tailStart reads the position to tail from: what is committed now has
// been seen, by construction of the caches (empty) and the hub (no waiter).
func (e *Engine) tailStart(ctx context.Context) (tailState, error) {
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
		wake := map[string]map[string]bool{} // as tx.wake
		for rows.Next() {
			var name string
			var meta bool
			var res sql.NullString
			if err := rows.Scan(&name, &meta, &res); err != nil {
				rows.Close()
				return err
			}
			inv.meta = inv.meta || meta
			cur, seen := wake[name]
			if !seen {
				inv.nss = append(inv.nss, name)
			}
			switch {
			case !res.Valid:
				wake[name] = nil
			case seen && cur == nil:
			case cur == nil:
				wake[name] = map[string]bool{res.String: true}
			default:
				cur[res.String] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for ns, names := range wake {
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
	if gen != s.gen {
		inv.meta = true
	}
	if inv.meta {
		inv.flushDocs, inv.flushDEKs, inv.flushEpochKeys = true, true, true
	}
	if inv.meta || len(inv.nss) > 0 {
		e.invalidate(inv, true)
	}
	s.from, s.gen = max(s.from, to), gen
	e.tailFrom.Store(s.from)
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
