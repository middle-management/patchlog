package core

// The second CDN purge (D.8).
//
// A CDN tag purge (§8.3) is sent right after the commit that needs it
// (updateOnce). But an instance whose read cache is still within its
// staleness bound, a replica that lags, or a request that read before the
// commit and answers after the purge may still hand the CDN the content
// just purged, which would keep it at the edge for a year. So every purge
// is sent again once all of those have passed: the transaction that
// commits it also queues it in cdn_repurge, keyed on its namespace entry,
// due RepurgeDelay later, and the leader sends the due ones (repurgeLoop,
// Repurge) and deletes their rows. The queue commits with the purge, so a
// crash loses no second purge; one sent but not yet deleted when the
// leader stops is sent once more, which is harmless.

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// queueRepurge queues the second purge of the tags this write transaction
// purges, keyed on the last namespace entry it appended.
func (t *tx) queueRepurge() {
	if t.e.opt.RepurgeDelay < 0 || len(t.tags) == 0 {
		return
	}
	tags, err := json.Marshal(t.tags)
	t.must(err)
	var key any
	if t.lastNS != 0 {
		key = t.lastNS
	}
	due := t.now.Add(t.e.opt.RepurgeDelay).UnixMilli()
	_, err = t.Exec(`INSERT INTO cdn_repurge (ns_seq, tags, due) VALUES (?,?,?) ON CONFLICT DO NOTHING`, key, string(tags), due)
	t.must(err)
}

// Repurge sends the second purges that are due (D.8) and returns how many
// it sent. Each is sent, then its row deleted, one at a time; in a leader's
// job (repurgeLoop) it checks before each that the leader lock is held.
func (e *Engine) Repurge(ctx context.Context) (int, error) {
	n := 0
	for {
		batch, err := e.be.dueRepurges(ctx, e.now())
		if err != nil || len(batch) == 0 {
			return n, err
		}
		for _, d := range batch {
			if err := e.jobStep(ctx); err != nil {
				return n, err
			}
			if len(d.tags) > 0 {
				e.opt.Purger.PurgeTags(d.tags)
				n++
			}
			if err := e.be.doneRepurge(ctx, d.key); err != nil {
				return n, err
			}
		}
	}
}

// dueRepurge is a queued second purge: its tags, and its key in the
// backend's queue.
type dueRepurge struct {
	key  any
	tags []string
}

// sqlDueRepurges lists up to 100 second purges due at now (cdn_repurge).
func (e *Engine) sqlDueRepurges(ctx context.Context, now time.Time) ([]dueRepurge, error) {
	var batch []dueRepurge
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT id, tags FROM cdn_repurge WHERE due <= ? ORDER BY id LIMIT 100`, now.UnixMilli())
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var id int64
			var raw string
			t.must(rows.Scan(&id, &raw))
			d := dueRepurge{key: id}
			if json.Unmarshal([]byte(raw), &d.tags) != nil {
				d.tags = nil // unreadable: dropped by Repurge
			}
			batch = append(batch, d)
		}
		return nil
	})
	return batch, err
}

// sqlDoneRepurge dequeues a sent second purge.
func (e *Engine) sqlDoneRepurge(ctx context.Context, key any) error {
	return e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`DELETE FROM cdn_repurge WHERE id = ?`, key)
		t.must(err)
		return nil
	})
}

// repurgeLoop runs Repurge every interval on the leader until Close.
func (e *Engine) repurgeLoop(interval time.Duration) {
	defer e.bg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-e.stop:
				case <-ctx.Done():
				}
				cancel()
			}()
			if e.leader(ctx) {
				if _, err := e.Repurge(leaderJob(ctx)); err != nil && ctx.Err() == nil {
					log.Printf("cdn repurge: %v", err)
				}
			}
			cancel()
		}
	}
}
