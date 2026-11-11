package index

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// trustRepairMaxPause bounds the pause between two reads of a purged
// namespace's document whose catalog.trust is to be recorded again
// (repairTrustOf).
const trustRepairMaxPause = 5 * time.Minute

// repairTrust records again, once Run starts, the catalog.trust of every
// namespace the index serves whose purge-ns it applied (ns_state) and of
// which it holds none (catalog_trust): the state a release before v0.82
// could leave, by forgetMember forgetting it when the reconciler stopped
// the namespace's follower for visibility (ownsTrust), or by a snapshot
// that met the namespace purged and read no document for it (Apply).
// Nothing else reads it again: a purged namespace has no follower (follow
// returns before it starts one, so neither the trustAt of a follower that
// resumes nor the read at a snapshot's purge-ns ever runs for it), no
// entry follows its purge-ns, and a restart keeps ns_state; only a
// rebuild, which forgets ns_state and follows it anew, did. Without it the
// namespace counts as no catalog for good (fsTrust), and a partial reader
// of a namespace it covers is 403 with no marker instead of reading it
// dark (§A.4, §B.11.9 Where: "the last one the origin stored or the
// service read").
//
// Each namespace is repaired on its own, off the path that opens the
// index and starts its followers: one whose document can't be read yet
// holds up no other, and no follower. It returns once every one is
// settled, or ctx is done.
func (ix *Index) repairTrust(ctx context.Context) {
	lost, err := ix.trustLost(ctx)
	if err != nil {
		if ctx.Err() == nil {
			ix.opt.Logf("index: the purged namespaces without a catalog.trust: %v", err)
		}
		return
	}
	var wg sync.WaitGroup
	for ns, at := range lost {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ix.repairTrustOf(ctx, ns, at)
		}()
	}
	wg.Wait()
}

// trustLost are the namespaces the index serves (known) whose purge-ns it
// applied and whose catalog.trust it holds none of, each with the
// checkpoint it holds of it: its purge-ns entry, the last of its log.
func (ix *Index) trustLost(ctx context.Context) (map[string]string, error) {
	rows, err := ix.db.QueryContext(ctx, `SELECT s.ns, c.ns_id FROM ns_state s JOIN checkpoints c ON c.origin = ? AND c.ns = s.ns
		WHERE s.purged = 1 AND NOT EXISTS (SELECT 1 FROM catalog_trust t WHERE t.ns = s.ns)`, ix.origin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lost := map[string]string{}
	for rows.Next() {
		var ns, at string
		if err := rows.Scan(&ns, &at); err != nil {
			return nil, err
		}
		lost[ns] = at
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for ns, at := range lost {
		// One the index served once and no longer does is none of its
		// own: its trust is never recorded (dropUnfollowedTrust).
		if at == "" || !ix.known(ns) {
			delete(lost, ns)
		}
	}
	return lost, nil
}

// repairTrustOf reads the document of ns, a purged namespace the index
// serves and holds no catalog.trust of, at at, its purge-ns entry, where
// the origin still serves it unless ns is sealed (§8.5), as Apply reads it
// for a purge-ns met in place of a snapshot's listing (the same read,
// under the index's own grant), and records its catalog.trust
// (recordTrustLost). A document that is 410 (a sealed namespace's) is
// never read again: ns stays without one, no catalog, the reading that
// shows least, and is tried once more at the next start. Any other error
// (the origin down, a refusal that may pass) is retried after a pause that
// doubles up to trustRepairMaxPause, until ctx is done.
func (ix *Index) repairTrustOf(ctx context.Context, ns, at string) {
	pause := time.Second
	if ix.testTrustRepairPause > 0 {
		pause = ix.testTrustRepairPause
	}
	for {
		if ix.testTrustRepair != nil {
			ix.testTrustRepair(ctx, ns)
		}
		doc, err := ix.c.NSDoc(ctx, ns, at)
		switch {
		case ctx.Err() != nil:
			return
		case client.IsPurged(err):
			ix.opt.Logf("index: %s is purged and its document at %s gone (%v): its catalog.trust, which the index doesn't hold, can't be read again; it counts as no catalog", ns, at, err)
			return
		case err == nil:
			recorded, err := ix.recordTrustLost(ctx, ns, at, doc.Value)
			if err == nil {
				if recorded {
					ix.opt.Logf("index: %s is purged and the index held no catalog.trust of it: recorded from its document at %s", ns, at)
					// What coverage reads may have changed.
					ix.kickMembers()
				}
				return
			}
			ix.opt.Logf("index: recording the catalog.trust of %s, purged: %v; again in %s", ns, err, pause)
		default:
			ix.opt.Logf("index: the catalog.trust of %s, purged, at %s: %v; again in %s", ns, at, err, pause)
		}
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if pause *= 2; pause > trustRepairMaxPause {
			pause = trustRepairMaxPause
		}
	}
}

// recordTrustLost records ns's catalog.trust as doc, its document at at,
// gives it, where ns is still what repairTrust found: a namespace the
// index serves, purged at the checkpoint at, without one. It reports
// whether it recorded it. Decided in the transaction, with ix.wmu held:
// one recorded meanwhile stays, and none is ever recorded for a namespace
// the index doesn't serve or hasn't applied the purge of.
func (ix *Index) recordTrustLost(ctx context.Context, ns, at string, doc map[string]any) (bool, error) {
	if !ix.known(ns) {
		return false, nil
	}
	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var lost bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM ns_state WHERE ns = ? AND purged = 1)
		AND EXISTS (SELECT 1 FROM checkpoints WHERE origin = ? AND ns = ? AND ns_id = ?)
		AND NOT EXISTS (SELECT 1 FROM catalog_trust WHERE ns = ?)`, ns, ix.origin, ns, at, ns).Scan(&lost)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if !lost {
		return false, nil
	}
	if err := recordTrust(ctx, tx, ns, doc); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
