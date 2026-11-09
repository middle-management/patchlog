package core

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/lru"
)

// Filtered long-poll and events (§B.11.9 Long-poll, Events, Cost).
//
// Each fetch of a waiter or a stream is admitted on its own, at the current
// checkpoint (filteredAdmit), as §7.3 repeats an event stream's read check
// before each page and keep-alive. The page it is then served is a
// function of (namespace, gs, since, page size, at) alone, at pinning
// every namespace visibility reads, so the waiters of one gs woken by the
// same commit share it: one read makes it (liveReads, under a key of its
// own, never an unfiltered one's), recent ones are kept (filteredLiveDone),
// and the view that judges its entries is one per (gs, at)
// (filteredViews), so each new entry's visibility is judged once per gs
// per wake (Cost, SHOULD). None of it is the readcache's or the unfiltered
// long-poll's: those answers are a namespace's whole log.

// filteredViews keeps the views recent filtered live reads judged with, by
// engine, namespace, gs and at: a view's answers are fixed by its gs and
// checkpoint, so the waiters of one gs share its memo.
var filteredViews struct {
	sync.Mutex
	lru lru.Cache[string, *fview]
}

// filteredLiveDone keeps recent filtered live answers by their share key
// (filteredLiveKey), for waiters that ask once the shared read is done.
var filteredLiveDone struct {
	sync.Mutex
	lru lru.Cache[string, *Log]
}

const filteredLiveMax = 1024

// testFilteredLiveRead, if set, is called by a filtered live read between
// its admission and the read of its page, for tests of what commits there.
var testFilteredLiveRead func()

// filteredLiveKey is the share key of a filtered live read: never an
// unfiltered one's, whose keys start with a namespace name.
func filteredLiveKey(e *Engine, ns, gs, since string, limit int, at string) string {
	return fmt.Sprintf("\x01filtered\x00%p\x00%s\x00%s\x00%s\x00%s\x00%s", e, ns, gs, since, strconv.Itoa(limit), at)
}

// sharedView is the view the waiters of fv's gs at fv's checkpoint share,
// fv itself if it is the first.
func sharedView(e *Engine, fv *fview) *fview {
	k := fmt.Sprintf("%p\x00%s\x00%s\x00%s", e, fv.fs.n.name, fv.gs, fv.cp.at)
	filteredViews.Lock()
	defer filteredViews.Unlock()
	if v, ok := filteredViews.lru.Get(k); ok {
		return v
	}
	if filteredViews.lru.MaxEntries == 0 {
		filteredViews.lru.MaxEntries = filteredLiveMax
	}
	filteredViews.lru.Put(k, fv, 1)
	return fv
}

// FilteredLiveLog serves a fetch of GET /ns/{ns}/g/{gs}/log?live=long-poll
// (§B.11.9 Long-poll) and of /ns/{ns}/g/{gs}/events (Events): the request
// is admitted at the current checkpoint, and answered with a page of the
// log after since up to the head as its gs sees it there (filteredRange):
// its visible entries, possibly none, Last the newest entry scanned, which
// a follower moves past hidden entries with, and More whether the log goes
// on. From a purged namespace's purge-ns entry it is 410 purged (§8.5).
// The page is shared by the waiters of the same gs, since and at.
func (e *Engine) FilteredLiveLog(ctx context.Context, ns, gs, since string, limit int, cred Credentials) (*Log, *FilteredInfo, error) {
	var fv *fview
	var info *FilteredInfo
	var until time.Time
	err := e.read(ctx, func(t *tx) error {
		n, fs, err := t.filteredOpen(ns, cred)
		if err != nil {
			return err
		}
		v, aerr := t.filteredAdmit(n, fs, gs, t.filteredCurrent(fs), cred)
		if aerr != nil {
			return aerr
		}
		if n.purged && since != "" {
			if id, err := ids.Parse(since); err == nil {
				if s, ok := t.nsLogSeq(n.id, id); ok && s == n.headSeq.Int64 {
					return t.purgedRead(n)
				}
			}
		}
		fv, info, until = v, filteredInfo(n, v), t.admittedUntil(n, cred, v.a)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	fv = sharedView(e, fv)
	key := filteredLiveKey(e, ns, fv.gs, since, limit, fv.cp.at)
	filteredLiveDone.Lock()
	lg, ok := filteredLiveDone.lru.Get(key)
	filteredLiveDone.Unlock()
	if !ok {
		v, err, _ := e.liveReads.Do(key, func() (any, error) {
			// The read serves every waiter that joined it: one waiter's
			// cancellation doesn't end it.
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if testFilteredLiveRead != nil {
				testFilteredLiveRead()
			}
			var lg *Log
			err := e.read(sctx, func(t *tx) error {
				n := t.nsByName(ns)
				if n == nil || n.id != fv.fs.n.id {
					return notFound()
				}
				lg = t.filteredRange(n, fv, since, fv.cp.seqs[ns], limit)
				return nil
			})
			if err == nil && len(lg.Entries) <= maxLiveDoneEntries {
				filteredLiveDone.Lock()
				if filteredLiveDone.lru.MaxEntries == 0 {
					filteredLiveDone.lru.MaxEntries = filteredLiveMax
				}
				filteredLiveDone.lru.Put(key, lg, 1)
				filteredLiveDone.Unlock()
			}
			return lg, err
		})
		if err != nil {
			return nil, nil, err
		}
		lg = v.(*Log)
	}
	// Shared: each waiter gets its own copy, with its own admission's end.
	out := *lg
	out.Until = until
	return &out, info, nil
}
