package core

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/lru"
)

// Filtered long-poll and events (§7.9 Long-poll, Events, Cost).
//
// Each fetch of a waiter or a stream is admitted on its own, at the current
// checkpoint (filteredAdmit), as §7.3 repeats an event stream's read check
// before each page and keep-alive. The page it is then served is a
// function of (namespace, view, since, page size, at) alone, at pinning
// every namespace visibility reads, so the waiters of one view woken by the
// same commit share it: one read makes it (liveReads, under a key of its
// own, never an unfiltered one's), recent ones are kept (filteredLiveDone),
// and the view that judges its entries is one per (view, at)
// (filteredViews), so each new entry's visibility is judged once per view
// per wake (Cost, SHOULD). None of it is the readcache's or the unfiltered
// long-poll's: those answers are a namespace's whole log.

// filteredViews keeps the views recent filtered live reads judged with, by
// engine, namespace, view and at: a view's answers are fixed by its view and
// checkpoint, so the waiters of one view share its memo.
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
func filteredLiveKey(e *Engine, ns, view, since string, limit int, at string) string {
	return fmt.Sprintf("\x01filtered\x00%p\x00%s\x00%s\x00%s\x00%s\x00%s", e, ns, view, since, strconv.Itoa(limit), at)
}

// sharedView is the view the waiters of fv's view at fv's checkpoint share,
// fv itself if it is the first.
func sharedView(e *Engine, fv *fview) *fview {
	k := fmt.Sprintf("%p\x00%s\x00%s\x00%s", e, fv.fs.n.name, fv.view, fv.cp.at)
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

// FilteredLiveLog serves a fetch of GET /ns/{ns}/view/{view}/log?live=long-poll
// (§7.9 Long-poll) and of /ns/{ns}/view/{view}/events (Events): the request
// is admitted at the current checkpoint, and answered with a page of the
// log after since up to the head as its view sees it there (filteredRange):
// its visible entries, possibly none, Last the newest entry scanned, which
// a follower moves past hidden entries with, and More whether the log goes
// on. From a purged namespace's purge-ns entry it is 410 purged (§8.5).
// The page is shared by the waiters of the same view, since and at.
func (e *Engine) FilteredLiveLog(ctx context.Context, ns, view, since string, limit int, cred Credentials) (*Log, *FilteredInfo, error) {
	return e.filteredLiveLog(ctx, ns, view, since, limit, cred, false)
}

// FilteredEventLog is FilteredLiveLog for /ns/{ns}/view/{view}/events: in
// a sealed namespace each entry is its own JWE, an event's data, where a
// long-poll answer is one (§7.9 Sealed namespaces, §E.2.2).
func (e *Engine) FilteredEventLog(ctx context.Context, ns, view, since string, limit int, cred Credentials) (*Log, *FilteredInfo, error) {
	return e.filteredLiveLog(ctx, ns, view, since, limit, cred, true)
}

func (e *Engine) filteredLiveLog(ctx context.Context, ns, view, since string, limit int, cred Credentials, events bool) (*Log, *FilteredInfo, error) {
	var fv *fview
	var info *FilteredInfo
	var until time.Time
	err := e.read(ctx, func(t *tx) error {
		n, fs, err := t.filteredOpen(ns, cred)
		if err != nil {
			return err
		}
		v, aerr := t.filteredAdmit(n, fs, view, t.filteredCurrent(fs), cred)
		if aerr != nil {
			return aerr
		}
		fv, info, until = v, filteredInfo(v), t.credUntil(cred, v.a)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if fv.unrestricted {
		// An unrestricted reader's /ns/{ns} cookie reads unfiltered: its
		// pages are its own, never the view's readers' (no share, no
		// keeping).
		var lg *Log
		err := e.read(ctx, func(t *tx) error {
			n := t.nsByName(ns)
			if n == nil || n.id != fv.fs.n.id {
				return notFound()
			}
			if n.purged {
				return t.purgedRead(n) // since the read above (§8.5)
			}
			lg = t.filteredRange(n, fv, since, fv.cp.seq, limit)
			if len(lg.Entries) > 0 {
				// A page with none is answered 204, nothing sealed.
				t.filteredRangeSealing(n, fv, since, fv.cp.at, lg, events)
			}
			return nil
		})
		if err == nil {
			err = e.sealFilteredLog(ctx, lg)
		}
		if err != nil {
			return nil, nil, err
		}
		lg.Until = until
		return lg, info, nil
	}
	fv = sharedView(e, fv)
	key := filteredLiveKey(e, ns, fv.view, since, limit, fv.cp.at)
	if events {
		key += "\x00events"
	}
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
				if n.purged {
					return t.purgedRead(n) // since the read above (§8.5)
				}
				lg = t.filteredRange(n, fv, since, fv.cp.seq, limit)
				if len(lg.Entries) > 0 {
					t.filteredRangeSealing(n, fv, since, fv.cp.at, lg, events)
				}
				return nil
			})
			if err == nil {
				// Sealed once for the waiters that share it (§E.2.2:
				// readers accept any copy).
				err = e.sealFilteredLog(sctx, lg)
			}
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
