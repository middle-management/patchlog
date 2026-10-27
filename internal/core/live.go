package core

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Long-poll reads of a namespace log shared by their waiters (§7.7).
//
// A write wakes every long-poll waiting on its namespace (Wait), and each
// reads the log after its since again. Through a CDN the waiters of a
// public namespace are one request (§9), but a private namespace's are each
// a request of their own unless the edge verifies edge grants (§C.5), and
// then every write costs a read transaction per waiter: thousands of
// identical reads for a namespace thousands of devices follow
// (docs/CAPACITY.md).
//
// So a waiter's first read is checked as any read is, and when that
// decision can stand for later reads of the same request it comes with a
// LivePass. Reads with a valid pass skip the read check and are shared:
// waiters of one namespace, since and page size woken by the same commit
// make one read, whose Log they all serve (and keep serving to waiters of
// that commit that ask after the read is done: liveDone). A pass is valid
// while
//
//   - no commit that changes what any read may return has happened since
//     the check: the read cache's meta counter (readcache.go), which
//     configuration changes (keys, roles, revocations, the read mode),
//     purges, prunes, restores and key destruction move, holds the value
//     loaded before the check's transaction began, even (no such commit in
//     flight), and on Postgres the tailer is fresh, as for the cached reads;
//   - the grant hasn't expired: a pass ends at the earliest exp of its
//     blocks;
//   - and the decision didn't depend on the time otherwise: a grant whose
//     key, block or role rules refer to /now (or to the whole envelope)
//     gets no pass, nor does an edge grant, which can be withdrawn without
//     a configuration change.
//
// Anything else is read and checked on its own, as before.

// LivePass stands for a long-poll request's read check of a namespace log
// while it holds (see above). It belongs to that one request.
type LivePass struct {
	ns    string
	meta  uint64
	until time.Time // zero: no grant expiry
}

// liveRead is namespaceLog's part in a live read: shared reads skip the
// check, which the waiters' passes stand for; a checked read records in
// pass whether its decision may stand for later ones.
type liveRead struct {
	shared bool
	meta   uint64 // the meta counter loaded before the transaction began
	pass   *LivePass
}

// liveDone keeps the answers of recent shared reads by key, for waiters
// woken by the same commit that ask once the read is done: the key holds
// the namespace's log counter, so an answer stands until the namespace's
// next commit, after which no waiter asks for its key. Past
// maxLiveDone answers it starts over.
type liveDone struct {
	mu sync.Mutex
	m  map[string]*Log
}

const maxLiveDone = 1024

// maxLiveDoneEntries bounds the answers liveDone keeps: waiters at the
// head get the few entries of one commit; a larger answer is shared while
// its read is under way, not kept.
const maxLiveDoneEntries = 64

func (d *liveDone) get(key string) *Log {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[key]
}

func (d *liveDone) put(key string, lg *Log) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil || len(d.m) >= maxLiveDone {
		d.m = map[string]*Log{}
	}
	d.m[key] = lg
}

// testLiveRead, if set, runs at the start of every shared read (tests).
var testLiveRead func(*Engine)

// errNotShared ends a shared read that can't serve the waiters (the
// namespace is gone): each reads on its own instead.
var errNotShared = errors.New("core: live read not shared")

// decided records the pass a read check allows (see above).
func (l *liveRead) decided(t *gate, n *nsRow, cred Credentials, a *actor) {
	if l.meta%2 != 0 {
		return
	}
	p := &LivePass{ns: n.name, meta: l.meta}
	cfg := t.config(n.configSeq)
	switch {
	case cfg.Read == "public" || t.e.opt.AuthDisabled:
	case cred.Edge != nil || a == nil || a.verified == nil || a.grant == nil:
		return
	case timeDependent(a):
		return
	default:
		for _, b := range a.grant.Blocks {
			if b.Exp != nil && (p.until.IsZero() || b.Exp.Before(p.until)) {
				p.until = *b.Exp
			}
		}
	}
	l.pass = p
}

// timeDependent reports whether a rule of a's key, blocks or roles may
// decide by /now: one that refers to it or to the whole envelope, or
// doesn't compile.
func timeDependent(a *actor) bool {
	v := a.verified
	rs := append(append([]any(nil), v.KeyRules...), v.BlockRules...)
	if v.HasRoles() {
		_, roles := v.Allows("read")
		for _, r := range roles {
			rs = append(rs, v.RoleRules(r)...)
		}
	}
	for _, rv := range rs {
		r, err := compileCached(rv)
		if err != nil || r.Refs()["now"] || r.Refs()["*"] {
			return true
		}
	}
	return false
}

// valid reports whether p still stands for its request's read check of ns.
func (e *Engine) livePassValid(p *LivePass, ns string) bool {
	if p == nil || p.ns != ns || e.rc.meta.Load() != p.meta {
		return false
	}
	if e.rc.fresh != nil && !e.rc.fresh() {
		return false
	}
	return p.until.IsZero() || e.now().Before(p.until)
}

// NamespaceLiveLog is NamespaceLog from the current head for a long-poll
// (§7.7), with pass the one an earlier read of the same request returned
// (nil on its first read). It returns the pass to give the next read: nil
// when the read check's decision can't stand for it (see above). A read
// with a valid pass isn't checked again, and is shared with the other
// waiters of the namespace reading the same since and page.
func (e *Engine) NamespaceLiveLog(ctx context.Context, ns, since string, limit int, cred Credentials, pass *LivePass) (*Log, *LivePass, error) {
	if e.livePassValid(pass, ns) {
		// The namespace's log counter is in the key: it moves before a
		// commit wakes the waiters (invalidate), so a waiter woken by a
		// write joins only reads that began after it, which see the write.
		gen := e.rc.nsGen(ns).Load()
		key := ns + "\x00" + since + "\x00" + strconv.Itoa(limit) + "\x00" + strconv.FormatUint(gen, 10)
		e.liveJoins.Add(1)
		if lg := e.liveDone.get(key); lg != nil && e.livePassValid(pass, ns) {
			return lg, pass, nil
		}
		v, err, _ := e.liveReads.Do(key, func() (any, error) {
			// The read serves every waiter that joined it: one waiter's
			// cancellation doesn't end it.
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			e.liveShared.Add(1)
			if testLiveRead != nil {
				testLiveRead(e)
			}
			lg, err := e.namespaceLog(sctx, ns, "", since, limit, Credentials{}, false, "", &liveRead{shared: true})
			if err == nil && len(lg.Entries) <= maxLiveDoneEntries {
				e.liveDone.put(key, lg)
			}
			return lg, err
		})
		// A read that began before the pass's meta moved served a
		// decision that may no longer hold: only a pass still valid now
		// takes its answer.
		if err == nil && e.livePassValid(pass, ns) {
			return v.(*Log), pass, nil
		}
		if err != nil && !errors.Is(err, errNotShared) && ctx.Err() == nil {
			return nil, nil, err
		}
	}
	live := &liveRead{meta: e.rc.meta.Load()}
	lg, err := e.namespaceLog(ctx, ns, "", since, limit, cred, false, "", live)
	if err != nil {
		return nil, nil, err
	}
	return lg, live.pass, nil
}
