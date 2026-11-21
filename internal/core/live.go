package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
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
//   - and the grant hasn't expired: a pass ends at the earliest exp of its
//     blocks. A read's time window is its grant's nbf and exp: a rule
//     that refers to /now never passes for a read (§C.2 item 5), so no
//     decision depends on the time otherwise. An edge grant gets no pass,
//     as it can be withdrawn without a configuration change.
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
func (l *liveRead) decided(t *tx, n *nsRow, cred Credentials, a *actor) {
	if l.meta%2 != 0 {
		return
	}
	ok, _, until := standing(t, n, cred, a)
	if ok {
		l.pass = &LivePass{ns: n.name, meta: l.meta, until: until}
	}
}

// standing reports whether a read check that passed can stand for later
// reads (see above), and if so whether it holds for any credentials (a
// public namespace, or authentication disabled) and until when (zero: no
// grant expiry).
func standing(t *tx, n *nsRow, cred Credentials, a *actor) (ok, anyone bool, until time.Time) {
	cfg := t.config(n.configSeq)
	switch {
	case cfg.Read == "public" || t.e.opt.AuthDisabled:
		return true, true, time.Time{}
	case cred.Edge != nil || a == nil || a.verified == nil || a.grant == nil:
		return false, false, time.Time{}
	}
	for _, b := range a.grant.Blocks {
		if b.Exp != nil && (until.IsZero() || b.Exp.Before(until)) {
			until = *b.Exp
		}
	}
	return true, false, until
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

// Quiet resources (§7.7).
//
// A resource long-poll reads its resource's log before it waits, and a
// device that follows its own resource asks again at every interval
// boundary: one read transaction per follower and interval, though the
// resource rarely changes. With tens of thousands of followers that is
// thousands of transactions a second that find nothing, and they are
// what limits the database (docs/CAPACITY.md, Resource followers).
//
// So a read that finds a resource's log at its head records the head, by
// resource and credentials, in quiet. A later long-poll of the same
// resource whose since is that head, with the same credentials, is
// answered "nothing after since" without a transaction while
//
//   - the resource's waiters' channel (WaitResource), taken before that
//     read's transaction began, is still open: no commit naming the
//     resource, nor one concerning the whole namespace, has been seen
//     since;
//   - the read check's decision still stands, as for a LivePass: the
//     meta counter holds the even value loaded before that transaction,
//     and the grant hasn't expired. A public namespace's, or any while
//     authentication is disabled, holds for every request; another's only
//     for the same bearer grant, never for an edge grant;
//   - on Postgres, the tailer's last successful poll started within
//     quietFreshFor.
//
// On Postgres a commit on another instance closes the channel, and a
// change to what reads may return moves the meta counter, when the
// tailer sees it, as it wakes this instance's waiters: until then a
// request answered here waits, as one that read would have, and the
// tailer's wake sends it to read. A quiet answer carries no content, only
// "nothing after since", so the tailer's lag delays a follower as it
// delays the waiters already waiting, and exposes nothing a purge or
// revocation withdrew. So it is bounded more loosely than the read
// cache's answers (freshFor), which carry content: a few seconds. A bound
// as tight as freshFor turned quiet answers off whenever the database was
// busy enough to slow one poll, and sent every follower to read, which
// made the database busier still (docs/CAPACITY.md, Resource followers).

// quietCache holds quiet resources by resource and credentials.
type quietCache struct {
	mu sync.Mutex
	m  map[string]quietEntry
}

type quietEntry struct {
	head   string
	public bool
	meta   uint64
	until  time.Time
	woken  <-chan struct{}
}

// maxQuiet bounds the quiet resources kept; past it a quarter of them,
// in map order (random), are dropped.
const maxQuiet = 1 << 18

// quietRead is resourceLog's part in a live read: the meta counter and
// the resource's waiters' channel, both taken before its transaction
// began, and what its read check decided (standing).
type quietRead struct {
	meta   uint64
	woken  <-chan struct{}
	ok     bool
	anyone bool
	until  time.Time
}

func closed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// quietKeys are the keys a request's quiet entry may be under: any
// credentials', and its bearer grant's.
func quietKeys(ns, name string, cred Credentials) (anyone, own string) {
	anyone = ns + "\x00" + name + "\x00"
	if cred.Edge == nil && cred.Bearer != "" {
		sum := sha256.Sum256([]byte(cred.Bearer))
		own = anyone + string(sum[:])
	}
	return anyone, own
}

// quietFreshFor is how recently the tailer must have polled for quiet
// answers on Postgres (see above): a quarter of the long-poll interval,
// and never less than freshFor.
func (e *Engine) quietFreshFor() time.Duration {
	return max(e.freshFor(), e.LongPollInterval()/4)
}

// quietServing reports whether quiet answers may be given now.
func (e *Engine) quietServing() bool {
	return e.rc.fresh == nil || e.tailedWithin(e.quietFreshFor())
}

// quietLog answers a long-poll from since without a transaction, or nil;
// stale reports an answer withheld because the tailer is behind.
func (e *Engine) quietLog(ns, name, since string, cred Credentials) (lg *Log, stale bool) {
	anyone, own := quietKeys(ns, name, cred)
	for _, k := range []string{anyone, own} {
		if k == "" {
			continue
		}
		q, ok := e.quiet.get(k)
		if !ok || q.head != since {
			continue
		}
		if closed(q.woken) || q.meta != e.rc.meta.Load() || !q.until.IsZero() && !e.now().Before(q.until) {
			e.quiet.drop(k)
			continue
		}
		if !e.quietServing() {
			return nil, true
		}
		return &Log{Status: 200, Public: q.public, Until: q.until, Last: since}, false
	}
	return nil, false
}

// rememberQuiet records a live read that ended at its resource's head.
func (e *Engine) rememberQuiet(ns, name string, cred Credentials, lg *Log, q *quietRead) {
	if !q.ok || lg.Status != 200 || lg.More || lg.Last == "" || q.meta%2 != 0 ||
		e.rc.meta.Load() != q.meta || !e.quietServing() || closed(q.woken) {
		return
	}
	anyone, own := quietKeys(ns, name, cred)
	k := anyone
	if !q.anyone {
		if own == "" {
			return
		}
		k = own
	}
	e.quiet.put(k, quietEntry{head: lg.Last, public: lg.Public, meta: q.meta, until: q.until, woken: q.woken})
}

func (c *quietCache) get(k string) (quietEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	q, ok := c.m[k]
	return q, ok
}

func (c *quietCache) drop(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, k)
}

func (c *quietCache) put(k string, q quietEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]quietEntry{}
	}
	if _, ok := c.m[k]; !ok && len(c.m) >= maxQuiet {
		n := len(c.m) / 4
		for d := range c.m {
			if n == 0 {
				break
			}
			delete(c.m, d)
			n--
		}
	}
	c.m[k] = q
}

// ResourceLiveLog is ResourceLog from the current head for a long-poll
// (§7.7): from a quiet resource's head it answers without a transaction
// (see above), and a read that ends at the head is recorded for the next.
func (e *Engine) ResourceLiveLog(ctx context.Context, ns, name, since string, limit int, cred Credentials) (*Log, error) {
	answer := "read"
	if since != "" {
		lg, stale := e.quietLog(ns, name, since, cred)
		if lg != nil {
			e.liveQuiet.Add(1)
			e.countLiveRead("memory")
			return lg, nil
		}
		if stale {
			answer = "stale"
		}
	}
	e.countLiveRead(answer)
	// The channel before the counter, both before the transaction: a
	// commit the snapshot misses has yet to bump the counter, or close
	// the channel, or both.
	q := &quietRead{woken: e.WaitResource(ns, name)}
	q.meta = e.rc.meta.Load()
	lg, err := e.resourceLog(ctx, ns, name, "", since, limit, cred, q, false)
	if err == nil && lg != nil {
		e.rememberQuiet(ns, name, cred, lg, q)
	}
	return lg, err
}

func (e *Engine) countLiveRead(answer string) {
	if in := inst.Get(); in != nil {
		in.liveReads.Add(context.Background(), 1, metric.WithAttributes(attrAnswer.String(answer)))
	}
}
