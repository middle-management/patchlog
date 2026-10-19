package dav

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/webdav"
)

// Locks live in memory, per user (x/net/webdav's memLS, §H.6, §H.7) and
// narrowing (scope), so every token of one user and scope holds them,
// within the user's bounds: x/net/webdav keeps a
// lock's owner XML as sent and a lock with Timeout: Infinite forever, one
// per path, so a read-only grant could pin a body's worth of memory per
// document it reads.

// maxLockOwner bounds a lock's owner XML (Finder's and Windows' are under
// a hundred bytes).
const maxLockOwner = 1024

// boundedLS is a scope's lock system, as one request uses it: owners of at
// most maxLockOwner bytes, timeouts of at most ScratchIdle (Infinite too),
// at most MaxLocks locks for the user. A refusal is recorded for
// errWriter, as x/net/webdav answers any error of Create with a 500.
type boundedLS struct {
	webdav.LockSystem
	st *reqState
}

// clamp is a lock duration within ScratchIdle; negative is infinite.
func (l *boundedLS) clamp(d time.Duration) time.Duration {
	if max := l.st.s.opt.ScratchIdle; d < 0 || d > max {
		return max
	}
	return d
}

func (l *boundedLS) Create(now time.Time, d webdav.LockDetails) (string, error) {
	st, sc := l.st, l.st.sc
	if len(d.OwnerXML) > maxLockOwner {
		return "", st.record(fail(http.StatusBadRequest, "a lock's owner is at most %d bytes", maxLockOwner))
	}
	d.Duration = l.clamp(d.Duration)
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	n := 0
	for _, o := range sc.p.scopes {
		o.expireLocksLocked(now)
		n += len(o.locked)
	}
	if n >= st.s.opt.MaxLocks {
		return "", st.record(fail(http.StatusInsufficientStorage, "at most %d locks are kept per user", st.s.opt.MaxLocks))
	}
	tok, err := l.LockSystem.Create(now, d)
	if err != nil {
		return "", err
	}
	sc.locked[tok] = heldLock{exp: now.Add(d.Duration), root: slashClean(d.Root)}
	return tok, nil
}

func (l *boundedLS) Refresh(now time.Time, token string, d time.Duration) (webdav.LockDetails, error) {
	d = l.clamp(d)
	ld, err := l.LockSystem.Refresh(now, token, d)
	if err == nil {
		sc := l.st.sc
		sc.p.mu.Lock()
		if h, ok := sc.locked[token]; ok {
			h.exp = now.Add(d)
			sc.locked[token] = h
		}
		sc.p.mu.Unlock()
	}
	return ld, err
}

func (l *boundedLS) Unlock(now time.Time, token string) error {
	err := l.LockSystem.Unlock(now, token)
	sc := l.st.sc
	sc.p.mu.Lock()
	if _, ok := sc.locked[token]; ok && (err == nil || err == webdav.ErrNoSuchLock) {
		delete(sc.locked, token)
	}
	sc.p.mu.Unlock()
	return err
}

// Confirm is memLS's, but for the destination of a MOVE or COPY (name1),
// whose If header's lock tokens are its source's: memLS requires the
// destination to be locked by one of them too, so a client moving or
// copying a file it holds locked, with that token, was refused (412). A
// destination no token confirms is confirmed as x/net/webdav confirms one
// without an If header: by a lock of its own for the request, which
// conflicts with any other.
func (l *boundedLS) Confirm(now time.Time, name0, name1 string, conditions ...webdav.Condition) (func(), error) {
	release, err := l.LockSystem.Confirm(now, name0, name1, conditions...)
	if err != webdav.ErrConfirmationFailed || name1 == "" {
		return release, err
	}
	release0 := func() {}
	if name0 != "" {
		if release0, err = l.LockSystem.Confirm(now, name0, "", conditions...); err != nil {
			return nil, err
		}
	}
	if release1, err := l.LockSystem.Confirm(now, "", name1, conditions...); err == nil {
		return func() {
			release1()
			release0()
		}, nil
	}
	tok, err := l.LockSystem.Create(now, webdav.LockDetails{Root: name1, Duration: time.Minute, ZeroDepth: true})
	if err != nil {
		release0()
		return nil, webdav.ErrConfirmationFailed
	}
	return func() {
		l.LockSystem.Unlock(now, tok)
		release0()
	}, nil
}

// heldLock is one of a user's locks: when it expires, and the path it was
// taken on.
type heldLock struct {
	exp  time.Time
	root string
}

// unlockUnder drops the scope's locks taken on name or below it: a
// DELETE that passed destroys them (RFC 4918 §9.6.1), and a MOVE moves no
// lock with its source (§9.9.4), so neither is left to answer the client
// 423 for a lock it can't hold any more.
func (sc *scope) unlockUnder(name string, now time.Time) {
	sc.p.mu.Lock()
	var toks []string
	for tok, h := range sc.locked {
		if h.root == name || strings.HasPrefix(h.root, strings.TrimSuffix(name, "/")+"/") {
			toks = append(toks, tok)
		}
	}
	sc.p.mu.Unlock()
	for _, tok := range toks {
		err := sc.locks.Unlock(now, tok)
		sc.p.mu.Lock()
		if _, ok := sc.locked[tok]; ok && (err == nil || err == webdav.ErrNoSuchLock) {
			delete(sc.locked, tok)
		}
		sc.p.mu.Unlock()
	}
}

// expireLocksLocked forgets the locks of sc expired by now, as memLS does.
func (sc *scope) expireLocksLocked(now time.Time) {
	for tok, h := range sc.locked {
		if !now.Before(h.exp) {
			delete(sc.locked, tok)
		}
	}
}
