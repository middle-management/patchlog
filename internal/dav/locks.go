package dav

import (
	"net/http"
	"time"

	"golang.org/x/net/webdav"
)

// Locks live in memory, per principal (x/net/webdav's memLS), within
// bounds: x/net/webdav keeps a lock's owner XML as sent and a lock with
// Timeout: Infinite forever, one per path, so a read-only grant could pin
// a body's worth of memory per document it reads.

// maxLockOwner bounds a lock's owner XML (Finder's and Windows' are under
// a hundred bytes).
const maxLockOwner = 1024

// boundedLS is a principal's lock system, as one request uses it: owners
// of at most maxLockOwner bytes, timeouts of at most ScratchIdle (Infinite
// too), at most MaxLocks locks for the principal and four times that for
// its grant root. A refusal is recorded for errWriter, as x/net/webdav
// answers any error of Create with a 500.
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
	st, p := l.st, l.st.p
	if len(d.OwnerXML) > maxLockOwner {
		return "", st.record(fail(http.StatusBadRequest, "a lock's owner is at most %d bytes", maxLockOwner))
	}
	d.Duration = l.clamp(d.Duration)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocksLocked(now)
	a := p.acct
	a.mu.Lock()
	full := len(p.locked) >= st.s.opt.MaxLocks || a.locks >= 4*st.s.opt.MaxLocks
	a.mu.Unlock()
	if full {
		return "", st.record(fail(http.StatusInsufficientStorage, "at most %d locks are kept per user", st.s.opt.MaxLocks))
	}
	tok, err := l.LockSystem.Create(now, d)
	if err != nil {
		return "", err
	}
	p.locked[tok] = now.Add(d.Duration)
	a.mu.Lock()
	a.locks++
	a.mu.Unlock()
	return tok, nil
}

func (l *boundedLS) Refresh(now time.Time, token string, d time.Duration) (webdav.LockDetails, error) {
	d = l.clamp(d)
	ld, err := l.LockSystem.Refresh(now, token, d)
	if err == nil {
		p := l.st.p
		p.mu.Lock()
		if _, ok := p.locked[token]; ok {
			p.locked[token] = now.Add(d)
		}
		p.mu.Unlock()
	}
	return ld, err
}

func (l *boundedLS) Unlock(now time.Time, token string) error {
	err := l.LockSystem.Unlock(now, token)
	p := l.st.p
	p.mu.Lock()
	if _, ok := p.locked[token]; ok && (err == nil || err == webdav.ErrNoSuchLock) {
		delete(p.locked, token)
		p.acct.mu.Lock()
		p.acct.locks--
		p.acct.mu.Unlock()
	}
	p.mu.Unlock()
	return err
}

// expireLocksLocked forgets the locks of p expired by now, as memLS does.
func (p *principal) expireLocksLocked(now time.Time) {
	n := 0
	for tok, exp := range p.locked {
		if !now.Before(exp) {
			delete(p.locked, tok)
			n++
		}
	}
	if n > 0 {
		p.acct.mu.Lock()
		p.acct.locks -= n
		p.acct.mu.Unlock()
	}
}
