package core

import (
	"database/sql"
	"errors"
)

// A remote branch whose source is raised to a level this server lacks
// (§1, Conformance: Addendum E) can't follow the raise (§G.5.2): what it
// mirrored would be served below the level its source now serves it at.
// So it answers for every resource its source had at at, read through or
// written on since, and not purged since (§8.3), as for a failed fetch
// (502 upstream, §G.3, §12.1), and refuses writes to them other than
// purges the same way, at step 2.1 of §6.2 (purgedItems) and at check 2
// of §7.8 for uploads and copies (blobs.go); and so does each branch on
// this server whose base chain reaches that remote branch, for those it
// reads through or has written on since. A batch's local source takes no
// blobs from any of them (batchSource.blob). The follower marks such a
// remote branch when it sees the raise in the source's log
// (followLevel, remote_levels.lacks).
//
// A raise the server could make but whose config writes failed (followLevel
// records it for a rebase, and retryLevel tries it again at every sync) is
// held the same way, for the same resources, and answered the same 502
// upstream, without Retry-After (§1: a raise that "needs a level its server
// lacks, or hasn't succeeded"): a branch never serves what it reads through
// at a weaker level than its base serves it, once it sees the raise
// (Addendum E Levels, Invariant), so until the raise is made it serves none
// of it.
//
// A raise to e2e, which a source running an earlier draft may still make
// (this draft refuses it, Levels), is one the branch can't follow at all:
// it raises itself as far as Levels allow, to sealed (followTarget), and
// keeps answering 502 upstream for what its source had at at, whatever
// level it reaches, since sealed is still below the level its source now
// serves that content at (v0.82, CONFORMANCE scenario 74). What the
// branch created itself, which its source never had, is served as usual.

// lostRemote is the remote branch in n's chain, n itself or a base of it,
// whose source was raised to a level it hasn't followed (remoteHeld): the
// branch, the origin of its source, which a 502 names (§12.1), and whether
// that is for a level this server lacks. ok is false if there is none, as
// for every namespace that doesn't read through a remote branch.
func (t *tx) lostRemote(n *nsRow) (branch *nsRow, origin string, lacks, ok bool) {
	for b := n; b.isBranch() && !b.isShadow(); b = t.nsByID(b.base.Int64) {
		if t.remoteShadow(b) == nil {
			continue
		}
		origin, lacks, held := t.remoteHeld(b)
		if !held {
			return nil, "", false, false
		}
		return b, origin, lacks, true
	}
	return nil, "", false, false
}

// remoteHeld reports whether remote branch b holds back what it had at at
// (lostRemote): it recorded a raise of its source (remote_levels) that
// needs a level this server lacks (lacks), that it hasn't made as far
// as Levels allow (followTarget), its config writes having failed, or
// that it can't make at all, a raise to e2e. origin is its source's
// deployment.
func (t *tx) remoteHeld(b *nsRow) (origin string, lacks, held bool) {
	var level int
	err := t.QueryRow(`SELECT r.origin, l.lacks, l.level FROM remote_levels l JOIN remote_bases r ON r.branch = l.branch WHERE l.branch = ?`, b.id).Scan(&origin, &lacks, &level)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false
	}
	t.must(err)
	// A server that has lost its key store since lacks every level.
	lacks = lacks || t.e.opt.KeyStore == nil
	// A raise to e2e is never made: a namespace is end-to-end from its
	// creation or never (Levels), so a source an earlier draft raised
	// after at stays above whatever level the branch reaches, and what
	// it had at at is held for good, until a rebase or a purge
	// (CONFORMANCE scenario 74; Reading this spec).
	return origin, lacks, lacks || level == levelE2E || followTarget(level) > t.config(b.configSeq).level
}

// upstreamCovers reports whether name, as n sees it (v), is one of the
// resources the lost remote branch rb answers 502 for: one its source had
// at at, which rb's shadows mirror as it was then, live or tombstoned,
// and which n doesn't see purged. A resource the branches created
// themselves, or purged since, isn't (410 for a purged one, §8.3).
func (t *tx) upstreamCovers(rb *nsRow, name string, v *view) bool {
	if v.state == Purged || v.state == NotFound {
		return false
	}
	at := rb.baseAt.Int64
	switch t.resolve(t.nsByID(rb.base.Int64), name, &at).state {
	case Live, Tombstoned:
		return true
	}
	return false
}

// upstreamLevelErr is the 502 upstream of a resource whose source was
// raised to a level this server lacks (§1, §12.1): origin names the
// deployment of the remote base in the chain.
func upstreamLevelErr(origin, name string) *Error {
	return apiErr(502, "upstream", "origin", origin, "message",
		name+" is read through a remote branch whose source at "+origin+" was raised to an encryption level this server lacks, "+
			"so it isn't served or written here below that level (§1, §G.5.2); a purge still works")
}

// levelHeldErr is the 502 upstream of a resource read through a remote
// branch whose source's raise it hasn't been able to make (remoteHeld): the
// same answer as a lacking level (§1, §12.1), without Retry-After; the raise
// is still tried again at every sync (retryLevel) and at start
// (catchUpLevels).
func levelHeldErr(origin, name string) *Error {
	return apiErr(502, "upstream", "origin", origin, "message",
		name+" is read through a remote branch whose source at "+origin+" was raised to an encryption level this server hasn't raised the branch to, or can't, as to e2e, which only a creation sets, "+
			"so it isn't served or written here below that level (§1, §G.5.2); a raise that can be made is tried again at every sync, or rebase the branch; a purge still works")
}

// upstreamRefusal is the 502 upstream of §1 for a write, other than a
// purge, to resource name of n, or a read of it: a remote branch whose
// source was raised to a level this server lacks, or a branch whose base
// chain reaches one, answers 502 { code: "upstream", origin } for every
// resource its source had at `at`, read through or written since and not
// purged since (§1, §6.2 step 2.1, §12.1); one whose raise failed
// otherwise, the same 502 (levelHeldErr). For a write it comes at step 2.1, after
// the purged-namespace check and before a purged resource's 410 and the
// idempotent-retry lookup; for a read, once the read check has passed
// (reader), before any other answer but a purged namespace's 410. nil
// while no source is followed past a raise: every write goes on to the
// rest of the gate.
func (t *tx) upstreamRefusal(n *nsRow, name string) *Error {
	if n.purged {
		return nil
	}
	rb, origin, lacks, ok := t.lostRemote(n)
	if !ok || !t.upstreamCovers(rb, name, t.resolve(n, name, nil)) {
		return nil
	}
	if !lacks {
		return levelHeldErr(origin, name)
	}
	return upstreamLevelErr(origin, name)
}
