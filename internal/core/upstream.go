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

// lostRemote is the remote branch in n's chain, n itself or a base of it,
// whose source was raised to a level this server lacks: the branch, and
// the origin of its source, which a 502 names (§12.1). ok is false if
// there is none, as for every namespace that doesn't read through a
// remote branch.
func (t *tx) lostRemote(n *nsRow) (branch *nsRow, origin string, ok bool) {
	for b := n; b.isBranch() && !b.isShadow(); b = t.nsByID(b.base.Int64) {
		if t.remoteShadow(b) == nil {
			continue
		}
		err := t.QueryRow(`SELECT r.origin FROM remote_levels l JOIN remote_bases r ON r.branch = l.branch WHERE l.branch = ? AND l.lacks = 1`, b.id).Scan(&origin)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", false
		}
		t.must(err)
		return b, origin, true
	}
	return nil, "", false
}

// upstreamCovers reports whether name, as n sees it (v), is one of the
// resources the lost remote branch rb answers 502 for: one its source had
// at at, which rb's shadows mirror as it was then, live or tombstoned,
// and which n doesn't see purged. A resource the branches created
// themselves, or purged since, isn't (410 for a purged one, §8.3).
func (t *gate) upstreamCovers(rb *nsRow, name string, v *view) bool {
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

// upstreamRefusal is the 502 upstream of §1 for a write, other than a
// purge, to resource name of n, or a read of it: a remote branch whose
// source was raised to a level this server lacks, or a branch whose base
// chain reaches one, answers 502 { code: "upstream", origin } for every
// resource its source had at `at`, read through or written since and not
// purged since (§1, §6.2 step 2.1, §12.1). For a write it comes at step
// 2.1, after the purged-namespace check and before a purged resource's
// 410 and the idempotent-retry lookup; for a read, once the read check
// has passed (reader), before any other answer but a purged namespace's
// 410. nil while no source is followed past a raise: every write goes on
// to the rest of the gate.
func (t *gate) upstreamRefusal(n *nsRow, name string) *Error {
	if n.purged {
		return nil
	}
	rb, origin, ok := t.lostRemote(n)
	if !ok || !t.upstreamCovers(rb, name, t.resolve(n, name, nil)) {
		return nil
	}
	return upstreamLevelErr(origin, name)
}
