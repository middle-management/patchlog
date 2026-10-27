package core

// Content from before a raise to e2e (Addendum E Levels, After a raise).
//
// A namespace raised to e2e (e2e_raises, e2e.go) keeps serving what was
// stored before the raise as at the level before: in the clear after a
// raise from none or at-rest, and after a raise from sealed sealed as
// §E.2.2 says, with the last epoch and pad setting before the raise in
// place of the current ones. That content is the revisions, resource log
// entries, namespace documents and log ranges from before the raise, the
// grants first recorded before it (grants.go) and the blobs those
// revisions reference (sealedblobs.go, blobs.go).
//
// Which content. A resource's revisions up to its head as of the entry
// before the raising one (preRaiseHead) are from before the raise; in the
// namespace log, the entries before the raising entry. A namespace with
// dependents can't be raised, and a branch is e2e only over an e2e base,
// so a raised namespace is never a local branch: what a branch of it
// reads through from before the raise is the raised base's, and the
// branch serves it as the base does (§E.2.2 "Branches of a raised base"),
// the same stored bytes, kid and pl naming the base. A remote branch's
// shadows follow their source (remote_branch.go).
//
// Epochs. A revision from before a raise from sealed is sealed under the
// epoch it was written in (rev_epochs), else the one its first stored
// sealing fixed, else the last epoch before the raise (preRaiseEpoch); a
// namespace entry under the epoch of the configuration in force after it,
// if sealed, else the last one before the raise; a log range under the
// last epoch before the raise. Sealings are stored in the sealed table
// under the raised namespace, as at E2, so one stored before the raise is
// served unchanged.
//
// Paging. No log page spans the raise (§7.1 Paging): a namespace log page
// ends before the raising entry, and a resource log page before the first
// revision written with or after it, though a page always holds one
// entry. So a page is entirely from before the raise, served as at the
// level before, or entirely after it.
//
// Folds. An E3 reader folds a revision written at e2e from the latest
// prune snapshot at or before it, or, where the resource's last revision
// from before the raise is later, from that revision (preRaiseFoldSince):
// /rev/{since} serves its document as at the level before, and the range
// after it holds only what was written end to end (F-E1).

import (
	"database/sql"
	"errors"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// preRaise is content from before an e2e raise as a namespace serves it.
type preRaise struct {
	// m is the namespace raised: the one serving the content, or the base
	// a branch reads it through from, whose sealed table, epoch keys, ns
	// and kid seal it.
	m     *nsRow
	raise *e2eRaise
}

// sealed reports content from before a raise from sealed, served sealed.
func (p *preRaise) sealed() bool { return p.raise.level == levelSealed }

// resOwner returns the namespace of resource row res.
func (t *tx) resOwner(n *nsRow, res int64) *nsRow {
	var ns int64
	t.must(t.QueryRow(`SELECT ns FROM resources WHERE res = ?`, res).Scan(&ns))
	if ns == n.id {
		return n
	}
	return t.nsByID(ns)
}

// preRaiseOf reports whether e2e namespace n serves revision or tombstone
// row r as content from before an e2e raise (Addendum E Levels): r is of a
// raised namespace, n or a base n reads it through, and at or before the
// resource's head as of the entry before the raise. nil otherwise, and in
// a namespace that isn't e2e.
func (t *tx) preRaiseOf(n *nsRow, r *revRow) *preRaise {
	if r == nil || !t.isE2E(n) {
		return nil
	}
	m := t.resOwner(n, r.res)
	if m == nil || m.isShadow() {
		return nil
	}
	raise := t.e2eRaiseOf(m)
	if raise == nil || r.seq > t.preRaiseHead(raise, r.res) {
		return nil
	}
	return &preRaise{m: m, raise: raise}
}

// preRaiseBoundary returns the newest row of to's chain, crossing foreign
// parents, that e2e namespace n serves as content from before an e2e
// raise, or nil if there is none: where the chain's revisions written end
// to end begin (§7.1 Paging, Addendum E Levels).
func (t *tx) preRaiseBoundary(n *nsRow, to *revRow) *revRow {
	if !t.isE2E(n) {
		return nil
	}
	for _, seg := range t.ancestry(to) {
		m := t.resOwner(n, seg.res)
		if m == nil || m.isShadow() {
			return nil
		}
		raise := t.e2eRaiseOf(m)
		if raise == nil {
			// A namespace e2e from its creation (a branch of the raised
			// base): written end to end, the base's segment may not be.
			continue
		}
		h := t.preRaiseHead(raise, seg.res)
		if h == 0 {
			return nil
		}
		return t.rev(min(h, seg.max))
	}
	return nil
}

// preRaiseRange decides whether the resource log range (since, to] of e2e
// namespace n spans an e2e raise (§7.1 Paging): if so it returns the row
// its first page ends at, the last one from before the raise, else nil. A
// since that isn't an ancestor of to is left to logBetween (404).
func (t *tx) preRaiseRange(n *nsRow, to *revRow, since *ids.ID) *revRow {
	b := t.preRaiseBoundary(n, to)
	if b == nil || b.seq == to.seq {
		return nil
	}
	if since == nil {
		return b
	}
	if *since == b.id || t.findInAncestry(b, *since) == nil {
		// The range starts at or after the boundary, or isn't a range.
		return nil
	}
	return b
}

// preRaiseFoldSince is where an E3 reader folds revision row of e2e
// namespace n from (F-E1): the latest prune snapshot at or before it
// (e2eFoldSince), or, where the chain's last revision from before an e2e
// raise is later, that revision, whose document /rev serves as at the
// level before: the last live one at or before it where it is a
// tombstone, the range then holding the tombstone. "" for the genesis.
func (t *tx) preRaiseFoldSince(n *nsRow, row *revRow) string {
	since := t.e2eFoldSince(row)
	b := t.preRaiseBoundary(n, row)
	if b == nil || b.seq == row.seq {
		return since
	}
	if since != "" {
		sid, err := ids.Parse(since)
		if err == nil && (sid == b.id || t.findInAncestry(b, sid) == nil) {
			// The snapshot is at or after the boundary.
			return since
		}
	}
	if l := t.lastLive(b); l.kind == kindRev {
		return l.id.String()
	}
	return since
}

// preRaiseResJob prepares the sealing of a resource document (kind doc) or
// log entry (kind entry) of row, from before p's raise from sealed, as p.m
// serves it under name (resJob, §E.2.2): under K_r of the epoch it is
// served under (preRaiseEpoch), padded as p.m padded before the raise.
// The job is stored under p.m (finishSeal with p.m.id).
func (t *tx) preRaiseResJob(p *preRaise, name string, row *revRow, kind string, plain func() []byte) *sealJob {
	m := p.m
	j := &sealJob{kind: kind, key: name + "/" + row.id.String(), name: name, revSeq: row.seq}
	if t.stored(m, j) {
		return j
	}
	plKind := seal.KindDoc
	if kind == sealEntry {
		plKind = seal.KindRev
		if row.kind == kindTombstone {
			plKind = seal.KindTombstone
		}
	}
	e := t.preRaiseEpoch(m, row, p.raise)
	kr, err := seal.ResourceKey(t.epochKey(m.id, e), m.name, name)
	t.must(err)
	j.kid, j.k, j.pl, j.plain = seal.Kid(m.name, e), kr, seal.ResourcePL(m.name, name, row.id.String(), plKind), plain()
	j.pad = p.raise.pad
	return j
}

// preRaiseEntryEpoch is the epoch that seals n's namespace entry seq from
// before its raise from sealed (configJob): the one in force after it,
// where n was sealed then, else the last epoch before the raise.
func (t *tx) preRaiseEntryEpoch(n *nsRow, raise *e2eRaise, seq int64) int {
	var cseq int64
	t.must(t.QueryRow(`SELECT config_seq FROM ns_log WHERE seq = ?`, seq).Scan(&cseq))
	if c := t.config(cseq); c.level == levelSealed {
		return c.Epoch
	}
	return raise.epoch
}

// preRaiseConfigJob is configJob for a namespace document of n at ns_log
// seq, from before its raise from sealed.
func (t *tx) preRaiseConfigJob(n *nsRow, raise *e2eRaise, seq int64, nsID string, doc []byte) *sealJob {
	j := &sealJob{kind: sealConfig, key: nsID}
	if t.stored(n, j) {
		return j
	}
	e := t.preRaiseEntryEpoch(n, raise, seq)
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.epochKey(n.id, e), seal.NamespaceDocPL(n.name, nsID), doc
	j.pad = raise.pad
	return j
}

// preRaiseRangeJob is rangeJob for a range of n's namespace log from
// before its raise from sealed: sealed under K_e of the last epoch before
// the raise, which stands for the current one (§E.2.2).
func (t *tx) preRaiseRangeJob(n *nsRow, raise *e2eRaise, since, toID string, plain func() []byte) *sealJob {
	j := &sealJob{kind: sealRange, key: since + ":" + toID}
	if t.stored(n, j) {
		return j
	}
	e := raise.epoch
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.epochKey(n.id, e), seal.RangePL(n.name, since, toID), plain()
	j.pad = raise.pad
	return j
}

// preRaiseResourceEvents is sealResourceEvents for events from before n's
// raise from sealed: under K_r of the last epoch before the raise.
func (t *tx) preRaiseResourceEvents(n *nsRow, raise *e2eRaise, name string, es []map[string]any) []string {
	if len(es) == 0 {
		return nil
	}
	kr, err := seal.ResourceKey(t.epochKey(n.id, raise.epoch), n.name, name)
	t.must(err)
	kid := seal.Kid(n.name, raise.epoch)
	out := make([]string, len(es))
	for i, d := range es {
		kind, _ := d["kind"].(string)
		jwe, err := seal.SealMaybePadded(kr, kid, seal.ResourceEventPL(n.name, name, kind), jsonv.Canonical(d), raise.pad)
		t.must(err)
		out[i] = jwe
	}
	return out
}

// preRaiseGrant reports whether grant id served by e2e namespace n is from
// before a raise from sealed (§C.3.1, Addendum E Levels): first recorded,
// in n or the local bases it reads through up to their at, by an entry of
// a raised namespace before its raising entry. Bases' entries up to at
// come before the branch's own, so the deepest namespace recording it
// recorded it first. It returns that namespace, whose key seals the grant
// as it serves it, its raise and the entry's seq; nil otherwise.
func (t *tx) preRaiseGrant(n *nsRow, id ids.ID) (*nsRow, *e2eRaise, int64) {
	var first *nsRow
	var firstSeq int64
	var bound sql.NullInt64
	for cur := n; cur != nil && !cur.isShadow(); {
		q := `SELECT seq FROM ns_log WHERE grant_id = ? AND ns = ? ORDER BY seq LIMIT 1`
		args := []any{id[:], cur.id}
		if bound.Valid {
			q = `SELECT seq FROM ns_log WHERE grant_id = ? AND ns = ? AND seq <= ? ORDER BY seq LIMIT 1`
			args = append(args, bound.Int64)
		}
		var seq int64
		switch err := t.QueryRow(q, args...).Scan(&seq); {
		case err == nil:
			first, firstSeq = cur, seq
		case !errors.Is(err, sql.ErrNoRows):
			t.must(err)
		}
		if !cur.base.Valid {
			break
		}
		bound = cur.baseAt
		cur = t.nsByID(cur.base.Int64)
	}
	if first == nil {
		return nil, nil, 0
	}
	raise := t.e2eRaiseOf(first)
	if raise == nil || raise.level != levelSealed || raise.seq != 0 && firstSeq >= raise.seq {
		return nil, nil, 0
	}
	return first, raise, firstSeq
}

// nsPreRaise returns n's raise to e2e if its namespace entry seq is from
// before it (Addendum E Levels), nil otherwise.
func (t *tx) nsPreRaise(n *nsRow, seq int64) *e2eRaise {
	if !t.isE2E(n) {
		return nil
	}
	if r := t.e2eRaiseOf(n); r != nil && r.seq != 0 && seq < r.seq {
		return r
	}
	return nil
}

// preRaiseConfig is the namespace document in force just before raise,
// the one the raising configuration replaced.
func (t *tx) preRaiseConfig(raise *e2eRaise) *Config {
	var parent sql.NullInt64
	t.must(t.QueryRow(`SELECT parent_seq FROM ns_config WHERE seq = ?`, raise.configSeq).Scan(&parent))
	return t.config(parent.Int64)
}

// preRaiseKeysOpen is keysOpen for content of resource name that n serves
// from before p's raise from sealed (keywindow.go): whether any of creds
// gets from n's /keys the keys it gives as at E2 for the epochs before the
// raise (Addendum E Levels, §E.2.3), K_r of name or K_e as
// keysOpenResource decides, for one of epochs. The §E.2.3 window is
// applied to the raised namespace's epochs as at E2, with the last epoch
// and namespace document before the raise standing for the current ones;
// in a branch of the raised namespace, to the branch's grants, as its
// /keys gives the base's keys for what it reads through.
func (t *tx) preRaiseKeysOpen(n *nsRow, p *preRaise, name string, epochs map[int]bool, creds []Credentials) bool {
	if len(epochs) == 0 || n.purged || p.m.purged {
		return false
	}
	cfg := t.preRaiseConfig(p.raise)
	all := t.epochStarts(`epoch_keys`, p.m.id, p.raise.epoch)
	within := func(a *actor) bool {
		for _, e := range t.grantEpochsOf(all, cfg, a) {
			if epochs[e] {
				return true
			}
		}
		return false
	}
	if t.e.opt.AuthDisabled {
		return within(nil)
	}
	for _, c := range creds {
		if c.Bearer == "" {
			continue
		}
		// As /keys authenticates (keysReader).
		a, err := t.keysReader(n, c, func(a *actor) bool { return a != nil && a.verified.Can["read"] })
		if err != nil || !t.keysOpenResource(a, name) {
			continue
		}
		if within(a) {
			return true
		}
	}
	return false
}
