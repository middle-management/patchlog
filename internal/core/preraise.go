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
// shadow of a source raised before at records the raise where the
// source's log has it, holds the source's keys of the epochs before it
// (insertShadow, MF-37) and the epoch each mirrored entry was served
// under (rev_epochs), so the branch serves that content as the source
// does, kid and pl naming the source (kidName), never the shadow.
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
	if m == nil {
		return nil
	}
	// A remote branch's shadow of a source raised before at has the raise
	// too, where the source's log has it (insertShadow, MF-37).
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
		if m == nil {
			return nil
		}
		raise := t.e2eRaiseOf(m)
		if raise == nil {
			if m.isShadow() {
				// A shadow of a source with no raise before at.
				return nil
			}
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
	// Named as the base serves it: a remote branch's shadow by its
	// source's name (kidName), whose keys it holds (MF-37).
	kns := t.kidName(m)
	kr, err := seal.ResourceKey(t.epochKey(m.id, e), kns, name)
	t.must(err)
	j.kid, j.k, j.pl, j.plain = seal.Kid(kns, e), kr, seal.ResourcePL(kns, name, row.id.String(), plKind), plain()
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

// preRaiseKeysOpen is keysOpen for content of resource name that n serves
// from before p's raise from sealed (keywindow.go): whether any of creds
// gets from n's /keys the keys it gives as at E2 for the epochs before the
// raise (Addendum E Levels, §E.2.3), K_r of name or K_e as
// keysOpenResource decides, for one of epochs: those preRaiseKeyWindow
// gives, judged against the current epoch, so none to a grant without nbf
// or while authentication is disabled.
func (t *tx) preRaiseKeysOpen(n *nsRow, p *preRaise, name string, epochs map[int]bool, creds []Credentials) bool {
	if len(epochs) == 0 || n.purged || p.m.purged {
		return false
	}
	within := func(a *actor) bool {
		for _, e := range t.preRaiseKeyWindow(n, p, a) {
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

// preRaiseKeyWindow lists the epochs from before p's raise from sealed
// whose keys n's /keys gives grant a (Addendum E Levels, §E.2.3): where n
// is the raised namespace, its window over every epoch, judged against
// its current epoch (preRaiseWindow); in a branch of it, those the base
// epochs give from it as of the at of the branch reading it through
// (baseEpochs). None where p's namespace is neither.
func (t *tx) preRaiseKeyWindow(n *nsRow, p *preRaise, a *actor) []int {
	if n.id == p.m.id {
		return t.preRaiseWindow(p.m, p.raise, a)
	}
	for child := n; child.isBranch(); {
		b := t.nsByID(child.base.Int64)
		if b == nil {
			return nil
		}
		if b.id == p.m.id {
			var out []int
			for _, e := range t.baseEpochs(b, child.baseAt.Int64, a) {
				if e <= p.raise.epoch {
					out = append(out, e)
				}
			}
			return out
		}
		child = b
	}
	return nil
}

// --- blobs ----------------------------------------------------------------

// preRaiseBlob reports whether e2e namespace n serves blob bid, in the
// history of resource name ending at head, as a blob from before a raise
// from sealed (§E.2.2, §7.1, Addendum E Levels): one a revision of that
// history from before the raise references, served or not. It keeps its
// epoch URLs, under those revisions' epochs only, and is never served in
// the clear; it returns the raise, nil for any other blob.
func (t *tx) preRaiseBlob(n *nsRow, head *revRow, bid ids.ID) *preRaise {
	if head == nil || !t.isE2E(n) {
		return nil
	}
	for _, seg := range t.ancestry(head) {
		m := t.resOwner(n, seg.res)
		if m == nil {
			return nil
		}
		raise := t.e2eRaiseOf(m)
		if raise == nil {
			if m.isShadow() {
				return nil
			}
			continue // written end to end (preRaiseBoundary)
		}
		if raise.level != levelSealed {
			return nil
		}
		h := min(t.preRaiseHead(raise, seg.res), seg.max)
		var ok bool
		t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_refs WHERE res = ? AND bid = ? AND from_seq <= ?)`, seg.res, bid[:], h).Scan(&ok))
		if !ok {
			return nil
		}
		return &preRaise{m: m, raise: raise}
	}
	return nil
}

// preRaiseSegment returns the segment of head's history holding p's
// content from before the raise, capped at its last revision from before
// it, and false if there is none.
func (t *tx) preRaiseSegment(p *preRaise, head *revRow) (segment, bool) {
	for _, seg := range t.ancestry(head) {
		var ns int64
		t.must(t.QueryRow(`SELECT ns FROM resources WHERE res = ?`, seg.res).Scan(&ns))
		if ns != p.m.id {
			continue
		}
		h := min(t.preRaiseHead(p.raise, seg.res), seg.max)
		return segment{res: seg.res, max: h}, h > 0
	}
	return segment{}, false
}

// preRaiseBlobEpochs is blobEpochs for a blob from before p's raise from
// sealed: the epochs under which the still served revisions from before
// the raise that reference it are served (preRaiseEpoch), those written
// sealed by their rev_epochs, the others by their stored sealing (§E.2.2).
func (t *tx) preRaiseBlobEpochs(p *preRaise, head *revRow, bid ids.ID) map[int]bool {
	out := map[int]bool{}
	seg, ok := t.preRaiseSegment(p, head)
	if !ok {
		return out
	}
	where := ` WHERE b.res = ? AND b.bid = ? AND r.seq <= ? AND r.kind = 0 AND ` + servedRev
	rows, err := t.Query(`SELECT DISTINCT e.epoch`+refRevs+` JOIN rev_epochs e ON e.seq = r.seq`+where, seg.res, bid[:], seg.max)
	t.must(err)
	for rows.Next() {
		var e int
		t.must(rows.Scan(&e))
		out[e] = true
	}
	rows.Close()
	rows, err = t.Query(`SELECT substr(s.jwe, 1, 4096)`+refRevs+` JOIN sealed s ON s.ns = ? AND s.rev_seq = r.seq AND s.kind IN ('doc', 'entry')`+where+
		` AND NOT EXISTS (SELECT 1 FROM rev_epochs e WHERE e.seq = r.seq)`, p.m.id, seg.res, bid[:], seg.max)
	t.must(err)
	for rows.Next() {
		var prefix string
		t.must(rows.Scan(&prefix))
		if e, ok := jweEpoch(prefix); ok {
			out[e] = true
		}
	}
	rows.Close()
	return out
}

// preRaiseBlobRev returns the newest still served revision from before p's
// raise in head's history whose document references bid, or nil.
func (t *tx) preRaiseBlobRev(p *preRaise, head *revRow, bid ids.ID) *revRow {
	seg, ok := t.preRaiseSegment(p, head)
	if !ok {
		return nil
	}
	where := ` WHERE b.res = ? AND b.bid = ? AND r.seq <= ? AND r.kind = 0 AND ` + servedRev
	var seq int64
	err := t.QueryRow(`SELECT r.seq`+refRevs+where+` ORDER BY r.seq DESC LIMIT 1`, seg.res, bid[:], seg.max).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	return t.rev(seq)
}

// preRaiseBlobHead is sealedBlobHead for a blob from before p's raise from
// sealed, served by e2e namespace n: 302 to the latest epoch it is served
// under; where none of its referencing revisions has one yet, the sealing
// of the newest of them under the epoch it is served under, which fixes
// it once stored (under p.m); without any, 404 (no-store). Never the
// plaintext.
func (t *tx) preRaiseBlobHead(p *preRaise, name string, head *revRow, bid ids.ID, out *Blob) *sealJob {
	if e := latestEpoch(t.preRaiseBlobEpochs(p, head, bid)); e > 0 {
		out.Status, out.Epoch = 302, e
		return nil
	}
	if r := t.preRaiseBlobRev(p, head, bid); r != nil {
		if b, err := t.docBytesAt(r); err == nil {
			return t.preRaiseResJob(p, name, r, sealDoc, func() []byte { return b })
		}
	}
	out.Status, out.NoStore = 404, true
	return nil
}

// preRaiseBlobKeyEpochs is blobKeyEpochs for a blob from before p's raise
// from sealed: the epochs a request for it would be served under, those
// fixed, or, where none is, the one a request would fix by sealing its
// newest referencing revision (preRaiseBlobHead).
func (t *tx) preRaiseBlobKeyEpochs(p *preRaise, head *revRow, bid ids.ID) map[int]bool {
	eps := t.preRaiseBlobEpochs(p, head, bid)
	if len(eps) == 0 {
		if r := t.preRaiseBlobRev(p, head, bid); r != nil {
			eps[t.preRaiseEpoch(p.m, r, p.raise)] = true
		}
	}
	return eps
}

// preRaiseBlobOpens reports whether creds get keys opening blob bid of
// resource name of e2e namespace n where it is a blob from before a raise
// from sealed, as a copy or a batch's local source from n needs (§2.1
// Protection, §7.8): true for any other blob, which n serves as uploaded.
func (t *tx) preRaiseBlobOpens(n *nsRow, name string, bid ids.ID, creds []Credentials) bool {
	head := t.resolve(n, name, nil).head
	p := t.preRaiseBlob(n, head, bid)
	if p == nil {
		return true
	}
	return t.preRaiseKeysOpen(n, p, name, t.preRaiseBlobKeyEpochs(p, head, bid), creds)
}
