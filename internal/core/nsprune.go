package core

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// PruneRequest is POST /r/{ns}/{name}/prune (§8.6).
type PruneRequest struct {
	Horizon string
	Keep    []string
	// KeepSent reports that the request sent keep, so that keep: []
	// (clear the keep set) is told from no keep (leave it) (§8.6, §6.4.1).
	KeepSent bool
	// Snapshot is the horizon's document sealed by a key-holding client
	// (seal.SealSnapshot), required for e2e resources and refused
	// elsewhere (§8.6).
	Snapshot string
	// Precondition reports that the request sent If-Match or
	// If-None-Match, which a prune doesn't take: 428 at step 2.5 (§7.2,
	// §8.6). Both together are the server's 400.
	Precondition bool
}

// PruneResult is the answer to a prune.
type PruneResult struct {
	Horizon string // the effective horizon
	// NSID is the prune entry's ns_id, if the prune moved the horizon or
	// changed the keep set (§8.6).
	NSID    string
	Archive string // the URL of the archive written, if any
}

// Prune prunes a resource's history below a horizon (§8.6), archiving the
// pruned range first when an archive destination is configured. In a
// branch it moves nothing (pruneInBranch).
//
// The prune verb suffices when the archive exists and neither the horizon
// nor a change to the keep set goes below what the resource's retention
// rule keeps, which is everything where no rule matches it; otherwise the
// grant must be chained to a * key.
//
// The checks follow §6.2: the verb and the rate limits (step 1); a purged
// namespace or resource (2.1); a precondition sent, which a prune doesn't
// take (2.5); the horizon, keep and snapshot, and at E3 the archive (4);
// the *-key guard and the rules (6).
func (e *Engine) Prune(ctx context.Context, req Request, name string, pr PruneRequest) (*PruneResult, error) {
	var out *PruneResult
	err := e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(req.NS)
		if n == nil {
			return t.absentNS(req.NS, req.Cred)
		}
		cfg := t.config(n.configSeq)
		a, aerr := t.authenticate(n.name, n, cfg, req.Cred, nil)
		if aerr != nil {
			return aerr
		}
		if err := t.authorize(a, "prune", name); err != nil {
			return err
		}
		// A prune isn't exempt: a token from the principal, namespace and
		// per-resource buckets, checked last in step 1 (§6.6).
		if err := t.rateLimit(n, cfg, a, []string{name}, 1); err != nil {
			return err
		}
		// 410 after authorisation and the rate limits, like every write
		// (§6.2 step 2.1, §8.5); then §1's 502, and a purged resource's
		// 410 (§8.3).
		if n.purged {
			return t.purgedNS(n)
		}
		if err := t.upstreamRefusal(n, name); err != nil {
			return err
		}
		v := t.resolve(n, name, nil)
		if v.state == Purged {
			return gone()
		}
		// A prune takes no precondition: one sent is 428 at step 2.5
		// (§7.2, §8.6).
		if pr.Precondition {
			return apiErr(428, "precondition_required", "message", "a prune takes no precondition (§7.2, §8.6)")
		}
		if v.state == NotFound {
			return notFound()
		}
		// Step 4: horizon, keep and snapshot (§6.2, §8.6).
		hid, err := ids.Parse(pr.Horizon)
		var h *revRow
		if err == nil {
			h = t.findInAncestry(v.head, hid)
		}
		if h == nil {
			return invalid("horizon must be the head or an ancestor of it (§8.6)")
		}
		if len(pr.Keep) > cfg.Limits.KeepPerResource {
			return limitErr(422, "keepPerResource", int64(len(pr.Keep)), int64(cfg.Limits.KeepPerResource), "too many kept revisions")
		}
		e2e := t.e2eContent(n, name)
		switch {
		case !e2e && pr.Snapshot != "":
			return invalid("snapshot is only for e2e resources, whose documents the server can't compute (§8.6)")
		case e2e && len(pr.Keep) > 0:
			return invalid("keep is not supported for e2e resources: the server can't keep documents it can't compute (protect revisions with retention or a lower horizon)")
		case e2e && pr.Snapshot == "":
			return invalid("pruning an e2e resource needs the horizon's document as a sealed snapshot (§8.6)")
		}
		// The envelope's doc is { horizon, keep? } as sent (§6.4.1).
		doc := map[string]any{"horizon": pr.Horizon}
		if pr.KeepSent {
			doc["keep"] = anyStrings(pr.Keep)
		}
		env := t.basicEnvelope("prune", name, a)
		env["writes"], env["patches"], env["doc"] = []any{}, []any{}, doc
		if n.isBranch() {
			res, err := t.pruneInBranch(n, cfg, a, name, v, hid, pr, env)
			out = res
			return err
		}
		// Outside a branch, each keep id is a revision of the resource
		// whose document is still served, whether or not the horizon
		// moves (§8.6).
		var keep []*revRow
		for _, k := range pr.Keep {
			kid, err := ids.Parse(k)
			var row *revRow
			if err == nil {
				row = t.findInAncestry(v.head, kid)
			}
			if row == nil || row.kind != kindRev {
				return invalid("keep lists a revision that is not in the resource's history")
			}
			if _, err := t.docBytesAt(row); err != nil {
				return invalid(fmt.Sprintf("keep lists revision %s, whose document is no longer served (§8.6)", k))
			}
			keep = append(keep, row)
		}
		keepStrs := pr.Keep
		if !pr.KeepSent {
			// A prune without keep leaves the keep set (§8.6).
			keep, keepStrs = t.storedKeep(v.own)
		}
		h = t.protect(n, cfg, v.own.id, h)
		rule := cfg.retentionRule(name)
		dest, hasArchive := t.archiveDest(rule)
		noArchive := rule != nil && rule.NoArchive
		if noArchive {
			// The rule prunes without an archive (§8.6).
			dest, hasArchive = "", false
		}
		if e2e && !hasArchive {
			return invalid("pruning an e2e resource needs an archive destination (§8.6)")
		}
		eff, moves := t.effectiveHorizon(v.own, h)
		if e2e && moves {
			// At E3 the snapshot is the requested horizon's document, so
			// an effective horizon that moves the horizon but isn't it is
			// 422 naming it, and the snapshot's header is checked, both
			// at step 4, before the *-key guard (§6.2, §8.6, §E.3.1).
			// pruneToE2E checks them again as it writes.
			if eff.id != hid {
				return apiErr(422, "invalid", "message", "the horizon moves down to a protected revision (§8.6); seal the snapshot for that one", "horizon", eff.id.String())
			}
			epoch, why := t.snapshotEpoch(n, cfg, eff)
			if err := t.checkSealedHeader(n, pr.Snapshot, seal.SnapshotPL(n.name, name, eff.id.String()), "snapshot", epoch, why); err != nil {
				return err
			}
		}
		// Step 6: the *-key guard, then the rules (§6.2).
		if !a.star {
			// Applying a rule that says "archive": false, within what it
			// keeps, needs only prune: the * key was needed to write it.
			if !hasArchive && !noArchive {
				return forbidden("pruning where no archive is configured needs a grant chained to a * key")
			}
			// Retention keeps everything where no rule matches the
			// resource, so a prune that moves the horizon there goes
			// below it (§8.6).
			if moves && (rule == nil || eff.seq > t.retentionBoundary(rule, v.own)) {
				return forbidden("going below what retention keeps, everything where no retention rule matches the resource, needs a grant chained to a * key (§8.6)")
			}
			// A prune that changes only the keep set drops the documents
			// below the horizon that it no longer keeps (pruneTo), such as
			// those an earlier * prune kept; dropping one that retention
			// keeps goes below it as much as moving the horizon would. A
			// prune that moves the horizon within what retention keeps
			// drops only documents below it, and an E3 prune that moves
			// nothing writes nothing (pruneToE2E).
			if !e2e && !moves && pr.KeepSent && keepChanged(v.own, keepStrs) {
				keepSeqs, preserve := t.keptBelow(n, name, v.own, eff, keep)
				if drop := t.droppedBelow(v.own.id, eff.seq, keepSeqs, preserve); len(drop) > 0 && (rule == nil || drop[len(drop)-1] >= t.retentionBoundary(rule, v.own)) {
					return forbidden("dropping a kept document that retention keeps, everything where no retention rule matches the resource, needs a grant chained to a * key (§8.6)")
				}
			}
		}
		if err := t.checkRules(cfg, a, env, false); err != nil {
			return err
		}
		var res *PruneResult
		var perr error
		if e2e {
			res, perr = t.pruneToE2E(n, cfg, name, v.own, h, hid, pr, dest, t.actorID(a))
		} else {
			res, perr = t.pruneTo(n, name, v.own, h, keep, keepStrs, pr.KeepSent, dest, hasArchive, t.actorID(a))
		}
		if perr != nil {
			return perr
		}
		out = res
		return nil
	})
	return out, err
}

// pruneInBranch finishes a prune in branch n once the checks it shares with
// a base's have passed (§8.6 "Branches don't prune"): only the base prunes
// the history a branch reads through, and a branch's own entries are
// protected until it is purged. It runs the rules, moves no horizon,
// ignores keep, which is checked only against keepPerResource, writes
// nothing, and answers the resource's current horizon as the branch sees
// it. No archive is needed, nor a * key, since nothing is pruned. At E3 the
// snapshot is still checked at step 4, its kid included: it must name the
// branch, never a base, and the epoch snapshotEpoch gives for the horizon's
// chain, as outside a branch (§13, F-B6, §E.3.1).
func (t *tx) pruneInBranch(n *nsRow, cfg *Config, a *actor, name string, v *view, hid ids.ID, pr PruneRequest, env map[string]any) (*PruneResult, error) {
	if t.e2eContent(n, name) {
		epoch, why := t.snapshotEpoch(n, cfg, t.findInAncestry(v.head, hid))
		if err := t.checkSealedHeader(n, pr.Snapshot, seal.SnapshotPL(n.name, name, hid.String()), "snapshot", epoch, why); err != nil {
			return nil, err
		}
	}
	if err := t.checkRules(cfg, a, env, false); err != nil {
		return nil, err
	}
	return &PruneResult{Horizon: t.branchHorizon(v.head)}, nil
}

// branchHorizon is a resource's horizon as a branch sees it (§8.6): that of
// the newest segment of head's ancestry whose resource has one, a base's
// the branch reads through, as its pruned revisions' 410 names it (§7.1);
// otherwise the ancestry's genesis.
func (t *tx) branchHorizon(head *revRow) string {
	segs := t.ancestry(head)
	for _, sg := range segs {
		if id := t.horizonID(sg.res); id != "" {
			return id
		}
	}
	var g int64
	t.must(t.QueryRow(`SELECT seq FROM revisions WHERE res = ? AND first = 1`, segs[len(segs)-1].res).Scan(&g))
	return t.revID(g).String()
}

// storedKeep is own's keep set (§8.6): its revisions in the resource's
// history, and their ids as stored.
func (t *tx) storedKeep(own *resRow) (keep []*revRow, keepStrs []string) {
	if !own.keep.Valid || !own.headSeq.Valid {
		return nil, nil
	}
	head := t.rev(own.headSeq.Int64)
	a, _ := jsonv.MustParse([]byte(own.keep.String)).([]any)
	for _, x := range a {
		s, _ := x.(string)
		id, err := ids.Parse(s)
		if err != nil {
			continue
		}
		if row := t.findInAncestry(head, id); row != nil && row.kind == kindRev {
			keep = append(keep, row)
			keepStrs = append(keepStrs, s)
		}
	}
	return keep, keepStrs
}

// keepChanged reports whether keep, as a set, differs from own's stored
// keep set (§8.6); an absent set is empty.
func keepChanged(own *resRow, keep []string) bool {
	var old []string
	if own.keep.Valid {
		a, _ := jsonv.MustParse([]byte(own.keep.String)).([]any)
		for _, x := range a {
			s, _ := x.(string)
			old = append(old, s)
		}
	}
	set := func(xs []string) map[string]bool {
		m := make(map[string]bool, len(xs))
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	a, b := set(old), set(keep)
	if len(a) != len(b) {
		return true
	}
	for x := range a {
		if !b[x] {
			return true
		}
	}
	return false
}

// effectiveHorizon is the horizon a prune to h, which protect has already
// moved down, leaves own at, never below the current one (§8.6), and
// whether that moves the horizon: a horizon with nothing of its resource's
// chain below it (a first entry) prunes nothing.
func (t *tx) effectiveHorizon(own *resRow, h *revRow) (*revRow, bool) {
	if cur := own.horizonSeq; cur.Valid && h.seq <= cur.Int64 {
		return t.rev(cur.Int64), false
	}
	var below bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ? AND seq < ?)`, own.id, h.seq).Scan(&below))
	return h, below
}

// protect moves a horizon down past the protected revisions of §8.6: the
// retry window and the heads as of the at of every live local branch and
// every unexpired remote branch registration.
func (t *tx) protect(n *nsRow, cfg *Config, res int64, h *revRow) *revRow {
	var minSeq sql.NullInt64
	cutoff := t.now.Add(-cfg.Limits.RetryWindow).UnixMilli()
	t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ? AND created >= ?`, res, cutoff).Scan(&minSeq))
	if minSeq.Valid && minSeq.Int64 < h.seq {
		h = t.rev(minSeq.Int64)
	}
	var ats []int64
	for _, b := range t.allBranchesOf(n) {
		ats = append(ats, b.baseAt.Int64)
	}
	// Remote branches whose registration hasn't expired (§G.3).
	ats = append(ats, t.registeredAts(n)...)
	for _, at := range ats {
		var p int64
		if err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq <= ? ORDER BY ns_seq DESC LIMIT 1`, res, at).Scan(&p); err == nil && p < h.seq {
			h = t.rev(p)
		}
	}
	return h
}

// keptBelow is what keeps its document below h, the effective horizon of a
// prune of own keeping keep (§8.6): keepSeqs holds h (for a tombstone the
// last live revision), keep, and the referenced schema revisions that still
// have their patch sets (nil rows); preserve holds the referenced schema
// revisions already below an earlier horizon, which keep the snapshot they
// have.
func (t *tx) keptBelow(n *nsRow, name string, own *resRow, h *revRow, keep []*revRow) (keepSeqs map[int64]*revRow, preserve map[int64]bool) {
	refs := t.referencedPaths()
	keepSeqs = map[int64]*revRow{}
	keepSeqs[t.lastLive(h).seq] = t.lastLive(h)
	for _, k := range keep {
		keepSeqs[k.seq] = k
	}
	preserve = map[int64]bool{}
	rows, err := t.Query(`SELECT seq, id, patches IS NOT NULL FROM revisions WHERE res = ? AND seq < ? AND kind = 0`, own.id, h.seq)
	t.must(err)
	for rows.Next() {
		var seq int64
		var id []byte
		var hasPatches bool
		t.must(rows.Scan(&seq, &id, &hasPatches))
		if refs["/r/"+n.name+"/"+name+"/rev/"+ids.FromBytes(id).String()] {
			if hasPatches {
				keepSeqs[seq] = nil
			} else {
				preserve[seq] = true
			}
		}
	}
	rows.Close()
	return keepSeqs, preserve
}

// droppedBelow lists the stored documents of res below the horizon hseq
// that a prune keeping keepSeqs and preserve (keptBelow) drops, in seq
// order: intermediate snapshots (D.4) and the documents an earlier keep set
// kept but this one doesn't, or pruned revisions would still be served.
func (t *tx) droppedBelow(res, hseq int64, keepSeqs map[int64]*revRow, preserve map[int64]bool) []int64 {
	rows, err := t.Query(`SELECT seq FROM snapshots WHERE res = ? AND seq < ? ORDER BY seq`, res, hseq)
	t.must(err)
	var drop []int64
	for rows.Next() {
		var seq int64
		t.must(rows.Scan(&seq))
		if _, kept := keepSeqs[seq]; !kept && !preserve[seq] {
			drop = append(drop, seq)
		}
	}
	rows.Close()
	return drop
}

// pruneTo prunes own below h, which protect has already moved down, and
// with keepSent replaces its keep set with keep (keepStrs as sent);
// otherwise keep is the stored set, which stays. With archive set, the
// pruned range is written to dest first, and nothing is dropped unless
// that succeeds. A prune entry, targeting the effective horizon, is
// appended only if the horizon moved or the keep set changed: a prune that
// changes nothing writes nothing (§8.6).
func (t *tx) pruneTo(n *nsRow, name string, own *resRow, h *revRow, keep []*revRow, keepStrs []string, keepSent bool, dest string, archive bool, author int64) (*PruneResult, error) {
	cur := own.horizonSeq
	h, moves := t.effectiveHorizon(own, h)
	changed := keepSent && keepChanged(own, keepStrs)
	res := &PruneResult{Horizon: h.id.String()}
	if !moves && !changed {
		return res, nil
	}
	keepSeqs, preserve := t.keptBelow(n, name, own, h, keep)
	// A prune that changes only the keep set moves nothing: the documents
	// it keeps below the horizon are those still served there, which have
	// their snapshots, and those above it are served anyway.
	docs := map[int64][]byte{}
	if moves {
		for seq, row := range keepSeqs {
			if row == nil {
				row = t.rev(seq)
			}
			doc, err := t.docBytesAt(row)
			if err != nil {
				return nil, invalid("a kept revision was already pruned")
			}
			docs[seq] = doc
		}
	}
	// Archive before dropping anything (§8.6).
	if moves && archive {
		from := own.horizonSeq.Int64
		if !cur.Valid {
			t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ?`, own.id).Scan(&from))
		}
		u, err := t.writeArchive(n, name, own.id, from, h, dest)
		if err != nil {
			return nil, err
		}
		res.Archive = u
	}
	for seq, doc := range docs {
		_, err := t.Exec(`INSERT INTO snapshots (seq, res, doc) VALUES (?,?,?) ON CONFLICT (seq) DO UPDATE SET res = excluded.res, doc = excluded.doc`, seq, own.id, t.putDoc("snapshots", own.id, seq, doc))
		t.must(err)
	}
	// Attachments no kept document references end (§7.8); the archive
	// written above, or when the horizon passed them, carries their blobs.
	kept := make([]int64, 0, len(keepSeqs)+len(preserve))
	for seq := range keepSeqs {
		kept = append(kept, seq)
	}
	for seq := range preserve {
		kept = append(kept, seq)
	}
	var epochs map[ids.ID]map[int]bool
	if t.isSealedNS(n) {
		// The epochs each blob is served under, before (§E.2.2).
		epochs = t.resourceBlobEpochs(n, own)
	}
	t.pruneBlobs(own.id, h.seq, kept)
	// Only patch sets go: ids, created times, gestures and a head's size
	// and digest (headMeta) are metadata the rows keep, so /heads at an
	// earlier ns_id lists a pruned head as it did.
	_, err := t.Exec(`UPDATE revisions SET patches = NULL WHERE res = ? AND seq < ? AND kind = 0`, own.id, h.seq)
	t.must(err)
	// Below the horizon only the documents kept above survive.
	for _, seq := range t.droppedBelow(own.id, h.seq, keepSeqs, preserve) {
		_, err = t.Exec(`DELETE FROM snapshots WHERE seq = ?`, seq)
		t.must(err)
	}
	t.flushDocs = true
	// Sealed copies of what was pruned go too, wherever they are served
	// (a branch reads through); kept documents keep their bytes, the
	// preserved schema revisions' included, which are still served and so
	// keep the sealing stored once (§E.2.2).
	keptDocs := make(map[int64]*revRow, len(keepSeqs)+len(preserve))
	for seq, row := range keepSeqs {
		keptDocs[seq] = row
	}
	for seq := range preserve {
		keptDocs[seq] = nil
	}
	t.deletePrunedSealed(own.id, h.seq, keptDocs)
	if moves {
		_, err = t.Exec(`UPDATE resources SET horizon_seq = ? WHERE res = ?`, h.seq, own.id)
		t.must(err)
	}
	if keepSent {
		// keep replaces the keep set, and [] clears it (§8.6).
		_, err = t.Exec(`UPDATE resources SET keep = ? WHERE res = ?`, string(jsonv.Canonical(anyStrings(keepStrs))), own.id)
		t.must(err)
	}
	if epochs != nil {
		t.pruneBlobEpochs(n, name, own.id, epochs)
	}
	target := h.seq
	_, nsID := t.appendNS(n, map[string]any{"resource": name, "kind": "prune", "target": h.id.String()}, &own.id, &target, n.configSeq, author)
	res.NSID = nsID.String()
	return res, nil
}
