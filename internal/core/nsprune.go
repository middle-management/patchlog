package core

import (
	"context"
	"database/sql"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
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
	NSID    string // the prune entry's ns_id, if the horizon moved
	Archive string // the URL of the archive written, if any
}

// Prune prunes a resource's history below a horizon (§8.6), archiving the
// pruned range first when an archive destination is configured.
//
// The prune verb suffices when the archive exists and the horizon doesn't go
// below what the resource's retention rule keeps; otherwise the grant must
// be chained to a * key.
func (e *Engine) Prune(ctx context.Context, req Request, name string, pr PruneRequest) (*PruneResult, error) {
	return e.be.prune(ctx, req, name, pr)
}

// sqlPrune is Prune on SQL.
func (e *Engine) sqlPrune(ctx context.Context, req Request, name string, pr PruneRequest) (*PruneResult, error) {
	var out *PruneResult
	err := e.update(ctx, func(t *tx) error {
		p, perr := t.planPrune(req, name, pr)
		if perr != nil {
			return perr
		}
		var res *PruneResult
		var err error
		if p.e2e {
			res, err = t.pruneToE2E(p.n, p.cfg, name, p.own, p.h, p.hid, pr, p.dest, t.actorID(p.a))
		} else {
			res, err = t.pruneTo(p.n, name, p.own, p.h, p.keep, pr.Keep, p.dest, p.hasArchive, t.actorID(p.a))
		}
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// prunePlan is a prune the gate allowed (§8.6): of own, to horizon h,
// keeping keep.
type prunePlan struct {
	n          *nsRow
	cfg        *Config
	a          *actor // nil: the retention applier
	own        *resRow
	h          *revRow
	hid        ids.ID
	keep       []*revRow
	keepStrs   []string
	dest       string
	hasArchive bool
	e2e        bool
}

// planPrune checks a prune (§8.6, §6.2): authentication, the verb, the
// horizon and keep set, what the rules and retention allow.
func (t *gate) planPrune(req Request, name string, pr PruneRequest) (*prunePlan, *Error) {
	n := t.nsForWrite(req.NS)
	if n == nil {
		return nil, t.absentNS(req.NS, req.Cred)
	}
	cfg := t.config(n.configSeq)
	a, aerr := t.authenticate(n.name, n, cfg, req.Cred, nil)
	if aerr != nil {
		return nil, aerr
	}
	if err := t.authorize(a, "prune", name); err != nil {
		return nil, err
	}
	// 410 after authorisation, like every write (§6.2).
	if n.purged {
		return nil, t.purgedNS(n)
	}
	if n.isBranch() {
		return nil, invalid("branches don't prune (§8.6)")
	}
	v := t.resolve(n, name, nil)
	if v.state == NotFound {
		return nil, notFound()
	}
	if v.state == Purged {
		return nil, gone()
	}
	hid, err := ids.Parse(pr.Horizon)
	if err != nil {
		return nil, invalid("horizon must be an ancestor of the head")
	}
	h := t.findInAncestry(v.head, hid)
	if h == nil {
		return nil, invalid("horizon must be an ancestor of the head")
	}
	if len(pr.Keep) > cfg.Limits.KeepPerResource {
		return nil, limitErr(422, "keepPerResource", int64(len(pr.Keep)), int64(cfg.Limits.KeepPerResource), "too many kept revisions")
	}
	e2e := t.e2eContent(n, name)
	switch {
	case !e2e && pr.Snapshot != "":
		return nil, invalid("snapshot is only for e2e resources, whose documents the server can't compute (§8.6)")
	case e2e && len(pr.Keep) > 0:
		return nil, invalid("keep is not supported for e2e resources: the server can't keep documents it can't compute (protect revisions with retention or a lower horizon)")
	case e2e && pr.Snapshot == "":
		return nil, invalid("pruning an e2e resource needs the horizon's document as a sealed snapshot (§8.6)")
	}
	var keep []*revRow
	for _, k := range pr.Keep {
		kid, err := ids.Parse(k)
		var row *revRow
		if err == nil {
			row = t.findInAncestry(v.head, kid)
		}
		if row == nil || row.kind != kindRev {
			return nil, invalid("keep lists a revision that is not in the resource's history")
		}
		keep = append(keep, row)
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
		return nil, invalid("pruning an e2e resource needs an archive destination (§8.6)")
	}
	if !a.star {
		// Applying a rule that says "archive": false, within what it
		// keeps, needs only prune: the * key was needed to write it.
		if !hasArchive && !noArchive {
			return nil, forbidden("pruning where no archive is configured needs a grant chained to a * key")
		}
		if rule != nil && h.seq > t.retentionBoundary(rule, v.own) {
			return nil, forbidden("going below what retention keeps needs a grant chained to a * key")
		}
	}
	env := t.basicEnvelope("prune", name, a)
	env["writes"], env["patches"] = []any{}, []any{}
	env["doc"] = map[string]any{"horizon": pr.Horizon, "keep": anyStrings(pr.Keep)}
	if err := t.checkRules(cfg, a, env, false); err != nil {
		return nil, err
	}
	return &prunePlan{n: n, cfg: cfg, a: a, own: v.own, h: h, hid: hid, keep: keep, keepStrs: pr.Keep, dest: dest, hasArchive: hasArchive, e2e: e2e}, nil
}

// protect moves a horizon down past the protected revisions of §8.6: the
// retry window and the heads as of the at of every live local branch and
// every unexpired remote branch registration.
func (t *gate) protect(n *nsRow, cfg *Config, res int64, h *revRow) *revRow {
	cutoff := t.now.Add(-cfg.Limits.RetryWindow).UnixMilli()
	if seq, ok := t.firstRevSince(res, cutoff); ok && seq < h.seq {
		h = t.rev(seq)
	}
	var ats []int64
	for _, b := range t.allBranchesOf(n) {
		ats = append(ats, b.baseAt.Int64)
	}
	// Remote branches whose registration hasn't expired (§G.3).
	ats = append(ats, t.registeredAts(n)...)
	for _, at := range ats {
		if p, ok := t.headAtEntry(res, at); ok && p < h.seq {
			h = t.rev(p)
		}
	}
	return h
}

// firstRevSince is res's first revision created at or after cutoff
// (milliseconds).
func (t *tx) firstRevSince(res, cutoff int64) (int64, bool) {
	var seq sql.NullInt64
	t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ? AND created >= ?`, res, cutoff).Scan(&seq))
	return seq.Int64, seq.Valid
}

// headAtEntry is res's head as of its namespace's log entry at.
func (t *tx) headAtEntry(res, at int64) (int64, bool) {
	var p int64
	if err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq <= ? ORDER BY ns_seq DESC LIMIT 1`, res, at).Scan(&p); err != nil {
		return 0, false
	}
	return p, true
}

// pruneTo prunes own below h, which protect has already moved down. With
// archive set, the pruned range is written to dest first, and nothing is
// dropped unless that succeeds.
func (t *tx) pruneTo(n *nsRow, name string, own *resRow, h *revRow, keep []*revRow, keepStrs []string, dest string, archive bool, author int64) (*PruneResult, error) {
	cur := own.horizonSeq
	if cur.Valid && h.seq <= cur.Int64 {
		return &PruneResult{Horizon: t.rev(cur.Int64).id.String()}, nil
	}
	// A horizon with nothing of its resource's chain below it (a first
	// entry) prunes nothing, and a prune that changes nothing writes
	// nothing (§8.6).
	var below bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ? AND seq < ?)`, own.id, h.seq).Scan(&below))
	if !below {
		return &PruneResult{Horizon: h.id.String()}, nil
	}
	// Documents that stay available: the horizon (and for a tombstone the
	// last live document), kept revisions and referenced schemas.
	refs := t.referencedPaths()
	keepSeqs := map[int64]*revRow{}
	keepSeqs[t.lastLive(h).seq] = t.lastLive(h)
	for _, k := range keep {
		keepSeqs[k.seq] = k
	}
	// Referenced schema revisions keep their documents; one already below
	// an earlier horizon keeps the snapshot it has.
	preserve := map[int64]bool{}
	rrows, qerr := t.Query(`SELECT seq, id, patches IS NOT NULL FROM revisions WHERE res = ? AND seq < ? AND kind = 0`, own.id, h.seq)
	t.must(qerr)
	for rrows.Next() {
		var seq int64
		var id []byte
		var hasPatches bool
		t.must(rrows.Scan(&seq, &id, &hasPatches))
		if refs["/r/"+n.name+"/"+name+"/rev/"+ids.FromBytes(id).String()] {
			if hasPatches {
				keepSeqs[seq] = nil
			} else {
				preserve[seq] = true
			}
		}
	}
	rrows.Close()
	docs := map[int64][]byte{}
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
	// Archive before dropping anything (§8.6).
	res := &PruneResult{Horizon: h.id.String()}
	if archive {
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
	// written above carries their blobs.
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
	// Below the horizon only the documents kept above survive:
	// intermediate snapshots (D.4) and an earlier prune's keep set go,
	// or pruned revisions would still be served.
	srows, qerr := t.Query(`SELECT seq FROM snapshots WHERE res = ? AND seq < ?`, own.id, h.seq)
	t.must(qerr)
	var drop []int64
	for srows.Next() {
		var seq int64
		t.must(srows.Scan(&seq))
		if _, kept := keepSeqs[seq]; !kept && !preserve[seq] {
			drop = append(drop, seq)
		}
	}
	srows.Close()
	for _, seq := range drop {
		_, err = t.Exec(`DELETE FROM snapshots WHERE seq = ?`, seq)
		t.must(err)
	}
	t.flushDocs = true
	// Sealed copies of what was pruned go too, wherever they are served
	// (a branch reads through); kept documents keep their bytes.
	t.deletePrunedSealed(own.id, h.seq, keepSeqs)
	keepJSON := string(jsonv.Canonical(anyStrings(keepStrs)))
	_, err = t.Exec(`UPDATE resources SET horizon_seq = ?, keep = ? WHERE res = ?`, h.seq, keepJSON, own.id)
	t.must(err)
	if epochs != nil {
		t.pruneBlobEpochs(n, name, own.id, epochs)
	}
	target := h.seq
	_, nsID := t.appendNS(n, map[string]any{"resource": name, "kind": "prune", "target": h.id.String()}, &own.id, &target, n.configSeq, author)
	res.NSID = nsID.String()
	return res, nil
}
