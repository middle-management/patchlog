package core

// End-to-end namespaces on DynamoDB (§E.3; e2e.go). The gate's checks
// and the keys relay are the SQL path's; the table keeps each epoch's
// start as a keyless EPOCHKEY item (beginsEpoch), each e2e revision's
// declared blobs on its REV item (declared, standing in for blob_refs),
// no head documents, and a prune's client-sealed snapshot as an E2ESNAP
// item.

import (
	"bytes"
	"context"
	"errors"
	"log"
	"slices"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
)

// declaredAt: the declared list of row, or for a tombstone that of the
// last live revision before it (§E.3.1).
func (r *ddbReads) declaredAt(row *revRow) []ids.ID {
	for row.kind == kindTombstone && row.parentSeq.Valid {
		row = r.rev(row.parentSeq.Int64)
	}
	if row.kind == kindTombstone {
		return nil
	}
	k := r.revs[row.seq].key
	ri, err := r.s.RevAt(r.ctx, k.ns, k.name, k.pos)
	r.must(err)
	if ri == nil {
		return nil
	}
	var out []ids.ID
	for _, s := range ri.Declared {
		if id, err := ids.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b ids.ID) int { return bytes.Compare(a[:], b[:]) })
	return out
}

func (r *ddbReads) e2eSnapshot(row *revRow) string {
	k := r.revs[row.seq].key
	jwe, err := r.s.E2ESnapshot(r.ctx, k.ns, k.name, k.pos)
	r.must(err)
	return jwe
}

// e2eFoldSince: the latest snapshot at or before row, across its
// ancestry.
func (r *ddbReads) e2eFoldSince(row *revRow) string {
	for _, sg := range r.ancestry(row) {
		k := r.res[sg.res]
		pos, err := r.s.LatestE2ESnapshot(r.ctx, k.ns, k.name, r.revs[sg.max].key.pos)
		r.must(err)
		if pos > 0 {
			return r.rev(r.revHandle(k.ns, k.name, pos)).id.String()
		}
	}
	return ""
}

// pruneE2E prunes an e2e resource below p.h (pruneToE2E of e2e.go): the
// archive first, then the commit, which records snapshot as the horizon's
// document; finishPrune drops the patch sets below it, the earlier
// snapshots and the attachments no declared list keeps.
func (b *ddbBackend) pruneE2E(ctx context.Context, r *ddbReads, g *gate, p *prunePlan, snapshot, author, grant string, noAuth bool) (*PruneResult, error) {
	own, h := p.own, p.h
	if own.horizonSeq.Valid && h.seq <= own.horizonSeq.Int64 {
		return &PruneResult{Horizon: r.horizonID(own.id)}, nil
	}
	hk := r.revs[h.seq].key
	ns, name := hk.ns, hk.name
	if hk.pos <= 1 {
		return &PruneResult{Horizon: h.id.String()}, nil
	}
	if _, perr := ddbCheck(func() bool {
		if err := g.checkE2EPrune(p.n, p.cfg, name, h, p.hid, snapshot); err != nil {
			panic(err)
		}
		return true
	}); perr != nil {
		return nil, perr
	}
	var oldHorizon uint64
	if own.horizonSeq.Valid {
		oldHorizon = r.revs[own.horizonSeq.Int64].key.pos
	}
	arch, err := b.writeArchive(ctx, r, g, p)
	if err != nil {
		return nil, err
	}
	rr := r.resItem(own.id)
	c := &ddb.Commit{
		NS: ns, Author: author, Created: g.now.UnixMilli(), Grant: grant, NoAuth: noAuth, Via: viaOf(p.a),
		CfgPos: r.cfgs[p.n.configSeq].pos, CfgID: r.cfgRow(p.n.configSeq).ID,
		Entry: map[string]any{"resource": name, "kind": "prune", "target": h.id.String()}, Kind: "prune",
		Prune: &ddb.CommitPrune{
			Name: name, HeadPos: rr.HeadPos, HeadID: rr.HeadID, OldHorizon: oldHorizon,
			HorizonPos: hk.pos, HorizonID: h.id.String(), Base: hk.pos, Keep: "[]",
			Archive: arch, E2ESnapshot: snapshot,
		},
	}
	cres, err := b.commit(ctx, c)
	if err != nil {
		if errors.Is(err, ddb.ErrStale) {
			return nil, err
		}
		return nil, ddbAsErr(err)
	}
	// /rev/{h} serves the snapshot now, not the fold redirect a CDN may
	// hold (pruneToE2E).
	b.committed(ns, "r:"+ns+"/"+name)
	if err := b.finishPrune(ctx, ns, name); err != nil {
		log.Printf("ddb: prune of %s/%s committed, its content left to the sweep: %v", ns, name, err)
	}
	res := &PruneResult{Horizon: h.id.String(), NSID: cres.NSID}
	if arch != nil {
		res.Archive = arch.URL
	}
	return res, nil
}

// e2eLiveBlobs lists the blobs an e2e resource's served revisions declare
// (pruneBlobsE2E of e2e.go): the horizon's (its snapshot's document's,
// for a tombstone the last live one's) and every revision's after it.
func (b *ddbBackend) e2eLiveBlobs(ctx context.Context, ns, name string, rr *ddb.ResRow) (map[ids.ID]bool, error) {
	live := map[ids.ID]bool{}
	add := func(ri *ddb.RevInfo) {
		for _, s := range ri.Declared {
			if id, err := ids.Parse(s); err == nil {
				live[id] = true
			}
		}
	}
	for pos := rr.HorizonPos; pos > 0; pos-- {
		ri, err := b.store.RevAt(ctx, ns, name, pos)
		if err != nil {
			return nil, err
		}
		if ri == nil {
			break
		}
		if ri.Kind != "tombstone" {
			add(ri)
			break
		}
	}
	err := b.store.RevsBetween(ctx, ns, name, rr.HorizonPos, rr.HeadPos, 0, func(ri *ddb.RevInfo) bool {
		add(ri)
		return true
	})
	return live, err
}

// archivedDeclared is archivedBlobs for an e2e resource: its revisions'
// declared lists stand in for blob_refs, a blob listed at the first
// revision of each run declaring it (a tombstone keeps its last live
// revision's list), and at the range's start for a run reaching into it.
func (r *ddbReads) archivedDeclared(k ddbResRef, fromSeq, lastSeq int64) map[int64][]ids.ID {
	out := map[int64][]ids.ID{}
	prev := map[ids.ID]bool{}
	for pos := r.revs[fromSeq].key.pos; pos <= r.revs[lastSeq].key.pos; pos++ {
		h := r.revHandle(k.ns, k.name, pos)
		cur := map[ids.ID]bool{}
		for _, bid := range r.declaredAt(r.rev(h)) {
			cur[bid] = true
			if !prev[bid] {
				out[h] = append(out[h], bid)
			}
		}
		prev = cur
	}
	return out
}
