package core

// Pruning on DynamoDB (§8.6): the gate's planPrune or planRetention over
// the table's reads, then the commit of what they decided
// (ddb.Commit.Prune), checked again if what it pinned moved. The
// documents that stay below the horizon — its last live one, the keep
// set's, referenced schema revisions' — are snapshots written just
// before the commit. Reads go by the horizon from the commit on; the
// patch sets below it, the snapshots an earlier prune kept that this one
// doesn't, and the attachments no servable document references go right
// after it (finishPrune), or, if the instance stopped first, with the
// next blob sweep. A prune that archives writes its archive first
// (ddbarchive.go); e2e namespaces can't be created here.

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func (b *ddbBackend) prune(ctx context.Context, req Request, name string, pr PruneRequest) (res *PruneResult, err error) {
	e := b.e
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true}}
		type planned struct {
			p   *prunePlan
			err *Error
		}
		out, perr := ddbCheck(func() planned {
			p, err := g.planPrune(req, name, pr)
			return planned{p, err}
		})
		switch {
		case perr != nil:
			return nil, perr
		case out.err != nil:
			return nil, out.err
		}
		gid, err := b.storeGrant(ctx, out.p.a, out.p.cfg.level >= levelAtRest)
		if err != nil {
			return nil, err
		}
		var res *PruneResult
		if out.p.e2e {
			res, err = b.pruneE2E(ctx, r, g, out.p, pr.Snapshot, out.p.a.id(), gid, out.p.a.noAuth)
		} else {
			res, err = b.pruneTo(ctx, r, g, out.p, out.p.a.id(), gid, out.p.a.noAuth)
		}
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		return res, err
	}
	return nil, apiErr(409, "conflict", "detail", "the resource's state kept moving")
}

// retain applies retention to name in ns (ApplyRetention).
func (b *ddbBackend) retain(ctx context.Context, ns, name string) (checked, pruned bool, err error) {
	e := b.e
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true}}
		type planned struct {
			p       *prunePlan
			checked bool
			err     error
		}
		out, perr := ddbCheck(func() planned {
			p, checked, err := g.planRetention(ns, name)
			return planned{p, checked, err}
		})
		switch {
		case perr != nil:
			return false, false, perr
		case out.p == nil || out.err != nil:
			return out.checked, false, out.err
		}
		res, err := b.pruneTo(ctx, r, g, out.p, RetentionAuthor, "", false)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return true, false, err
		}
		return true, res.NSID != "", nil
	}
	return true, false, apiErr(409, "conflict", "detail", "the resource's state kept moving")
}

// prunePlanned is what a prune commits: the documents that stay below
// the new horizon, by position, and the earlier snapshots it keeps.
type prunePlanned struct {
	docs     map[uint64][]byte
	preserve []uint64
	base     uint64 // the horizon's last live revision
}

// pruneTo prunes p.own below p.h (pruneTo of nsops.go), as author under
// grant: ddb.ErrStale if what it pinned moved.
func (b *ddbBackend) pruneTo(ctx context.Context, r *ddbReads, g *gate, p *prunePlan, author, grant string, noAuth bool) (*PruneResult, error) {
	own, h := p.own, p.h
	if own.horizonSeq.Valid && h.seq <= own.horizonSeq.Int64 {
		return &PruneResult{Horizon: r.horizonID(own.id)}, nil
	}
	hk := r.revs[h.seq].key
	ns, name := hk.ns, hk.name
	// A horizon with nothing below it (a first entry) prunes nothing,
	// and a prune that changes nothing writes nothing (§8.6).
	if hk.pos <= 1 {
		return &PruneResult{Horizon: h.id.String()}, nil
	}
	var oldHorizon uint64
	if own.horizonSeq.Valid {
		oldHorizon = r.revs[own.horizonSeq.Int64].key.pos
	}
	pl, perr := ddbCheck(func() *prunePlanned {
		pl := &prunePlanned{docs: map[uint64][]byte{}}
		rows := map[uint64]*revRow{}
		base := g.lastLive(h)
		pl.base = r.revs[base.seq].key.pos
		rows[pl.base] = base
		for _, k := range p.keep {
			rows[r.revs[k.seq].key.pos] = k
		}
		// Referenced schema revisions keep their documents; one already
		// below an earlier horizon keeps the snapshot it has.
		prefix := "/r/" + p.n.name + "/" + name + "/rev/"
		for path := range g.referencedPaths() {
			id, err := ids.Parse(strings.TrimPrefix(path, prefix))
			if !strings.HasPrefix(path, prefix) || err != nil {
				continue
			}
			row := r.revByID(p.n, name, id)
			if row == nil || row.kind != kindRev {
				continue
			}
			switch pos := r.revs[row.seq].key.pos; {
			case pos >= hk.pos:
			case pos < oldHorizon:
				pl.preserve = append(pl.preserve, pos)
			default:
				rows[pos] = row
			}
		}
		for pos, row := range rows {
			doc, err := g.docBytesAt(row)
			if err != nil {
				panic(invalid("a kept revision was already pruned"))
			}
			pl.docs[pos] = doc
		}
		return pl
	})
	if perr != nil {
		return nil, perr
	}
	// Archive before anything is dropped (§8.6).
	var arch *ddb.ArchiveRow
	if p.hasArchive {
		var err error
		if arch, err = b.writeArchive(ctx, r, g, p); err != nil {
			return nil, err
		}
	}
	if p.cfg.level >= levelAtRest {
		dek, err := b.dekFor(ctx, ns, name, true)
		if err != nil {
			return nil, asErrOrNil(err)
		}
		for pos, doc := range pl.docs {
			pl.docs[pos] = []byte(sealValue(dek, "snap", ns, name, strconv.FormatUint(pos, 10), string(doc)))
		}
	}
	if err := b.store.PutSnapshots(ctx, ns, name, pl.docs); err != nil {
		return nil, ddbAsErr(err)
	}
	kept := pl.preserve
	for pos := range pl.docs {
		kept = append(kept, pos)
	}
	var epochs map[ids.ID]map[int]bool
	if p.cfg.level == levelSealed {
		// The epochs each blob is served under, before (§E.2.2).
		var err error
		if epochs, err = b.blobEpochsOf(ctx, ns, name); err != nil {
			return nil, err
		}
	}
	rr := r.resItem(own.id)
	c := &ddb.Commit{
		NS: ns, Author: author, Created: g.now.UnixMilli(), Grant: grant, NoAuth: noAuth,
		CfgPos: r.cfgs[p.n.configSeq].pos, CfgID: r.cfgRow(p.n.configSeq).ID,
		Entry: map[string]any{"resource": name, "kind": "prune", "target": h.id.String()}, Kind: "prune",
		Prune: &ddb.CommitPrune{
			Name: name, HeadPos: rr.HeadPos, HeadID: rr.HeadID, OldHorizon: oldHorizon,
			HorizonPos: hk.pos, HorizonID: h.id.String(), Base: pl.base,
			Keep: string(jsonv.Canonical(anyStrings(p.keepStrs))), Kept: kept, Archive: arch,
		},
	}
	cres, err := b.commit(ctx, c)
	if err != nil {
		if errors.Is(err, ddb.ErrStale) {
			return nil, err
		}
		return nil, ddbAsErr(err)
	}
	if err := b.finishPrune(ctx, ns, name); err != nil {
		log.Printf("ddb: prune of %s/%s committed, its content left to the sweep: %v", ns, name, err)
	}
	if epochs != nil {
		if err := b.pruneBlobEpochs(ctx, ns, name, epochs); err != nil {
			log.Printf("ddb: prune of %s/%s committed, its blobs' pruned epochs not marked: %v", ns, name, err)
		}
	}
	res := &PruneResult{Horizon: h.id.String(), NSID: cres.NSID}
	if arch != nil {
		res.Archive = arch.URL
	}
	return res, nil
}

// finishPrune drops what a committed prune of name in ns left
// (ddb.Store.PruneContent), ends the attachments no document it leaves
// servable references, as SQL's pruneBlobs does in the prune, and then
// its marker. It is idempotent: the sweep finishes one interrupted.
func (b *ddbBackend) finishPrune(ctx context.Context, ns, name string) error {
	ok, err := b.store.PruneContent(ctx, ns, name)
	if err != nil || !ok {
		return err
	}
	for attempt := 0; ; attempt++ {
		err := b.endAttachments(ctx, ns, name)
		if err == nil {
			break
		}
		if !errors.Is(err, ddb.ErrStale) || attempt >= ddbAttempts {
			return err
		}
	}
	return b.store.DonePruning(ctx, ns, name)
}

// endAttachments ends name's attachments that no document from its
// horizon's on, nor a kept one, references (§7.8), then collects the
// bytes nothing names any more. ddb.ErrStale if a write moved the head
// meanwhile: it may reference one.
func (b *ddbBackend) endAttachments(ctx context.Context, ns, name string) error {
	rr, err := b.store.Resource(ctx, ns, name)
	if err != nil || rr == nil || rr.Purged {
		return err
	}
	atts, err := b.store.Attachments(ctx, ns, name, false)
	if err != nil || len(atts) == 0 {
		return err
	}
	lvl, err := b.nsLevelOf(ctx, ns)
	if err != nil {
		return err
	}
	if lvl == levelE2E && name != KeyringName {
		live, err := b.e2eLiveBlobs(ctx, ns, name, rr)
		if err != nil {
			return err
		}
		return b.endUnreferenced(ctx, ns, name, rr, atts, live)
	}
	live := map[ids.ID]bool{}
	refs := func(doc any) error {
		for _, ref := range blobRefsOf(doc) {
			live[ref.bid] = true
		}
		return nil
	}
	if err := b.store.EachSnapshot(ctx, ns, name, func(_ uint64, doc any) error { return refs(doc) }); err != nil {
		return err
	}
	if err := b.store.EachDoc(ctx, ns, name, rr.HeadPos, refs); err != nil {
		return err
	}
	return b.endUnreferenced(ctx, ns, name, rr, atts, live)
}

// endUnreferenced ends the attachments atts of name that live doesn't
// name, with their sealings, and collects their bytes.
func (b *ddbBackend) endUnreferenced(ctx context.Context, ns, name string, rr *ddb.ResRow, atts []*ddb.BlobRow, live map[ids.ID]bool) error {
	var hashes [][]byte
	for _, a := range atts {
		bid, err := ids.Parse(a.Bid)
		if err != nil || live[bid] {
			continue
		}
		if err := b.store.EndAttachment(ctx, ns, name, a.Bid, rr.HeadPos, rr.HeadID); err != nil {
			return err
		}
		hashes = append(hashes, a.Hash)
		// Its sealings go with it (pruneBlobEpochs of sealedblobs.go).
		sealings, err := b.store.DeleteBlobEpochs(ctx, ns, name, a.Bid)
		b.e.removeFiles(sealings)
		if err != nil {
			return err
		}
	}
	files, err := b.store.CollectBytes(ctx, hashes)
	b.e.removeFiles(files)
	return err
}
