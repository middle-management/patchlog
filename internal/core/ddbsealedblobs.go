package core

// Blobs of sealed namespaces on DynamoDB (§E.2.2; sealedblobs.go). The
// epochs a blob is served under are derived as on SQL, from the
// revisions referencing it: with no blob_refs here, a segment's served
// documents (from its horizon on, and the kept ones below) are folded
// once per check and their references collected. A revision's epoch is
// the one it was written in (its REV item's), else that of its stored
// sealing. Sealings and the 410 markers of pruned epochs are BLOBEPOCH
// items (ddb/blobepochs.go), a sealing in a file under "e/" when the
// engine has a blob store.

import (
	"context"
	"encoding/hex"
	"io"
	"slices"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
)

// blobRefPositions lists, per blob, the positions of seg's served
// revisions whose documents reference it, ascending.
func (r *ddbReads) blobRefPositions(seg segment) map[ids.ID][]uint64 {
	if out, ok := r.blobRefs[seg]; ok {
		return out
	}
	out := map[ids.ID][]uint64{}
	if r.blobRefs == nil {
		r.blobRefs = map[segment]map[ids.ID][]uint64{}
	}
	r.blobRefs[seg] = out
	k := r.res[seg.res]
	rr := r.resItem(seg.res)
	if rr == nil || rr.Purged {
		return out
	}
	maxPos := r.revs[seg.max].key.pos
	add := func(pos uint64, doc any) {
		seen := map[ids.ID]bool{}
		for _, ref := range blobRefsOf(doc) {
			if !seen[ref.bid] {
				seen[ref.bid] = true
				out[ref.bid] = append(out[ref.bid], pos)
			}
		}
	}
	from := uint64(1)
	if rr.HorizonPos > 0 {
		from = rr.HorizonPos
		r.must(r.s.EachSnapshot(r.ctx, k.ns, k.name, func(pos uint64, doc any) error {
			if pos < from && pos <= maxPos {
				add(pos, doc)
			}
			return nil
		}))
	}
	if from <= maxPos {
		r.must(r.s.EachDocIn(r.ctx, k.ns, k.name, from, maxPos, func(pos uint64, doc any) error {
			add(pos, doc)
			return nil
		}))
	}
	for _, ps := range out {
		slices.Sort(ps)
	}
	return out
}

// servedEpochs adds to out the epochs under which n serves name's
// revision at pos in ns: the one it was written in, if n's own and it has
// one; else those of its stored sealings.
func (r *ddbReads) servedEpochs(n *nsRow, ns, name string, pos uint64, out map[int]bool) {
	ri, err := r.s.RevAt(r.ctx, ns, name, pos)
	r.must(err)
	if ri == nil || ri.Kind == "tombstone" {
		return
	}
	if ns == r.nsName(n.id) && ri.Epoch > 0 {
		out[ri.Epoch] = true
		return
	}
	for _, kind := range []string{sealDoc, sealEntry} {
		jwe, _, err := r.s.Sealed(r.ctx, r.nsName(n.id), kind, name+"/"+ri.ID)
		r.must(err)
		if e, ok := jweEpoch(jwe); ok && jwe != "" {
			out[e] = true
		}
	}
}

func (r *ddbReads) blobEpochs(n *nsRow, head *revRow, bid ids.ID) map[int]bool {
	out := map[int]bool{}
	if head == nil {
		return out
	}
	for _, seg := range r.ancestry(head) {
		k := r.res[seg.res]
		for _, pos := range r.blobRefPositions(seg)[bid] {
			r.servedEpochs(n, k.ns, k.name, pos, out)
		}
	}
	return out
}

func (r *ddbReads) blobEpochRow(n *nsRow, name string, bid ids.ID, ep int) (data []byte, file string, ok bool) {
	data, file, ok, err := r.s.BlobEpoch(r.ctx, r.nsName(n.id), name, bid.String(), ep)
	r.must(err)
	return data, file, ok
}

// sealedBlobHead: as SQL's (sealedblobs.go).
func (r *ddbReads) sealedBlobHead(n *nsRow, name string, bid ids.ID, out *Blob) *sealJob {
	v := r.resolve(n, name, nil)
	if e := latestEpoch(r.blobEpochs(n, v.head, bid)); e > 0 {
		out.Status, out.Epoch = 302, e
		return nil
	}
	if v.head != nil {
		if job := r.newestBlobRev(n, name, v.head, bid); job != nil {
			return job
		}
	}
	out.Status, out.NoStore = 404, true
	return nil
}

// newestBlobRev prepares the sealing of the newest still served revision
// of the history ending at head whose document references bid, or nil.
func (r *ddbReads) newestBlobRev(n *nsRow, name string, head *revRow, bid ids.ID) *sealJob {
	for _, seg := range r.ancestry(head) {
		k := r.res[seg.res]
		ps := r.blobRefPositions(seg)[bid]
		for i := len(ps) - 1; i >= 0; i-- {
			row := r.rev(r.revHandle(k.ns, k.name, ps[i]))
			b, err := r.docBytesAt(row)
			if err != nil {
				continue
			}
			return r.resJob(n, name, row, sealDoc, func() []byte { return b })
		}
	}
	return nil
}

// storeSealedBlob: put-if-absent of the BLOBEPOCH item, after reading
// again that the blob is still served under the epoch; a lost race's file
// is deleted.
func (b *ddbBackend) storeSealedBlob(ctx context.Context, job *sealedBlobJob, sealed []byte) ([]byte, error) {
	e := b.e
	r := newDDBReads(b, ctx)
	g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now()}}
	served, perr := ddbCheck(func() bool {
		n := g.nsByName(job.ns)
		if n == nil || n.purged || g.servableBlob(n, job.name, job.bid).status != 200 {
			return false
		}
		return r.blobEpochs(n, r.resolve(n, job.name, nil).head, job.bid)[job.epoch]
	})
	if perr != nil || !served {
		return nil, asErrOrNil(perr)
	}
	data := sealed
	mine, err := e.blobs.put(ddb.BlobEpochFile(job.ns, hex.EncodeToString(job.bid[:]), job.epoch), sealed)
	if err != nil {
		return nil, err
	}
	if mine != "" {
		data = nil
	}
	sd, sf, err := b.store.PutBlobEpoch(ctx, job.ns, job.name, job.bid.String(), job.epoch, data, mine, e.now().UnixMilli())
	if mine != "" && sf != mine {
		e.removeFiles([]string{mine})
	}
	switch {
	case err != nil:
		return nil, ddbAsErr(err)
	case sf == mine && mine != "":
		return sealed, nil
	case sf != "":
		f, err := e.blobs.open(sf)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(f)
	}
	return sd, nil
}

// blobEpochsOf lists, for every blob name in ns attaches, the epochs ns
// serves it under: what a prune compares against afterwards
// (resourceBlobEpochs).
func (b *ddbBackend) blobEpochsOf(ctx context.Context, ns, name string) (map[ids.ID]map[int]bool, error) {
	atts, err := b.store.Attachments(ctx, ns, name, false)
	if err != nil || len(atts) == 0 {
		return nil, err
	}
	r := newDDBReads(b, ctx)
	g := &gate{checkReads: r, checkState: &checkState{e: b.e, now: b.e.now()}}
	return ddbCheck(func() map[ids.ID]map[int]bool {
		out := map[ids.ID]map[int]bool{}
		n := g.nsByName(ns)
		if n == nil {
			return out
		}
		head := r.resolve(n, name, nil).head
		for _, a := range atts {
			if bid, err := ids.Parse(a.Bid); err == nil {
				out[bid] = r.blobEpochs(n, head, bid)
			}
		}
		return out
	})
}

// pruneBlobEpochs runs after a prune of name in ns, given the epochs each
// blob was served under before (pruneBlobEpochs of sealedblobs.go): an
// epoch no longer served is marked (410), its sealing deleted. The
// sealings of attachments the prune ended go with them (endAttachments).
func (b *ddbBackend) pruneBlobEpochs(ctx context.Context, ns, name string, before map[ids.ID]map[int]bool) error {
	now, err := b.blobEpochsOf(ctx, ns, name)
	if err != nil {
		return err
	}
	for bid, eps := range before {
		after, ok := now[bid]
		if !ok {
			continue // ended
		}
		for ep := range eps {
			if after[ep] {
				continue
			}
			f, err := b.store.MarkBlobEpoch(ctx, ns, name, bid.String(), ep, b.e.now().UnixMilli())
			if err != nil {
				return ddbAsErr(err)
			}
			if f != "" {
				b.e.removeFiles([]string{f})
			}
		}
	}
	return nil
}
