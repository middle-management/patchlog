package core

// Archives on DynamoDB (§8.6, §D.4). A prune that archives builds its
// archive with the gate's archiveBundle over the table's reads — the
// range's documents, folded, stand in for blob_refs — writes it before
// its commit, and records it in the commit (ddb.CommitPrune.Archive), as
// SQL writes it in the prune's transaction before dropping anything. A
// purge deletes the archives with its content (finishPurge). Restoring
// puts patch sets back; once none is missing below the horizon, the
// horizon goes and the attachments pruning ended come back from the blob
// lines.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// writeArchive writes the archive of p.own's range from its horizon (or
// genesis) up to (excluding) p.h to p.dest, and returns its record for
// the prune's commit.
func (b *ddbBackend) writeArchive(ctx context.Context, r *ddbReads, g *gate, p *prunePlan) (*ddb.ArchiveRow, error) {
	own := p.own
	from := own.horizonSeq.Int64
	if !own.horizonSeq.Valid {
		from = r.firstRev(own.id)
	}
	ab, perr := ddbCheck(func() *builtArchive { return g.archiveBundle(p.n, own.name, own.id, from, p.h) })
	if perr != nil {
		return nil, perr
	}
	// The archiver streams the entries from the reads, which panic with
	// what they meet.
	entries := ab.b.Entries
	ab.b.Entries = func(yield func(ArchiveEntry) error) error {
		err, perr := ddbCheck(func() error { return entries(yield) })
		if perr != nil {
			return perr
		}
		return err
	}
	u, err := b.e.opt.Archiver.Write(ctx, p.dest, ab.key, ab.b)
	if err != nil {
		return nil, fmt.Errorf("writing archive %s: %w", ab.key, err)
	}
	rec := &ddb.ArchiveRow{
		FromPos: r.revs[from].key.pos, ToPos: r.revs[ab.lastSeq].key.pos,
		Key: ab.key, URL: u, Created: g.now.UnixMilli(),
	}
	for _, bid := range ab.bids {
		rec.Bids = append(rec.Bids, bid.String())
	}
	return rec, nil
}

// deleteArchives deletes the archives of name in ns ("" for all of ns's)
// and their records (§8.3: purge reaches archives).
func (b *ddbBackend) deleteArchives(ctx context.Context, ns, name string) error {
	as, err := b.store.Archives(ctx, ns, name)
	if err != nil || len(as) == 0 {
		return err
	}
	a := b.e.opt.Archiver
	if a == nil {
		return fmt.Errorf("%s/%s has archives but no archiver is configured to delete them", ns, name)
	}
	done := map[string]bool{}
	for _, rec := range as {
		if !done[rec.URL] {
			if err := a.Delete(ctx, rec.URL); err != nil {
				return fmt.Errorf("deleting archive %s: %w", rec.URL, err)
			}
			done[rec.URL] = true
		}
		if err := b.store.DeleteArchive(ctx, ns, rec); err != nil {
			return err
		}
	}
	return nil
}

func (b *ddbBackend) archives(ctx context.Context, ns, name string) ([]ArchiveRecord, error) {
	var nss []string
	err := b.gateRead(ctx, func(t *gate) error {
		for _, n := range t.allNamespaces() {
			if !n.purged && (ns == "" || n.name == ns) {
				nss = append(nss, n.name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(nss)
	var out []ArchiveRecord
	for _, n := range nss {
		as, err := b.store.Archives(ctx, n, name)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		purged := map[string]bool{}
		for _, a := range as {
			p, ok := purged[a.Name]
			if !ok {
				rr, err := b.store.Resource(ctx, n, a.Name)
				if err != nil {
					return nil, ddbAsErr(err)
				}
				p = rr == nil || rr.Purged
				purged[a.Name] = p
			}
			if p {
				continue
			}
			from, err := b.store.RevAt(ctx, n, a.Name, a.FromPos)
			if err != nil {
				return nil, ddbAsErr(err)
			}
			to, err := b.store.RevAt(ctx, n, a.Name, a.ToPos)
			if err != nil {
				return nil, ddbAsErr(err)
			}
			if from == nil || to == nil {
				continue
			}
			out = append(out, ArchiveRecord{NS: n, Name: a.Name, Key: a.Key, URL: a.URL, From: from.ID, To: to.ID, Created: formatTime(a.Created)})
		}
	}
	return out, nil
}

func (b *ddbBackend) restore(ctx context.Context, ns, name string, entries func(yield func(ArchiveEntry) error) error) (*RestoreResult, error) {
	e := b.e
	out := &RestoreResult{}
	n, err := b.store.Namespace(ctx, ns)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if n == nil {
		return nil, notFound()
	}
	rr, err := b.store.Resource(ctx, ns, name)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	level, err := b.nsLevelOf(ctx, ns)
	if err != nil {
		return nil, err
	}
	var dek []byte
	if level >= levelAtRest && rr != nil && !rr.Purged {
		if dek, err = b.dekFor(ctx, ns, name, true); err != nil {
			return nil, asErrOrNil(err)
		}
	}
	if n.Purged || rr != nil && rr.Purged {
		out.Purged = true
		return out, entries(func(ArchiveEntry) error { return nil })
	}
	if rr == nil {
		return nil, notFound()
	}
	blobs := map[ids.ID]*ArchiveBlob{}
	err = entries(func(en ArchiveEntry) error {
		if en.Blob != nil {
			// Verified against its id (§3.7) when the line was read.
			if bid, err := ids.Parse(en.Blob.ID); err == nil && ids.Blob(en.Blob.Type, en.Blob.Nonce, en.Blob.Data) == bid {
				blobs[bid] = en.Blob
			}
			return nil
		}
		id, err := ids.Parse(en.ID)
		if err != nil {
			out.Skipped++
			return nil
		}
		ri, err := b.store.ReadRevOf(ctx, ns, name, id.String())
		if err != nil {
			return err
		}
		switch {
		case ri == nil:
			out.Skipped++
			return nil
		case ri.Kind == "tombstone" || !ri.Pruned:
			out.Present++
			return nil
		case en.Kind != "rev" || en.Patches == nil:
			out.Skipped++
			return nil
		}
		var parent *ids.ID
		if ri.ParentID != "" {
			pid, err := ids.Parse(ri.ParentID)
			if err != nil {
				return err
			}
			parent = &pid
		}
		canon := jsonv.Canonical(en.Patches)
		if en.Parent != ri.ParentID || ids.Revision(parent, canon) != id {
			out.Skipped++
			return nil
		}
		if _, err := patch.Parse(jsonv.MustParse(canon)); err != nil {
			out.Skipped++
			return nil
		}
		stored := string(canon)
		if dek != nil {
			stored = sealValue(dek, "rev", ns, name, ri.ID, stored)
		}
		ok, err := b.store.RestorePatches(ctx, ns, name, ri.Pos, stored)
		if err != nil {
			return err
		}
		if ok {
			out.Restored++
		} else {
			out.Present++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// What a patch set put back makes servable, and the horizon's going,
	// change what reads answer.
	inv := invalidation{nss: []string{ns}, meta: true, flushDocs: true}
	e.rc.begin(inv)
	defer e.invalidate(inv, false)
	if rr.HorizonPos == 0 {
		// Cleared before: every document is stored.
		if out.Blobs, err = b.restoreBlobs(ctx, ns, name, ownerFor(level, ns, name), blobs); err != nil {
			return nil, err
		}
		if err := b.store.ClearBlobEpochMarkers(ctx, ns, name); err != nil {
			return nil, ddbAsErr(err)
		}
		return out, nil
	}
	missing, err := b.store.PatchesMissing(ctx, ns, name, rr.HorizonPos)
	if err != nil || missing {
		return out, asErrOrNil(err)
	}
	if err := b.store.ClearHorizon(ctx, ns, name, rr.HorizonPos); err != nil {
		return nil, ddbAsErr(err)
	}
	if out.Blobs, err = b.restoreBlobs(ctx, ns, name, ownerFor(level, ns, name), blobs); err != nil {
		return nil, err
	}
	// The pruned epochs' revisions are served again (clearPrunedEpochs).
	if err := b.store.ClearBlobEpochMarkers(ctx, ns, name); err != nil {
		return nil, ddbAsErr(err)
	}
	b.committed(ns, "r:"+ns+"/"+name)
	out.Cleared = true
	return out, nil
}

// restoreBlobs brings back name's attachments that pruning ended, from
// the archives' blob lines (restoreBlobs of archive.go). It returns how
// many it brought back.
func (b *ddbBackend) restoreBlobs(ctx context.Context, ns, name, owner string, blobs map[ids.ID]*ArchiveBlob) (int, error) {
	ended, err := b.store.Attachments(ctx, ns, name, true)
	if err != nil {
		return 0, ddbAsErr(err)
	}
	n := 0
	for _, a := range ended {
		bid, err := ids.Parse(a.Bid)
		if err != nil {
			continue
		}
		ab := blobs[bid]
		if ab == nil || ab.Type != a.Type || ab.Nonce != a.Nonce || int64(len(ab.Data)) != a.Size {
			continue
		}
		h := sha256.Sum256(ab.Data)
		key, err := b.putOwnedBytes(ctx, owner, h[:], ab.Data)
		if err != nil {
			return n, err
		}
		if err := b.store.RestoreAttachment(ctx, ns, name, a.Bid, key, owner); err != nil {
			return n, ddbAsErr(err)
		}
		n++
	}
	return n, nil
}
