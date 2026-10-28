package core

// Blob uploads on DynamoDB (§7.8): the SQL path's checks (gateBlob) over
// the table's reads, the bytes stored (ddb.Store.PutBytes: inline, or in
// a file of the blob store), then the pending entry, conditioned on the
// configuration the checks ran under — checked again if it moved, as a
// write is. Attaching is the write's commit (attachOf, ddbwrite.go);
// serving is openBlob on the gate (blobs.go).

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
)

func (b *ddbBackend) uploadBlob(ctx context.Context, req Request, name string, bid ids.ID, up BlobUpload) error {
	e := b.e
	var g *blobGate
	// An encrypted resource's bytes are its own (ddbcrypt.go): a copy of
	// another's is stored again under its key, from their plaintext.
	var owner string
	var copied []byte
	if err := b.gateRead(ctx, func(t *gate) error {
		gg, err := t.gateBlob(req, name, bid, &up, true)
		g = gg
		if err != nil {
			return err
		}
		owner = ownerFor(t.nsLevel(gg.n), gg.n.name, name)
		if gg.src != nil && t.checkReads.(*ddbReads).ownerName(gg.src.owner) != owner {
			copied = t.blobBytes(gg.src)
		}
		return nil
	}); err != nil {
		return err
	}
	data, err := e.readUpload(g, &up, bid)
	if err != nil {
		return err
	}
	if copied != nil {
		data = copied
	}
	var hash []byte
	store := func() error {
		h := sha256.Sum256(data)
		var err error
		hash, err = b.putOwnedBytes(ctx, owner, h[:], data)
		return err
	}
	if g.src != nil && copied == nil {
		hash = g.src.hash // stored already: the source's attachment names them
	} else if err := store(); err != nil {
		return err
	}
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		if attempt > 0 && (g.src == nil || copied != nil) {
			// A purge may have collected the bytes since (PutPending's
			// condition on them): stored again.
			if err := store(); err != nil {
				return err
			}
		}
		r := newDDBReads(ctx, b)
		t := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true}}
		type checked struct {
			g   *blobGate
			err *Error
		}
		out, perr := ddbCheck(func() checked {
			g, err := t.gateBlob(req, name, bid, &up, false)
			return checked{g, err}
		})
		switch {
		case perr != nil:
			return perr
		case out.err != nil:
			return out.err
		}
		g := out.g
		size := int64(len(data))
		if g.src != nil {
			size = g.src.size
		}
		if err := g.checkSize(size); err != nil {
			return err
		}
		ns := r.nsName(g.n.id)
		err := b.store.PutPending(ctx, ns, r.cfgs[g.n.configSeq].pos, r.cfgRow(g.n.configSeq).ID, r.uploaderVer, &ddb.BlobRow{
			Name: name, Bid: bid.String(), Type: g.typ, Nonce: g.nonce, Size: size, Hash: hash, Owner: owner,
			Created: t.now.UnixMilli(), Uploader: g.uploader,
		})
		if errors.Is(err, ddb.ErrStale) {
			observeConflict()
			continue
		}
		if err != nil {
			return ddbAsErr(err)
		}
		return nil
	}
	return apiErr(409, "conflict", "detail", "the namespace's configuration kept moving")
}

// putBytes stores blob bytes: in a file of the blob store when there
// is one (whose name the BYTES item records), else in the item.
func (b *ddbBackend) putBytes(ctx context.Context, hash, data []byte) error {
	return b.putFile(ctx, bytesFile(0, hash), hash, data)
}

// putFile is putBytes under a file name prefix: an encrypted resource's
// bytes aren't under the plaintext ones' "0/" (putOwnedBytes).
func (b *ddbBackend) putFile(ctx context.Context, prefix string, hash, data []byte) error {
	e := b.e
	now := e.now().UnixMilli()
	if e.blobs.root() == "" {
		_, err := b.store.PutBytes(ctx, hash, data, "", now)
		return asErrOrNil(err)
	}
	name, err := e.blobs.put(prefix, data)
	if err != nil {
		return err
	}
	existed, err := b.store.PutBytes(ctx, hash, data, name, now)
	if existed || err != nil {
		e.removeFiles([]string{name})
	}
	return asErrOrNil(err)
}

func asErrOrNil(err error) error {
	if err == nil {
		return nil
	}
	return ddbAsErr(err)
}

// bytesGrace is how long after an upload touched bytes the sweep leaves
// them, though nothing names them: the upload writes its pending entry
// after the bytes, in a request of its own.
const bytesGrace = 10 * time.Minute

// blobStats is BlobStats over a scan of the table.
func (b *ddbBackend) blobStats(ctx context.Context) (*BlobStats, error) {
	e := b.e
	blobs, _, bytes, err := b.store.ScanBlobs(ctx)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	s := &BlobStats{Dir: e.blobs.root(), Bytes: len(bytes)}
	for _, b := range blobs {
		if b.Attachment && b.Pruned {
			s.Pruned++
		} else if b.Attachment {
			s.Attached++
		} else {
			s.Pending++
		}
	}
	for _, b := range bytes {
		s.Size += b.Size
		if b.File != "" {
			s.Files++
		}
	}
	return s, nil
}

// sweepBlobs is SweepBlobs: the pending entries past their
// namespace's blobGrace, then the bytes nothing names any more (gcBytes
// of the SQL path, which collects them as the last row naming them goes).
func (b *ddbBackend) sweepBlobs(ctx context.Context) (int, error) {
	e := b.e
	// Purges whose content is still to go first (ddbpurge.go): their
	// attachments and pending entries then name no bytes.
	pnss, pnames, err := b.store.Purging(ctx)
	if err != nil {
		return 0, ddbAsErr(err)
	}
	for i := range pnss {
		if err := b.finishPurge(ctx, pnss[i], pnames[i]); err != nil {
			return 0, ddbAsErr(err)
		}
	}
	// Namespaces raised to encryption at rest whose content is still to
	// be encrypted (ddbcrypt.go).
	encs, err := b.store.Encrypting(ctx)
	if err != nil {
		return 0, ddbAsErr(err)
	}
	for _, ns := range encs {
		if err := b.encryptNamespace(ctx, ns); err != nil {
			return 0, ddbAsErr(err)
		}
	}
	// So do prunes: their ended attachments name no bytes either
	// (ddbprune.go).
	pnss, pnames, err = b.store.Pruning(ctx)
	if err != nil {
		return 0, ddbAsErr(err)
	}
	for i := range pnss {
		if err := b.finishPrune(ctx, pnss[i], pnames[i]); err != nil {
			return 0, ddbAsErr(err)
		}
	}
	blobs, nss, bytes, err := b.store.ScanBlobs(ctx)
	if err != nil {
		return 0, ddbAsErr(err)
	}
	cutoffs := map[string]int64{}
	cutoff := func(ns string) (int64, error) {
		if c, ok := cutoffs[ns]; ok {
			return c, nil
		}
		var c int64
		err := b.gateRead(ctx, func(t *gate) error {
			if n := t.nsByName(ns); n != nil {
				c = t.blobCutoff(t.config(n.configSeq))
			}
			return nil
		})
		cutoffs[ns] = c
		return c, err
	}
	named := map[string]bool{}
	swept := 0
	for i, bl := range blobs {
		if !bl.Attachment {
			c, err := cutoff(nss[i])
			if err != nil {
				return swept, err
			}
			if bl.Created < c {
				ok, err := b.store.DeletePending(ctx, nss[i], bl, c)
				if err != nil {
					return swept, ddbAsErr(err)
				}
				if ok {
					swept++
					continue
				}
			}
		}
		if !bl.Pruned {
			named[string(bl.Hash)] = true
		}
	}
	touched := e.now().Add(-bytesGrace).UnixMilli()
	var files []string
	for _, by := range bytes {
		if named[string(by.Hash)] {
			continue
		}
		ok, err := b.store.DeleteBytes(ctx, by.Hash, touched)
		if err != nil {
			return swept, ddbAsErr(err)
		}
		if ok && by.File != "" {
			files = append(files, by.File)
		}
	}
	e.removeFiles(files)
	return swept, nil
}
