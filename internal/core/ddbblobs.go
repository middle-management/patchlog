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

func (e *Engine) ddbUploadBlob(ctx context.Context, req Request, name string, bid ids.ID, up BlobUpload) error {
	var g *blobGate
	if err := e.ddbGateRead(ctx, func(t *gate) error {
		gg, err := t.gateBlob(req, name, bid, &up, true)
		g = gg
		return asErr(err)
	}); err != nil {
		return err
	}
	data, err := e.readUpload(g, &up, bid)
	if err != nil {
		return err
	}
	var hash []byte
	if g.src != nil {
		hash = g.src.hash // stored already: bytes are never collected here
	} else {
		h := sha256.Sum256(data)
		hash = h[:]
		if err := e.ddbPutBytes(ctx, hash, data); err != nil {
			return err
		}
	}
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(e, ctx)
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
		err := e.ddb.store.PutPending(ctx, ns, r.cfgs[g.n.configSeq].pos, r.cfgRow(g.n.configSeq).ID, r.uploaderVer, &ddb.BlobRow{
			Name: name, Bid: bid.String(), Type: g.typ, Nonce: g.nonce, Size: size, Hash: hash,
			Created: t.now.UnixMilli(), Uploader: g.uploader,
		})
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return ddbAsErr(err)
		}
		return nil
	}
	return apiErr(409, "conflict", "detail", "the namespace's configuration kept moving")
}

// ddbPutBytes stores blob bytes: in a file of the blob store when there
// is one (whose name the BYTES item records), else in the item.
func (e *Engine) ddbPutBytes(ctx context.Context, hash, data []byte) error {
	now := e.now().UnixMilli()
	if e.blobs == nil {
		_, err := e.ddb.store.PutBytes(ctx, hash, data, "", now)
		return asErrOrNil(err)
	}
	name, err := e.putBlob(ctx, bytesFile(0, hash), data)
	if err != nil {
		return err
	}
	existed, err := e.ddb.store.PutBytes(ctx, hash, data, name, now)
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

// ddbBlobStats is BlobStats over a scan of the table.
func (e *Engine) ddbBlobStats(ctx context.Context) (*BlobStats, error) {
	blobs, _, bytes, err := e.ddb.store.ScanBlobs(ctx)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	s := e.newBlobStats()
	s.Bytes = len(bytes)
	for _, b := range blobs {
		if b.Attachment {
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

// ddbSweepBlobs is SweepBlobs: the pending entries past their
// namespace's blobGrace, then the bytes nothing names any more (gcBytes
// of the SQL path, which collects them as the last row naming them goes).
func (e *Engine) ddbSweepBlobs(ctx context.Context) (int, error) {
	blobs, nss, bytes, err := e.ddb.store.ScanBlobs(ctx)
	if err != nil {
		return 0, ddbAsErr(err)
	}
	cutoffs := map[string]int64{}
	cutoff := func(ns string) (int64, error) {
		if c, ok := cutoffs[ns]; ok {
			return c, nil
		}
		var c int64
		err := e.ddbGateRead(ctx, func(t *gate) error {
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
	for i, b := range blobs {
		if !b.Attachment {
			c, err := cutoff(nss[i])
			if err != nil {
				return swept, err
			}
			if b.Created < c {
				ok, err := e.ddb.store.DeletePending(ctx, nss[i], b, c)
				if err != nil {
					return swept, ddbAsErr(err)
				}
				if ok {
					swept++
					continue
				}
			}
		}
		named[string(b.Hash)] = true
	}
	touched := e.now().Add(-bytesGrace).UnixMilli()
	var files []string
	for _, b := range bytes {
		if named[string(b.Hash)] {
			continue
		}
		ok, err := e.ddb.store.DeleteBytes(ctx, b.Hash, touched)
		if err != nil {
			return swept, ddbAsErr(err)
		}
		if ok && b.File != "" {
			files = append(files, b.File)
		}
	}
	e.removeFiles(files)
	return swept, nil
}
