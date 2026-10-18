package dav

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// Raw files (§H.1): read from their blobs through the core, streamed, and
// saved by uploading a blob and setting the reference's members (§H.4).

// rawFile is a raw file being read (§H.6 "Raw bytes"): its blob, fetched
// through the core as the handler reads, from where it last sought, never
// a redirect to the core's origin.
type rawFile struct {
	noDeadProps
	st       *reqState
	ctx      context.Context
	ns, name string
	ref      rawRef
	fi       *fileInfo
	off      int64         // where the next Read starts
	body     io.ReadCloser // the blob from pos on, once opened
	pos      int64
}

// rawFile returns live raw file hd to read. A GET of the whole file opens
// the blob at once, so a core that can't serve it is the answer, rather
// than a body cut short.
func (st *reqState) rawFile(ctx context.Context, hd headDoc, fi *fileInfo) (*rawFile, error) {
	f := &rawFile{st: st, ctx: ctx, ns: hd.ns, name: hd.name, ref: *hd.m.raw, fi: fi}
	if st.method == "GET" && st.hdr != nil && st.hdr.Get("Range") == "" && st.hdr.Get("If-None-Match") == "" && st.hdr.Get("If-Modified-Since") == "" {
		if err := f.open(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// open opens the blob at f.off.
func (f *rawFile) open() error {
	if f.body != nil {
		f.body.Close()
		f.body = nil
	}
	b, err := f.st.p.c.OpenBlob(f.ctx, f.ns, f.name, f.ref.bid, f.off)
	if err != nil {
		return err
	}
	f.body, f.pos = b.Body, f.off
	if b.Status == http.StatusOK && f.off > 0 {
		// The range wasn't taken: skip to it.
		if _, err := io.CopyN(io.Discard, f.body, f.off); err != nil {
			return fmt.Errorf("dav: %s/%s: blob %s ends before %d: %w", f.ns, f.name, f.ref.bid, f.off, err)
		}
	}
	return nil
}

func (f *rawFile) Read(p []byte) (int, error) {
	if f.off >= f.ref.size {
		return 0, io.EOF
	}
	if f.body == nil || f.pos != f.off {
		if err := f.open(); err != nil {
			return 0, err
		}
	}
	if rest := f.ref.size - f.off; int64(len(p)) > rest {
		p = p[:rest]
	}
	n, err := f.body.Read(p)
	f.off += int64(n)
	f.pos = f.off
	switch {
	case err == io.EOF && f.off < f.ref.size:
		return n, fmt.Errorf("dav: %s/%s: blob %s ends at %d of %d bytes: %w", f.ns, f.name, f.ref.bid, f.off, f.ref.size, io.ErrUnexpectedEOF)
	case err == io.EOF:
		return n, nil
	}
	return n, err
}

func (f *rawFile) Seek(offset int64, whence int) (int64, error) {
	n := offset
	switch whence {
	case io.SeekCurrent:
		n += f.off
	case io.SeekEnd:
		n += f.ref.size
	}
	if n < 0 {
		return 0, os.ErrInvalid
	}
	f.off = n
	return n, nil
}

func (f *rawFile) Close() error {
	if f.body != nil {
		f.body.Close()
		f.body = nil
	}
	return nil
}

func (f *rawFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (f *rawFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (f *rawFile) Stat() (os.FileInfo, error)         { return f.fi, nil }

// refValue is a blob reference as a document holds it (§7.8).
func refValue(bid, typ string, size int, nonce string) map[string]any {
	m := map[string]any{"$blob": bid, "type": typ, "size": float64(size)}
	if nonce != "" {
		m["nonce"] = nonce
	}
	return m
}

// commitRaw writes body as raw file ns/name (§H.1, §H.4), typed by its
// name and upload (fileType), and returns the revision holding it, which
// holds exactly body. A new name is created and a tombstoned one restored
// (§8.2), the blob uploaded first. A live raw file's save compares its
// base (the revision the PUT's If-Match names, else the closest of those
// the principal was served or wrote, rebased) with the head first: raw
// files have no paths to merge, so any change of its bytes between them
// is a conflict (409), and only then is the blob uploaded, once however
// often the head moves (412), and the reference's members set one by one,
// never the root, so $schema and $successor stay. Bytes the head already
// holds write nothing, nonces or not. Where nonces apply (§C.7) the blob
// has a Blob-Nonce and the root a fresh $nonce. pre: the file is the
// PUT's, whose preconditions hold for it.
func (st *reqState) commitRaw(ctx context.Context, ns, name string, body []byte, pre bool) (string, bool, error) {
	in := st.s.nsInfo(ctx, st.p, ns)
	if in.sealed {
		return "", false, notOffered(ns)
	}
	if in.blobSize > 0 && len(body) > in.blobSize {
		return "", false, fail(http.StatusRequestEntityTooLarge, "the file is %d bytes, over the blobSize of %d bytes namespace %s sets (§6.6, §7.8); nothing was uploaded", len(body), in.blobSize, ns)
	}
	typ := fileType(name, st.ctype)
	nonce := ""
	if in.nonce {
		nonce = seal.NewNonce()
	}
	bid := client.BlobID(typ, nonce, body)
	ref := refValue(bid, typ, len(body), nonce)
	uploaded := false
	upload := func() error {
		if !uploaded {
			if _, err := st.p.c.UploadBlob(ctx, ns, name, typ, nonce, body); err != nil {
				return err
			}
			uploaded = true
		}
		return nil
	}
	same := func(doc any) bool { return client.RawBlobOf(doc) == bid }
	var rev string
	st.made = ""
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		switch h.State {
		case client.Purged:
			return false, fail(http.StatusForbidden, "%s/%s was purged; its name can't be used again (§8.3)", ns, name)
		case client.Live:
			if pre && st.noneMatch {
				return false, fail(http.StatusPreconditionFailed, "%s/%s exists (If-None-Match: *)", ns, name)
			}
			cur, err := st.s.doc(ctx, st.p, ns, name, h.ID)
			switch {
			case err != nil:
				return false, err
			case cur.sealed:
				return false, notOffered(ns)
			case cur.raw == nil:
				return false, fail(http.StatusConflict, "%s/%s is a JSON document, shown as %s.json: a file of other content can't take its name (§H.2)", ns, name, name)
			case cur.raw.typ == typ && sameBytes(cur.raw, body):
				// It holds these bytes already: no write, but the principal
				// has the head now.
				st.s.remember(st.p, ns, name, record{rev: h.ID}, false)
				rev = h.ID
				return false, nil
			}
			out, _, err := st.rebased(ctx, ns, name, ref, cur.value, refOf)
			if err != nil {
				return false, err
			}
			if err := upload(); err != nil {
				return false, err
			}
			ps := merge.Diff(refOf(cur.value), out)
			paths := writesOf(refOf(cur.value), ps)
			ps = withNonce(in, cur.value, ps)
			res, err := st.p.c.Append(ctx, ns, name, h.ID, ps)
			switch {
			case client.IsStale(err):
				return true, nil
			case client.IsGone(err):
				return false, fail(http.StatusConflict, "%s/%s was deleted meanwhile", ns, name)
			case err != nil:
				return false, err
			}
			rev = res.ID
			st.wrote(ns, name, cur.value, ps, paths, res, ref, nil, same)
			return false, nil
		}
		if pre && st.matchAny && !st.placeholder {
			return false, fail(http.StatusPreconditionFailed, "%s/%s doesn't exist (If-Match: *)", ns, name)
		}
		if err := upload(); err != nil {
			return false, err
		}
		var res *client.WriteResult
		var parent any = map[string]any{}
		var ps []any
		if h.State == client.NotFound {
			ps = withNonce(in, ref, client.GenesisPatches(ref))
			res, err = st.p.c.Create(ctx, ns, name, ps)
		} else if parent, ps, err = st.rawRestorePatches(ctx, in, ns, name, h, ref); err == nil {
			res, err = st.p.c.Restore(ctx, ns, name, h.ID, ps)
		}
		if client.IsStale(err) || client.IsGone(err) {
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile; reload it", ns, name)
		}
		if err != nil {
			return false, err
		}
		rev = res.ID
		st.made = rev
		st.wrote(ns, name, parent, ps, writesOf(parent, ps), res, ref, nil, same)
		return false, nil
	})
	return rev, err == nil, err
}

// rawRestorePatches is the patch set restoring tombstoned ns/name as raw
// file ref, and the last live document it applies to (§8.2): a raw one's
// reference rebased and set member by member, as over a live one; any
// other's root replaced, the file being another.
func (st *reqState) rawRestorePatches(ctx context.Context, in nsInfo, ns, name string, h *client.Head, ref map[string]any) (any, []any, error) {
	whole := func() (any, []any, error) {
		return map[string]any{}, withNonce(in, ref, []any{map[string]any{"op": "replace", "path": "", "value": ref}}), nil
	}
	if h.Last == "" {
		return whole()
	}
	last, err := st.s.doc(ctx, st.p, ns, name, h.Last)
	switch {
	case pruned(err):
		return whole()
	case err != nil:
		return nil, nil, err
	case last.sealed, last.raw == nil:
		return whole()
	}
	out, _, err := st.rebased(ctx, ns, name, ref, last.value, refOf)
	if err != nil {
		return nil, nil, err
	}
	return last.value, withNonce(in, last.value, merge.Diff(refOf(last.value), out)), nil
}

// sameBytes reports whether raw file cur holds body: the blob id of body,
// with cur's type and nonce, is cur's.
func sameBytes(cur *rawRef, body []byte) bool {
	return cur != nil && client.BlobID(cur.typ, cur.nonce, body) == cur.bid
}
