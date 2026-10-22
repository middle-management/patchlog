package dav

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// Raw files (§H.1): read from their blobs through the core, streamed, and
// saved by uploading a blob and setting the reference's members (§H.4).

// rawFile is a raw file being read (§H.6 "Raw bytes"): its blob, fetched
// through the core as the handler reads, from where it last sought, never
// a redirect to the core's origin.
type rawFile struct {
	deadProps
	st       *reqState
	ctx      context.Context
	ns, name string
	ref      rawRef
	fi       *fileInfo
	off      int64         // where the next Read starts
	body     io.ReadCloser // the blob from pos on, once opened
	pos      int64
}

// rawFile returns live raw file hd, at path, to read. A GET of the whole
// file opens the blob at once, so a core that can't serve it is the
// answer, rather than a body cut short.
func (st *reqState) rawFile(ctx context.Context, hd headDoc, fi *fileInfo, path string) (*rawFile, error) {
	f := &rawFile{deadProps: deadProps{st, path}, st: st, ctx: ctx, ns: hd.ns, name: hd.name, ref: *hd.m.raw, fi: fi}
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
	b, err := f.st.tk.c.OpenBlob(f.ctx, f.ns, f.name, f.ref.bid, f.off)
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

// blobSrc is the blob of a raw file being copied (a COPY's source, a
// MOVE's to another namespace or tree): the copy keeps its id, and copies
// it rather than uploading it again (§7.8 Blob-From, §H.5).
type blobSrc struct {
	ns, name string
	ref      rawRef
}

// commitRaw writes body as raw file ns/name (§H.1, §H.4), typed by its
// file name and upload, else as the file there now is (fileType, once
// its head is read: the type is part of the blob id), and returns the
// revision holding it, and whether that holds exactly body. A new name
// is created and a tombstoned one restored (§8.2), the blob uploaded
// first. A live raw file's save checks its base against the head first
// (rawBase): raw files have no paths to merge, so any change of its
// bytes by someone else since is a conflict (409), and only then is the
// blob uploaded, once however often the head moves (412), and the
// reference's members set one by one, never the root, so $schema and
// $successor stay. A save is stored with the uploaded bytes, or refused:
// only bytes the head already holds, as its type, write nothing, nonces
// or not, and answer the head (§H.1 "Identity", §H.4). Where nonces apply
// (§C.7) the blob has a Blob-Nonce and the root a fresh $nonce. A copy of
// a raw file whose type comes out as the source's keeps its blob's id,
// nonce or not (§7.8), and the blob is copied with Blob-From, or uploaded
// again where the core refuses that (a source of a higher rank, §7.8).
func (st *reqState) commitRaw(ctx context.Context, ns, name string, body []byte, o saveOpts) (string, bool, error) {
	in := st.s.nsInfo(ctx, st.tk, ns)
	if in.sealed {
		return "", false, notOffered(ns)
	}
	if in.blobSize > 0 && len(body) > in.blobSize {
		return "", false, overLimit("blobSize", int64(len(body)), int64(in.blobSize), "(§6.6, §7.8): the file is larger than namespace %s's blobs may be; nothing was uploaded", ns)
	}
	if o.fname == "" {
		o.fname = name
	}
	nonce := ""
	if in.nonce {
		nonce = seal.NewNonce()
	}
	sent := map[string]bool{} // blobs uploaded or copied, by id
	upload := func(b rawBlob) error {
		if sent[b.bid] {
			return nil
		}
		if b.from != nil {
			err := st.tk.c.CopyBlob(ctx, ns, name, b.bid, b.from.ns, b.from.name, "")
			ae, isAPI := client.AsAPIError(err)
			switch {
			case err == nil:
				sent[b.bid] = true
				return nil
			case !isAPI || ae.Status != http.StatusNotFound && ae.Status != http.StatusUnprocessableEntity:
				return err
			}
		}
		if _, err := st.tk.c.UploadBlob(ctx, ns, name, b.typ, b.nonce, body); err != nil {
			return err
		}
		sent[b.bid] = true
		return nil
	}
	var rev string
	exact := true
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if o.fresh && h.State != client.NotFound {
			return false, taken(ns, name)
		}
		switch h.State {
		case client.Purged:
			return false, purgedErr(ns, name)
		case client.Live:
			if o.pre && st.noneMatch {
				return false, fail(http.StatusPreconditionFailed, "%s/%s exists (If-None-Match: *)", ns, name)
			}
			cur, err := st.s.doc(ctx, st.tk, ns, name, h.ID)
			switch {
			case err != nil:
				return false, err
			case cur.sealed:
				return false, notOffered(ns)
			case cur.raw == nil:
				return false, fail(http.StatusConflict, "%s/%s is a JSON document, shown as %s.json: a file of other content can't take its name (§H.2)", ns, name, name)
			}
			b := st.rawBlobOf(o.fname, cur.raw.typ, nonce, body)
			if cur.raw.typ == b.typ && sameBytes(cur.raw, body) {
				// It holds these bytes already: no write, but the principal
				// has the head now.
				st.s.remember(st.p, ns, name, record{rev: h.ID}, false)
				rev = h.ID
				return false, nil
			}
			if err := st.rawBase(ctx, ns, name, h.ID); err != nil {
				return false, err
			}
			if err := upload(b); err != nil {
				return false, err
			}
			ps := merge.Diff(refOf(cur.value), refOf(b.ref))
			paths := writesOf(refOf(cur.value), ps)
			ps = withNonce(in, cur.value, ps)
			res, err := st.tk.c.Append(ctx, ns, name, h.ID, ps)
			switch {
			case client.IsStale(err):
				return true, nil
			case client.IsGone(err):
				return false, fail(http.StatusConflict, "%s/%s was deleted meanwhile", ns, name)
			case err != nil:
				return false, err
			}
			rev = res.ID
			st.wrote(ns, name, cur.value, ps, paths, res, b.ref, nil, b.holds(body))
			return false, nil
		}
		if o.pre && st.matchAny && !st.placeholder {
			return false, fail(http.StatusPreconditionFailed, "%s/%s doesn't exist (If-Match: *)", ns, name)
		}
		if o.pre && st.ifMatch != "" && h.State == client.NotFound {
			return false, noRevision(ns, name, st.ifMatch)
		}
		var res *client.WriteResult
		var parent any = map[string]any{}
		var ps []any
		var b rawBlob
		if h.State == client.NotFound {
			b = st.rawBlobOf(o.fname, "", nonce, body)
			if err := upload(b); err != nil {
				return false, err
			}
			ps = withNonce(in, b.ref, client.GenesisPatches(b.ref))
			res, err = st.tk.c.Create(ctx, ns, name, ps)
		} else {
			// What the restore writes is settled (a 409 over someone
			// else's delete uploads nothing) before the blob goes up: the
			// file restored as it was keeps its type (fileType). The
			// attempt's err is assigned, not shadowed: the Restore's
			// refusal is what the switch below answers (§H.6).
			var last *docEntry
			last, err = st.tombBase(ctx, ns, name, h)
			if err != nil {
				return false, err
			}
			had := ""
			if last != nil && last.raw != nil {
				had = last.raw.typ
			}
			b = st.rawBlobOf(o.fname, had, nonce, body)
			var write bool
			if parent, ps, write, err = st.rawRestorePatches(ctx, in, ns, name, h, last, b, body); err != nil {
				return false, err
			}
			if write {
				if err := upload(b); err != nil {
					return false, err
				}
			}
			if res, err = st.tk.c.Restore(ctx, ns, name, h.ID, ps); err == nil {
				st.s.markOwn(st.p, ns, name, res.ID)
			}
		}
		switch {
		case goneSince(err):
			// Tombstoned since its head was read: written over the
			// tombstone, read again (the blob sent stays sent).
			return true, nil
		case client.IsStale(err):
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile; reload it", ns, name)
		case err != nil:
			return false, err
		}
		rev = res.ID
		exact = st.wrote(ns, name, parent, ps, writesOf(parent, ps), res, b.ref, nil, b.holds(body))
		return false, nil
	})
	return rev, err == nil && exact, err
}

// rawBlob is the blob a raw file's save writes (rawBlobOf): body as type
// typ under nonce, its id and its reference (§7.8), and from, a COPY's or
// MOVE's source blob it is copied from (Blob-From), if any.
type rawBlob struct {
	typ, nonce, bid string
	ref             map[string]any
	from            *blobSrc
}

// rawBlobOf is the blob of body saved as file fname, whose file there has
// type had ("" for none): typed by fileType, under nonce, but the blob of
// the file a COPY or MOVE copies (copySrc), its id and its nonce kept,
// where the type comes out as its and its bytes are body's (§7.8, §H.5).
func (st *reqState) rawBlobOf(fname, had, nonce string, body []byte) rawBlob {
	b := rawBlob{typ: fileType(fname, st.ctype, had, body), nonce: nonce}
	if from := st.copySrc; from != nil && from.ref.typ == b.typ && from.ref.size == int64(len(body)) && client.BlobID(b.typ, from.ref.nonce, body) == from.ref.bid {
		b.nonce, b.from = from.ref.nonce, from
	}
	b.bid = client.BlobID(b.typ, b.nonce, body)
	b.ref = refValue(b.bid, b.typ, len(body), b.nonce)
	return b
}

// holds reports, of a document, whether it holds body as b's type: the
// uploaded value (§H.1 "Identity"), under b's nonce or the one a file
// restored as it was has.
func (b rawBlob) holds(body []byte) func(doc any) bool {
	return func(doc any) bool {
		r := rawRefOf(doc, client.RawBlobOf(doc))
		return r != nil && r.typ == b.typ && sameBytes(r, body)
	}
}

// rawRestorePatches is the patch set writing raw file b, uploaded as
// body, over tombstoned ns/name, the last live document it applies to
// (§8.2), and whether it writes b, as tombBase said (last): restored
// moments after the principal's own DELETE, a raw last document's base
// checked (rawBase) and its reference's members set one by one, as over
// a live one, or restored as it was where that already holds body as
// b's type; else, or over another kind of file, a new file, the root
// replaced.
func (st *reqState) rawRestorePatches(ctx context.Context, in nsInfo, ns, name string, h *client.Head, last *docEntry, b rawBlob, body []byte) (any, []any, bool, error) {
	if last == nil || last.raw == nil {
		return map[string]any{}, withNonce(in, b.ref, []any{map[string]any{"op": "replace", "path": "", "value": b.ref}}), true, nil
	}
	if last.raw.typ == b.typ && sameBytes(last.raw, body) {
		return last.value, withNonce(in, last.value, []any{}), false, nil
	}
	if err := st.rawBase(ctx, ns, name, h.Last); err != nil {
		return nil, nil, false, err
	}
	return last.value, withNonce(in, last.value, merge.Diff(refOf(last.value), refOf(b.ref))), true, nil
}

// rawBase refuses a save of raw file ns/name over head revision headRev
// holding other bytes than the save's, or nil: it writes them (§H.4
// "Raw files"). Raw files have no paths to merge, so their base is
// checked, never merged from: the versions the client may hold are the
// revision its If-Match names, else every version the principal was
// served or wrote (candidates), and if, after any of them, someone else
// changed the file's bytes (an entry the principal didn't write set a
// reference member or the root, spans) or deleted or restored it, the
// save would overwrite theirs unseen: a 409 asking for a reload, a
// version the client had saved unchanged included (§H.1 "Identity": a
// raw save is always stored with the uploaded value, so none is answered
// as if it were). The principal's own writes since are its own to
// replace, so its consecutive saves never conflict, whatever their
// sizes: a version is never picked by how close its reference is to the
// save's. One that writes by a token refused a save of it that hasn't
// read it since is a 409 too (refusedSave).
func (st *reqState) rawBase(ctx context.Context, ns, name, headRev string) error {
	if err := st.rawBaseOf(ctx, ns, name, headRev); err != nil {
		return err
	}
	// Not by a token refused a save of it and that hasn't read it since.
	return st.refusedSave(ns, name)
}

// rawBaseOf is rawBase but for refusedSave.
func (st *reqState) rawBaseOf(ctx context.Context, ns, name, headRev string) error {
	cs, lost, err := st.candidates(ctx, ns, name)
	switch {
	case err != nil:
		return err
	case lost:
		st.refuse(ns, name)
		return lostBase(ns, name)
	case len(cs) == 0:
		return nil
	}
	all := make([]int, len(cs))
	for i := range all {
		all[i] = i
	}
	sp, err := st.spans(ctx, ns, name, headRev, cs, all)
	if err != nil {
		return err
	}
	foreign, changed := false, false
	for _, c := range cs {
		s := sp[c.rev]
		foreign = foreign || s.foreign
		changed = changed || slices.ContainsFunc(s.writes, refWrite)
	}
	switch {
	case foreign:
		st.refuse(ns, name)
		return fail(http.StatusConflict, "%s/%s was deleted or restored by someone else since you opened it (§11.3): your save isn't written over that; reload it and save again", ns, name)
	case changed:
		st.refuse(ns, name)
		return fail(http.StatusConflict, "%s/%s was changed by someone else since you opened it: its bytes (/$blob), which a raw file has no paths to merge by (§H.4), so your save isn't written over theirs; reload it and save again", ns, name)
	}
	return nil
}

// refWrite reports whether a write at p sets a raw file's reference: one
// of its members, or the root.
func refWrite(p pointer.Pointer) bool {
	return len(p) == 0 || slices.Contains([]string{"$blob", "type", "size", "nonce"}, p[0])
}

// sameBytes reports whether raw file cur holds body: the blob id of body,
// with cur's type and nonce, is cur's.
func sameBytes(cur *rawRef, body []byte) bool {
	return cur != nil && client.BlobID(cur.typ, cur.nonce, body) == cur.bid
}
