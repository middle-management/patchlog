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
// file name and upload (fileType), and returns the revision holding it,
// and whether that holds exactly body. A new name is created and a
// tombstoned one restored (§8.2), the blob uploaded first. A live raw
// file's save checks its base against the head first (rawBase): raw
// files have no paths to merge, so any change of its bytes by someone
// else since is a conflict (409), and only then is the blob uploaded,
// once however often the head moves (412), and the reference's members
// set one by one, never the root, so $schema and $successor stay. Bytes
// the head already holds write nothing, nonces or not, nor does a version
// the client had saved unchanged (rawBase). Where nonces
// apply (§C.7) the blob has a Blob-Nonce and the root a fresh $nonce. A
// copy of a raw file of the same type keeps its blob's id, nonce or not
// (§7.8), and the blob is copied with Blob-From, or uploaded again where
// the core refuses that (a source of a higher rank, §7.8).
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
	typ := fileType(o.fname, st.ctype)
	nonce := ""
	if in.nonce {
		nonce = seal.NewNonce()
	}
	from := st.copySrc
	if from != nil && from.ref.typ == typ && from.ref.size == int64(len(body)) && client.BlobID(typ, from.ref.nonce, body) == from.ref.bid {
		nonce = from.ref.nonce
	} else {
		from = nil
	}
	bid := client.BlobID(typ, nonce, body)
	ref := refValue(bid, typ, len(body), nonce)
	uploaded := false
	upload := func() error {
		if uploaded {
			return nil
		}
		if from != nil {
			err := st.tk.c.CopyBlob(ctx, ns, name, bid, from.ns, from.name, "")
			ae, isAPI := client.AsAPIError(err)
			switch {
			case err == nil:
				uploaded = true
				return nil
			case !isAPI || ae.Status != http.StatusNotFound && ae.Status != http.StatusUnprocessableEntity:
				return err
			}
		}
		if _, err := st.tk.c.UploadBlob(ctx, ns, name, typ, nonce, body); err != nil {
			return err
		}
		uploaded = true
		return nil
	}
	same := func(doc any) bool { return client.RawBlobOf(doc) == bid }
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
			case cur.raw.typ == typ && sameBytes(cur.raw, body):
				// It holds these bytes already: no write, but the principal
				// has the head now.
				st.s.remember(st.p, ns, name, record{rev: h.ID}, false)
				rev = h.ID
				return false, nil
			}
			write, err := st.rawBase(ctx, ns, name, body, h.ID)
			if err != nil {
				return false, err
			}
			if !write {
				// A version the client had, unchanged, over someone
				// else's bytes since: nothing is written, nor is it the
				// head's content (no ETag), as a JSON file's (edit).
				rev, exact = h.ID, false
				return false, nil
			}
			if err := upload(); err != nil {
				return false, err
			}
			ps := merge.Diff(refOf(cur.value), refOf(ref))
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
			st.wrote(ns, name, cur.value, ps, paths, res, ref, nil, same)
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
		if h.State == client.NotFound {
			if err := upload(); err != nil {
				return false, err
			}
			ps = withNonce(in, ref, client.GenesisPatches(ref))
			res, err = st.tk.c.Create(ctx, ns, name, ps)
		} else {
			// What the restore writes is settled (a 409 over someone
			// else's delete uploads nothing) before the blob goes up.
			var write bool
			if parent, ps, write, err = st.rawRestorePatches(ctx, in, ns, name, h, ref, body); err != nil {
				return false, err
			}
			if !write {
				exact = false
			} else if err := upload(); err != nil {
				return false, err
			}
			if res, err = st.tk.c.Restore(ctx, ns, name, h.ID, ps); err == nil {
				st.s.markOwn(st.p, ns, name, res.ID)
			}
		}
		if client.IsStale(err) || client.IsGone(err) && !client.IsPurged(err) {
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile; reload it", ns, name)
		}
		if err != nil {
			return false, err
		}
		rev = res.ID
		exact = st.wrote(ns, name, parent, ps, writesOf(parent, ps), res, ref, nil, same) && exact
		return false, nil
	})
	return rev, err == nil && exact, err
}

// rawRestorePatches is the patch set writing raw file ref, uploaded as
// body, over tombstoned ns/name, the last live document it applies to
// (§8.2), and whether it writes ref, as tombBase says: restored moments
// after the principal's own DELETE, a raw last document's base checked
// (rawBase) and its reference's members set one by one, as over a live
// one, or restored as it was where rawBase writes nothing; else, or over
// another kind of file, a new file, the root replaced.
func (st *reqState) rawRestorePatches(ctx context.Context, in nsInfo, ns, name string, h *client.Head, ref map[string]any, body []byte) (any, []any, bool, error) {
	last, err := st.tombBase(ctx, ns, name, h)
	switch {
	case err != nil:
		return nil, nil, false, err
	case last == nil, last.raw == nil:
		return map[string]any{}, withNonce(in, ref, []any{map[string]any{"op": "replace", "path": "", "value": ref}}), true, nil
	}
	write := !sameBytes(last.raw, body)
	if write {
		if write, err = st.rawBase(ctx, ns, name, body, h.Last); err != nil {
			return nil, nil, false, err
		}
	}
	if !write {
		return last.value, withNonce(in, last.value, []any{}), false, nil
	}
	return last.value, withNonce(in, last.value, merge.Diff(refOf(last.value), refOf(ref))), true, nil
}

// rawBase says whether a save of raw file ns/name with body, over head
// revision headRev holding other bytes, writes them (§H.4 "Raw files").
// Raw files have no paths to merge, so their base is checked, never
// merged from: the versions the client may hold are the revision its
// If-Match names, else every version the principal was served or wrote
// (candidates), and if, after any of them, someone else changed the
// file's bytes (an entry the principal didn't write set a reference
// member or the root, spans) or deleted or restored it, writing body
// would overwrite theirs unseen: a 409 asking for a reload, but for a
// version the client had saved unchanged with no write of the
// principal's after it, which writes nothing (false), as a JSON file's
// unchanged save (edit). The principal's own writes since are its own to
// replace, so its consecutive saves never conflict, whatever their sizes:
// a version is never picked by how close its reference is to body's.
func (st *reqState) rawBase(ctx context.Context, ns, name string, body []byte, headRev string) (bool, error) {
	cs, lost, err := st.candidates(ctx, ns, name)
	switch {
	case err != nil:
		return false, err
	case lost:
		st.s.refuse(st.p, ns, name)
		return false, lostBase(ns, name)
	case len(cs) == 0:
		return true, nil
	}
	all := make([]int, len(cs))
	for i := range all {
		all[i] = i
	}
	sp, err := st.spans(ctx, ns, name, headRev, cs, all)
	if err != nil {
		return false, err
	}
	foreign, changed := false, false
	for _, c := range cs {
		s := sp[c.rev]
		foreign = foreign || s.foreign
		changed = changed || slices.ContainsFunc(s.writes, refWrite)
	}
	if !foreign && !changed {
		return true, nil
	}
	if !foreign {
		for i, c := range cs {
			if sameBytes(rawRefOf(c.doc, client.RawBlobOf(c.doc)), body) && !wroteAfter(cs, i) {
				return false, nil
			}
		}
	}
	st.s.refuse(st.p, ns, name)
	if foreign {
		return false, fail(http.StatusConflict, "%s/%s was deleted or restored by someone else since you opened it (§11.3): your save isn't written over that; reload it and save again", ns, name)
	}
	return false, fail(http.StatusConflict, "%s/%s was changed by someone else since you opened it: its bytes (/$blob), which a raw file has no paths to merge by (§H.4), so your save isn't written over theirs; reload it and save again", ns, name)
}

// refWrite reports whether a write at p sets a raw file's reference: one
// of its members, or the root.
func refWrite(p pointer.Pointer) bool {
	return len(p) == 0 || slices.Contains([]string{"$blob", "type", "size", "nonce"}, p[0])
}

// wroteAfter reports whether the principal wrote a version recorded after
// cs[i].
func wroteAfter(cs []candidate, i int) bool {
	for _, c := range cs {
		if c.wrote && c.seq > cs[i].seq {
			return true
		}
	}
	return false
}

// sameBytes reports whether raw file cur holds body: the blob id of body,
// with cur's type and nonce, is cur's.
func sameBytes(cur *rawRef, body []byte) bool {
	return cur != nil && client.BlobID(cur.typ, cur.nonce, body) == cur.bid
}
