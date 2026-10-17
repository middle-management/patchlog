package dav

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	"github.com/middle-management/patchlog/internal/client"
)

// errNotExist is what the WebDAV handler takes as "no such file".
var errNotExist = os.ErrNotExist

// kind is what a path names.
type kind int

const (
	kMissing      kind = iota // nothing, nor a directory to make it in
	kRoot                     // /
	kNSDir                    // a flat namespace
	kCatDir                   // a catalog's root (Addendum B)
	kDoc                      // a flat namespace's {name}.json
	kFolder                   // a catalog folder under the folder it names
	kPlacement                // a catalog placement {ns}.{name}.json under the folder it names
	kNewFolder                // a folder name that isn't under that folder (MKCOL)
	kNewPlacement             // a placement file name that isn't under that folder (PUT)
	kScratch                  // any other name in a directory: a scratch file
)

// target is a resolved path.
type target struct {
	kind            kind
	path, dir, base string
	ns              string // the namespace or catalog it is in
	// docNS and docName are the content document of a kDoc, kPlacement
	// or kNewPlacement.
	docNS, docName string
	// node is the catalog node of a kFolder, kPlacement, kNewFolder or
	// kNewPlacement, and parent the folder its path puts it in ("" for
	// the catalog's root).
	node, parent string
}

func (t target) isDir() bool {
	return t.kind == kRoot || t.kind == kNSDir || t.kind == kCatDir || t.kind == kFolder
}

// isDoc: the path names a document's file (which may not be live).
func (t target) isDoc() bool {
	return t.kind == kDoc || t.kind == kPlacement || t.kind == kNewPlacement
}

// resourceOf is the resource name of a document file name {name}.json.
func resourceOf(file string) (string, bool) {
	name, ok := strings.CutSuffix(file, ".json")
	return name, ok && client.ValidResourceName(name)
}

// resolve says what name names for the request's principal.
func (st *reqState) resolve(ctx context.Context, name string) (target, error) {
	name = slashClean(name)
	t := target{path: name, dir: path.Dir(name), base: path.Base(name)}
	if name == "/" {
		t.kind = kRoot
		return t, nil
	}
	segs := strings.Split(name[1:], "/")
	t.ns = segs[0]
	switch {
	case len(segs) == 1 && st.s.flat[t.ns]:
		t.kind = kNSDir
	case len(segs) == 1 && st.s.cats[t.ns]:
		t.kind = kCatDir
	case len(segs) == 1:
		t.kind = kScratch
	case st.s.flat[t.ns] && len(segs) == 2:
		if res, ok := resourceOf(segs[1]); ok {
			t.kind, t.docNS, t.docName = kDoc, t.ns, res
		} else {
			t.kind = kScratch
		}
	case st.s.cats[t.ns]:
		return st.resolveCatalog(ctx, t, segs[1:])
	default:
		t.kind = kMissing
	}
	return t, nil
}

// fileInfo is a file or directory as the handler sees it. A document's
// ETag is its revision id; a written file's is the revision its close
// committed.
type fileInfo struct {
	name  string
	size  int64
	mod   time.Time
	dir   bool
	mode  fs.FileMode
	rev   string
	ctype string
	w     *writeFile
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi *fileInfo) ModTime() time.Time { return fi.mod }
func (fi *fileInfo) IsDir() bool        { return fi.dir }
func (fi *fileInfo) Sys() any           { return nil }

// ETag implements webdav.ETager.
func (fi *fileInfo) ETag(context.Context) (string, error) {
	rev := fi.rev
	if fi.w != nil && fi.w.rev != "" {
		rev = fi.w.rev
	}
	if rev == "" {
		return "", webdav.ErrNotImplemented
	}
	return `"` + rev + `"`, nil
}

// ContentType implements webdav.ContentTyper, so listings don't open
// files to sniff them.
func (fi *fileInfo) ContentType(context.Context) (string, error) {
	if fi.ctype == "" {
		return "", webdav.ErrNotImplemented
	}
	return fi.ctype, nil
}

func (st *reqState) dirInfo(name string) *fileInfo {
	return &fileInfo{name: name, dir: true, mode: fs.ModeDir | 0o755, mod: st.s.start}
}

func (st *reqState) docInfo(name string, hd headDoc) *fileInfo {
	fi := &fileInfo{name: name, size: int64(len(hd.e.rendered)), rev: hd.rev, mode: 0o644, ctype: "application/json",
		mod: st.s.modTime(st.p, docKey(hd.ns, hd.name, hd.rev), hd.e)}
	if hd.e.sealed {
		fi.mode = 0o444
	}
	return fi
}

func scratchInfo(name string, f *scratchFile) *fileInfo {
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	return &fileInfo{name: name, size: int64(len(f.data)), mod: f.mod, mode: 0o644, ctype: ct}
}

// listing is a directory's entries as read once per request.
type listing struct {
	infos  []os.FileInfo
	byName map[string]*fileInfo
	docs   map[string]headDoc // file name -> document
}

// list reads directory t: its documents, folders and placements as the
// core has them now (each request reads them again), and the principal's
// scratch files in it.
func (st *reqState) list(ctx context.Context, t target) (*listing, error) {
	if l := st.lists[t.path]; l != nil {
		return l, nil
	}
	l := &listing{byName: map[string]*fileInfo{}, docs: map[string]headDoc{}}
	add := func(fi *fileInfo) {
		if l.byName[fi.name] == nil {
			l.byName[fi.name] = fi
			l.infos = append(l.infos, fi)
		}
	}
	var files []headDoc
	var names []string
	switch t.kind {
	case kRoot:
		for _, ns := range st.s.namespaces() {
			add(st.dirInfo(ns))
		}
	case kNSDir:
		hs, err := st.s.liveHeads(ctx, st.p, t.ns)
		if err != nil {
			return nil, err
		}
		if st.s.nsInfo(ctx, st.p, t.ns).sealed {
			// Listed, not read: their documents are sealed (Addendum E).
			for _, h := range hs {
				h.e = &docEntry{sealed: true}
				l.docs[h.name+".json"] = h
				add(st.docInfo(h.name+".json", h))
			}
			break
		}
		files = hs
		for _, h := range hs {
			names = append(names, h.name+".json")
		}
	case kCatDir, kFolder:
		cg, err := st.graph(ctx, t.ns)
		if err != nil {
			return nil, err
		}
		for _, n := range cg.children(t.node) {
			if n.Kind == kindFolder {
				add(st.dirInfo(n.Name))
				continue
			}
			files = append(files, headDoc{ns: n.ItemNS, name: n.ItemName})
			names = append(names, n.Name+".json")
		}
	}
	if len(files) > 0 {
		// Placements whose content isn't live (dangling, §B.3) are left
		// out: fetchHeads drops them, so pair names up by resource.
		byRes := map[string]string{}
		for i, f := range files {
			byRes[f.ns+"/"+f.name] = names[i]
		}
		docs, err := st.s.fetchHeads(ctx, st.p, files)
		if err != nil {
			return nil, err
		}
		for _, hd := range docs {
			name := byRes[hd.ns+"/"+hd.name]
			l.docs[name] = hd
			add(st.docInfo(name, hd))
		}
	}
	for name, f := range st.scratchList(t.path) {
		add(scratchInfo(name, f))
	}
	sort.Slice(l.infos, func(i, j int) bool { return l.infos[i].Name() < l.infos[j].Name() })
	if st.lists == nil {
		st.lists = map[string]*listing{}
	}
	st.lists[t.path] = l
	return l, nil
}

// docAt returns the live document a document path names, from the
// directory's listing if the request read it, else from its head.
func (st *reqState) docAt(ctx context.Context, t target) (headDoc, bool, error) {
	if l := st.lists[t.dir]; l != nil {
		hd, ok := l.docs[t.base]
		return hd, ok, nil
	}
	h, err := st.p.c.Head(ctx, t.docNS, t.docName)
	if err != nil || h.State != client.Live {
		return headDoc{}, false, err
	}
	e, err := st.s.doc(ctx, st.p, t.docNS, t.docName, h.ID)
	if err != nil {
		return headDoc{}, false, err
	}
	return headDoc{ns: t.docNS, name: t.docName, rev: h.ID, e: e}, true, nil
}

// stat is Stat of a resolved path.
func (st *reqState) stat(ctx context.Context, t target) (*fileInfo, error) {
	switch {
	case t.kind == kMissing:
		return nil, errNotExist
	case t.isDir():
		// A listing is read here, before the handler writes anything, so
		// its failure (a 401 or 403 upstream) is the answer.
		if st.method == "PROPFIND" && st.depth != "0" && t.path == st.path {
			if _, err := st.list(ctx, t); err != nil {
				return nil, err
			}
		}
		return st.dirInfo(t.base), nil
	}
	if l := st.lists[t.dir]; l != nil {
		if fi := l.byName[t.base]; fi != nil {
			return fi, nil
		}
		return nil, errNotExist
	}
	if t.kind == kDoc || t.kind == kPlacement {
		hd, live, err := st.docAt(ctx, t)
		if err != nil {
			return nil, err
		}
		if live {
			return st.docInfo(t.base, hd), nil
		}
	}
	if f, ok := st.scratchGet(t.path); ok {
		return scratchInfo(t.base, f), nil
	}
	return nil, errNotExist
}

// davFS is the webdav.FileSystem; the principal comes with each request's
// context.
type davFS struct{ s *Server }

func (d *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	st := state(ctx)
	t, err := st.resolve(ctx, name)
	if err != nil {
		return nil, st.record(upstream(err))
	}
	fi, err := st.stat(ctx, t)
	if err != nil {
		return nil, st.record(upstream(err))
	}
	return fi, nil
}

func (d *davFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	st := state(ctx)
	f, err := st.open(ctx, name, flag)
	if err != nil {
		return nil, st.record(upstream(err))
	}
	return f, nil
}

func (st *reqState) open(ctx context.Context, name string, flag int) (webdav.File, error) {
	t, err := st.resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	if flag&os.O_TRUNC != 0 {
		// A write (PUT, the destination of a COPY, a LOCK of a new name):
		// buffered, and committed on close.
		switch {
		case t.kind == kMissing:
			return nil, errNotExist
		case t.isDir():
			return nil, fail(http.StatusMethodNotAllowed, "%s is a directory", t.path)
		case t.isDoc():
			w := &writeFile{st: st, ctx: ctx, t: t}
			return w, nil
		}
		return &writeFile{st: st, ctx: ctx, t: t, scratch: true}, nil
	}
	fi, err := st.stat(ctx, t)
	if err != nil {
		return nil, err
	}
	if fi.dir {
		l, err := st.list(ctx, t)
		if err != nil {
			return nil, err
		}
		return &dirFile{fi: fi, infos: l.infos}, nil
	}
	if fi.rev == "" {
		f, ok := st.scratchGet(t.path)
		if !ok {
			return nil, errNotExist
		}
		return &memFile{Reader: bytes.NewReader(f.data), fi: fi}, nil
	}
	hd, live, err := st.docAt(ctx, t)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errNotExist
	}
	if hd.e.sealed {
		if st.method == "GET" || st.method == "HEAD" || st.method == "POST" {
			return nil, fail(http.StatusNotImplemented, "%s/%s is sealed (Addendum E); sealed and end-to-end documents aren't served over WebDAV", hd.ns, hd.name)
		}
		return &memFile{Reader: bytes.NewReader(nil), fi: fi}, nil
	}
	if st.method == "GET" {
		// What the principal now has is the base of its next save.
		st.p.setServed(hd.ns, hd.name, &served{rev: hd.rev}, 0)
	}
	return &memFile{Reader: bytes.NewReader(hd.e.rendered), fi: fi}, nil
}

func (d *davFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	st := state(ctx)
	return st.record(upstream(st.mkdir(ctx, name)))
}

func (st *reqState) mkdir(ctx context.Context, name string) error {
	if st.method == "COPY" {
		return fail(http.StatusForbidden, "folders aren't copied; move them, or make one and move what goes in it")
	}
	t, err := st.resolve(ctx, name)
	if err != nil {
		return err
	}
	switch t.kind {
	case kMissing:
		return errNotExist
	case kRoot, kNSDir, kCatDir, kFolder:
		return os.ErrExist
	case kNewFolder:
		return st.mkFolder(ctx, t)
	}
	if st.s.cats[t.ns] && t.ns != t.base {
		return fail(http.StatusForbidden, "a folder's name is a resource name without a dot (§3.6, §B.2): lowercase letters, digits, _ and -")
	}
	return fail(http.StatusForbidden, "directories are made only in catalogs (Addendum B); the root lists the served namespaces, and a flat namespace holds documents only")
}

func (d *davFS) RemoveAll(ctx context.Context, name string) error {
	st := state(ctx)
	return st.record(upstream(st.removeAll(ctx, name)))
}

func (st *reqState) removeAll(ctx context.Context, name string) error {
	t, err := st.resolve(ctx, name)
	if err != nil {
		return err
	}
	defer st.changed()
	if (st.method == "MOVE" || st.method == "COPY") && t.path == st.dst {
		// The handler clears an existing destination before moving or
		// copying onto it: a document or catalog node there is written
		// over (an edit, a move), never deleted first.
		if t.isDir() || t.kind == kPlacement {
			return nil
		}
		if t.kind == kDoc {
			if _, live, err := st.docAt(ctx, t); err != nil || live {
				return err
			}
		}
		st.scratchRemove(t.path)
		return nil
	}
	switch t.kind {
	case kMissing:
		return errNotExist
	case kRoot, kNSDir, kCatDir:
		return fail(http.StatusForbidden, "the namespaces served are fixed; %s can't be deleted here", t.path)
	case kDoc:
		if _, live, err := st.docAt(ctx, t); err != nil {
			return err
		} else if live {
			return st.deleteDoc(ctx, t.docNS, t.docName)
		}
	case kFolder, kPlacement:
		if t.kind == kPlacement {
			if _, live, err := st.docAt(ctx, t); err != nil {
				return err
			} else if !live {
				break
			}
		}
		return st.unplace(ctx, t)
	}
	if !st.scratchRemove(t.path) {
		return errNotExist
	}
	return nil
}

func (d *davFS) Rename(ctx context.Context, oldName, newName string) error {
	st := state(ctx)
	return st.record(upstream(st.rename(ctx, oldName, newName)))
}

// rename is a MOVE: the handler has cleared an existing destination
// (removeAll, which leaves documents in place).
func (st *reqState) rename(ctx context.Context, oldName, newName string) error {
	src, err := st.resolve(ctx, oldName)
	if err != nil {
		return err
	}
	dst, err := st.resolve(ctx, newName)
	if err != nil {
		return err
	}
	defer st.changed()
	live := false
	if src.kind == kDoc || src.kind == kPlacement {
		if _, live, err = st.docAt(ctx, src); err != nil {
			return err
		}
	}
	switch {
	case src.kind == kMissing || dst.kind == kMissing:
		return errNotExist
	case live && (dst.kind == kScratch || dst.kind == kNewFolder):
		// An editor moving the original aside as a backup before writing
		// the new version: the backup is a copy, the document stays.
		hd, _, err := st.docAt(ctx, src)
		if err != nil {
			return err
		}
		if hd.e.sealed {
			return fail(http.StatusNotImplemented, "%s/%s is sealed (Addendum E)", hd.ns, hd.name)
		}
		return st.scratchPut(dst.path, hd.e.rendered)
	case live || src.kind == kFolder:
		if st.isCatalogMove(src, dst) {
			return st.move(ctx, src, dst)
		}
		return fail(http.StatusForbidden, "names are identity (§3.6, §B.1): a document can't be renamed or moved to another namespace; copy it to a new name and delete the old one")
	case src.isDir():
		return fail(http.StatusForbidden, "%s can't be moved", src.path)
	}
	f, ok := st.scratchGet(src.path)
	if !ok {
		return errNotExist
	}
	switch {
	case dst.isDoc():
		// The atomic save: a temporary file moved over the document is
		// a write of its content.
		if err := st.commit(ctx, dst, f.data); err != nil {
			return err
		}
		st.scratchRemove(src.path)
		return nil
	case dst.kind == kScratch || dst.kind == kNewFolder:
		st.scratchRename(src.path, dst.path)
		return nil
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// commit writes body to the document a path names: an edit, a create or a
// restore, or for a new placement also the placement (§B.2). An empty
// body creates nothing: a client making a file before writing it (LOCK,
// Finder's 0-byte PUT) gets a placeholder, and a live document isn't
// truncated.
func (st *reqState) commit(ctx context.Context, t target, body []byte) error {
	_, err := st.commitRev(ctx, t, body)
	return err
}

func (st *reqState) commitRev(ctx context.Context, t target, body []byte) (string, error) {
	defer st.changed()
	if len(bytes.TrimSpace(trimBOM(body))) == 0 {
		if t.kind != kNewPlacement {
			hd, live, err := st.docAt(ctx, t)
			if err != nil {
				return "", err
			}
			if live {
				return hd.rev, nil
			}
		}
		return "", st.scratchPut(t.path, nil)
	}
	v, err := parseBody(body)
	if err != nil {
		return "", err
	}
	var rev string
	if t.kind == kNewPlacement {
		rev, err = st.place(ctx, t, v)
	} else {
		rev, err = st.commitDoc(ctx, t.docNS, t.docName, v)
	}
	if err != nil {
		return "", err
	}
	st.scratchRemove(t.path)
	return rev, nil
}

// writeFile buffers a written file whole; Close commits it, to the core
// for a document name, to the scratch store for any other.
type writeFile struct {
	st      *reqState
	ctx     context.Context
	t       target
	scratch bool
	buf     bytes.Buffer
	err     error
	closed  bool
	rev     string
}

func (w *writeFile) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.st.s.opt.MaxFileSize {
		w.err = w.st.record(fail(http.StatusRequestEntityTooLarge, "a file is at most %d bytes", w.st.s.opt.MaxFileSize))
		return 0, w.err
	}
	return w.buf.Write(p)
}

func (w *writeFile) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if w.scratch {
		return w.st.record(w.st.scratchPut(w.t.path, bytes.Clone(w.buf.Bytes())))
	}
	rev, err := w.st.commitRev(w.ctx, w.t, w.buf.Bytes())
	w.rev = rev
	return w.st.record(upstream(err))
}

func (w *writeFile) Read([]byte) (int, error)           { return 0, os.ErrPermission }
func (w *writeFile) Seek(int64, int) (int64, error)     { return 0, nil }
func (w *writeFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (w *writeFile) Stat() (os.FileInfo, error)         { return w.info(), nil }
func (w *writeFile) info() *fileInfo {
	return &fileInfo{name: w.t.base, size: int64(w.buf.Len()), mod: w.st.s.opt.Now(), mode: 0o644, w: w}
}

// memFile is a file read from memory: a document's rendering or a scratch
// file. Dead properties (PROPPATCH, as Windows and macOS send after
// writing) are accepted and not kept.
type memFile struct {
	*bytes.Reader
	fi *fileInfo
}

func (f *memFile) Close() error                       { return nil }
func (f *memFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (f *memFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (f *memFile) Stat() (os.FileInfo, error)         { return f.fi, nil }

// DeadProps implements webdav.DeadPropsHolder: none are kept.
func (f *memFile) DeadProps() (map[xml.Name]webdav.Property, error) { return nil, nil }

// Patch implements webdav.DeadPropsHolder: every change succeeds and is
// dropped.
func (f *memFile) Patch(ps []webdav.Proppatch) ([]webdav.Propstat, error) {
	st := webdav.Propstat{Status: http.StatusOK}
	for _, p := range ps {
		for _, prop := range p.Props {
			st.Props = append(st.Props, webdav.Property{XMLName: prop.XMLName})
		}
	}
	return []webdav.Propstat{st}, nil
}

// dirFile is a directory's listing.
type dirFile struct {
	fi    *fileInfo
	infos []os.FileInfo
	pos   int
}

func (f *dirFile) Close() error                   { return nil }
func (f *dirFile) Read([]byte) (int, error)       { return 0, io.EOF }
func (f *dirFile) Seek(int64, int) (int64, error) { return 0, nil }
func (f *dirFile) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (f *dirFile) Stat() (os.FileInfo, error)     { return f.fi, nil }
func (f *dirFile) Readdir(n int) ([]os.FileInfo, error) {
	rest := f.infos[f.pos:]
	if n <= 0 {
		f.pos = len(f.infos)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	if n > len(rest) {
		n = len(rest)
	}
	f.pos += n
	return rest[:n], nil
}
