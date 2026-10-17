package dav

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
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
	kScratch                  // any other name in a directory: a scratch file or directory
	kBadName                  // a .json name a person gave that names no document: refused
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
	sdir         bool // a kScratch that is a scratch directory
}

func (t target) isDir() bool {
	return t.kind == kRoot || t.kind == kNSDir || t.kind == kCatDir || t.kind == kFolder || t.kind == kScratch && t.sdir
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
	if len(segs) > 1 && st.isScratchDir(t.dir) {
		// In a scratch directory, every name is scratch: a macOS app's
		// safe save writes {name}.json there before moving it out. In a
		// file manager's folder not yet named, the .json names a person
		// gives are refused, as anywhere else.
		return st.scratchAt(t, !st.inAppDir(t.dir), nil), nil
	}
	switch {
	case len(segs) == 1 && st.s.flat[t.ns]:
		t.kind = kNSDir
	case len(segs) == 1 && st.s.cats[t.ns]:
		t.kind = kCatDir
	case len(segs) == 1:
		t = st.scratchAt(t, true, nil)
	case st.s.flat[t.ns] && len(segs) == 2:
		if res, ok := resourceOf(segs[1]); ok {
			t.kind, t.docNS, t.docName = kDoc, t.ns, res
		} else {
			t = st.scratchAt(t, true, func(orig string) bool {
				h, err := st.head(ctx, t.ns, orig)
				return err == nil && h.State == client.Live
			})
		}
	case st.s.cats[t.ns]:
		return st.resolveCatalog(ctx, t, segs[1:])
	default:
		t.kind = kMissing
	}
	return t, nil
}

// scratchAt makes t a scratch path; named, a name a person may have given
// it: a .json name (any case) that doesn't start with a dot is refused,
// since it would be kept only in memory and vanish (a Save As
// "Report.json"), but for the name a file manager gives a copy of a
// document beside it (Finder's Duplicate "x copy.json"), which the rename
// that follows commits: beside reports whether the document a copy's
// name names is in t's directory. Editors' and the system's own files
// start with a dot or end otherwise (.x.json.swp, ._x.json, x.json~,
// 4913).
func (st *reqState) scratchAt(t target, named bool, beside func(orig string) bool) target {
	t.kind = kScratch
	f, ok := st.scratchPeek(t.path)
	t.sdir = ok && f.dir
	if named && !ok && !strings.HasPrefix(t.base, ".") && strings.HasSuffix(strings.ToLower(t.base), ".json") {
		if orig, isCopy := copyOf(t.base); !isCopy || beside == nil || !beside(orig) {
			t.kind = kBadName
		}
	}
	return t
}

// copyNames are the names file managers give a copy of x.json made beside
// it: Finder's "x copy.json", "x copy 2.json" and "x 2.json" (Keep Both);
// Explorer's "x - Copy.json", "x - Copy (2).json", "Copy of x.json" and
// "x (1).json"; GNOME's "x (copy).json", "x (another copy).json", "x (3rd
// copy).json".
var copyNames = regexp.MustCompile(`^(?:(?i:copy of )(.+)|(.+?)(?:(?i: copy)(?: \d+)?|(?i: - copy)(?: \(\d+\))?| \((?i:copy|another copy|\d+(?:st|nd|rd|th) copy)\)| \(\d+\)| \d+))\.json$`)

// copyOf returns the resource name of the document a copy's name names.
func copyOf(base string) (string, bool) {
	m := copyNames.FindStringSubmatch(base)
	if m == nil {
		return "", false
	}
	orig := m[1] + m[2]
	return orig, client.ValidResourceName(orig)
}

// appDir reports a directory name apps save through (macOS's safe save
// "(A Document Being Saved By TextEdit)", .TemporaryItems, any name
// starting with a dot), rather than one a person gave.
func appDir(base string) bool {
	return strings.HasPrefix(base, ".") || strings.HasPrefix(base, "(A Document Being Saved By ")
}

// newFolderNames are the names file managers give a folder they make,
// before it is named: Finder's "untitled folder", Explorer's "New
// folder", GNOME's "Untitled Folder", numbered.
var newFolderNames = regexp.MustCompile(`^(?i:untitled folder|new folder)(?: \d+| \(\d+\))?$`)

// inAppDir reports whether dir, a scratch directory, is or is in one apps
// save through.
func (st *reqState) inAppDir(dir string) bool {
	for d := dir; d != "/" && st.isScratchDir(d); d = path.Dir(d) {
		if appDir(path.Base(d)) {
			return true
		}
	}
	return false
}

// mayScratchDir refuses a scratch directory at t (MKCOL, or a scratch
// directory moved there) where a person named it: outside a catalog,
// documents saved in it would be kept in memory only. Apps' directories
// are made anywhere, and in a catalog folder a file manager's new folder,
// to be named.
func (st *reqState) mayScratchDir(t target) error {
	switch {
	case appDir(t.base), st.isScratchDir(t.dir) && st.inAppDir(t.dir):
		return nil
	case st.s.cats[t.ns] && t.dir != "/" && !st.isScratchDir(t.dir):
		if newFolderNames.MatchString(t.base) {
			return nil
		}
		return fail(http.StatusForbidden, "%q isn't a folder name: a catalog folder's name is a resource name without a dot, of lowercase letters, digits, \"_\" and \"-\" (§3.6, §B.2)", t.base)
	}
	return fail(http.StatusForbidden, "folders are made only in catalogs: %s can't hold one (a folder there would keep what is saved in it in memory only)", t.dir)
}

// badName is the refusal of a kBadName.
func (st *reqState) badName(t target) error {
	if st.s.cats[t.ns] {
		return fail(http.StatusForbidden, "%q names no document: in a catalog folder a file is a placement, {ns}.{name}.json, and a folder a resource name without a dot (§3.6, §B.2); a file named otherwise would only be kept in memory for a while, so it is refused", t.base)
	}
	return fail(http.StatusForbidden, "%q names no document: a document's file is {name}.json, a resource name of lowercase letters, digits, \".\", \"_\" and \"-\" (§3.6); a file named otherwise would only be kept in memory for a while, so it is refused", t.base)
}

// fileInfo is a file or directory as the handler sees it. A document's
// ETag is its revision id; a written file's is the revision its close
// committed, if that holds exactly what was written.
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
	fi := &fileInfo{name: name, size: int64(len(st.repr(hd))), rev: hd.rev, mode: 0o644, ctype: "application/json",
		mod: st.s.modTime(st.p, docKey(hd.ns, hd.name, hd.rev), hd.e)}
	if hd.e.sealed {
		fi.mode = 0o444
	}
	return fi
}

func scratchInfo(name string, f *scratchFile) *fileInfo {
	if f.dir {
		return &fileInfo{name: name, dir: true, mode: fs.ModeDir | 0o755, mod: f.mod}
	}
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
// core has them now (each request reads a flat namespace again; a
// catalog's tree is kept CatalogTTL), and the principal's scratch files
// in it.
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
	head := st.p.c.Head
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
		head = cg.itemHead(st.p)
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
		docs, err := st.s.fetchHeads(ctx, st.p, files, head)
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

// head reads ns/name's head once per request (until it writes).
func (st *reqState) head(ctx context.Context, ns, name string) (*client.Head, error) {
	k := ns + "/" + name
	if h := st.heads[k]; h != nil {
		return h, nil
	}
	h, err := st.p.c.Head(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	if st.heads == nil {
		st.heads = map[string]*client.Head{}
	}
	st.heads[k] = h
	return h, nil
}

// docAt returns the live document a document path names, from the
// directory's listing if the request read it, else from its head.
func (st *reqState) docAt(ctx context.Context, t target) (headDoc, bool, error) {
	if l := st.lists[t.dir]; l != nil {
		hd, ok := l.docs[t.base]
		return hd, ok, nil
	}
	h, err := st.head(ctx, t.docNS, t.docName)
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
		if t.kind == kScratch {
			if f, ok := st.scratchGet(t.path); ok {
				return scratchInfo(t.base, f), nil
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

// fail records err for the answer, or, for an entry of a PROPFIND listing
// other than the one requested (props open each), skips that entry
// (handlePropfindError): the multistatus has begun, and an error there
// would cut it short.
func (st *reqState) fail(name string, err error) error {
	err = upstream(err)
	var de *davError
	if st.method == "PROPFIND" && slashClean(name) != st.path && errors.As(err, &de) {
		st.s.opt.Logf("dav: PROPFIND %s: %s left out: %v", st.path, name, err)
		return skipped{err}
	}
	return st.record(err)
}

// skipped is an error x/net/webdav's PROPFIND leaves an entry out for.
type skipped struct{ error }

func (skipped) Is(target error) bool { return target == fs.ErrPermission }

func (d *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	st := state(ctx)
	t, err := st.resolve(ctx, name)
	if err != nil {
		return nil, st.fail(name, err)
	}
	fi, err := st.stat(ctx, t)
	if err != nil {
		return nil, st.fail(name, err)
	}
	return fi, nil
}

func (d *davFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	st := state(ctx)
	f, err := st.open(ctx, name, flag)
	if err != nil {
		return nil, st.fail(name, err)
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
		case t.kind == kBadName:
			return nil, st.badName(t)
		case t.isDir():
			return nil, fail(http.StatusMethodNotAllowed, "%s is a directory", t.path)
		}
		if err := st.preconditions(ctx, t); err != nil {
			return nil, err
		}
		switch {
		case t.isDoc():
			if err := st.writable(ctx, t); err != nil {
				return nil, err
			}
			return &writeFile{st: st, ctx: ctx, t: t}, nil
		}
		return &writeFile{st: st, ctx: ctx, t: t, scratch: true}, nil
	}
	fi, err := st.stat(ctx, t)
	if err != nil {
		return nil, err
	}
	if fi.dir {
		// Listed when read (Readdir), not when opened: a PROPFIND opens
		// every entry it lists for its properties.
		return &dirFile{st: st, ctx: ctx, t: t, fi: fi}, nil
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
	if st.method == "GET" && t.path == st.path {
		// What the client now has is a base of its next save, once the
		// body is sent (a 304 sends none). A client whose copy is suspect
		// gets the document whatever its validators say.
		st.serve = &stagedServe{ns: hd.ns, name: hd.name, rev: hd.rev}
		if st.hdr != nil && st.s.stale(st.p, hd.ns, hd.name, hd.rev) {
			st.hdr.Del("If-None-Match")
			st.hdr.Del("If-Modified-Since")
		}
	}
	return &memFile{Reader: bytes.NewReader(st.repr(hd)), fi: fi}, nil
}

// preconditions checks a PUT's If-None-Match: * (create only) and
// If-Match: * (edit only), which x/net/webdav doesn't, against what the
// path holds now; a document's write checks them again (commitDoc).
func (st *reqState) preconditions(ctx context.Context, t target) error {
	if !st.noneMatch && !st.matchAny {
		return nil
	}
	fi, err := st.stat(ctx, t)
	if err != nil && !errors.Is(err, errNotExist) {
		return err
	}
	// An empty placeholder at a document's path (a LOCK of a new name)
	// exists, as listed, though the core has no document there yet.
	st.placeholder = err == nil && t.isDoc() && fi.rev == ""
	switch {
	case st.noneMatch && err == nil:
		return fail(http.StatusPreconditionFailed, "%s exists (If-None-Match: *)", t.path)
	case st.matchAny && err != nil:
		return fail(http.StatusPreconditionFailed, "%s doesn't exist (If-Match: *)", t.path)
	}
	return nil
}

func (d *davFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	st := state(ctx)
	return st.fail(name, st.mkdir(ctx, name))
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
	case kBadName:
		return st.badName(t)
	case kScratch:
		// Not a catalog folder: a scratch directory (an app's safe save,
		// a file manager's "untitled folder" before it is named).
		if err := st.mayScratchDir(t); err != nil {
			return err
		}
		return st.scratchMkdir(t.path)
	}
	return fail(http.StatusForbidden, "%s names a document, not a directory", t.path)
}

func (d *davFS) RemoveAll(ctx context.Context, name string) error {
	st := state(ctx)
	return st.fail(name, st.removeAll(ctx, name))
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
		if t.kind != kScratch && t.isDir() || t.kind == kPlacement {
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
			return st.deleteDoc(ctx, t.docNS, t.docName, st.ifMatch)
		}
	case kFolder, kPlacement:
		if t.kind == kPlacement {
			hd, live, err := st.docAt(ctx, t)
			if err != nil {
				return err
			} else if !live {
				break
			}
			if st.ifMatch != "" && hd.rev != st.ifMatch {
				return fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", hd.ns, hd.name, st.ifMatch)
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
	return st.fail(oldName, st.rename(ctx, oldName, newName))
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
	case dst.kind == kBadName:
		return st.badName(dst)
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
		if err := st.scratchPut(dst.path, st.repr(hd)); err != nil {
			return err
		}
		// The client takes the name for free now, and may create it
		// only (davfs2's If-None-Match: *): that write is the edit.
		st.p.setAside(src.path, st.s.opt.Now())
		return nil
	case live || src.kind == kFolder:
		if st.isCatalogMove(src, dst) {
			return st.move(ctx, src, dst)
		}
		return fail(http.StatusForbidden, "names are identity (§3.6, §B.1): a document can't be renamed or moved to another namespace; copy it to a new name and delete the old one")
	case src.kind == kScratch && src.sdir:
		switch dst.kind {
		case kNewFolder:
			// A folder made as "untitled folder", then named: the
			// catalog folder it is named.
			if err := st.mkFolder(ctx, dst); err != nil {
				return err
			}
			if err := st.scratchRename(src.path, dst.path); err != nil {
				return err
			}
			st.scratchUnmark(dst.path)
			return nil
		case kScratch:
			if err := st.mayScratchDir(dst); err != nil {
				return err
			}
			return st.scratchRename(src.path, dst.path)
		}
		return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
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
		if err := st.writable(ctx, dst); err != nil {
			return err
		}
		if _, _, err := st.commitRev(ctx, dst, f.data); err != nil {
			return err
		}
		st.scratchRemove(src.path)
		return nil
	case dst.kind == kScratch || dst.kind == kNewFolder:
		return st.scratchRename(src.path, dst.path)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// commitRev writes body to the document a path names: an edit, a create
// or a restore, or for a new placement also the placement (§B.2). It
// returns the revision now holding it, and whether that holds exactly
// body. An empty body creates nothing: a client making a file before
// writing it (LOCK, Finder's 0-byte PUT) gets a placeholder, and a live
// document isn't truncated.
func (st *reqState) commitRev(ctx context.Context, t target, body []byte) (string, bool, error) {
	defer st.changed()
	if len(bytes.TrimSpace(trimBOM(body))) == 0 {
		if t.kind != kNewPlacement {
			hd, live, err := st.docAt(ctx, t)
			if err != nil {
				return "", false, err
			}
			if live {
				return hd.rev, false, nil
			}
		}
		return "", true, st.scratchPut(t.path, nil)
	}
	v, err := parseBody(body)
	if err != nil {
		return "", false, err
	}
	var rev string
	var exact bool
	if t.kind == kNewPlacement {
		rev, exact, err = st.place(ctx, t, v, body, true)
	} else {
		rev, exact, err = st.commitDoc(ctx, t.docNS, t.docName, v, body, true)
	}
	if err != nil {
		return "", false, err
	}
	st.scratchRemove(t.path)
	return rev, exact, nil
}

// writeFile buffers a written file whole; Close commits it, to the core
// for a document name, to the scratch store for any other. The buffers of
// every request together hold at most InflightBytes, those of one grant
// root's at most rootInflight (503 beyond).
type writeFile struct {
	st      *reqState
	ctx     context.Context
	t       target
	scratch bool
	buf     bytes.Buffer
	held    int64
	err     error
	closed  bool
	rev     string
}

func (w *writeFile) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.buf.Len()+len(p) > w.st.s.opt.MaxFileSize {
		w.err = w.st.record(fail(http.StatusRequestEntityTooLarge, "a file is at most %d bytes", w.st.s.opt.MaxFileSize))
		return 0, w.err
	}
	n := int64(len(p))
	if !w.st.s.inflight.TryAcquire(n) {
		w.err = w.st.record(&davError{status: http.StatusServiceUnavailable, msg: "the server is receiving too many files at once; try again",
			header: http.Header{"Retry-After": {"2"}}})
		return 0, w.err
	}
	if !w.st.p.acct.hold(n, w.st.s.rootInflight()) {
		w.st.s.inflight.Release(n)
		w.err = w.st.record(&davError{status: http.StatusServiceUnavailable, msg: "you are sending too many files at once; try again",
			header: http.Header{"Retry-After": {"2"}}})
		return 0, w.err
	}
	w.held += n
	return w.buf.Write(p)
}

func (w *writeFile) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer func() {
		w.st.s.inflight.Release(w.held)
		w.st.p.acct.release(w.held)
	}()
	switch {
	case w.err != nil:
		return w.err
	case w.st.bodyErr != nil:
		// Cut short: nothing of it is written.
		return w.st.record(&davError{status: http.StatusBadRequest, msg: "the request body didn't arrive whole; nothing was written", cause: w.st.bodyErr})
	case w.scratch:
		return w.st.record(w.st.scratchPut(w.t.path, bytes.Clone(w.buf.Bytes())))
	}
	rev, exact, err := w.st.commitRev(w.ctx, w.t, bytes.Clone(w.buf.Bytes()))
	if exact {
		w.rev = rev
	} else {
		// Merged, reformatted or given a $nonce: the revision isn't what
		// the client sent, so it gets no validator for it (RFC 9110
		// §9.3.4); a cache would keep what it sent under the revision's
		// tag.
		w.st.noETag = true
	}
	return w.st.record(upstream(err))
}

func (w *writeFile) Read([]byte) (int, error)           { return 0, os.ErrPermission }
func (w *writeFile) Seek(int64, int) (int64, error)     { return 0, nil }
func (w *writeFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (w *writeFile) Stat() (os.FileInfo, error)         { return w.info(), nil }
func (w *writeFile) info() *fileInfo {
	return &fileInfo{name: w.t.base, size: int64(w.buf.Len()), mod: w.st.s.opt.Now(), mode: 0o644, w: w}
}

// noDeadProps implements webdav.DeadPropsHolder for files and
// directories: dead properties (PROPPATCH, as Windows and macOS send after
// writing or making a folder) are accepted and not kept.
type noDeadProps struct{}

// DeadProps implements webdav.DeadPropsHolder: none are kept.
func (noDeadProps) DeadProps() (map[xml.Name]webdav.Property, error) { return nil, nil }

// Patch implements webdav.DeadPropsHolder: every change succeeds and is
// dropped.
func (noDeadProps) Patch(ps []webdav.Proppatch) ([]webdav.Propstat, error) {
	st := webdav.Propstat{Status: http.StatusOK}
	for _, p := range ps {
		for _, prop := range p.Props {
			st.Props = append(st.Props, webdav.Property{XMLName: prop.XMLName})
		}
	}
	return []webdav.Propstat{st}, nil
}

// memFile is a file read from memory: a document's rendering or a scratch
// file.
type memFile struct {
	*bytes.Reader
	noDeadProps
	fi *fileInfo
}

func (f *memFile) Close() error                       { return nil }
func (f *memFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (f *memFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (f *memFile) Stat() (os.FileInfo, error)         { return f.fi, nil }

// dirFile is a directory, listed on its first Readdir.
type dirFile struct {
	noDeadProps
	st    *reqState
	ctx   context.Context
	t     target
	fi    *fileInfo
	infos []os.FileInfo
	read  bool
	pos   int
}

func (f *dirFile) Close() error                   { return nil }
func (f *dirFile) Read([]byte) (int, error)       { return 0, io.EOF }
func (f *dirFile) Seek(int64, int) (int64, error) { return 0, nil }
func (f *dirFile) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (f *dirFile) Stat() (os.FileInfo, error)     { return f.fi, nil }
func (f *dirFile) Readdir(n int) ([]os.FileInfo, error) {
	if !f.read {
		l, err := f.st.list(f.ctx, f.t)
		if err != nil {
			return nil, f.st.fail(f.t.path, err)
		}
		f.infos, f.read = l.infos, true
	}
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
