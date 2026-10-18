package dav

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
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
	"github.com/middle-management/patchlog/internal/jsonv"
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
	kDoc                      // a flat namespace's JSON file, {name}.json (§H.2 "Flat view")
	kRaw                      // a flat namespace's raw file, named by its resource name
	kFolder                   // a catalog folder under the folder it names
	kPlacement                // a catalog placement {ns}.{name}.json under the folder it names
	kNewFolder                // a folder name that isn't under that folder (MKCOL)
	kNewPlacement             // a placement file name that isn't under that folder (PUT)
	kScratch                  // a scratch file or directory (§H.6)
	kBadName                  // a name no file can have there: refused
)

// target is a resolved path.
type target struct {
	kind            kind
	path, dir, base string
	ns              string // the namespace or catalog it is in
	// docNS and docName are the content document of a kDoc, kRaw,
	// kPlacement or kNewPlacement, live or not; rawName is the raw document
	// a new kDoc's file is instead when its content isn't JSON (§H.1).
	docNS, docName, rawName string
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
	return t.kind == kDoc || t.kind == kRaw || t.kind == kPlacement || t.kind == kNewPlacement
}

// resolve says what name names for the request's principal, noting the
// document path a PUT writes (saveTo): one in a catalog whose read failed
// too (a 429, a timeout), as a placement's file, whose DELETE that
// follows may find the catalog read.
func (st *reqState) resolve(ctx context.Context, name string) (target, error) {
	t, err := st.resolveName(ctx, name)
	if st.method == "PUT" && st.saveTo == "" && slashClean(name) == st.path {
		switch {
		case err == nil && t.isDoc():
			st.saveTo, st.saveDoc = t.path, t.kind == kDoc || t.kind == kRaw
		case err != nil && st.placementPath(st.path):
			st.saveTo = st.path
		}
	}
	return t, err
}

func (st *reqState) resolveName(ctx context.Context, name string) (target, error) {
	name = slashClean(name)
	t := target{path: name, dir: path.Dir(name), base: path.Base(name)}
	if name == "/" {
		t.kind = kRoot
		return t, nil
	}
	segs := strings.Split(name[1:], "/")
	t.ns = segs[0]
	if st.s.flat[t.ns] || st.s.cats[t.ns] {
		if ok, err := st.offered(ctx, t.ns); err != nil || !ok {
			if err == nil {
				err = notOffered(t.ns)
			}
			return t, err
		}
	}
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
		return st.resolveFlat(ctx, t)
	case st.s.cats[t.ns]:
		return st.resolveCatalog(ctx, t, segs[1:])
	default:
		t.kind = kMissing
	}
	return t, nil
}

// resolveFlat resolves t, a name in flat namespace t.ns's directory (§H.2
// "Flat view"): a live raw document by its resource name, another live
// one as {name}.json, or as {name} (2).json where a raw one has that name;
// else a scratch name (§H.6), a new file a resource name can make (raw,
// or JSON for a {name}.json of JSON content: commitRev), a scratch file
// kept there (a copy a file manager made beside a file), or a name no
// file can have here.
func (st *reqState) resolveFlat(ctx context.Context, t target) (target, error) {
	hd, kind, ok, err := st.flatOwner(ctx, t.ns, t.dir, t.base)
	switch {
	case err != nil:
		return t, err
	case ok:
		t.kind, t.docNS, t.docName = kind, t.ns, hd.name
		return t, nil
	case scratchName(t.base):
		return st.scratchAt(t, false, nil), nil
	}
	t.docNS = t.ns
	if stem, ok := strings.CutSuffix(t.base, ".json"); ok && client.ValidResourceName(stem) {
		t.kind, t.docName = kDoc, stem
		if client.ValidResourceName(t.base) {
			t.rawName = t.base
		}
		return t, nil
	}
	if client.ValidResourceName(t.base) {
		t.kind, t.docName = kRaw, t.base
		return t, nil
	}
	if _, ok := st.scratchPeek(t.path); ok {
		return st.scratchAt(t, false, nil), nil
	}
	if orig, ok := copyOf(t.base); ok {
		if _, _, live, err := st.flatOwner(ctx, t.ns, t.dir, orig); err != nil || live {
			return st.scratchAt(t, false, nil), err
		}
	}
	t.kind = kBadName
	return t, nil
}

// flatOwner returns the live document whose file is named base in flat
// namespace ns's directory dir, and the file's kind (kRaw or kDoc): a raw
// document named base; else a JSON one named {stem} for {stem}.json, or for
// {stem} (2).json where a raw {stem}.json takes {stem}.json (dupName). The
// directory's listing answers if the request read it, else heads.
func (st *reqState) flatOwner(ctx context.Context, ns, dir, base string) (headDoc, kind, bool, error) {
	live := func(name string) (headDoc, bool, error) {
		if !client.ValidResourceName(name) {
			return headDoc{}, false, nil
		}
		if l := st.lists[dir]; l != nil {
			hd, ok := l.res[name]
			return hd, ok, nil
		}
		h, err := st.head(ctx, ns, name)
		if err != nil || h.State != client.Live {
			return headDoc{}, false, err
		}
		m, err := st.s.meta(ctx, st.p, ns, name, h.ID)
		if hidden(err) || err == nil && m.sealed {
			return headDoc{}, false, nil
		}
		return headDoc{ns: ns, name: name, rev: h.ID, m: m}, err == nil, err
	}
	if hd, ok, err := live(base); err != nil || ok && hd.m.raw != nil {
		return hd, kRaw, ok, err
	}
	stem, isJSON := strings.CutSuffix(base, ".json")
	if d, n, dup := dupOf(base); dup && n == 2 {
		// {stem} (2).json: JSON document {stem} if a raw {stem}.json is
		// live, which keeps the name.
		if stem, isJSON = strings.CutSuffix(d, ".json"); !isJSON {
			return headDoc{}, 0, false, nil
		}
		if r, ok, err := live(d); err != nil || !ok || r.m.raw == nil {
			return headDoc{}, 0, false, err
		}
	}
	if !isJSON {
		return headDoc{}, 0, false, nil
	}
	hd, ok, err := live(stem)
	if err != nil || !ok || hd.m.raw != nil {
		return headDoc{}, 0, false, err
	}
	return hd, kDoc, true, nil
}

// scratchAt makes t a scratch path; named, at the root or in a catalog
// folder, a name a person may have given it: a .json name (any case) that
// doesn't start with a dot is refused, since it would be kept only in
// memory and vanish (a Save As "Report.json"), but for the name a file
// manager gives a copy of a file beside it (Finder's Duplicate "x
// copy.json"), which the rename that follows commits: beside reports
// whether the file a copy's name names is in t's directory. Editors' and
// the system's own files start with a dot or end otherwise (.x.json.swp,
// ._x.json, x.json~, 4913). A flat namespace's directory refuses more
// (resolveFlat).
func (st *reqState) scratchAt(t target, named bool, beside func(orig string) bool) target {
	t.kind = kScratch
	f, ok := st.scratchPeek(t.path)
	t.sdir = ok && f.dir
	if named && !ok && !scratchName(t.base) && !strings.HasPrefix(t.base, ".") && strings.HasSuffix(strings.ToLower(t.base), ".json") {
		if orig, isCopy := copyOf(t.base); !isCopy || beside == nil || !beside(orig) {
			t.kind = kBadName
		}
	}
	return t
}

// copyNames are the names file managers give a copy of x.json (or any
// x.ext, or x) made beside it: Finder's "x copy.json", "x copy 2.json" and
// "x 2.json" (Keep Both); Explorer's "x - Copy.json", "x - Copy (2).json",
// "Copy of x.json" and "x (1).json"; GNOME's "x (copy).json", "x (another
// copy).json", "x (3rd copy).json". Each holds a space, so no resource
// name looks like one.
var copyNames = regexp.MustCompile(`^(?:(?i:copy of )(.+)|(.+?)(?:(?i: copy)(?: \d+)?|(?i: - copy)(?: \(\d+\))?| \((?i:copy|another copy|\d+(?:st|nd|rd|th) copy)\)| \(\d+\)| \d+)(\.[^. ]*)?)$`)

// copyOf returns the name of the file a copy's name names.
func copyOf(base string) (string, bool) {
	m := copyNames.FindStringSubmatch(base)
	if m == nil {
		return "", false
	}
	return m[1] + m[2] + m[3], true
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
	switch {
	case st.s.cats[t.ns]:
		return fail(http.StatusForbidden, "%q names no document: in a catalog folder a file is a placement, {ns}.{name}.json, and a folder a resource name without a dot (§3.6, §B.2); a file named otherwise would only be kept in memory for a while, so it is refused", t.base)
	case st.s.flat[t.ns]:
		return fail(http.StatusForbidden, "%q names no file and can't name one: in a namespace's directory (the flat view, §H.2) a file is named by its resource name, 1 to 128 lowercase letters, digits, \".\", \"_\" and \"-\" starting with a letter or digit (§3.6), and a JSON document by {name}.json; a file named otherwise would only be kept in memory for a while, so it is refused", t.base)
	}
	return fail(http.StatusForbidden, "%q names no document: the root holds the namespaces served, and their files are in them; a file named otherwise would only be kept in memory for a while, so it is refused", t.base)
}

// notOffered is the answer for sealed and end-to-end namespace ns, whose
// content needs keys this server doesn't hold (§H.7): it isn't offered at
// all, rather than shown as empty files that seem writable.
func notOffered(ns string) error {
	return fail(http.StatusNotFound, "namespace %s is sealed or end-to-end encrypted (Addendum E), and this server holds no keys, so it doesn't offer it (§H.7)", ns)
}

// offered reports whether namespace ns is offered to the principal: one
// that isn't sealed or end-to-end (notOffered), or whose document its
// grant can't read (it then gets what the core answers), or doesn't name.
// A document that couldn't be read for now (a 429, a 5xx) is the error.
func (st *reqState) offered(ctx context.Context, ns string) (bool, error) {
	if st.p.named != nil && !st.p.named[ns] {
		return true, nil
	}
	in, err := st.s.nsInfoErr(ctx, st.p, ns)
	return !in.sealed, err
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

// docInfo is a live document's file (§H.3): a raw file's size and type
// are its reference's; a JSON file's size is its rendering's, or that of
// the bytes the principal wrote, which it reads back (repr). Its time is
// when the head was written (modTime).
func (st *reqState) docInfo(name string, hd headDoc) *fileInfo {
	fi := &fileInfo{name: name, rev: hd.rev, mode: 0o644, size: hd.m.size, ctype: "application/json",
		mod: st.s.modTime(st.p, docKey(hd.ns, hd.name, hd.rev), hd.created, hd.m.modified)}
	if r := hd.m.raw; r != nil {
		fi.ctype = r.typ
	} else if b := st.s.exactOf(st.p, hd.ns, hd.name, hd.rev); b != nil {
		fi.size = int64(len(b))
	}
	return fi
}

func scratchInfo(name string, f *scratchFile) *fileInfo {
	if f.dir {
		return &fileInfo{name: name, dir: true, mode: fs.ModeDir | 0o755, mod: f.mod}
	}
	ct := fileType(name, f.ctype)
	if m := mime.TypeByExtension(path.Ext(name)); ct == "application/octet-stream" && m != "" {
		ct = m
	}
	return &fileInfo{name: name, size: int64(len(f.data)), mod: f.mod, mode: 0o644, ctype: ct}
}

// listing is a directory's entries as read once per request.
type listing struct {
	infos  []os.FileInfo
	byName map[string]*fileInfo
	docs   map[string]headDoc // file name -> document
	res    map[string]headDoc // a flat namespace's: resource name -> document
}

// list reads directory t: its files, folders and placements as the core
// has them now (each request reads a flat namespace again; a catalog's
// tree is kept CatalogTTL), and the principal's scratch files in it. The
// root lists the namespaces offered (§H.7). A flat namespace lists the
// head rows of /heads (§H.3) by the flat view's names (§H.2): a raw
// document by its name, any other as {name}.json, and one whose name a
// raw one has as {name} (2).json; each revision's document is read once
// for its file's size and type (Server.metas).
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
	switch t.kind {
	case kRoot:
		for _, ns := range st.s.namespaces() {
			// One whose document couldn't be read for now is listed, and
			// answers for itself when opened.
			if ok, err := st.offered(ctx, ns); ok || err != nil {
				add(st.dirInfo(ns))
			}
		}
	case kNSDir:
		hs, err := st.s.liveHeads(ctx, st.p, t.ns)
		if err != nil {
			return nil, err
		}
		if hs, err = st.s.fetchHeads(ctx, st.p, hs, st.p.c.Head, false); err != nil {
			return nil, err
		}
		l.res = map[string]headDoc{}
		for _, hd := range hs {
			if !hd.m.sealed {
				l.res[hd.name] = hd
			}
		}
		taken := func(name string) bool { h, ok := l.res[name]; return ok && h.m.raw != nil }
		for _, hd := range l.res {
			name := hd.name
			if hd.m.raw == nil {
				if name += ".json"; taken(name) {
					name = dupName(name, taken)
				}
			}
			l.docs[name] = hd
			add(st.docInfo(name, hd))
		}
	case kCatDir, kFolder:
		cg, err := st.graph(ctx, t.ns)
		if err != nil {
			return nil, err
		}
		var files []headDoc
		var names []string
		sealed := map[string]bool{}
		for _, n := range cg.children(t.node) {
			if n.Kind == kindFolder {
				add(st.dirInfo(n.Name))
				continue
			}
			s, ok := sealed[n.ItemNS]
			if !ok {
				s = st.s.nsInfo(ctx, st.p, n.ItemNS).sealed
				sealed[n.ItemNS] = s
			}
			if !s {
				files = append(files, headDoc{ns: n.ItemNS, name: n.ItemName})
				names = append(names, n.Name+".json")
			}
		}
		// Placements whose content isn't live (dangling, §B.3) are left
		// out: fetchHeads drops them, so pair names up by resource. Items
		// in sealed and end-to-end namespaces aren't offered (§H.7).
		byRes := map[string]string{}
		for i, f := range files {
			byRes[f.ns+"/"+f.name] = names[i]
		}
		docs, err := st.s.fetchHeads(ctx, st.p, files, cg.itemHead(st.p), false)
		if err != nil {
			return nil, err
		}
		for _, hd := range docs {
			if hd.m.sealed {
				continue
			}
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
// directory's listing if the request read it, else from its head: for a
// flat namespace's file, only a document of its kind (a JSON document's
// file names no raw one, nor a raw file a JSON one), and never a sealed
// one, which isn't offered (§H.7).
func (st *reqState) docAt(ctx context.Context, t target) (headDoc, bool, error) {
	if l := st.lists[t.dir]; l != nil {
		hd, ok := l.docs[t.base]
		return hd, ok, nil
	}
	if t.kind == kPlacement && st.s.nsInfo(ctx, st.p, t.docNS).sealed {
		return headDoc{}, false, nil
	}
	h, err := st.head(ctx, t.docNS, t.docName)
	if err != nil || h.State != client.Live {
		return headDoc{}, false, err
	}
	m, err := st.s.meta(ctx, st.p, t.docNS, t.docName, h.ID)
	if err != nil {
		return headDoc{}, false, err
	}
	hd := headDoc{ns: t.docNS, name: t.docName, rev: h.ID, m: m}
	switch {
	case m.sealed, t.kind == kDoc && m.raw != nil, t.kind == kRaw && m.raw == nil:
		return hd, false, nil
	}
	return hd, true, nil
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
	if t.kind == kDoc || t.kind == kRaw || t.kind == kPlacement {
		hd, live, err := st.docAt(ctx, t)
		if err != nil {
			return nil, err
		}
		if live {
			return st.docInfo(t.base, hd), nil
		}
		if t.kind == kPlacement && st.method == "DELETE" && t.path == st.path {
			// A placement whose item isn't live (dangling, §B.3): not
			// listed, but there for its DELETE, which unplaces it.
			return &fileInfo{name: t.base, mode: 0o644, mod: st.s.start}, nil
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
			return nil, st.undoOwnDelete(ctx, t, err)
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
	served := (st.method == "GET" || st.method == "HEAD") && t.path == st.path
	if served && st.resp != nil {
		// A file is served as its type, and whatever it holds, no page of
		// this origin, which holds the users' credentials, runs it, nor
		// does a browser take it for another type (§H.6 "Raw bytes").
		st.resp.Set("Content-Type", fi.ctype)
		st.resp.Set("X-Content-Type-Options", "nosniff")
		st.resp.Set("Content-Security-Policy", "sandbox")
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
	if served {
		// What the client now has is a base of its next save, once a GET's
		// body is sent (a 304 sends none). A client whose copy is suspect
		// gets the file whatever its validators say (§H.1 "Identity").
		if st.method == "GET" {
			st.serve = &stagedServe{ns: hd.ns, name: hd.name, rev: hd.rev}
		}
		if st.hdr != nil && st.s.stale(st.p, hd.ns, hd.name, hd.rev) {
			st.hdr.Del("If-None-Match")
			st.hdr.Del("If-Modified-Since")
		}
	}
	if r := hd.m.raw; r != nil {
		if st.method == "COPY" && t.path == st.path {
			// The copy's type is the source's (fileType).
			st.ctype = r.typ
		}
		return st.rawFile(ctx, hd, fi)
	}
	f := &docFile{st: st, ctx: ctx, hd: hd, fi: fi}
	if served {
		// Read now, so a failure is the answer.
		if err := f.load(); err != nil {
			return nil, err
		}
	}
	return f, nil
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
		// RFC 4918 §9.3.1: 409, the parent not being a collection.
		return fail(http.StatusConflict, "%s can't be made: %s isn't a folder here (a file, or nothing); make the folders above it first", t.path, t.dir)
	case kRoot, kNSDir, kCatDir, kFolder:
		return os.ErrExist
	case kNewFolder:
		return st.mkFolder(ctx, t)
	case kBadName, kScratch:
		// Not a catalog folder: a scratch directory (an app's safe save,
		// a file manager's "untitled folder" before it is named), which
		// a name no file can have may be (§H.6).
		if t.kind == kBadName && !appDir(t.base) {
			return st.badName(t)
		}
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
		if t.kind == kDoc || t.kind == kRaw {
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
	case kDoc, kRaw:
		if _, live, err := st.docAt(ctx, t); err != nil {
			return err
		} else if live {
			if err := st.afterRefusedSave(ctx, t); err != nil {
				return err
			}
			return st.deleteDoc(ctx, t.docNS, t.docName, st.ifMatch)
		}
	case kFolder, kPlacement:
		if t.kind == kPlacement {
			if err := st.afterRefusedSave(ctx, t); err != nil {
				return err
			}
			// A placement whose item isn't live (dangling, §B.3) isn't
			// listed, but its path unplaces it: else it would keep its
			// folder from being deleted, with nothing to show for it.
			hd, live, err := st.docAt(ctx, t)
			switch {
			case err != nil:
				return err
			case st.ifMatch != "" && (!live || hd.rev != st.ifMatch):
				return fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", t.docNS, t.docName, st.ifMatch)
			}
		}
		return st.unplace(ctx, t)
	}
	if !st.scratchRemove(t.path) {
		return errNotExist
	}
	return nil
}

// afterRefusedSave refuses, once, a DELETE of the document's file t that
// follows the principal's refused save of it (refusedSaveFor), unless it
// names the revision it deletes. A document in a frozen namespace isn't
// deleted anyway: its DELETE gets the core's refusal (§8.4).
func (st *reqState) afterRefusedSave(ctx context.Context, t target) error {
	if st.ifMatch != "" {
		return nil
	}
	r, left, ok := st.p.takeRefusedSave(t.path, st.s.opt.Now())
	if !ok {
		return nil
	}
	if (t.kind == kDoc || t.kind == kRaw) && st.s.nsInfo(ctx, st.p, t.docNS).frozen {
		st.p.clearRefusedSave(t.path)
		return nil
	}
	again := "delete it again to delete it"
	if left > 0 {
		again = fmt.Sprintf("it follows %d refused saves, each refusing one DELETE: delete it %d more times to delete it", left+1, left+1)
	}
	return fail(http.StatusConflict, "%s wasn't deleted: this DELETE follows a refused save of the same file (%d, moments ago), and some clients (rclone) delete a file whose upload failed; %s",
		t.path, r.status, again)
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
	if src.kind == kDoc || src.kind == kRaw || src.kind == kPlacement {
		if _, live, err = st.docAt(ctx, src); err != nil {
			return err
		}
	}
	switch {
	case src.kind == kMissing || dst.kind == kMissing:
		return errNotExist
	case dst.kind == kBadName && !(src.kind == kScratch && src.sdir && appDir(dst.base)):
		return st.badName(dst)
	case live && (dst.kind == kScratch || dst.kind == kNewFolder):
		// An editor moving the original aside as a backup before writing
		// the new version: the backup is a copy, the document stays.
		hd, _, err := st.docAt(ctx, src)
		if err != nil {
			return err
		}
		b, err := st.fileBytes(ctx, &hd)
		if err != nil {
			return err
		}
		ctype := "application/json"
		if hd.m.raw != nil {
			ctype = hd.m.raw.typ
		}
		if err := st.scratchPut(dst.path, b, ctype); err != nil {
			return err
		}
		// The client takes the name for free now, and may create it
		// only (davfs2's If-None-Match: *): that write is the edit.
		st.p.setAside(src.path, st.s.opt.Now())
		return nil
	case live || src.kind == kFolder:
		switch {
		case st.isCatalogMove(src, dst):
			return st.move(ctx, src, dst)
		case live && (src.kind == kDoc || src.kind == kRaw) && (dst.kind == kNewPlacement || dst.kind == kPlacement) && dst.docNS == src.docNS && dst.docName == src.docName:
			// A document of a flat directory into a catalog folder: the
			// same document placed there, as a COPY places it. It stays
			// in its namespace, so in the flat directory too.
			return st.placeByMove(ctx, src, dst)
		case live && src.kind == kPlacement && (dst.kind == kDoc || dst.kind == kRaw) && dst.docNS == src.docNS && dst.docName == src.docName:
			// A placement onto its own item's file in the flat directory:
			// unplaced, as a DELETE of it does (§B.7); the item stays.
			return st.unplace(ctx, src)
		case src.kind == kFolder && dst.ns == src.ns && dst.base != src.base:
			return fail(http.StatusForbidden, "folder names are identity (§3.6, §B.2): folder %s can't be renamed; make a folder %s, move what is in %s into it, then delete %s", src.node, dst.base, src.node, src.node)
		case src.kind == kFolder:
			return fail(http.StatusForbidden, "folder %s moves only between the folders of catalog %s", src.node, src.ns)
		case src.kind == kPlacement && (dst.kind == kNewPlacement || dst.kind == kPlacement) && dst.ns == src.ns:
			return fail(http.StatusForbidden, "names are identity (§3.6, §B.1): a placement is named by its item, %s.%s, and can't be renamed; move it to another folder under the same name", src.docNS, src.docName)
		}
		return fail(http.StatusForbidden, "names are identity (§3.6, §B.1): a file can't be renamed or moved to another namespace here; copy it to a new name and delete the old one, or, into a catalog folder, under its own name {ns}.{name}.json")
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
		case kScratch, kBadName:
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
		st.ctype = f.ctype
		if _, _, err := st.commitRev(ctx, dst, f.data); err != nil {
			return st.undoOwnDelete(ctx, dst, upstream(err))
		}
		st.scratchRemove(src.path)
		return nil
	case dst.kind == kScratch || dst.kind == kNewFolder:
		return st.scratchRename(src.path, dst.path)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// placeByMove places the document of flat path src in catalog folder
// dst, as a COPY would: its content written to the placement's path,
// which edits nothing.
func (st *reqState) placeByMove(ctx context.Context, src, dst target) error {
	if err := st.writable(ctx, dst); err != nil {
		return err
	}
	hd, live, err := st.docAt(ctx, src)
	switch {
	case err != nil:
		return err
	case !live:
		return errNotExist
	}
	b, err := st.fileBytes(ctx, &hd)
	if err != nil {
		return err
	}
	_, _, err = st.commitRev(ctx, dst, b)
	return err
}

// fileBytes returns live file hd's content as its reader gets it: a JSON
// file's representation (repr), or a raw file's bytes, read whole from its
// blob, at most MaxFileSize of them (413 beyond).
func (st *reqState) fileBytes(ctx context.Context, hd *headDoc) ([]byte, error) {
	if r := hd.m.raw; r != nil {
		if r.size > int64(st.s.opt.MaxFileSize) {
			return nil, fail(http.StatusRequestEntityTooLarge, "%s/%s is %d bytes, and a file kept or copied here whole is at most %d bytes", hd.ns, hd.name, r.size, st.s.opt.MaxFileSize)
		}
		b, err := st.p.c.GetBlob(ctx, hd.ns, hd.name, r.bid, r.nonce)
		if err != nil {
			return nil, err
		}
		return b.Data, nil
	}
	if _, err := st.entry(ctx, hd); err != nil {
		return nil, err
	}
	return st.repr(*hd), nil
}

// commitRev writes body to the file a path names: an edit, a create or a
// restore, or for a new placement also the placement (§B.2), as a file of
// the kind kindOf says (§H.1). It returns the revision now holding it,
// and whether that holds exactly body. An empty body creates nothing: a
// client making a file before writing it (LOCK, Finder's 0-byte PUT) gets
// a placeholder, and a live file isn't truncated.
func (st *reqState) commitRev(ctx context.Context, t target, body []byte) (string, bool, error) {
	defer st.changed()
	raw, name, v, err := st.kindOf(ctx, t, body)
	if err != nil {
		return "", false, err
	}
	if len(body) == 0 || !raw && len(bytes.TrimSpace(trimBOM(body))) == 0 {
		if t.kind != kNewPlacement {
			hd, live, err := st.docAt(ctx, t)
			if err != nil {
				return "", false, err
			}
			if live {
				return hd.rev, false, nil
			}
		}
		return "", true, st.scratchPut(t.path, nil, st.ctype)
	}
	if !raw && v == nil {
		if v, err = parseBody(body); err != nil {
			return "", false, err
		}
	}
	var rev string
	var exact bool
	switch {
	case t.kind == kNewPlacement:
		rev, exact, err = st.place(ctx, t, v, body, raw, true)
	case raw:
		rev, exact, err = st.commitRaw(ctx, t.docNS, name, body, true)
	default:
		rev, exact, err = st.commitDoc(ctx, t.docNS, t.docName, v, body, true)
	}
	if err != nil {
		return "", false, err
	}
	st.scratchRemove(t.path)
	return rev, exact, nil
}

// kindOf says whether body, written to t, is a raw file's content, and of
// which resource, or else a JSON file's, parsed if it was (§H.1): a raw
// file's path takes any bytes; a live JSON file only JSON; a new {name}.json
// is JSON document {name} if body is I-JSON (a BOM dropped), else raw file
// {name}.json; one the principal deleted moments ago is restored as the
// file it was, JSON or raw (§H.6 "Delete, then write"); a placement's item
// keeps its kind, and a new one is JSON.
func (st *reqState) kindOf(ctx context.Context, t target, body []byte) (bool, string, any, error) {
	switch t.kind {
	case kRaw:
		return true, t.docName, nil, nil
	case kDoc:
		if t.rawName == "" {
			return false, t.docName, nil, nil
		}
		now := st.s.opt.Now()
		_, live, err := st.docAt(ctx, t)
		switch {
		case err != nil || live || st.p.deletedOwn(t.docNS, t.docName, "", now):
			return false, t.docName, nil, err
		case st.p.deletedOwn(t.docNS, t.rawName, "", now):
			return true, t.rawName, nil, nil
		}
		if v, err := jsonv.Parse(trimBOM(body)); err == nil {
			return false, t.docName, v, nil
		}
		return true, t.rawName, nil, nil
	case kPlacement, kNewPlacement:
		h, err := st.head(ctx, t.docNS, t.docName)
		if err != nil || h.State != client.Live {
			return false, t.docName, nil, err
		}
		m, err := st.s.meta(ctx, st.p, t.docNS, t.docName, h.ID)
		return err == nil && m.raw != nil, t.docName, nil, err
	}
	return false, t.docName, nil, nil
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
	case w.scratch && w.err == nil && w.st.bodyErr == nil:
		return w.st.record(w.st.scratchPut(w.t.path, bytes.Clone(w.buf.Bytes()), w.st.ctype))
	case w.scratch:
		return w.st.record(w.failure())
	case w.err != nil, w.st.bodyErr != nil:
		// Nothing of it is written; a save that deleted the original
		// first gets it back.
		return w.st.record(w.st.undoOwnDelete(w.ctx, w.t, w.failure()))
	}
	rev, exact, err := w.st.commitRev(w.ctx, w.t, bytes.Clone(w.buf.Bytes()))
	if exact {
		w.rev = rev
	} else {
		// Merged with others' edits: the revision isn't what the client
		// sent, so it gets no validator for it (RFC 9110 §9.3.4, §H.1); a
		// cache would keep what it sent under the revision's tag.
		w.st.noETag = true
	}
	return w.st.record(w.st.undoOwnDelete(w.ctx, w.t, upstream(err)))
}

// failure is why a written file isn't committed: a Write refused it (too
// large, too many at once), or its body was cut short.
func (w *writeFile) failure() error {
	if w.err != nil {
		return w.err
	}
	return &davError{status: http.StatusBadRequest, msg: "the request body didn't arrive whole; nothing was written", cause: w.st.bodyErr}
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

// memFile is a scratch file, read from memory.
type memFile struct {
	*bytes.Reader
	noDeadProps
	fi *fileInfo
}

func (f *memFile) Close() error                       { return nil }
func (f *memFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (f *memFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (f *memFile) Stat() (os.FileInfo, error)         { return f.fi, nil }

// docFile is a JSON file being read: its representation (repr), read from
// its document when first read or sought, not when opened, as a PROPFIND
// opens every file it lists for its properties.
type docFile struct {
	noDeadProps
	st  *reqState
	ctx context.Context
	hd  headDoc
	fi  *fileInfo
	r   *bytes.Reader
}

func (f *docFile) load() error {
	if f.r == nil {
		if _, err := f.st.entry(f.ctx, &f.hd); err != nil {
			return err
		}
		f.r = bytes.NewReader(f.st.repr(f.hd))
	}
	return nil
}

func (f *docFile) Read(p []byte) (int, error) {
	if err := f.load(); err != nil {
		return 0, err
	}
	return f.r.Read(p)
}

func (f *docFile) Seek(offset int64, whence int) (int64, error) {
	if err := f.load(); err != nil {
		return 0, err
	}
	return f.r.Seek(offset, whence)
}

func (f *docFile) Close() error                       { return nil }
func (f *docFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (f *docFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (f *docFile) Stat() (os.FileInfo, error)         { return f.fi, nil }

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
