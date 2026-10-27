package dav

import (
	"bufio"
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
	"unicode/utf8"

	"golang.org/x/net/webdav"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// errNotExist is what the WebDAV handler takes as "no such file".
var errNotExist = os.ErrNotExist

// kind is what a path names.
type kind int

const (
	kMissing   kind = iota // nothing, nor a directory to make it in
	kRoot                  // /
	kNSDir                 // a flat namespace
	kCatDir                // a file tree's top level (§H.2), the children of files.root
	kDoc                   // a flat namespace's JSON file, {name}.json (§H.2 "Flat view")
	kRaw                   // a flat namespace's raw file, named by its resource name
	kFolder                // a tree's folder, by its title in the folder it is in
	kPlacement             // a tree's file, a placement, by its title in the folder it is in
	kNewNode               // a name in a tree's folder that no child has: a new file (PUT) or folder (MKCOL)
	kScratch               // a scratch file or directory (§H.6)
	kBadName               // a name no file can have there: refused
)

// target is a resolved path.
type target struct {
	kind            kind
	path, dir, base string
	ns              string // the namespace or catalog it is in
	// docNS and docName are the content document of a kDoc, kRaw or
	// kPlacement, live or not; rawName is the raw document a new kDoc's
	// file is instead when its content isn't JSON (§H.1).
	docNS, docName, rawName string
	// node is the catalog node of a kCatDir (files.root), kFolder or
	// kPlacement, and parent the folder node its path puts a kFolder,
	// kPlacement or kNewNode in; title is the name a kFolder or kPlacement
	// is shown by there, or the title a kNewNode gets (in NFC).
	node, parent, title string
	// listedAs is the name a kFolder or kPlacement was found by, before
	// duplicates were numbered (nodeName): a write checks the node still
	// has it (stillNamed)
	listedAs string
	sdir     bool // a kScratch that is a scratch directory
	// otherCase: a kFolder or kPlacement named by another case of its
	// name, which compares equal (nameKey) but isn't it
	otherCase bool
	// hiddenTop: a name at the top level of a tree whose files.root is
	// hidden from the reader, that top level its roots (§B.11.5, §H.3;
	// topWrite)
	hiddenTop bool
}

func (t target) isDir() bool {
	return t.kind == kRoot || t.kind == kNSDir || t.kind == kCatDir || t.kind == kFolder || t.kind == kScratch && t.sdir
}

// shownAs is the name t's file or folder has in its directory's listing:
// a tree's node the name it is shown by there (a client whose file system
// ignores case may ask for it under another case), else the path's.
func (t target) shownAs() string {
	if t.kind == kFolder || t.kind == kPlacement {
		return t.title
	}
	return t.base
}

// isDoc: the path names a document's file (which may not be live), or a
// file a write makes in a tree.
func (t target) isDoc() bool {
	return t.kind == kDoc || t.kind == kRaw || t.kind == kPlacement || t.kind == kNewNode
}

// resolve says what name names for the request's principal, noting the
// document path a PUT writes (saveTo): one in a tree whose read failed
// too (a 429, a timeout), as a file's, whose DELETE that follows may find
// the tree read.
func (st *reqState) resolve(ctx context.Context, name string) (target, error) {
	t, err := st.resolveName(ctx, name)
	if st.method == "PUT" && st.saveTo == "" && slashClean(name) == st.path {
		switch {
		case err == nil && t.isDoc():
			st.saveTo, st.saveDoc = t.path, t.kind == kDoc || t.kind == kRaw
		case err != nil && st.treePath(st.path):
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
		if why, err := st.offered(ctx, t.ns); err != nil || why != nil {
			if err == nil {
				err = why
			}
			return t, err
		}
	}
	if len(segs) > 1 && st.isScratchDir(t.dir) {
		// In a scratch directory, an app's (mayScratchDir), every name is
		// scratch: a macOS app's safe save writes the file there before
		// moving it out.
		return st.scratchAt(t, false), nil
	}
	switch {
	case len(segs) == 1 && st.s.flat[t.ns]:
		t.kind = kNSDir
	case len(segs) == 1 && st.s.cats[t.ns]:
		t.kind = kCatDir
		if c, err := st.treeConf(ctx, t.ns); err == nil {
			t.node = c.files.root
		}
	case len(segs) == 1:
		t = st.scratchAt(t, true)
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
// one as {name}.json, or as {name} (2).json, the name it has where a raw
// one has {name}.json, which keeps naming it for a client that had it
// once the raw one is gone; else a scratch name (§H.6), a new file a
// resource name can make (raw, or JSON for a {name}.json of JSON content:
// commitRev), a scratch file kept there, the destination of a COPY that
// a file manager names as a copy beside a live file (its Duplicate, which
// a rename commits), or a name no file can have here: never a scratch
// file a plain PUT makes under a name that only looks like one (a
// browser's "invoice (1).pdf"), which would vanish.
func (st *reqState) resolveFlat(ctx context.Context, t target) (target, error) {
	hd, kind, ok, err := st.flatOwner(ctx, t.ns, t.dir, t.base)
	switch {
	case err != nil:
		return t, err
	case ok:
		t.kind, t.docNS, t.docName = kind, t.ns, hd.name
		return t, nil
	case scratchName(t.base):
		return st.scratchAt(t, false), nil
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
		return st.scratchAt(t, false), nil
	}
	if orig, ok := copyOf(t.base); ok && st.method == "COPY" && t.path == st.dst {
		if _, _, live, err := st.flatOwner(ctx, t.ns, t.dir, orig); err != nil || live {
			return st.scratchAt(t, false), err
		}
	}
	t.kind = kBadName
	return t, nil
}

// flatOwner returns the live document whose file is named base in flat
// namespace ns's directory dir, and the file's kind (kRaw or kDoc): a raw
// document named base; else a JSON one named {stem} for {stem}.json, or for
// {stem} (2).json, its name where a raw {stem}.json takes {stem}.json
// (dupName), whether or not that raw one is still live. The directory's
// listing answers if the request read it, else heads.
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
		m, err := st.s.meta(ctx, st.tk, ns, name, h.ID)
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
		// {stem} (2).json: JSON document {stem}, shown so while a raw
		// {stem}.json takes {stem}.json, and still its name for a client
		// that has it open once that one is gone (it is listed as
		// {stem}.json then).
		stem, isJSON = strings.CutSuffix(d, ".json")
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

// scratchAt makes t a scratch path; named, at the root, where only
// editors' and systems' own files (scratchName) and app folders (appDir,
// made with MKCOL) can be: any other name is refused, since no file there
// reaches the core, and kept only in memory it would vanish (a report.pdf
// dropped on the mount's top folder, a Save As "Report.json"). A flat
// namespace's directory refuses more (resolveFlat); a tree makes any
// other name a new file (resolveCatalog).
func (st *reqState) scratchAt(t target, named bool) target {
	t.kind = kScratch
	f, ok := st.scratchPeek(t.path)
	t.sdir = ok && f.dir
	if named && !ok && !scratchName(t.base) {
		t.kind = kBadName
	}
	return t
}

// copyNames are the names file managers give a copy of x.json (or any
// x.ext, or x) made beside it: Finder's "x copy.json", "x copy 2.json" and
// "x 2.json" (Keep Both); Explorer's "x - Copy.json", "x - Copy (2).json",
// "Copy of x.json" and "x (1).json"; GNOME's "x (copy).json", "x (another
// copy).json", "x (3rd copy).json". Each holds a space, so no resource
// name looks like one: in the flat view such a copy of a file is a
// scratch file, which the rename that follows commits; in a tree it is a
// file like any other.
var copyNames = regexp.MustCompile(`^(?:(?i:copy of )(.+)|(.+?)(?:(?i: copy)(?: \d+)?|(?i: - copy)(?: \(\d+\))?| \((?i:copy|another copy|\d+(?:st|nd|rd|th) copy)\)| \(\d+\)| \d+)(\.[^. ]*)?)$`)

// copyOf returns the name of the file a copy's name names.
func copyOf(base string) (string, bool) {
	m := copyNames.FindStringSubmatch(base)
	if m == nil {
		return "", false
	}
	return m[1] + m[2] + m[3], true
}

// appDir reports a directory name apps and systems save through, kept as
// a scratch directory (§H.6 "folders such as (A Document Being Saved By
// …)"): macOS's safe save "(A Document Being Saved By TextEdit)", and the
// folders macOS and Linux desktops make on a mounted volume
// (.TemporaryItems, .Trashes, .Trash, .Trash-{uid}, .Spotlight-V100,
// .fseventsd, .DocumentRevisions-V100). Any other name, a dot one too
// (.github, .vscode, .obsidian, which rclone and Finder copy with what is
// in them), is a person's folder.
func appDir(base string) bool {
	switch base {
	case ".TemporaryItems", ".Trashes", ".Trash", ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100":
		return true
	}
	return strings.HasPrefix(base, "(A Document Being Saved By ") || strings.HasPrefix(base, ".Trash-")
}

// mayScratchDir refuses a scratch directory at t (MKCOL, or a scratch
// directory moved there) but an app's: outside a tree, files saved in a
// folder a person made would be kept in memory only, and in a tree such a
// folder is a folder node (resolveCatalog).
func (st *reqState) mayScratchDir(t target) error {
	if appDir(t.base) || st.isScratchDir(t.dir) {
		return nil
	}
	return fail(http.StatusForbidden, "folders are made only in file trees (-catalog): %s can't hold one (a folder there would keep what is saved in it in memory only)", t.dir)
}

// replaced refuses a save of file t without a tag (§H.4) where its path
// names another document than the one the principal last read whole or
// wrote under it (pathOf), or none (a tree's new name), rather than
// taking that document's head as the base and writing the save over it:
// records are kept by document, and a path may come to name another, a
// tree's title given to a new item after the old one was deleted, or
// moved away, a raw x.json taking JSON document x's name. A reload, a GET
// of the path, records what it names now (or forgets it, finding none).
// A flat name whose document is the one read, deleted since, is left to
// the save (tombBase).
func (st *reqState) replaced(ctx context.Context, t target) error {
	if st.ifMatch != "" || st.matchAny {
		return nil
	}
	ns, name, ok := st.s.pathOf(st.p, t.path)
	if !ok {
		return nil
	}
	same := false
	switch t.kind {
	case kDoc, kRaw:
		same = ns == t.docNS && name == t.docName
		if !same && ns == t.docNS && t.rawName != "" && name == t.rawName {
			// The raw x.json that was shown as x.json, deleted since:
			// unless JSON document x now is.
			_, live, err := st.docAt(ctx, t)
			if err != nil {
				return err
			}
			same = !live
		}
	case kPlacement:
		same = ns == t.docNS && name == t.docName
	case kNewNode:
		d, ok := st.p.treeDeleted(t.path, st.s.opt.Now())
		same = ok && d.cat == t.ns && d.parent == t.parent && ns == d.itemNS && name == d.itemName
	default:
		return nil
	}
	if same {
		return nil
	}
	st.refuse(ns, name)
	now := "names no file now"
	if t.kind != kNewNode {
		now = fmt.Sprintf("names %s/%s now", t.docNS, t.docName)
	}
	return fail(http.StatusConflict, "%s held %s/%s when you opened it, and %s: it was deleted, moved or replaced since (§H.4), so your save isn't written over what is there; reload it", t.path, ns, name, now)
}

// otherCase refuses a write to t, a tree's file or folder named by
// another case of its name (§H.2 "Siblings"): a client whose file system
// tells case apart (rclone, davfs2) copying README.md and readme.md would
// otherwise write one over the other. A client that ignores case uses a
// file's name as listed, or as it read the file under (spelledSo); a
// folder's is refused whatever the request carries, a file never written
// over a folder.
func otherCase(t target) error {
	if t.kind == kFolder {
		return fail(http.StatusConflict, "%s: %q is a folder here, and names in this tree compare without case (§H.2), so %q isn't made beside it; use another name", t.path, t.title, t.base)
	}
	return fail(http.StatusConflict, "%s: %q is a file here, and names in this tree compare without case (§H.2), so %q isn't made beside it, nor written over it; write it as %q, or use another name", t.path, t.title, t.base, t.title)
}

// spelledSo reports whether a write to t, named by another case of its
// name, means that file: it names the revision it edited (If-Match, or an
// If header's entity tag, which the save checks is the file's), or the
// principal read or wrote that file under this spelling (pathOf).
func (st *reqState) spelledSo(t target) bool {
	if st.ifMatch != "" {
		return true
	}
	ns, name, ok := st.s.pathOf(st.p, t.path)
	return ok && ns == t.docNS && name == t.docName
}

// badName is the refusal of a kBadName.
func (st *reqState) badName(t target) error {
	if d, n, dup := dupOf(t.base); st.s.flat[t.ns] && dup && n == 2 {
		if stem, ok := strings.CutSuffix(d, ".json"); ok && client.ValidResourceName(stem) {
			return fail(http.StatusConflict, "%q was the name of JSON document %s/%s beside a raw %s (§H.2), and that document is gone: it names no file now; reload the folder", t.base, t.ns, stem, d)
		}
	}
	switch {
	case st.s.cats[t.ns]:
		_, err := newTitle(t.base)
		return err
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

// offered returns why namespace ns isn't offered to the request's token,
// or nil: a sealed or end-to-end one isn't (notOffered, §H.7; §7.4's
// writer block says, to any grant the namespace verifies), nor a catalog
// whose document makes no file tree (notTree, §H.2); one that refuses the
// token's grant, or whose document it can't read, is (it then gets what
// the core answers), as is one its grant doesn't name. An answer that
// couldn't be had for now (a 429, a 5xx) is the error.
func (st *reqState) offered(ctx context.Context, ns string) (why, err error) {
	if st.tk.named != nil && !st.tk.named[ns] {
		return nil, nil
	}
	in, err := st.s.nsInfoErr(ctx, st.tk, ns)
	switch {
	case err != nil:
		return nil, err
	case in.sealed:
		return notOffered(ns), nil
	case st.s.cats[ns] && in.notTree != "":
		return notTree(ns, in.notTree), nil
	}
	return nil, nil
}

// fileInfo is a file or directory as the handler sees it. A document's
// ETag is its revision id, weak where the bytes served are the writer's
// own (weak); a written file's is the revision its close committed, if
// that holds exactly what was written.
type fileInfo struct {
	name  string
	size  int64
	mod   time.Time
	dir   bool
	mode  fs.FileMode
	rev   string
	ctype string
	w     *writeFile
	// weak: the file reads as the bytes its writer uploaded, which
	// the revision holds exactly though its rendering differs (repr):
	// served under W/"{id}" (§H.1 "Writer's bytes")
	weak bool
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
	if fi.weak {
		return `W/"` + rev + `"`, nil
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

// docInfo is a live document's file (§H.3): its size and type as every
// tool lists them (files.MetaOf), but a JSON file's size is that of the
// bytes the principal wrote where it reads those back (repr), under a
// weak ETag (§H.1 "Writer's bytes"): everyone else reads the rendering
// under the strong one. Its time is when the head was written (modTime).
func (st *reqState) docInfo(name string, hd headDoc) *fileInfo {
	fi := &fileInfo{name: name, rev: hd.rev, mode: 0o644, size: hd.m.Size, ctype: hd.m.Type,
		mod: st.s.modTime(st.p, docKey(hd.ns, hd.name, hd.rev), hd.created, hd.m.modified)}
	if hd.m.raw == nil {
		if b := st.s.exactOf(st.p, hd.ns, hd.name, hd.rev); b != nil {
			fi.size, fi.weak = int64(len(b)), true
		}
	}
	return fi
}

func scratchInfo(name string, f *scratchFile) *fileInfo {
	if f.dir {
		return &fileInfo{name: name, dir: true, mode: fs.ModeDir | 0o755, mod: f.mod}
	}
	ct := declaredType(name, f.ctype)
	if ct == "" {
		ct = octetStream
		if m := mime.TypeByExtension(path.Ext(name)); m != "" {
			ct = m
		}
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

// list reads directory t: its files and folders as the core has them now
// (each request reads a flat namespace again; a catalog's tree is kept
// CatalogTTL), and the scope's scratch files in it. The root lists
// the namespaces offered (§H.7, §H.2). A flat namespace lists the head
// rows of /heads (§H.3) by the flat view's names (§H.2): a raw document
// by its name, any other as {name}.json, and one whose name a raw one has
// as {name} (2).json. A tree's folder lists its children by their names
// there (treeDir). Each revision's document is read once for its file's
// size and type (Server.metas), but where a tree service listed them
// (§H.3).
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
			if why, err := st.offered(ctx, ns); why == nil || err != nil {
				add(st.dirInfo(ns))
			}
		}
	case kNSDir:
		hs, err := st.s.liveHeads(ctx, st.tk, t.ns)
		if err != nil {
			return nil, err
		}
		if hs, err = st.s.fetchHeads(ctx, st.tk, hs, st.tk.c.Head, false); err != nil {
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
					name = dupName(name, false, taken)
				}
			}
			l.docs[name] = hd
			add(st.docInfo(name, hd))
		}
	case kCatDir, kFolder:
		d, err := st.treeDir(ctx, t.ns, t.node)
		if err != nil {
			return nil, err
		}
		var files []headDoc
		byRes := map[string]string{}
		for _, e := range d.entries {
			switch {
			case e.node.Kind == kindFolder:
				add(st.dirInfo(e.name))
			case e.meta != nil:
				// The file metadata the tree service listed (§H.3): no
				// item is read.
				hd := headDoc{ns: e.node.ItemNS, name: e.node.ItemName, rev: e.item.ID, created: e.modified, m: *e.meta, listed: true}
				l.docs[e.name] = hd
				add(st.docInfo(e.name, hd))
			default:
				files = append(files, headDoc{ns: e.node.ItemNS, name: e.node.ItemName, rev: e.item.ID})
				byRes[e.node.ItemNS+"/"+e.node.ItemName] = e.name
			}
		}
		// With tree-derived access, read under grants the catalog issues
		// (§B.11.5 /read-grants). fetchHeads leaves out what it can't
		// read, so names pair up by resource (an item is placed once per
		// catalog, §B.2).
		if err := st.readGrants(ctx, t.ns, files); err != nil {
			return nil, err
		}
		docs, err := st.s.fetchHeads(ctx, st.tk, files, nil, false)
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
	h, err := st.tk.c.Head(ctx, ns, name)
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
// directory's listing if the request read it (a PROPFIND, for a file a
// tree service listed), else from its head: for a
// flat namespace's file, only a document of its kind (a JSON document's
// file names no raw one, nor a raw file a JSON one), and never a sealed
// one, which isn't offered (§H.7).
func (st *reqState) docAt(ctx context.Context, t target) (headDoc, bool, error) {
	if l := st.lists[t.dir]; l != nil {
		// A file the tree service listed (§H.3) is shown from its listing,
		// as a PROPFIND opens it; anything else reads its document.
		if hd, ok := l.docs[t.shownAs()]; !ok || !hd.listed || st.method == "PROPFIND" {
			return hd, ok, nil
		}
	}
	// With tree-derived access, under a grant the catalog issues for the
	// item (§H.2 "Access"), to edit where the request writes it.
	if err := st.itemAccess(ctx, t, st.writes() && (t.path == st.path || t.path == st.dst)); err != nil {
		return headDoc{}, false, err
	}
	if t.kind == kPlacement && st.s.nsInfo(ctx, st.tk, t.docNS).sealed {
		return headDoc{}, false, nil
	}
	h, err := st.head(ctx, t.docNS, t.docName)
	if err != nil || h.State != client.Live {
		return headDoc{}, false, err
	}
	m, err := st.s.meta(ctx, st.tk, t.docNS, t.docName, h.ID)
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
		if fi := l.byName[t.shownAs()]; fi != nil {
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
	}
	if f, ok := st.scratchGet(t.path); ok {
		return scratchInfo(t.base, f), nil
	}
	return nil, errNotExist
}

// davFS is the webdav.FileSystem; the token and its user come with each
// request's context.
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
	if st.method == "MOVE" && t.path == st.dst && st.dst != st.path && (t.kind == kFolder || t.kind == kPlacement) {
		// A rename to another case of the node's own name, which compares
		// equal (nameKey): no other file is there, whatever Overwrite says.
		if src, err := st.resolve(ctx, st.path); err == nil && src.kind == t.kind && src.ns == t.ns && src.node == t.node {
			return nil, errNotExist
		}
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
		// buffered, and committed on close. A COPY's file refused sets a
		// guard, as a PUT's does (saveTo, §H.6); so does a PUT or COPY
		// refused onto a tree's folder, which the DELETE that follows
		// (rclone's) would otherwise delete.
		switch {
		case st.method == "COPY" && t.path == st.dst && (t.isDoc() || t.kind == kFolder):
			st.saveTo = t.path
		case st.method == "PUT" && t.path == st.path && t.kind == kFolder:
			st.saveTo = t.path
		}
		switch {
		case t.kind == kMissing:
			return nil, errNotExist
		case t.kind == kBadName:
			return nil, st.badName(t)
		case t.kind == kFolder && t.otherCase:
			// Another case of a folder's name (§H.2 "Siblings"): 409,
			// naming the folder, not the 403 or 405 of its own name.
			return nil, otherCase(t)
		case t.isDir() && (st.method == "COPY" || st.method == "MOVE"):
			// A file copied or moved onto a folder (§H.5): 403, not the
			// 405 of a PUT to one; Overwrite: F is x/net/webdav's 412.
			return nil, fail(http.StatusForbidden, "%s is a folder: a file copied or moved there doesn't replace it (§H.5)", t.path)
		case t.isDir():
			return nil, fail(http.StatusMethodNotAllowed, "%s is a directory", t.path)
		case t.kind == kPlacement && t.otherCase && !st.spelledSo(t):
			return nil, otherCase(t)
		}
		if err := st.preconditions(ctx, t); err != nil {
			return nil, st.undoOwnDelete(ctx, t, err)
		}
		if st.method == "PUT" && t.path == st.path {
			if err := st.replaced(ctx, t); err != nil {
				return nil, err
			}
		}
		switch {
		case t.isDoc():
			if err := st.writable(ctx, t); err != nil {
				return nil, err
			}
			max, err := st.maxWrite(ctx, t)
			if err != nil {
				return nil, err
			}
			return &writeFile{st: st, ctx: ctx, t: t, max: max}, nil
		}
		return &writeFile{st: st, ctx: ctx, t: t, scratch: true, max: st.s.opt.MaxFileSize}, nil
	}
	fi, err := st.stat(ctx, t)
	if errors.Is(err, errNotExist) && st.method == "GET" && t.path == st.path && t.docName != "" {
		// A file the core has gone, read: the reload a save refused over
		// someone else's delete asked for (tombBase).
		st.gone = []stagedServe{{ns: t.docNS, name: t.docName}}
		if t.rawName != "" {
			st.gone = append(st.gone, stagedServe{ns: t.docNS, name: t.rawName})
		}
	}
	if err != nil {
		return nil, err
	}
	if fi.dir {
		// Listed when read (Readdir), not when opened: a PROPFIND opens
		// every entry it lists for its properties.
		return &dirFile{deadProps: deadProps{st, t.path}, st: st, ctx: ctx, t: t, fi: fi}, nil
	}
	served := (st.method == "GET" || st.method == "HEAD") && t.path == st.path
	if served && st.resp != nil {
		// A file is served as its type, never one sniffed; nosniff and the
		// sandbox go with every answer (ServeHTTP, §H.6 "Raw bytes").
		st.resp.Set("Content-Type", fi.ctype)
	}
	if fi.rev == "" {
		f, ok := st.scratchGet(t.path)
		if !ok {
			return nil, errNotExist
		}
		return &memFile{deadProps: deadProps{st, t.path}, Reader: bytes.NewReader(f.data), fi: fi}, nil
	}
	hd, live, err := st.docAt(ctx, t)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errNotExist
	}
	if served {
		if err := st.ifMatchGet(t, hd.rev); err != nil {
			return nil, err
		}
		// What the client now has is a base of its next save, once a GET's
		// body is sent (a 304 sends none). A client whose copy is suspect
		// gets the file whatever its validators say (§H.1 "Identity").
		if st.method == "GET" {
			st.serve = &stagedServe{ns: hd.ns, name: hd.name, rev: hd.rev, path: t.path}
		}
		if st.hdr != nil && st.s.stale(st.p, hd.ns, hd.name, hd.rev, st.tk.id) {
			st.hdr.Del("If-None-Match")
			st.hdr.Del("If-Modified-Since")
		}
	}
	copied := st.method == "COPY" && (t.path == st.path || strings.HasPrefix(t.path, st.path+"/"))
	if copied {
		// The file a COPY copies next, itself or one in the folder it
		// copies (copyFolder): none of the last one's type or blob.
		st.ctype, st.copySrc = "", nil
	}
	if r := hd.m.raw; r != nil {
		if served && r.typ == pdfType {
			st.servePDF()
		}
		if copied {
			// The copy's type is the source's (fileType), and its blob the
			// source's, copied (§7.8, §H.5 "Copy").
			st.ctype = r.typ
			st.copySrc = &blobSrc{ns: hd.ns, name: hd.name, ref: *r}
		}
		return st.rawFile(ctx, hd, fi, t.path)
	}
	f := &docFile{deadProps: deadProps{st, t.path}, st: st, ctx: ctx, hd: hd, fi: fi}
	if served {
		// Read now, so a failure is the answer.
		if err := f.load(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// pdfType is the stored type of a PDF (§H.1).
const pdfType = "application/pdf"

// servePDF answers a GET or HEAD of a raw file stored as exactly
// application/pdf without the sandbox, which blanks browsers' PDF viewers
// (§7.8, §H.6 "Headers": PDFs are excepted), and still with nosniff; as
// an attachment (Content-Disposition), so no browser shows it in this
// origin, unless the deployment opts into inline display (InlinePDF).
// Only its 200 or 206 goes so: any other answer gets the sandbox back
// (errWriter).
func (st *reqState) servePDF() {
	if st.resp == nil {
		return
	}
	st.pdf = true
	st.resp.Del("Content-Security-Policy")
	if !st.s.opt.InlinePDF {
		st.resp.Set("Content-Disposition", "attachment")
	}
}

// ifMatchGet checks a GET's or HEAD's If-Match against revision rev of
// file t, which it serves, and takes it out of the request: a gateway
// takes a weak tag like the strong one in any If-Match (§H.1 "Writer's
// bytes"), where http.ServeContent compares them strongly (RFC 9110
// §13.1.1), which no weak tag passes, the writer's own W/"{id}"
// included. One that names neither * nor rev is a 412.
func (st *reqState) ifMatchGet(t target, rev string) error {
	if st.hdr == nil || st.hdr.Get("If-Match") == "" {
		return nil
	}
	im := st.hdr.Get("If-Match")
	for _, tag := range strings.Split(im, ",") {
		if tag = strings.TrimSpace(tag); tag == "*" || revOfETag(tag) == rev {
			st.hdr.Del("If-Match")
			return nil
		}
	}
	return fail(http.StatusPreconditionFailed, "%s is at revision %s, which its If-Match doesn't name", t.path, rev)
}

// preconditions checks a PUT's If-None-Match: * (create only) and
// If-Match: * (edit only), which x/net/webdav doesn't, against what the
// path holds now; a document's write checks them again (commitDoc). An
// If-Match (or If header) tag naming a revision is a 412 at a path that
// holds no file the tag could be of, a tree's new name or a scratch
// name, rather than a new file or a scratch write (§H.4, RFC 9110
// §13.1.1): its file was deleted, or the path came to name none; but for
// one the principal deleted moments ago, which the write restores (§H.6).
// A flat namespace's name checks it as it saves: a revision of its
// chain, deleted by someone else since, is that 409 (tombBase), and a
// name without one a 412.
func (st *reqState) preconditions(ctx context.Context, t target) error {
	if st.ifMatch != "" && st.method == "PUT" && t.path == st.path && t.kind != kDoc && t.kind != kRaw && t.kind != kPlacement && !st.deletedPath(t) {
		return fail(http.StatusPreconditionFailed, "%s holds no file, so none has revision %s (If-Match): it was deleted or moved, or the name now names nothing; reload it", t.path, st.ifMatch)
	}
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
	t, err := st.resolve(ctx, name)
	if err != nil {
		return err
	}
	if st.method == "COPY" {
		// x/net/webdav makes the copy of a folder before copying what is
		// in it, one by one.
		return st.copyFolder(ctx, t)
	}
	switch t.kind {
	case kMissing:
		// RFC 4918 §9.3.1: 409, the parent not being a collection.
		return fail(http.StatusConflict, "%s can't be made: %s isn't a folder here (a file, or nothing); make the folders above it first", t.path, t.dir)
	case kRoot, kNSDir, kCatDir, kFolder:
		return os.ErrExist
	case kNewNode:
		if appDir(t.base) {
			// An app saves through it: a scratch directory (§H.6).
			return st.scratchMkdir(t.path)
		}
		return st.mkFolder(ctx, t)
	case kBadName, kScratch:
		// Not a tree's folder: a scratch directory (an app's safe save),
		// which a name no file can have may be (§H.6); in a tree, a name
		// no title can be is refused as such.
		if err := st.mayScratchDir(t); err != nil {
			if t.kind == kBadName && st.s.cats[t.ns] {
				return st.badName(t)
			}
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
		if err := st.srcPrecondition(ctx); err != nil {
			return err
		}
		// The handler clears an existing destination before moving or
		// copying onto it: a document or a tree's node there is written
		// over (an edit, a rename), never deleted first.
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
		if hd, live, err := st.docAt(ctx, t); err != nil {
			return err
		} else if live {
			if err := st.afterRefusedSave(ctx, t); err != nil {
				return err
			}
			// Without a tag, the head read here is deleted (If-Match), and
			// one someone changed since is a 409 (§H.5 "Delete a file").
			match := st.ifMatch
			if match == "" {
				match = hd.rev
			}
			_, err := st.deleteDoc(ctx, t.docNS, t.docName, match)
			if de, ok := err.(*davError); ok && de.status == http.StatusPreconditionFailed && st.ifMatch == "" {
				err = movedSinceRead(t)
			}
			if err == nil {
				st.s.forgetPath(st.p, t.path)
			}
			return err
		}
	case kPlacement:
		if err := st.afterRefusedSave(ctx, t); err != nil {
			return err
		}
		err := st.deleteFile(ctx, t, st.ifMatch, "")
		if err == nil {
			st.s.forgetPath(st.p, t.path)
		}
		return err
	case kFolder:
		// A folder a PUT or COPY was refused onto, or a write to another
		// case of its name (§H.2 "Siblings"), is guarded as a file is
		// (§H.6).
		if err := st.afterRefusedSave(ctx, t); err != nil {
			return err
		}
		return st.deleteFolder(ctx, t)
	}
	if !st.scratchRemove(t.path) {
		return errNotExist
	}
	return nil
}

// afterRefusedSave refuses a DELETE of t, a document's file or a tree's
// folder, that follows the principal's refused save to its path, using up
// one guard (refusedSaveFor,
// §H.6), unless it names the revision it deletes, which passes and leaves
// the guards. A document in a frozen namespace isn't deleted anyway: its
// DELETE gets the core's refusal (§8.4), the guards left; whether it is
// frozen is read again for a guarded DELETE, not taken from what was read
// before the namespace froze.
func (st *reqState) afterRefusedSave(ctx context.Context, t target) error {
	now := st.s.opt.Now()
	if st.ifMatch != "" || !st.p.guarded(t.path, now) {
		return nil
	}
	if t.kind == kDoc || t.kind == kRaw {
		st.tk.forgetNS(t.docNS)
		if st.s.nsInfo(ctx, st.tk, t.docNS).frozen {
			return nil
		}
	}
	r, left, ok := st.p.takeRefusedSave(t.path, now)
	if !ok {
		return nil
	}
	again := "delete it again to delete it"
	if left > 0 {
		again = fmt.Sprintf("it follows %d refused saves, each refusing one DELETE: delete it %d more times to delete it", left+1, left+1)
	}
	what := "file"
	if t.kind == kFolder {
		what = "path, a folder's"
	}
	return fail(http.StatusConflict, "%s wasn't deleted: this DELETE follows a refused save of the same %s (%d, moments ago), and some clients (rclone) delete a file whose upload failed; %s",
		t.path, what, r.status, again)
}

func (d *davFS) Rename(ctx context.Context, oldName, newName string) error {
	st := state(ctx)
	return st.fail(oldName, st.rename(ctx, oldName, newName))
}

// rename is a MOVE: the handler has cleared an existing destination
// (removeAll, which leaves documents and nodes in place). A live file
// moved to a scratch name is an editor's backup: copied, it stays (§H.5).
// Where a tree is involved, a file moves as §H.5 says (moveFile) and a
// folder within its tree (moveFolder); in the flat view as §H.8 says
// (moveFlat). A scratch file moved onto a file's name is a save of its
// content, and a scratch directory moved to a tree's new name becomes a
// folder there.
func (st *reqState) rename(ctx context.Context, oldName, newName string) error {
	src, err := st.resolve(ctx, oldName)
	if err != nil {
		return err
	}
	dst, err := st.resolve(ctx, newName)
	if err != nil {
		return err
	}
	if err := st.srcPrecondition(ctx); err != nil {
		return err
	}
	defer st.changed()
	if dst.otherCase && !(src.ns == dst.ns && src.node == dst.node) && (dst.kind == kFolder || dst.kind == kPlacement && !st.spelledSo(dst)) {
		// Another case of a sibling's name, file or folder (§H.2
		// "Siblings"): refused, setting a guard (§H.6).
		st.onto = dst.path
		return otherCase(dst)
	}
	live := false
	if src.kind == kDoc || src.kind == kRaw || src.kind == kPlacement {
		if _, live, err = st.docAt(ctx, src); err != nil {
			return err
		}
	}
	tree := st.s.cats[src.ns] || st.s.cats[dst.ns]
	switch {
	case src.kind == kMissing || dst.kind == kMissing:
		return errNotExist
	case dst.kind == kBadName && !(src.kind == kScratch && src.sdir && appDir(dst.base)):
		return st.badName(dst)
	case live && dst.kind == kScratch:
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
		if err := st.scratchPut(dst.path, b, hd.m.Type); err != nil {
			return err
		}
		// The client takes the name for free now, and may create it
		// only (davfs2's If-None-Match: *): that write is the edit.
		st.p.setAside(src.path, st.s.opt.Now())
		return nil
	case live && st.deletedPath(dst):
		// A DELETE, then a MOVE onto the name (rclone's mount without a
		// cache saves through a temporary file so): a write to the path
		// of a file the user deleted moments ago restores it (§H.6), with
		// the content moved there, keeping its history.
		return st.moveOnto(ctx, src, dst)
	case live && tree:
		return st.moveFile(ctx, src, dst)
	case src.kind == kFolder:
		return st.moveFolder(ctx, src, dst)
	case live:
		return st.moveFlat(ctx, src, dst)
	case src.kind == kScratch && src.sdir:
		switch {
		case dst.kind == kNewNode && !appDir(dst.base):
			// An app's directory given a person's name in a tree: a
			// folder of that name, what is in it staying scratch.
			if err := st.mkFolder(ctx, dst); err != nil {
				return err
			}
			if err := st.scratchRename(src.path, dst.path); err != nil {
				return err
			}
			st.scratchUnmark(dst.path)
			return nil
		case dst.kind == kScratch, dst.kind == kBadName, dst.kind == kNewNode:
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
		// a write of its content, and one refused over a live file sets a
		// guard (§H.6).
		if dst.kind != kNewNode {
			if _, live, err := st.docAt(ctx, dst); err != nil {
				return err
			} else if live {
				st.onto = dst.path
			}
		}
		if err := st.replaced(ctx, dst); err != nil {
			return err
		}
		if err := st.writable(ctx, dst); err != nil {
			return err
		}
		st.ctype = f.ctype
		if _, _, err := st.commitRev(ctx, dst, f.data); err != nil {
			return st.undoOwnDelete(ctx, dst, upstream(err))
		}
		st.scratchRemove(src.path)
		return nil
	case dst.kind == kScratch:
		return st.scratchRename(src.path, dst.path)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// srcPrecondition checks a MOVE's precondition on its source, once,
// before anything is written (§H.5 "On any MOVE, a client's If-Match
// names the source"): the revision its If-Match (or If header) names
// must be the source's head, a file's (its item's, in a tree) or a
// folder's node's (F-H1), and If-Match: * asks that it exist; 412
// otherwise, as for a DELETE. A scratch file has no revision. The moves
// check it again where they read the source to write (moveOnto,
// moveAcross, batchMove, moveNode), and a move that copies deletes the
// source with If-Match on it (deleteSource).
func (st *reqState) srcPrecondition(ctx context.Context) error {
	if st.method != "MOVE" || st.srcMatch == "" && !st.srcAny || st.srcDone {
		return st.srcErr
	}
	st.srcDone = true
	st.srcErr = st.checkSource(ctx)
	return st.srcErr
}

// checkSource is srcPrecondition's check.
func (st *reqState) checkSource(ctx context.Context) error {
	src, err := st.resolve(ctx, st.path)
	if err != nil {
		return err
	}
	rev, exists := "", false
	switch src.kind {
	case kDoc, kRaw, kPlacement:
		hd, live, err := st.docAt(ctx, src)
		if err != nil {
			return err
		}
		rev, exists = hd.rev, live
	case kFolder:
		h, err := st.head(ctx, src.ns, src.node)
		if err != nil {
			return err
		}
		rev, exists = h.ID, h.State == client.Live
	case kScratch:
		_, exists = st.scratchGet(src.path)
	}
	switch {
	case !exists && st.srcAny:
		return fail(http.StatusPreconditionFailed, "%s doesn't exist (If-Match: *)", src.path)
	case !exists:
		return fail(http.StatusPreconditionFailed, "%s holds no file, so none has revision %s (If-Match names a MOVE's source, §H.5); reload it", src.path, st.srcMatch)
	case st.srcMatch != "" && rev != st.srcMatch:
		return st.sourceMoved(src.path)
	}
	return nil
}

// sourceMoved is a MOVE's 412 for a source whose head isn't the revision
// its If-Match names (srcPrecondition).
func (st *reqState) sourceMoved(p string) error {
	return fail(http.StatusPreconditionFailed, "%s changed since %s (If-Match, which names a MOVE's source, §H.5); reload it", p, st.srcMatch)
}

// deletedPath reports whether t is the path of a file the principal's
// DELETE removed within ownDeleteUndo (§H.6 "Delete, then write"): a flat
// namespace's resource, or a tree's file in the same folder.
func (st *reqState) deletedPath(t target) bool {
	now := st.s.opt.Now()
	switch t.kind {
	case kDoc, kRaw:
		return st.p.deletedOwn(t.docNS, t.docName, "", now) || t.rawName != "" && st.p.deletedOwn(t.docNS, t.rawName, "", now)
	case kNewNode:
		d, ok := st.p.treeDeleted(t.path, now)
		return ok && d.cat == t.ns && d.parent == t.parent
	}
	return false
}

// moveFlat is a MOVE of live file src of a flat namespace where no tree
// is involved (§H.8, §H.5): onto an existing file, a save of its content
// into it, which keeps that file's history (moveOnto); to a free name in
// another namespace, a copy and a delete (moveAcross); to a free name in
// its own, a create and a delete with $successor in one batch
// (batchMove).
func (st *reqState) moveFlat(ctx context.Context, src, dst target) error {
	if dst.kind != kDoc && dst.kind != kRaw {
		return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
	}
	if _, live, err := st.docAt(ctx, dst); err != nil {
		return err
	} else if live {
		return st.moveOnto(ctx, src, dst)
	}
	if dst.ns != src.ns {
		return st.moveAcross(ctx, src, dst)
	}
	return st.batchMove(ctx, src, dst)
}

// batchMove moves live file src of a flat namespace to dst, a free name in
// the same namespace (§H.8, §8.1): one batch (§7.5) creates the new
// resource with src's document, its $nonce and $successor aside (restores
// it so, if it is tombstoned), and appends $successor naming it to src
// before src's tombstone, with If-Match on src's head (again on the new
// head if it moved, 412). A raw file's blob is copied to the new resource
// first with Blob-From (§7.8), or uploaded again where the new name gives
// it another type, or its bytes aren't UTF-8 for its text/ type (§H.1).
// A JSON file keeps a {name}.json name and a raw file a raw one, and one
// whose root isn't an object, which can't carry $successor, isn't moved
// (403): it can be copied, then deleted.
func (st *reqState) batchMove(ctx context.Context, src, dst target) error {
	ns := src.ns
	in := st.s.nsInfo(ctx, st.tk, ns)
	if in.sealed {
		return notOffered(ns)
	}
	sent := map[string]bool{} // blobs copied or uploaded to the new resource
	return st.retrying(ctx, func() (bool, error) {
		sh, err := st.tk.c.Head(ctx, ns, src.docName)
		if err != nil {
			return false, err
		}
		if sh.State != client.Live {
			return false, errNotExist
		}
		if st.srcMatch != "" && sh.ID != st.srcMatch {
			return false, st.sourceMoved(src.path)
		}
		e, err := st.s.doc(ctx, st.tk, ns, src.docName, sh.ID)
		switch {
		case err != nil:
			return false, err
		case e.sealed:
			return false, notOffered(ns)
		}
		to := dst.docName
		m, obj := e.value.(map[string]any)
		switch {
		case e.raw != nil && dst.kind == kRaw:
		case e.raw != nil && dst.rawName != "":
			to = dst.rawName
		case e.raw != nil:
			return false, fail(http.StatusForbidden, "%s is a raw file, named by its resource name in a namespace's directory (§H.2), and %s names a JSON document; copy it there to keep its content as one", src.path, dst.base)
		case dst.kind != kDoc:
			return false, fail(http.StatusForbidden, "%s is a JSON file, shown as {name}.json in a namespace's directory (§H.2): it moves to another {name}.json; copy it to %s to keep its content as a raw file", src.path, dst.base)
		case !obj:
			return false, fail(http.StatusForbidden, "the root of %s is %s, which can't carry $successor (§8.1, §H.5), so it isn't moved; copy it to %s, then delete it", src.path, jsonKind(e.value), dst.base)
		}
		doc := map[string]any{}
		for k, v := range m {
			doc[k] = v
		}
		doc = files.Bare(doc).(map[string]any)
		if r := e.raw; r != nil {
			// The new name types the file, else its type does, as a copy's
			// upload (§H.1); a text/ type only for UTF-8 bytes, which are
			// read for it (textBlob).
			typ := declaredType(dst.base, r.typ)
			switch {
			case typ == "":
				typ = octetStream
			case typ == r.typ && strings.HasPrefix(typ, "text/"):
				ok, err := st.textBlob(ctx, ns, src.docName, r)
				if err != nil {
					return false, err
				}
				if !ok {
					typ = octetStream
				}
			}
			var b []byte
			if typ != r.typ {
				hd := headDoc{ns: ns, name: src.docName, rev: sh.ID, m: e.meta(), e: e}
				if b, err = st.fileBytes(ctx, &hd); err != nil {
					return false, err
				}
				if !textOK(typ, b) {
					typ = octetStream
				}
			}
			if typ == r.typ {
				if !sent[r.bid] {
					if err := st.tk.c.CopyBlob(ctx, ns, to, r.bid, ns, src.docName, ""); err != nil {
						return false, err
					}
					sent[r.bid] = true
				}
			} else {
				nonce := ""
				if in.nonce {
					nonce = seal.NewNonce()
				}
				delete(doc, "nonce")
				for k, v := range refValue(client.BlobID(typ, nonce, b), typ, len(b), nonce) {
					doc[k] = v
				}
				if bid := doc["$blob"].(string); !sent[bid] {
					if _, err := st.tk.c.UploadBlob(ctx, ns, to, typ, nonce, b); err != nil {
						return false, err
					}
					sent[bid] = true
				}
			}
		}
		th, err := st.tk.c.Head(ctx, ns, to)
		if err != nil {
			return false, err
		}
		item := client.BatchItem{Resource: to}
		switch th.State {
		case client.NotFound:
			item.IfNoneMatch = true
			item.Steps = []client.Step{client.PatchStep(withNonce(in, doc, client.GenesisPatches(doc)))}
		case client.Tombstoned:
			// Restored, a name moved away too: a MOVE is no save (movedAway).
			item.IfMatch = th.ID
			item.Steps = []client.Step{client.PatchStep(withNonce(in, doc, []any{map[string]any{"op": "replace", "path": "", "value": doc}}))}
		case client.Purged:
			return false, purgedErr(ns, to)
		default:
			return false, fail(http.StatusConflict, "%s/%s was made by someone else meanwhile; %s isn't moved", ns, to, src.path)
		}
		succ := withNonce(in, e.value, []any{map[string]any{"op": "add", "path": "/$successor", "value": to}})
		res, err := st.tk.c.Batch(ctx, ns, client.BatchRequest{Items: []client.BatchItem{item, {Resource: src.docName, IfMatch: sh.ID,
			Steps: []client.Step{client.PatchStep(succ), client.DeleteStep()}}}}, false)
		err = batchErr(err)
		if client.IsStale(err) || goneSince(err) {
			// A head moved since it was read: the new name made (412),
			// or tombstoned (412, or 410 gone from v0.73, §7.2), or the
			// source deleted (410). Read again.
			return true, nil
		}
		if err != nil {
			return false, err
		}
		st.committed = true
		st.s.forgetPath(st.p, src.path)
		st.s.notePath(st.p, dst.path, ns, to)
		if len(res.Items) == 2 && len(res.Items[1].IDs) == 2 {
			st.s.markOwn(st.p, ns, src.docName, res.Items[1].IDs[1])
		}
		if th.State == client.Tombstoned && len(res.Items) > 0 && len(res.Items[0].IDs) == 1 {
			st.s.markOwn(st.p, ns, to, res.Items[0].IDs[0])
		}
		return false, nil
	})
}

// textBlob reports whether raw file ns/name's blob r may keep a text/
// type: its bytes are UTF-8, a leading BOM allowed (textOK), read through
// without keeping them.
func (st *reqState) textBlob(ctx context.Context, ns, name string, r *rawRef) (bool, error) {
	b, err := st.tk.c.OpenBlob(ctx, ns, name, r.bid, 0)
	if err != nil {
		return false, err
	}
	defer b.Body.Close()
	br := bufio.NewReader(io.LimitReader(b.Body, r.size))
	if p, _ := br.Peek(3); bytes.Equal(p, []byte{0xEF, 0xBB, 0xBF}) {
		br.Discard(3)
	}
	for {
		c, n, err := br.ReadRune()
		switch {
		case err == io.EOF:
			return true, nil
		case err != nil:
			return false, err
		case c == utf8.RuneError && n == 1:
			return false, nil
		}
	}
}

// fileBytes returns live file hd's content as its reader gets it: a JSON
// file's representation (repr), or a raw file's bytes, read whole from its
// blob, at most MaxRawSize of them (413 beyond).
func (st *reqState) fileBytes(ctx context.Context, hd *headDoc) ([]byte, error) {
	if r := hd.m.raw; r != nil {
		if r.size > int64(st.s.opt.MaxRawSize) {
			return nil, overLimit("-max-raw-size", r.size, int64(st.s.opt.MaxRawSize), "(this gateway's bound on a raw file, which it copies here whole): %s/%s", hd.ns, hd.name)
		}
		b, err := st.tk.c.GetBlob(ctx, hd.ns, hd.name, r.bid, r.nonce)
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
// restore, or in a tree a new file, an item and its placement (newFile),
// as a file of the kind kindOf says (§H.1). It returns the revision now
// holding it ("" for none), and whether that holds exactly body. An empty
// body is a file like any other (§H.1): a raw file of 0 bytes, made or
// truncated, and a JSON file's 400; but where its content would decide
// its kind, a LOCK of a new name or a new .json name (Finder's 0-byte PUT
// before the content), it is held as an empty placeholder (holdEmpty).
func (st *reqState) commitRev(ctx context.Context, t target, body []byte) (string, bool, error) {
	defer st.changed()
	// With tree-derived access, a file's item is edited under a grant the
	// catalog issues for it (§H.2 "Access").
	if err := st.itemAccess(ctx, t, true); err != nil {
		return "", false, err
	}
	if len(body) == 0 {
		hold, err := st.holdEmpty(ctx, t)
		if err != nil {
			return "", false, err
		}
		if hold {
			return "", true, st.scratchPut(t.path, nil, st.ctype)
		}
	}
	raw, name, v, err := st.kindOf(ctx, t, body)
	if err != nil {
		return "", false, err
	}
	if !raw && v == nil {
		if v, err = parseBody(body); err != nil {
			return "", false, err
		}
	}
	// A raw file is typed by its name (fileType): a tree's file by its
	// title, a flat namespace's by its resource name.
	fname := name
	if t.kind == kPlacement || t.kind == kNewNode {
		fname = t.title
	}
	var rev string
	var exact bool
	switch {
	case t.kind == kNewNode:
		rev, exact, err = st.newFile(ctx, t, raw, v, body)
	case raw:
		rev, exact, err = st.commitRaw(ctx, t.docNS, name, body, saveOpts{pre: true, fname: fname})
	default:
		rev, exact, err = st.commitDoc(ctx, t.docNS, t.docName, v, body, saveOpts{pre: true})
	}
	if err != nil {
		return "", false, err
	}
	if t.kind != kNewNode {
		st.wroteTo = t.docNS + "/" + name
	}
	if ns, name, ok := strings.Cut(st.wroteTo, "/"); ok {
		st.s.notePath(st.p, t.path, ns, name)
	}
	st.scratchRemove(t.path)
	return rev, exact, nil
}

// holdEmpty reports whether an empty write to t is kept as an empty
// placeholder in scratch rather than written: one whose content decides
// its kind (§H.1), a LOCK of a new name or a new .json name, which Finder
// makes with a 0-byte PUT before it sends the content. Never a copy or a
// move of a raw file (copySrc), which is one of 0 bytes, nor a write over
// a live file, which a raw file takes and a JSON file refuses.
func (st *reqState) holdEmpty(ctx context.Context, t target) (bool, error) {
	switch {
	case st.copySrc != nil:
		return false, nil
	case t.kind == kDoc || t.kind == kRaw:
		if _, live, err := st.docAt(ctx, t); err != nil || live {
			return false, err
		}
	case t.kind != kNewNode:
		return false, nil
	}
	return st.method == "LOCK" || strings.HasSuffix(strings.ToLower(t.base), ".json"), nil
}

// kindOf says whether body, written to t, is a raw file's content, and of
// which resource, or else a JSON file's, parsed if it was (§H.1): a raw
// file's path takes any bytes; a live JSON file only JSON; a new {name}.json
// is JSON document {name} if body is I-JSON (a BOM dropped), else raw file
// {name}.json; one the principal deleted moments ago is restored as the
// file it was, JSON or raw (§H.6 "Delete, then write"); a tree's file
// keeps its item's kind, and a new one is JSON where its title ends in
// .json and body is I-JSON (newKind).
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
	case kPlacement:
		h, err := st.head(ctx, t.docNS, t.docName)
		if err != nil || h.State != client.Live {
			return false, t.docName, nil, err
		}
		m, err := st.s.meta(ctx, st.tk, t.docNS, t.docName, h.ID)
		return err == nil && m.raw != nil, t.docName, nil, err
	case kNewNode:
		if d, ok := st.p.treeDeleted(t.path, st.s.opt.Now()); ok && d.cat == t.ns && d.parent == t.parent {
			h, err := st.head(ctx, d.itemNS, d.itemName)
			if err != nil {
				return false, "", nil, err
			}
			rev := h.ID
			if h.State == client.Tombstoned {
				rev = h.Last
			}
			if h.State == client.Live || h.State == client.Tombstoned && rev != "" {
				if m, err := st.s.meta(ctx, st.tk, d.itemNS, d.itemName, rev); err == nil {
					return m.raw != nil, "", nil, nil
				}
			}
		}
		raw, v := newKind(t.title, body)
		return raw, "", v, nil
	}
	return false, t.docName, nil, nil
}

// newKind says whether a new file named name with body is raw, or else a
// JSON file, parsed (§H.1 "Which kind a new file is"): JSON if its name
// ends in .json, in any case, and body is I-JSON, a BOM dropped.
func newKind(name string, body []byte) (bool, any) {
	if strings.HasSuffix(strings.ToLower(name), ".json") {
		if v, err := jsonv.Parse(trimBOM(body)); err == nil {
			return false, v
		}
	}
	return true, nil
}

// maxWrite is how large a file written to document path t may be: a
// JSON file MaxFileSize (one live, a {name}.json only JSON can be, one the
// principal deleted moments ago, which the write restores, §H.6), any
// other MaxRawSize, a file that may be raw (§H.1).
func (st *reqState) maxWrite(ctx context.Context, t target) (int, error) {
	if t.kind == kDoc && (t.rawName == "" || st.p.deletedOwn(t.docNS, t.docName, "", st.s.opt.Now())) {
		return st.s.opt.MaxFileSize, nil
	}
	if t.kind == kDoc || t.kind == kPlacement {
		hd, live, err := st.docAt(ctx, t)
		if err != nil {
			return 0, err
		}
		if live && hd.m.raw == nil {
			return st.s.opt.MaxFileSize, nil
		}
	}
	return st.s.opt.MaxRawSize, nil
}

// writeFile buffers a written file whole, at most max bytes; Close
// commits it, to the core for a document name, to the scratch store for
// any other. The buffers of every request together hold at most
// InflightBytes, those of one user's at most userInflight (503 beyond).
type writeFile struct {
	st      *reqState
	ctx     context.Context
	t       target
	scratch bool
	max     int
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
	if n := w.buf.Len() + len(p); n > w.max {
		// The body read so far: a lower bound, as in the core's refusals
		// of a body it stopped reading (§6.6).
		key, what := "-max-file-size", "a JSON file or a temporary file"
		if w.max == w.st.s.opt.MaxRawSize && !w.scratch {
			key, what = "-max-raw-size", "a raw file"
		}
		w.err = w.st.record(overLimit(key, int64(n), int64(w.max), "(this gateway's bound on %s, which it buffers whole; it stopped reading there)", what))
		return 0, w.err
	}
	n := int64(len(p))
	if !w.st.s.inflight.TryAcquire(n) {
		w.err = w.st.record(&davError{status: http.StatusServiceUnavailable, msg: "the server is receiving too many files at once; try again",
			header: http.Header{"Retry-After": {"2"}}})
		return 0, w.err
	}
	if !w.st.p.hold(n, w.st.s.userInflight()) {
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
		w.st.p.unhold(w.held)
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

// deadProps implements webdav.DeadPropsHolder for files and directories:
// their dead properties (PROPPATCH, as Windows and macOS send after
// writing or making a folder), kept for the principal by path in bounded
// memory (§H.8 "kept in the gateway", principal.patchProps), never
// written to the core.
type deadProps struct {
	st   *reqState
	path string
}

// DeadProps implements webdav.DeadPropsHolder.
func (d deadProps) DeadProps() (map[xml.Name]webdav.Property, error) {
	return d.st.sc.deadProps(d.path), nil
}

// Patch implements webdav.DeadPropsHolder: every change is kept.
func (d deadProps) Patch(ps []webdav.Proppatch) ([]webdav.Propstat, error) {
	d.st.sc.patchProps(d.path, ps, d.st.s.opt.Now())
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
	deadProps
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
	deadProps
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
	deadProps
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
