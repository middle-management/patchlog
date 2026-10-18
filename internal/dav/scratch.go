package dav

import (
	"encoding/xml"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/webdav"
)

// Scratch files: names that aren't documents, such as editors' swap,
// backup and temporary files, .DS_Store and ._* (AppleDouble), the copies
// file managers make beside a document in the flat view, and empty files a
// client creates before writing them where their content decides their
// kind (a LOCK of a new name, a 0-byte PUT of a new .json name,
// holdEmpty); and scratch directories, which apps save through (a dot, macOS's
// "(A Document Being Saved By …)", mayScratchDir). They live in memory,
// per user (§H.6, §H.7), narrowing (scope) and path, bounded per user,
// and expire when left untouched for ScratchIdle. Only tokens of the
// scope that wrote one, and whose grant names its namespace (mayKeep),
// reach it. They are never written to the core: moving one onto a
// document name is how editors save.

type scratchFile struct {
	data  []byte
	ctype string // the upload's Content-Type, for the file it is moved onto (fileType)
	dir   bool
	mod   time.Time // last written
	used  time.Time // last touched
}

// junk reports the files macOS and Windows write beside others
// (AppleDouble ._*, .DS_Store, Thumbs.db): over the bounds, the least
// recently used of them make room, and one that still doesn't fit is
// dropped rather than refused, so copying many files in doesn't fail on
// them (a 507 reads as a full disk).
func junk(name string) bool {
	b := path.Base(name)
	return strings.HasPrefix(b, "._") || b == ".DS_Store" || b == "Thumbs.db"
}

// scratchGet returns the scope's scratch file or directory at name.
func (st *reqState) scratchGet(name string) (*scratchFile, bool) {
	if st.mayKeep(name) != nil {
		return nil, false
	}
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	f, ok := sc.scratch[name]
	if ok {
		st.touchLocked(name, st.s.opt.Now())
	}
	return f, ok
}

// scratchPeek returns the scope's scratch file or directory at name
// without touching it (resolving a path, listing).
func (st *reqState) scratchPeek(name string) (*scratchFile, bool) {
	if st.mayKeep(name) != nil {
		return nil, false
	}
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	f, ok := sc.scratch[name]
	return f, ok
}

// isScratchDir reports whether name is one of the scope's scratch
// directories.
func (st *reqState) isScratchDir(name string) bool {
	f, ok := st.scratchPeek(name)
	return ok && f.dir
}

// touchLocked marks name and the scratch directories it is in used.
func (st *reqState) touchLocked(name string, now time.Time) {
	for n := name; n != "/"; n = path.Dir(n) {
		f := st.sc.scratch[n]
		if f == nil {
			return
		}
		f.used = now
	}
}

// scratchPut stores data, uploaded as ctype, at name, within the bounds of
// the user and the server (507 beyond them, 413 for one file over
// MaxFileSize).
func (st *reqState) scratchPut(name string, data []byte, ctype string) error {
	return st.scratchSet(name, &scratchFile{data: data, ctype: ctype})
}

// scratchMkdir makes a scratch directory at name.
func (st *reqState) scratchMkdir(name string) error {
	if _, had := st.scratchPeek(name); had {
		return os.ErrExist
	}
	return st.scratchSet(name, &scratchFile{dir: true})
}

// mayKeep refuses a scratch file or directory at name in a served
// namespace the request's grant doesn't name: the server would keep it
// there for a user who can't list the namespace, nor write to it with
// this token; nor does such a token reach one there another token of the
// scope keeps (scratchGet, scratchPeek, scratchList), which may hold a
// document's text that the core refuses this one (§H.6, §C.2).
func (st *reqState) mayKeep(name string) error {
	if st.tk.named == nil {
		return nil
	}
	ns, _, _ := strings.Cut(strings.TrimPrefix(name, "/"), "/")
	if (st.s.flat[ns] || st.s.cats[ns]) && !st.tk.named[ns] {
		return fail(http.StatusForbidden, "your grant doesn't name namespace %s: nothing is kept there for you (temporary files included)", ns)
	}
	return nil
}

func (st *reqState) scratchSet(name string, f *scratchFile) error {
	s, sc := st.s, st.sc
	if err := st.mayKeep(name); err != nil {
		return err
	}
	if len(f.data) > s.opt.MaxFileSize {
		return overLimit("-max-file-size", int64(len(f.data)), int64(s.opt.MaxFileSize), "(this gateway's bound on a temporary file, kept in its memory)")
	}
	now := s.opt.Now()
	f.mod, f.used = now, now
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	if sc.dropped {
		return fail(http.StatusServiceUnavailable, "this login was signed out meanwhile; try again")
	}
	old := sc.scratch[name]
	if old != nil && old.dir != f.dir {
		return fail(http.StatusMethodNotAllowed, "%s is a %s", name, map[bool]string{true: "directory", false: "file"}[old.dir])
	}
	for {
		err := st.reserveLocked(old, len(f.data))
		if err == nil {
			break
		}
		if !st.evictJunkLocked(name) {
			if junk(name) {
				// Dropped, not refused.
				if old != nil {
					st.releaseLocked(name, old)
				}
				return nil
			}
			return err
		}
	}
	sc.scratch[name] = f
	st.touchLocked(path.Dir(name), now)
	return nil
}

// reserveLocked accounts for n bytes in place of old (nil: one more file)
// within the bounds, which are the user's, over their scopes: per scope,
// a narrowing being free, one user would keep them as many times. So a
// token's 507 depends on what the user's other scopes keep, which a token
// that reads less can measure (the size of a backup copy in another
// scope, the number of files there); a bound of their own per scope
// would multiply what a user keeps instead.
func (st *reqState) reserveLocked(old *scratchFile, n int) error {
	s, sc := st.s, st.sc
	delta, files := n, 1
	if old != nil {
		delta, files = n-len(old.data), 0
	}
	nfiles, nbytes := 0, 0
	for _, o := range sc.p.scopes {
		nfiles, nbytes = nfiles+len(o.scratch), nbytes+o.sbytes
	}
	if nfiles+files > s.opt.ScratchFiles {
		return fail(http.StatusInsufficientStorage, "at most %d temporary files and folders (editors' and systems' own, kept in memory, §H.6) are kept per user", s.opt.ScratchFiles)
	}
	if delta > 0 && nbytes+delta > s.opt.ScratchBytes {
		return fail(http.StatusInsufficientStorage, "at most %d bytes of temporary files are kept per user", s.opt.ScratchBytes)
	}
	if s.scratchTotal.Add(int64(delta)) > int64(s.opt.ScratchTotal) && delta > 0 {
		s.scratchTotal.Add(-int64(delta))
		return fail(http.StatusInsufficientStorage, "the server keeps no more temporary files")
	}
	sc.sbytes += delta
	return nil
}

// releaseLocked drops name, f, from the scratch store and its bounds.
func (st *reqState) releaseLocked(name string, f *scratchFile) {
	sc := st.sc
	delete(sc.scratch, name)
	sc.sbytes -= len(f.data)
	st.s.scratchTotal.Add(-int64(len(f.data)))
}

// evictJunkLocked drops the least recently used junk file but keep, false
// if there is none.
func (st *reqState) evictJunkLocked(keep string) bool {
	var name string
	var old *scratchFile
	for n, f := range st.sc.scratch {
		if n != keep && !f.dir && junk(n) && (old == nil || f.used.Before(old.used)) {
			name, old = n, f
		}
	}
	if old == nil {
		return false
	}
	st.releaseLocked(name, old)
	return true
}

// scratchRemove drops the scope's scratch file or directory at name,
// with everything in it.
func (st *reqState) scratchRemove(name string) bool {
	if st.mayKeep(name) != nil {
		return false
	}
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	f, ok := sc.scratch[name]
	if !ok {
		return false
	}
	st.releaseLocked(name, f)
	if f.dir {
		for n, g := range sc.scratch {
			if strings.HasPrefix(n, name+"/") {
				st.releaseLocked(n, g)
			}
		}
	}
	return true
}

// scratchUnmark drops the scratch directory entry at name, keeping what
// is in it: the directory became a tree's folder.
func (st *reqState) scratchUnmark(name string) {
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	if f, ok := sc.scratch[name]; ok {
		st.releaseLocked(name, f)
	}
}

// scratchRename moves a scratch file or directory, with everything in it;
// it replaces what is at newName.
func (st *reqState) scratchRename(oldName, newName string) error {
	if err := st.mayKeep(newName); err != nil {
		return err
	}
	if st.mayKeep(oldName) != nil {
		return os.ErrNotExist
	}
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	if sc.dropped {
		return fail(http.StatusServiceUnavailable, "this login was signed out meanwhile; try again")
	}
	f, ok := sc.scratch[oldName]
	if !ok {
		return os.ErrNotExist
	}
	moves := map[string]string{oldName: newName}
	if f.dir {
		for n := range sc.scratch {
			if rest, ok := strings.CutPrefix(n, oldName+"/"); ok {
				moves[n] = newName + "/" + rest
			}
		}
	}
	now := st.s.opt.Now()
	got := map[string]*scratchFile{}
	for from := range moves {
		got[from] = sc.scratch[from]
		delete(sc.scratch, from)
	}
	for from, to := range moves {
		if g, had := sc.scratch[to]; had {
			st.releaseLocked(to, g)
		}
		sc.scratch[to] = got[from]
	}
	f.used = now
	st.touchLocked(path.Dir(newName), now)
	return nil
}

// scratchMoveUnder moves the scope's scratch files and directories
// below dir to below to: a tree's folder was renamed or moved.
func (st *reqState) scratchMoveUnder(dir, to string) {
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	moves := map[string]*scratchFile{}
	for name, f := range sc.scratch {
		if rest, ok := strings.CutPrefix(name, dir+"/"); ok {
			moves[to+"/"+rest] = f
			delete(sc.scratch, name)
		}
	}
	for name, f := range moves {
		if g, had := sc.scratch[name]; had {
			st.releaseLocked(name, g)
		}
		sc.scratch[name] = f
	}
}

// scratchList lists the scope's scratch files and directories in
// directory dir, by name.
func (st *reqState) scratchList(dir string) map[string]*scratchFile {
	out := map[string]*scratchFile{}
	if st.mayKeep(dir+"/x") != nil {
		return out
	}
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	for name, f := range sc.scratch {
		if path.Dir(name) == dir {
			out[path.Base(name)] = f
		}
	}
	return out
}

// scratchUnder returns the paths of the scope's scratch files and
// directories below dir.
func (st *reqState) scratchUnder(dir string) []string {
	if st.mayKeep(dir+"/x") != nil {
		return nil
	}
	sc := st.sc
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	var out []string
	for name := range sc.scratch {
		if strings.HasPrefix(name, dir+"/") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// maxPropBytes bounds a user's dead properties (PROPPATCH), over their
// scopes, their names and values: over it, those of the path touched
// least recently go first. They are cosmetic (Windows' file times), so dropping them is
// better than refusing a client's write over them.
const maxPropBytes = 1 << 20

// propSet is one path's dead properties, what they cost, and when they
// were last set.
type propSet struct {
	props map[xml.Name]webdav.Property
	bytes int
	at    time.Time
}

func propCost(p webdav.Property) int {
	return len(p.XMLName.Space) + len(p.XMLName.Local) + len(p.Lang) + len(p.InnerXML) + 64
}

// deadProps returns the scope's dead properties of path.
func (sc *scope) deadProps(path string) map[xml.Name]webdav.Property {
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	ps := sc.props[path]
	if ps == nil {
		return nil
	}
	out := make(map[xml.Name]webdav.Property, len(ps.props))
	for k, v := range ps.props {
		out[k] = v
	}
	return out
}

// patchProps applies a PROPPATCH's changes to the scope's dead
// properties of path, within maxPropBytes over the user's scopes.
func (sc *scope) patchProps(path string, patches []webdav.Proppatch, now time.Time) {
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	if sc.dropped {
		return
	}
	ps := sc.props[path]
	if ps == nil {
		ps = &propSet{props: map[xml.Name]webdav.Property{}}
		sc.props[path] = ps
	}
	for _, pp := range patches {
		for _, prop := range pp.Props {
			if old, ok := ps.props[prop.XMLName]; ok {
				ps.bytes -= propCost(old)
				sc.pbytes -= propCost(old)
				delete(ps.props, prop.XMLName)
			}
			if !pp.Remove {
				ps.props[prop.XMLName] = prop
				ps.bytes += propCost(prop)
				sc.pbytes += propCost(prop)
			}
		}
	}
	ps.at = now
	if len(ps.props) == 0 {
		delete(sc.props, path)
	}
	// Within maxPropBytes over the user's scopes, as their scratch files
	// and locks are: a narrowing is free, so per scope one user would keep
	// it as many times. The path set least recently goes first, this
	// scope's before another's, so another token's PROPPATCHes push out
	// what one sets only when its own are gone.
	total := 0
	for _, o := range sc.p.scopes {
		total += o.pbytes
	}
	for total > maxPropBytes {
		from, old := sc, oldestKey(sc, path)
		if old == "" {
			for _, o := range sc.p.scopes {
				if o == sc {
					continue
				}
				if k := oldestKey(o, ""); k != "" && (old == "" || o.props[k].at.Before(from.props[old].at)) {
					from, old = o, k
				}
			}
		}
		if old == "" {
			from, old = sc, path
		}
		total -= from.props[old].bytes
		from.pbytes -= from.props[old].bytes
		delete(from.props, old)
	}
}

// oldestKey is the path of sc's dead properties set least recently but
// keep, "" if none.
func oldestKey(sc *scope, keep string) string {
	old := ""
	for k, o := range sc.props {
		if k != keep && (old == "" || o.at.Before(sc.props[old].at)) {
			old = k
		}
	}
	return old
}

// moveProps moves the scope's dead properties of the paths at or
// below from to below to (a MOVE that passed, RFC 4918 §9.9.1), or drops
// them, to "" (a DELETE that passed).
func (sc *scope) moveProps(from, to string) {
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	moved := map[string]*propSet{}
	for k, ps := range sc.props {
		if rest, ok := strings.CutPrefix(k, from); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			delete(sc.props, k)
			if to != "" {
				moved[to+rest] = ps
			} else {
				sc.pbytes -= ps.bytes
			}
		}
	}
	for k, ps := range moved {
		if old := sc.props[k]; old != nil {
			sc.pbytes -= old.bytes
		}
		sc.props[k] = ps
	}
}

// holds reports whether the scope keeps a scratch file or a lock
// unexpired at now: what dropping it would lose (scopeRoomLocked).
func (sc *scope) holds(now time.Time) bool {
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	sc.expireLocksLocked(now)
	return len(sc.scratch) > 0 || len(sc.locked) > 0
}

// drop drops every scratch file, lock and dead property of a scope
// being forgotten, returning the files' bytes; nothing is stored for it
// afterwards (a request still in flight gets a 503).
func (sc *scope) drop() int {
	sc.p.mu.Lock()
	defer sc.p.mu.Unlock()
	n := sc.sbytes
	sc.scratch, sc.sbytes, sc.dropped, sc.locked = map[string]*scratchFile{}, 0, true, map[string]heldLock{}
	sc.props, sc.pbytes = map[string]*propSet{}, 0
	return n
}

// expireScratch drops p's scratch files and dead properties untouched
// since before, in every scope, returning the files' bytes.
func (p *principal) expireScratch(before time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, sc := range p.scopes {
		m := 0
		for name, f := range sc.scratch {
			if f.used.Before(before) {
				delete(sc.scratch, name)
				m += len(f.data)
			}
		}
		sc.sbytes -= m
		n += m
		for k, ps := range sc.props {
			if ps.at.Before(before) {
				sc.pbytes -= ps.bytes
				delete(sc.props, k)
			}
		}
	}
	return n
}
