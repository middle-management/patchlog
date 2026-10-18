package dav

import (
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Scratch files: names that aren't documents, such as editors' swap,
// backup and temporary files, .DS_Store and ._* (AppleDouble), the copies
// file managers make beside a document in the flat view, and empty files a
// client creates under a document name before writing it (LOCK, a 0-byte
// PUT); and scratch directories, which apps save through (a dot, macOS's
// "(A Document Being Saved By …)", mayScratchDir). They live in memory,
// per principal and path, bounded per grant root, and expire when left
// untouched for ScratchIdle. They are never written to the core: moving
// one onto a document name is how editors save.

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

// scratchGet returns the principal's scratch file or directory at name.
func (st *reqState) scratchGet(name string) (*scratchFile, bool) {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.scratch[name]
	if ok {
		st.touchLocked(name, st.s.opt.Now())
	}
	return f, ok
}

// scratchPeek returns the principal's scratch file or directory at name
// without touching it (resolving a path, listing).
func (st *reqState) scratchPeek(name string) (*scratchFile, bool) {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.scratch[name]
	return f, ok
}

// isScratchDir reports whether name is one of the principal's scratch
// directories.
func (st *reqState) isScratchDir(name string) bool {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f := p.scratch[name]
	return f != nil && f.dir
}

// touchLocked marks name and the scratch directories it is in used.
func (st *reqState) touchLocked(name string, now time.Time) {
	for n := name; n != "/"; n = path.Dir(n) {
		f := st.p.scratch[n]
		if f == nil {
			return
		}
		f.used = now
	}
}

// scratchPut stores data, uploaded as ctype, at name, within the bounds of
// the principal's grant root and the server's (507 beyond them, 413 for
// one file over MaxFileSize).
func (st *reqState) scratchPut(name string, data []byte, ctype string) error {
	return st.scratchSet(name, &scratchFile{data: data, ctype: ctype})
}

// scratchMkdir makes a scratch directory at name.
func (st *reqState) scratchMkdir(name string) error {
	p := st.p
	p.mu.Lock()
	_, had := p.scratch[name]
	p.mu.Unlock()
	if had {
		return os.ErrExist
	}
	return st.scratchSet(name, &scratchFile{dir: true})
}

// mayKeep refuses a scratch file or directory at name in a served
// namespace the principal's grant doesn't name: the server would keep it
// there for a user who can't list the namespace, nor write to it.
func (st *reqState) mayKeep(name string) error {
	if st.p.named == nil {
		return nil
	}
	ns, _, _ := strings.Cut(strings.TrimPrefix(name, "/"), "/")
	if (st.s.flat[ns] || st.s.cats[ns]) && !st.p.named[ns] {
		return fail(http.StatusForbidden, "your grant doesn't name namespace %s: nothing is kept there for you (temporary files included)", ns)
	}
	return nil
}

func (st *reqState) scratchSet(name string, f *scratchFile) error {
	s, p := st.s, st.p
	if err := st.mayKeep(name); err != nil {
		return err
	}
	if len(f.data) > s.opt.MaxFileSize {
		return fail(http.StatusRequestEntityTooLarge, "a file is at most %d bytes", s.opt.MaxFileSize)
	}
	now := s.opt.Now()
	f.mod, f.used = now, now
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dropped {
		return fail(http.StatusServiceUnavailable, "this login was signed out meanwhile; try again")
	}
	old := p.scratch[name]
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
	p.scratch[name] = f
	st.touchLocked(path.Dir(name), now)
	return nil
}

// reserveLocked accounts for n bytes in place of old (nil: one more file)
// within the bounds.
func (st *reqState) reserveLocked(old *scratchFile, n int) error {
	s, p, a := st.s, st.p, st.p.acct
	delta, files := n, 1
	if old != nil {
		delta, files = n-len(old.data), 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.files+files > s.opt.ScratchFiles {
		return fail(http.StatusInsufficientStorage, "at most %d temporary files and folders (names that aren't {name}.json) are kept per user", s.opt.ScratchFiles)
	}
	if delta > 0 && a.bytes+delta > s.opt.ScratchBytes {
		return fail(http.StatusInsufficientStorage, "at most %d bytes of temporary files are kept per user", s.opt.ScratchBytes)
	}
	if s.scratchTotal.Add(int64(delta)) > int64(s.opt.ScratchTotal) && delta > 0 {
		s.scratchTotal.Add(-int64(delta))
		return fail(http.StatusInsufficientStorage, "the server keeps no more temporary files")
	}
	a.files += files
	a.bytes += delta
	p.sbytes += delta
	return nil
}

// releaseLocked drops name, f, from the scratch store and its bounds.
func (st *reqState) releaseLocked(name string, f *scratchFile) {
	p, a := st.p, st.p.acct
	delete(p.scratch, name)
	p.sbytes -= len(f.data)
	st.s.scratchTotal.Add(-int64(len(f.data)))
	a.mu.Lock()
	a.files--
	a.bytes -= len(f.data)
	a.mu.Unlock()
}

// evictJunkLocked drops the least recently used junk file but keep, false
// if there is none.
func (st *reqState) evictJunkLocked(keep string) bool {
	var name string
	var old *scratchFile
	for n, f := range st.p.scratch {
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

// scratchRemove drops the principal's scratch file or directory at name,
// with everything in it.
func (st *reqState) scratchRemove(name string) bool {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.scratch[name]
	if !ok {
		return false
	}
	st.releaseLocked(name, f)
	if f.dir {
		for n, g := range p.scratch {
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
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if f, ok := p.scratch[name]; ok {
		st.releaseLocked(name, f)
	}
}

// scratchRename moves a scratch file or directory, with everything in it;
// it replaces what is at newName.
func (st *reqState) scratchRename(oldName, newName string) error {
	if err := st.mayKeep(newName); err != nil {
		return err
	}
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dropped {
		return fail(http.StatusServiceUnavailable, "this login was signed out meanwhile; try again")
	}
	f, ok := p.scratch[oldName]
	if !ok {
		return os.ErrNotExist
	}
	moves := map[string]string{oldName: newName}
	if f.dir {
		for n := range p.scratch {
			if rest, ok := strings.CutPrefix(n, oldName+"/"); ok {
				moves[n] = newName + "/" + rest
			}
		}
	}
	now := st.s.opt.Now()
	got := map[string]*scratchFile{}
	for from := range moves {
		got[from] = p.scratch[from]
		delete(p.scratch, from)
	}
	for from, to := range moves {
		if g, had := p.scratch[to]; had {
			st.releaseLocked(to, g)
		}
		p.scratch[to] = got[from]
	}
	f.used = now
	st.touchLocked(path.Dir(newName), now)
	return nil
}

// scratchMoveUnder moves the principal's scratch files and directories
// below dir to below to: a tree's folder was renamed or moved.
func (st *reqState) scratchMoveUnder(dir, to string) {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	moves := map[string]*scratchFile{}
	for name, f := range p.scratch {
		if rest, ok := strings.CutPrefix(name, dir+"/"); ok {
			moves[to+"/"+rest] = f
			delete(p.scratch, name)
		}
	}
	for name, f := range moves {
		if g, had := p.scratch[name]; had {
			st.releaseLocked(name, g)
		}
		p.scratch[name] = f
	}
}

// scratchList lists the principal's scratch files and directories in
// directory dir, by name.
func (st *reqState) scratchList(dir string) map[string]*scratchFile {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]*scratchFile{}
	for name, f := range p.scratch {
		if path.Dir(name) == dir {
			out[path.Base(name)] = f
		}
	}
	return out
}

// scratchUnder returns the paths of the principal's scratch files and
// directories below dir.
func (st *reqState) scratchUnder(dir string) []string {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for name := range p.scratch {
		if strings.HasPrefix(name, dir+"/") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// dropScratch drops every scratch file and lock of a principal being
// forgotten, returning the files' bytes; nothing is stored for it
// afterwards (a request still in flight gets a 503).
func (p *principal) dropScratch() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.sbytes
	p.acct.mu.Lock()
	p.acct.files -= len(p.scratch)
	p.acct.bytes -= n
	p.acct.locks -= len(p.locked)
	p.acct.mu.Unlock()
	p.scratch, p.sbytes, p.dropped, p.locked = map[string]*scratchFile{}, 0, true, map[string]time.Time{}
	return n
}

// expireScratch drops scratch files untouched since before, returning
// their bytes.
func (p *principal) expireScratch(before time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, files := 0, 0
	for name, f := range p.scratch {
		if f.used.Before(before) {
			delete(p.scratch, name)
			n += len(f.data)
			files++
		}
	}
	p.sbytes -= n
	p.acct.mu.Lock()
	p.acct.files -= files
	p.acct.bytes -= n
	p.acct.mu.Unlock()
	return n
}
