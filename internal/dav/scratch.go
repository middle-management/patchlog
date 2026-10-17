package dav

import (
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// Scratch files: names that aren't documents, such as editors' swap,
// backup and temporary files, .DS_Store and ._* (AppleDouble), and empty
// files a client creates under a document name before writing it (LOCK,
// a 0-byte PUT). They live in memory, per principal and path, bounded,
// and expire when left untouched for ScratchIdle. They are never written
// to the core: moving one onto a document name is how editors save.

type scratchFile struct {
	data []byte
	mod  time.Time // last written
	used time.Time // last touched
}

// scratchGet returns the principal's scratch file at name.
func (st *reqState) scratchGet(name string) (*scratchFile, bool) {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.scratch[name]
	if ok {
		f.used = st.s.opt.Now()
	}
	return f, ok
}

// scratchPut stores data at name, within the principal's and the
// server's bounds (507 beyond them, 413 for one file over MaxFileSize).
func (st *reqState) scratchPut(name string, data []byte) error {
	s, p := st.s, st.p
	if len(data) > s.opt.MaxFileSize {
		return fail(http.StatusRequestEntityTooLarge, "a file is at most %d bytes", s.opt.MaxFileSize)
	}
	now := s.opt.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	old, had := p.scratch[name]
	delta := len(data)
	if had {
		delta -= len(old.data)
	} else if len(p.scratch) >= s.opt.ScratchFiles {
		return fail(http.StatusInsufficientStorage, "at most %d temporary files (names that aren't {name}.json) are kept per user", s.opt.ScratchFiles)
	}
	if p.sbytes+delta > s.opt.ScratchBytes {
		return fail(http.StatusInsufficientStorage, "at most %d bytes of temporary files are kept per user", s.opt.ScratchBytes)
	}
	if s.scratchTotal.Add(int64(delta)) > int64(s.opt.ScratchTotal) && delta > 0 {
		s.scratchTotal.Add(-int64(delta))
		return fail(http.StatusInsufficientStorage, "the server keeps no more temporary files")
	}
	p.sbytes += delta
	p.scratch[name] = &scratchFile{data: data, mod: now, used: now}
	return nil
}

// scratchRemove drops the principal's scratch file at name, if any.
func (st *reqState) scratchRemove(name string) bool {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.scratch[name]
	if ok {
		delete(p.scratch, name)
		p.sbytes -= len(f.data)
		st.s.scratchTotal.Add(-int64(len(f.data)))
	}
	return ok
}

// scratchRename moves a scratch file; it replaces one at newName.
func (st *reqState) scratchRename(oldName, newName string) bool {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.scratch[oldName]
	if !ok {
		return false
	}
	if g, had := p.scratch[newName]; had {
		p.sbytes -= len(g.data)
		st.s.scratchTotal.Add(-int64(len(g.data)))
	}
	delete(p.scratch, oldName)
	f.used = st.s.opt.Now()
	p.scratch[newName] = f
	return true
}

// scratchList lists the principal's scratch files in directory dir, by
// name.
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

// scratchUnder lists the principal's scratch files below dir.
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

// dropScratch drops every scratch file, returning their bytes.
func (p *principal) dropScratch() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.sbytes
	p.scratch, p.sbytes = map[string]*scratchFile{}, 0
	return n
}

// expireScratch drops scratch files untouched since before, returning
// their bytes.
func (p *principal) expireScratch(before time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for name, f := range p.scratch {
		if f.used.Before(before) {
			delete(p.scratch, name)
			n += len(f.data)
		}
	}
	p.sbytes -= n
	return n
}
