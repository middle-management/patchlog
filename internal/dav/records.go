package dav

import (
	"time"

	"github.com/middle-management/patchlog/internal/lru"
	"github.com/middle-management/patchlog/internal/pointer"
)

// Records are the versions of a document a principal's clients may hold,
// the candidates for the base of their next save (§11 submit): the
// revisions GET sent them (a 304 sends none), and what they wrote, as
// they wrote it. They are kept by principal id and document for
// RecordIdle, apart from the principal's locks and scratch files, which
// go sooner; a restart loses them. Each grant root's are kept apart:
// over RecordBytes, the root keeping the most gives way first, so one
// user's uploads don't push out another's records. Records dropped to
// stay within bounds are remembered as lost, so a save isn't rebased on
// what is left of them (base).

// maxRecords bounds a principal's records of one document. Over it, the
// oldest but the first goes (and never the latest write): the version an
// editor opened stays while a preview reads the revisions others make.
const maxRecords = 16

// maxForgotten bounds the documents a root remembers having lost records
// of.
const maxForgotten = 4096

// record is one version: rev's document as served, or as the principal
// wrote it.
type record struct {
	seq uint64 // the order of recording, over the server
	rev string
	// wrote: a write of the principal's that changed the document; paths
	// are what it changed (writesOf).
	wrote bool
	paths []pointer.Pointer
	// doc is the version as written, canonical JSON, where rev holds
	// another (merged with others' edits, or given a $nonce); nil: rev's
	// document.
	doc []byte
	// raw are the bytes uploaded, where rev holds exactly them and they
	// read otherwise rendered: the principal's representation of rev (its
	// bytes, its size), as a client checking what it uploaded expects.
	raw []byte
	at  time.Time
}

func (r record) cost() int { return 64 + len(r.doc) + len(r.raw) + 16*len(r.paths) }

// docRecs is a principal's records of one document, oldest first.
type docRecs struct {
	rs []record
	// reload: a save was refused (409) when the records were at this seq;
	// the principal's next read of the document drops the records older
	// than it, so the version reloaded is the base of the edit after it.
	reload uint64
	// lost: records of the document were dropped to stay within bounds;
	// until a reload, a save that changes it is refused rather than
	// rebased on what is left.
	lost bool
}

func (d docRecs) cost() int {
	n := 64
	for _, r := range d.rs {
		n += r.cost()
	}
	return n
}

// recStore is one grant root's records.
type recStore struct {
	docs      lru.Cache[string, docRecs] // by principal id and ns/name
	forgotten lru.Cache[string, bool]    // documents whose records the bounds dropped
	paths     lru.Cache[string, pathRec] // by principal id and path
	used      time.Time
}

// pathRec is the document a principal last read whole or wrote under a
// path (records are kept by document, and a path may come to name
// another: a tree's title given to a new item, a raw x.json taking the
// name of JSON document x), and when.
type pathRec struct {
	ns, name string
	at       time.Time
}

// maxPaths bounds the paths a grant root's principals' path records keep.
const maxPaths = 1 << 16

func recKey(p *principal, ns, name string) string { return p.id + "\x00" + ns + "/" + name }

// keepRaw returns the bytes a write uploaded, to read back as written, or
// nil where the rendering reads the same, or where they are more than a
// little larger than it: white space padding them would cost the
// records' budget, not the client's own.
func keepRaw(body, rendered []byte) []byte {
	if string(body) == string(rendered) || len(body) > 2*len(rendered)+4096 {
		return nil
	}
	return body
}

// storeLocked returns root's records, made if new.
func (s *Server) storeLocked(root string) *recStore {
	rs := s.recRoots[root]
	if rs == nil {
		rs = &recStore{used: s.opt.Now()}
		rs.docs.MaxEntries, rs.docs.MaxBytes = 1<<16, s.opt.RecordBytes
		rs.forgotten.MaxEntries = maxForgotten
		rs.paths.MaxEntries = maxPaths
		rs.docs.OnEvict = func(k string, _ docRecs) { rs.forgotten.Put(k, true, 1) }
		s.recRoots[root] = rs
	}
	return rs
}

// recordsOf returns p's records of ns/name, without those older than
// RecordIdle. Records the bounds dropped since the document's last reload
// make it lost.
func (s *Server) recordsOf(p *principal, ns, name string) docRecs {
	cut := s.opt.Now().Add(-s.opt.RecordIdle)
	k := recKey(p, ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	rs := s.storeLocked(p.acct.root)
	d, ok := rs.docs.Get(k)
	if !ok {
		_, lost := rs.forgotten.Get(k)
		return docRecs{lost: lost}
	}
	out := docRecs{reload: d.reload, lost: d.lost, rs: make([]record, 0, len(d.rs))}
	for _, r := range d.rs {
		if !r.at.Before(cut) {
			out.rs = append(out.rs, r)
		}
	}
	return out
}

// remember adds r to p's records of ns/name, the newest, in place of one
// of the same version (a revision served again, a write held by the same
// revision). A read (reload) drops the records older than a refused save.
func (s *Server) remember(p *principal, ns, name string, r record, reload bool) {
	now := s.opt.Now()
	if r.at.IsZero() {
		r.at = now
	}
	k := recKey(p, ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	s.recSeq++
	r.seq = s.recSeq
	st := s.storeLocked(p.acct.root)
	st.used = now
	old, ok := st.docs.Get(k)
	if !ok {
		if _, lost := st.forgotten.Get(k); lost {
			old.lost = true
			st.forgotten.Remove(k)
		}
	}
	// A read after a refused save is the reload it asked for: what was
	// recorded before the refusal goes.
	reloaded := reload && old.reload > 0
	d := docRecs{reload: old.reload, lost: old.lost, rs: make([]record, 0, len(old.rs)+1)}
	if reloaded {
		d.reload, d.lost = 0, false
	}
	for _, o := range old.rs {
		if reloaded && o.seq < old.reload {
			continue
		}
		if o.rev != r.rev || o.wrote != r.wrote {
			d.rs = append(d.rs, o)
		}
	}
	d.rs = append(d.rs, r)
	if len(d.rs) > maxRecords {
		d.rs = dropMiddle(d.rs)
	}
	// One document's records within a quarter of the budget, as the cache
	// keeps them: bytes to read back go first, then versions written
	// (which makes the document lost), oldest first.
	for i := 0; d.cost() > s.opt.RecordBytes/4 && i < len(d.rs); i++ {
		d.rs[i].raw = nil
	}
	for i := 0; d.cost() > s.opt.RecordBytes/4 && i < len(d.rs); {
		if d.rs[i].doc == nil {
			i++
			continue
		}
		d.rs = append(d.rs[:i:i], d.rs[i+1:]...)
		d.lost = true
	}
	before := st.docs.Bytes()
	st.docs.Put(k, d, d.cost())
	s.recBytes += st.docs.Bytes() - before
	s.trimRecordsLocked()
}

// dropMiddle drops one record of rs, which is over maxRecords: the oldest
// but the first, and but the newest write and the newest record.
func dropMiddle(rs []record) []record {
	keep := -1
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].wrote {
			keep = i
			break
		}
	}
	for i := 1; i < len(rs)-1; i++ {
		if i != keep {
			return append(rs[:i:i], rs[i+1:]...)
		}
	}
	return rs[1:]
}

// trimRecordsLocked drops records, least recently used first, from the
// root keeping the most, until all of them fit RecordBytes.
func (s *Server) trimRecordsLocked() {
	for s.recBytes > s.opt.RecordBytes {
		var big *recStore
		for _, rs := range s.recRoots {
			if rs.docs.Len() > 0 && (big == nil || rs.docs.Bytes() > big.docs.Bytes()) {
				big = rs
			}
		}
		if big == nil {
			s.recBytes = 0
			return
		}
		k, _, n, _ := big.docs.RemoveOldest()
		big.forgotten.Put(k, true, 1)
		s.recBytes -= n
	}
}

// sweepRecordsLocked forgets the roots that recorded nothing for
// RecordIdle, whose records have aged out.
func (s *Server) sweepRecordsLocked(now time.Time) {
	for root, rs := range s.recRoots {
		if now.Sub(rs.used) > s.opt.RecordIdle {
			s.recBytes -= rs.docs.Bytes()
			delete(s.recRoots, root)
		}
	}
}

// notePath records that p read ns/name whole, or wrote it, under path.
func (s *Server) notePath(p *principal, path, ns, name string) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	s.storeLocked(p.acct.root).paths.Put(p.id+"\x00"+path, pathRec{ns: ns, name: name, at: s.opt.Now()}, 1)
}

// pathOf returns the document p last read whole or wrote under path,
// within RecordIdle.
func (s *Server) pathOf(p *principal, path string) (string, string, bool) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	r, ok := s.storeLocked(p.acct.root).paths.Get(p.id + "\x00" + path)
	if !ok || s.opt.Now().Sub(r.at) > s.opt.RecordIdle {
		return "", "", false
	}
	return r.ns, r.name, true
}

// forgetPath forgets what p read or wrote under path: it deleted or moved
// the file there, or found it gone (a reload).
func (s *Server) forgetPath(p *principal, path string) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	s.storeLocked(p.acct.root).paths.Remove(p.id + "\x00" + path)
}

// refuse marks p's records of ns/name as refused: the save was a 409,
// which asks for a reload.
func (s *Server) refuse(p *principal, ns, name string) {
	k := recKey(p, ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	st := s.storeLocked(p.acct.root)
	st.used = s.opt.Now()
	d, ok := st.docs.Get(k)
	if !ok {
		_, d.lost = st.forgotten.Get(k)
		st.forgotten.Remove(k)
	}
	s.recSeq++
	d.reload = s.recSeq
	before := st.docs.Bytes()
	st.docs.Put(k, d, d.cost())
	s.recBytes += st.docs.Bytes() - before
	s.trimRecordsLocked()
}

// reloaded forgets p's records of ns/name, gone in the core, if a save of
// it was refused (refuse) since they were made: a GET found it gone, the
// reload that refusal asked for, so the next write makes it anew
// (tombBase) rather than meeting the refusal again.
func (s *Server) reloaded(p *principal, ns, name string) {
	k := recKey(p, ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	st := s.storeLocked(p.acct.root)
	d, ok := st.docs.Get(k)
	if !ok || d.reload == 0 {
		return
	}
	before := st.docs.Bytes()
	st.docs.Remove(k)
	st.forgotten.Remove(k)
	s.recBytes += st.docs.Bytes() - before
}

// stale reports whether a GET of ns/name at rev must send it whatever the
// client's validators say: a save of p's was refused (or its records
// lost) and the reload is due, or p's newest record is a write of its
// own that rev holds other than written (merged, or given a $nonce),
// which the client may have filed under rev's tag (davfs2 asks for it
// with a HEAD after a PUT without one).
func (s *Server) stale(p *principal, ns, name, rev string) bool {
	d := s.recordsOf(p, ns, name)
	if d.reload > 0 || d.lost {
		return true
	}
	if n := len(d.rs); n > 0 {
		r := d.rs[n-1]
		return r.rev == rev && r.wrote && r.doc != nil
	}
	return false
}

// exactOf returns the bytes p wrote that rev of ns/name holds exactly, or
// nil.
func (s *Server) exactOf(p *principal, ns, name, rev string) []byte {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	d, _ := s.storeLocked(p.acct.root).docs.Get(recKey(p, ns, name))
	for i := len(d.rs) - 1; i >= 0; i-- {
		if d.rs[i].rev == rev && d.rs[i].raw != nil {
			return d.rs[i].raw
		}
	}
	return nil
}

// repr is how the request's principal reads a document: the bytes it
// wrote, where the revision holds exactly them (so a client that checks
// the size of what it uploaded finds it), else the rendering.
func (st *reqState) repr(hd headDoc) []byte {
	if b := st.s.exactOf(st.p, hd.ns, hd.name, hd.rev); b != nil {
		return b
	}
	return hd.e.rendered
}

// stagedServe is the document a GET is answering with, under path: a
// record once its body is sent whole (errWriter), not on a 304 or for a
// range.
type stagedServe struct{ ns, name, rev, path string }

// served records a staged GET whose body went out: a reload, if a save
// was refused, and the document its path names now.
func (st *reqState) served() {
	if sv := st.serve; sv != nil {
		st.serve = nil
		st.s.remember(st.p, sv.ns, sv.name, record{rev: sv.rev}, true)
		st.s.notePath(st.p, sv.path, sv.ns, sv.name)
	}
}

// modTime is a file's time (§H.3): when its head was written, as the
// listing says (created) or its read did (modified, Last-Modified, §7.1),
// else when the principal was first shown it, later than any revision it
// saw before, so editors notice a change. Cores send times outside sealed
// and end-to-end namespaces, which aren't offered here (§H.7), so first
// sights are kept only in memory, for older cores, and start over when the
// server does.
func (s *Server) modTime(p *principal, k string, created, modified time.Time) time.Time {
	switch {
	case !created.IsZero():
		return created
	case !modified.IsZero():
		return modified
	}
	key := p.id + "\x00" + k
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if t, ok := s.seen.Get(key); ok {
		return t
	}
	now := s.opt.Now()
	s.seen.Put(key, now, 1)
	return now
}
