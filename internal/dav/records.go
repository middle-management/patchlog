package dav

import (
	"net/http"
	"slices"
	"time"

	"github.com/middle-management/patchlog/internal/lru"
	"github.com/middle-management/patchlog/internal/pointer"
)

// Records are the versions of a document a user's clients may hold, the
// candidates for the base of their next save (§11 submit, §H.4): the
// revisions GET sent them (a 304 sends none), and what they wrote, as
// they wrote it. They are kept per user (§H.7), so whichever of the
// user's tokens read or wrote a version, any of them saves from it, and
// by document, for RecordIdle, apart from the user's locks and scratch
// files, which go sooner; a restart loses them. Each user's are kept
// apart: over RecordBytes, the user keeping the most gives way first, so
// one user's uploads don't push out another's records. Records dropped
// to stay within bounds are remembered as lost, so a save isn't rebased
// on what is left of them (base). With them are the user's path records
// and the tombstones and restores the user wrote (markOwn).

// maxRecords bounds a user's records of one document. Over it, the
// oldest but the first goes (and never the latest write): the version an
// editor opened stays while a preview reads the revisions others make.
const maxRecords = 16

// maxForgotten bounds the documents a user's records remember having
// lost records of.
const maxForgotten = 4096

// record is one version: rev's document as served, or as the user wrote
// it.
type record struct {
	seq uint64 // the order of recording, over the server
	rev string
	// wrote: a write of the user's that changed the document; paths
	// are what it changed (writesOf).
	wrote bool
	paths []pointer.Pointer
	// doc is the version as written, canonical JSON, where rev holds
	// another (merged with others' edits, or given a $nonce); nil: rev's
	// document.
	doc []byte
	// raw are the bytes uploaded, where rev holds exactly them and they
	// read otherwise rendered: the user's representation of rev (its
	// bytes, its size), as a client checking what it uploaded expects.
	raw []byte
	at  time.Time
}

func (r record) cost() int { return 64 + len(r.doc) + len(r.raw) + 16*len(r.paths) }

// docRecs is a user's records of one document, oldest first.
type docRecs struct {
	rs []record
	// reload: a save was refused (409) when the records were at this seq;
	// the user's next read of the document drops the records older
	// than it, so the version reloaded is the base of the edit after it.
	reload uint64
	// lost: records of the document were dropped to stay within bounds;
	// a save that changes it is refused rather than rebased on what is
	// left, until the reload that refusal asks for (reload): a read
	// before it isn't that reload, since another of the user's programs
	// (one login in local mode) may still hold the version dropped, and
	// would save it over others' edits rebased on that read.
	lost bool
	// unread are the user's tokens (by id) that must read the document
	// themselves before they save it without a base, at most maxUnread
	// (refusedSave): one whose save of it was refused, or one verified
	// as this user having been another (loseRecords), that hasn't read
	// it since. One pushed out makes the document lost (addUnread).
	unread []string
}

func (d docRecs) cost() int {
	n := 64 + 32*len(d.unread)
	for _, r := range d.rs {
		n += r.cost()
	}
	return n
}

// recStore is one user's records.
type recStore struct {
	docs      lru.Cache[string, docRecs] // by ns/name
	forgotten lru.Cache[string, bool]    // documents whose records the bounds dropped
	paths     lru.Cache[string, pathRec] // by path
	own       lru.Cache[string, bool]    // by ns/name@id: the tombstones and restores the user wrote
	used      time.Time
}

// pathRec is the document a user last read whole or wrote under a
// path (records are kept by document, and a path may come to name
// another: a tree's title given to a new item, a raw x.json taking the
// name of JSON document x), and when.
type pathRec struct {
	ns, name string
	at       time.Time
}

// maxPaths bounds the paths a user's path records keep.
const maxPaths = 1 << 16

// maxOwn bounds the tombstones and restores a user's records remember
// having written (ownEntry).
const maxOwn = 1 << 12

func recKey(ns, name string) string { return ns + "/" + name }

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

// storeLocked returns p's records, made if new.
func (s *Server) storeLocked(p *principal) *recStore {
	rs := s.recRoots[p.id]
	if rs == nil {
		rs = &recStore{used: s.opt.Now()}
		rs.docs.MaxEntries, rs.docs.MaxBytes = 1<<16, s.opt.RecordBytes
		rs.forgotten.MaxEntries = maxForgotten
		rs.paths.MaxEntries = maxPaths
		rs.own.MaxEntries = maxOwn
		rs.docs.OnEvict = func(k string, _ docRecs) { rs.forgotten.Put(k, true, 1) }
		s.recRoots[p.id] = rs
	}
	return rs
}

// loseRecords marks the documents user from (its id) has records of, or
// had lost records of, as unread by token by in to's records (§H.4
// "records evicted"): by, verified as to now, was from's, and may have
// them open, while to's records don't hold what it opened, so its saves
// of them without a base are refused until it reads them itself
// (refusedSave), those of documents to has records of too (another of
// the person's tokens read them as to: other versions than by's client
// opened). Only by's: to's other tokens saving from what they read as
// to, or never read, aren't refused, and their reads aren't by's reload.
// The marks are records of their own, within to's records' bounds as
// any, made least recently used first, so that those bounds push out the
// documents from used longest ago first; one pushed out is remembered as
// lost (forgotten), which a save is refused over until a reload.
func (s *Server) loseRecords(from string, to *principal, by string) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	src := s.recRoots[from]
	dst := s.storeLocked(to)
	if src == nil || src == dst {
		return
	}
	lost, docs := src.forgotten.Keys(), src.docs.Keys() // most recently used first
	keys := make([]string, 0, len(lost)+len(docs))
	for i := len(lost) - 1; i >= 0; i-- {
		keys = append(keys, lost[i])
	}
	for i := len(docs) - 1; i >= 0; i-- {
		keys = append(keys, docs[i])
	}
	before := dst.docs.Bytes()
	for _, k := range keys {
		d, ok := dst.docs.Get(k)
		if !ok {
			_, d.lost = dst.forgotten.Get(k)
			dst.forgotten.Remove(k)
		}
		d.addUnread(by)
		dst.docs.Put(k, d, d.cost())
	}
	dst.used = s.opt.Now()
	s.recBytes += dst.docs.Bytes() - before
	s.trimRecordsLocked()
}

// markOwn remembers that user p wrote entry id of ns/name, a tombstone or
// a restore: one between a save's base and the head is no delete or
// restore by someone else (§11.3, §H.4), whichever of p's tokens wrote it
// (§H.7).
func (s *Server) markOwn(p *principal, ns, name, id string) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	rs := s.storeLocked(p)
	rs.used = s.opt.Now()
	rs.own.Put(ns+"/"+name+"@"+id, true, 1)
}

// ownEntry reports whether user p wrote entry id of ns/name, as far as
// its records remember (markOwn): one forgotten counts as someone else's,
// which a save from before refuses (a reload settles it).
func (s *Server) ownEntry(p *principal, ns, name, id string) bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	_, ok := s.storeLocked(p).own.Get(ns + "/" + name + "@" + id)
	return ok
}

// recordsOf returns p's records of ns/name, without those older than
// RecordIdle. Records the bounds dropped since the document's last reload
// make it lost.
func (s *Server) recordsOf(p *principal, ns, name string) docRecs {
	cut := s.opt.Now().Add(-s.opt.RecordIdle)
	k := recKey(ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	rs := s.storeLocked(p)
	d, ok := rs.docs.Get(k)
	if !ok {
		_, lost := rs.forgotten.Get(k)
		return docRecs{lost: lost}
	}
	out := docRecs{reload: d.reload, lost: d.lost, unread: d.unread, rs: make([]record, 0, len(d.rs))}
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
	k := recKey(ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	s.recSeq++
	r.seq = s.recSeq
	st := s.storeLocked(p)
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
	d := docRecs{reload: old.reload, lost: old.lost, unread: old.unread, rs: make([]record, 0, len(old.rs)+1)}
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
// user keeping the most, until all of them fit RecordBytes.
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

// sweepRecordsLocked forgets the users that recorded nothing for
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
	s.storeLocked(p).paths.Put(path, pathRec{ns: ns, name: name, at: s.opt.Now()}, 1)
}

// pathOf returns the document p last read whole or wrote under path,
// within RecordIdle.
func (s *Server) pathOf(p *principal, path string) (string, string, bool) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	r, ok := s.storeLocked(p).paths.Get(path)
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
	s.storeLocked(p).paths.Remove(path)
}

// maxUnread bounds the tokens a document's records keep as to read it
// themselves (docRecs.unread).
const maxUnread = 8

// refuse marks the principal's records of ns/name refused (Server.refuse)
// by the request's token.
func (st *reqState) refuse(ns, name string) { st.s.refuse(st.p, ns, name, st.tk.id) }

// refuse marks p's records of ns/name as refused: the save was a 409,
// which asks for a reload, by token by, which must read the document
// itself before it saves it again without a base (refusedSave). A token
// already to read it (unread) asks for none again: it hasn't read since,
// so the reload its earlier refusal asked for is still due, or was
// another of the user's programs' read, which holds the version it read.
// A refused retry of its upload (an rclone mount's own, the same bytes,
// whose rebase clashes as before, or a raw file's) or a switched token's
// refusal re-arming the user's reload would make that program's next
// read drop that version, and its next save without If-Match would then
// be rebased on that read alone, over what a third party changed since
// (§H.4).
func (s *Server) refuse(p *principal, ns, name, by string) {
	k := recKey(ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	st := s.storeLocked(p)
	st.used = s.opt.Now()
	d, ok := st.docs.Get(k)
	if !ok {
		_, d.lost = st.forgotten.Get(k)
		st.forgotten.Remove(k)
	} else if slices.Contains(d.unread, by) {
		return
	}
	if !d.addUnread(by) {
		s.recSeq++
		d.reload = s.recSeq
	}
	before := st.docs.Bytes()
	st.docs.Put(k, d, d.cost())
	s.recBytes += st.docs.Bytes() - before
	s.trimRecordsLocked()
}

// addUnread adds token by to d's unread, the newest, at most maxUnread,
// and reports whether that pushed the oldest out. The token pushed out
// may still hold a version from before its refusal or its switch, which
// a save rebased on the user's records would write over others' edits,
// so the document is then lost, as when the bounds drop records: a save
// that changes it is refused until the reload that refusal asks for. Not
// a reload already due (which is undone): another program's read, the
// next one, would be that reload, and let the token's save through.
func (d *docRecs) addUnread(by string) bool {
	if slices.Contains(d.unread, by) {
		return false
	}
	d.unread = append(slices.Clip(d.unread), by)
	if len(d.unread) <= maxUnread {
		return false
	}
	d.unread = d.unread[1:]
	d.lost, d.reload = true, 0
	return true
}

// readBy notes that token by of p's read ns/name whole (served), or found
// it gone (reloaded): the reload a refusal of its save asked for.
func (s *Server) readBy(p *principal, ns, name, by string) {
	k := recKey(ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	st := s.storeLocked(p)
	d, ok := st.docs.Get(k)
	if !ok || !slices.Contains(d.unread, by) {
		return
	}
	d.unread = slices.DeleteFunc(slices.Clone(d.unread), func(t string) bool { return t == by })
	before := st.docs.Bytes()
	st.docs.Put(k, d, d.cost())
	s.recBytes += st.docs.Bytes() - before
}

// refusedSave is the refusal of a save of ns/name without a base (no
// If-Match) by a token that must read it itself first (docRecs.unread):
// its save of it was refused (409), or it was verified as this user
// having been another (loseRecords), and it hasn't read it since; nil
// otherwise. The user's records are their tokens', and the reload a
// refusal asks for drops what was recorded before it, by whichever
// program reads the document; but the program refused still holds what
// it had, and may retry the refused upload on its own, the same bytes,
// as an rclone mount's write-back does (10 s, 20 s, 40 s… later).
// Rebased on what the other program read, that retry would be written
// over the edit the refusal was about (§H.4). A token is the program's as
// far as this server knows: two programs logging in with the same grant
// (local mode's one password) are one, and the other's read is that
// one's reload. This refusal asks for no reload of the user's: the
// token's own GET is the one it waits for, answered in full (stale), and
// a retry re-arming the user's would make another program's next read
// drop the version it has open, with its next save then rebased on that
// read alone.
func (st *reqState) refusedSave(ns, name string) error {
	if st.ifMatch != "" || st.matchAny {
		return nil
	}
	st.s.recMu.Lock()
	d, _ := st.s.storeLocked(st.p).docs.Get(recKey(ns, name))
	refused := slices.Contains(d.unread, st.tk.id)
	st.s.recMu.Unlock()
	if !refused {
		return nil
	}
	return fail(http.StatusConflict, "%s/%s: this login hasn't read it since a save of it by this login was refused, or since it logged in as another user than before (§H.4, §H.7): someone else may have changed it since the version this save was made from (a client retrying its upload, maybe), so it isn't written over their changes; reload it here and save your edit again, or name the version you edited (If-Match)", ns, name)
}

// reloaded forgets p's records of ns/name, gone in the core, if a save of
// it was refused (refuse) since they were made: a GET found it gone, the
// reload that refusal asked for, so the next write makes it anew
// (tombBase) rather than meeting the refusal again.
func (s *Server) reloaded(p *principal, ns, name, by string) {
	s.readBy(p, ns, name, by)
	k := recKey(ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	st := s.storeLocked(p)
	d, ok := st.docs.Get(k)
	if !ok || d.reload == 0 {
		return
	}
	before := st.docs.Bytes()
	if len(d.unread) > 0 {
		// Other tokens refused, which haven't found it gone.
		st.docs.Put(k, docRecs{unread: d.unread}, docRecs{unread: d.unread}.cost())
	} else {
		st.docs.Remove(k)
	}
	st.forgotten.Remove(k)
	s.recBytes += st.docs.Bytes() - before
}

// stale reports whether a GET of ns/name at rev must send it whatever the
// client's validators say: a save of p's was refused (or its records
// lost) and the reload is due, token by must read it itself
// (refusedSave), or p's newest record is a write of its
// own that rev holds other than written (merged, or given a $nonce),
// which the client may have filed under rev's tag (davfs2 asks for it
// with a HEAD after a PUT without one).
func (s *Server) stale(p *principal, ns, name, rev, by string) bool {
	d := s.recordsOf(p, ns, name)
	if d.reload > 0 || d.lost || slices.Contains(d.unread, by) {
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
	d, _ := s.storeLocked(p).docs.Get(recKey(ns, name))
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
		st.s.readBy(st.p, sv.ns, sv.name, st.tk.id)
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
