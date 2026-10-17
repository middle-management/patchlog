package dav

import "time"

// Records are the versions of a document a principal's clients may hold,
// the candidates for the base of their next save (§11 submit): the
// revisions GET sent them (a 304 sends none), and what they wrote, as
// they wrote it. They are kept by principal id and document for
// RecordIdle, within RecordBytes for every principal together, apart from
// the principal's locks and scratch files, which go sooner; a restart
// loses them.

// maxRecords bounds a principal's records of one document, the oldest
// dropped first.
const maxRecords = 8

// record is one version: rev's document as served, or raw, the bytes a
// write sent, now held by rev; exact when rev's document is what raw
// holds, so that raw is the principal's representation of rev (its bytes,
// its size) and rev the write's validator.
type record struct {
	rev   string
	raw   []byte // nil: served
	exact bool
	at    time.Time
}

func (r record) wrote() bool { return r.raw != nil }

func recKey(p *principal, ns, name string) string { return p.id + "\x00" + ns + "/" + name }

// recordsOf returns p's records of ns/name, oldest first, without those
// older than RecordIdle.
func (s *Server) recordsOf(p *principal, ns, name string) []record {
	cut := s.opt.Now().Add(-s.opt.RecordIdle)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	rs, _ := s.records.Get(recKey(p, ns, name))
	out := make([]record, 0, len(rs))
	for _, r := range rs {
		if !r.at.Before(cut) {
			out = append(out, r)
		}
	}
	return out
}

// remember adds r to p's records of ns/name, the newest, in place of one
// of the same version (a revision served again, a write held by the same
// revision).
func (s *Server) remember(p *principal, ns, name string, r record) {
	if r.at.IsZero() {
		r.at = s.opt.Now()
	}
	k := recKey(p, ns, name)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	old, _ := s.records.Get(k)
	rs := make([]record, 0, len(old)+1)
	for _, o := range old {
		if o.rev != r.rev || o.wrote() != r.wrote() {
			rs = append(rs, o)
		}
	}
	rs = append(rs, r)
	if len(rs) > maxRecords {
		rs = rs[len(rs)-maxRecords:]
	}
	cost := 64
	for _, x := range rs {
		cost += 64 + len(x.raw)
	}
	s.records.Put(k, rs, cost)
}

// exactOf returns the bytes p wrote that rev of ns/name holds exactly, or
// nil.
func (s *Server) exactOf(p *principal, ns, name, rev string) []byte {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	rs, _ := s.records.Get(recKey(p, ns, name))
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].rev == rev && rs[i].exact {
			return rs[i].raw
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

// stagedServe is the document a GET is answering with: a record once its
// body is sent (errWriter), not on a 304.
type stagedServe struct{ ns, name, rev string }

// served records a staged GET whose body went out.
func (st *reqState) served() {
	if sv := st.serve; sv != nil {
		st.serve = nil
		st.s.remember(st.p, sv.ns, sv.name, record{rev: sv.rev})
	}
}

// modTime is a document's Last-Modified: its creation time where known,
// else when the principal was first shown it, later than any revision it
// saw before, so editors notice a change. The latter starts over when the
// server does.
func (s *Server) modTime(p *principal, k string, e *docEntry) time.Time {
	if !e.created.IsZero() {
		return e.created
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
