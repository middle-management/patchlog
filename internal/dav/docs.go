package dav

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/middle-management/patchlog/internal/client"
)

// docEntry is a revision's document as served: rendered once, kept by
// revision id, which never changes what it names (§3.3).
type docEntry struct {
	value any
	// rendered is a JSON file's rendering (§H.1); raw is a raw file's blob
	// reference instead (§7.8), and rendered nil.
	rendered []byte
	raw      *rawRef
	// modified is the revision's creation time where known: Last-Modified
	// of its read (§7.1), or, for revisions this server wrote, the write's
	// log entry's. Zero otherwise, as from cores that send none.
	modified time.Time
	// sealed: the core served it sealed (application/jose, Addendum E),
	// which this server, holding no keys, doesn't offer (§H.7).
	sealed bool
}

// newEntry is the entry of document v, read or written at modified.
func newEntry(v any, modified time.Time) *docEntry {
	e := &docEntry{value: v, modified: modified}
	if e.raw = rawRefOf(v, client.RawBlobOf(v)); e.raw == nil {
		e.rendered = render(v)
	}
	return e
}

// fileMeta is what a listing shows of a revision's file (§H.3), read from
// its document once and kept by revision id for good, apart from the
// documents (Server.metas), which take more room.
type fileMeta struct {
	raw      *rawRef // a raw file's reference; nil for a JSON file
	size     int64   // the reference's size, or the rendering's length
	modified time.Time
	sealed   bool
}

func (e *docEntry) meta() fileMeta {
	m := fileMeta{raw: e.raw, size: int64(len(e.rendered)), modified: e.modified, sealed: e.sealed}
	if e.raw != nil {
		m.size = e.raw.size
	}
	return m
}

func docKey(ns, name, rev string) string { return ns + "/" + name + "@" + rev }

// doc returns ns/name at rev, from the cache or read with p's client.
// Callers read the head (or a listing of heads) with p's grant first, so a
// cached document is only handed to principals that may read it.
func (s *Server) doc(ctx context.Context, p *principal, ns, name, rev string) (*docEntry, error) {
	k := docKey(ns, name, rev)
	s.docMu.Lock()
	e, ok := s.docs.Get(k)
	s.docMu.Unlock()
	if ok {
		return e, nil
	}
	// One read per principal and revision at a time; another principal's
	// read could fail where this one's wouldn't.
	v, err, _ := s.group.Do(p.id+"|"+k, func() (any, error) {
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		d, err := p.c.Doc(ctx, ns, name, rev)
		<-s.sem
		var e *docEntry
		switch {
		case errors.Is(err, client.ErrNoKeys):
			e = &docEntry{sealed: true}
		case err != nil:
			return nil, err
		default:
			e = newEntry(d.Value, d.Modified)
		}
		s.keep(k, e)
		return e, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*docEntry), nil
}

// meta returns the file metadata of ns/name at rev, from the cache or read
// with its document (doc), on the same terms.
func (s *Server) meta(ctx context.Context, p *principal, ns, name, rev string) (fileMeta, error) {
	s.docMu.Lock()
	m, ok := s.metas.Get(docKey(ns, name, rev))
	s.docMu.Unlock()
	if ok {
		return m, nil
	}
	e, err := s.doc(ctx, p, ns, name, rev)
	if err != nil {
		return fileMeta{}, err
	}
	return e.meta(), nil
}

// keep caches a document under its key, and its metadata; the value
// counts twice its rendering.
func (s *Server) keep(k string, e *docEntry) {
	s.docMu.Lock()
	s.docs.Put(k, e, 3*len(e.rendered)+256)
	s.metas.Put(k, e.meta(), 1)
	s.docMu.Unlock()
}

// nsInfo is what writes to a namespace need from its document: whether
// it is sealed or end-to-end (not offered here, §H.7), whether writes add
// a fresh $nonce (§C.7) and whether the namespace requires one, a
// catalog's trust list (§B.3), and the size limits it sets (§6.6; 0 where
// it sets none, and the deployment's apply), for messages.
type nsInfo struct {
	sealed                bool
	frozen                bool // §8.4: it takes no writes, a DELETE neither
	nonce                 bool
	nonceRequired         bool
	trust                 []string
	patchSetSize, docSize int
	blobSize              int
	at                    time.Time
}

// nsInfo reads ns's document with p's grant, at most every 30 seconds. A
// document p can't read, as under a grant limited to some resources,
// means a fresh $nonce on every write (client.NeedsNonce, §C.7).
func (s *Server) nsInfo(ctx context.Context, p *principal, ns string) nsInfo {
	in, _ := s.nsInfoErr(ctx, p, ns)
	return in
}

// nsInfoErr is nsInfo, with the error of a read that failed for now (a
// 429, a 5xx, no answer), which isn't kept.
func (s *Server) nsInfoErr(ctx context.Context, p *principal, ns string) (nsInfo, error) {
	now := s.opt.Now()
	p.mu.Lock()
	in, ok := p.ns[ns]
	p.mu.Unlock()
	if ok && now.Sub(in.at) < 30*time.Second {
		return in, nil
	}
	in = nsInfo{at: now}
	h, err := p.c.NSHead(ctx, ns)
	var d *client.NSDoc
	if err == nil {
		d, err = p.c.NSDoc(ctx, ns, h.ID)
	}
	ae, isAPI := client.AsAPIError(err)
	switch {
	case errors.Is(err, client.ErrNoKeys):
		in.sealed, in.nonce, in.nonceRequired = true, true, true
	case err != nil && (!isAPI || ae.Status == 429 || ae.Status >= 500):
		return nsInfo{nonce: true}, err
	case err != nil:
		in.nonce = true
	default:
		enc, _ := d.Value["encryption"].(map[string]any)
		lv, _ := enc["level"].(string)
		in.sealed = lv == "sealed" || lv == "e2e"
		in.nonceRequired = d.Value["nonce"] == "required" || lv == "sealed"
		in.nonce = in.nonceRequired
		in.frozen = d.Value["frozen"] == true
		lim, _ := d.Value["limits"].(map[string]any)
		if n, ok := lim["patchSetSize"].(float64); ok {
			in.patchSetSize = int(n)
		}
		if n, ok := lim["documentSize"].(float64); ok {
			in.docSize = int(n)
		}
		if n, ok := lim["blobSize"].(float64); ok {
			in.blobSize = int(n)
		}
		cat, _ := d.Value["catalog"].(map[string]any)
		ts, _ := cat["trust"].([]any)
		for _, t := range ts {
			if t, ok := t.(string); ok {
				in.trust = append(in.trust, t)
			}
		}
	}
	p.mu.Lock()
	p.ns[ns] = in
	p.mu.Unlock()
	return in, nil
}

// headDoc is a live resource's head, the time it was written where a
// listing says (§7.4 created), its file's metadata, and, once read, its
// document.
type headDoc struct {
	ns, name, rev string
	created       time.Time
	m             fileMeta
	e             *docEntry
}

// entry returns hd's document, read if it wasn't.
func (st *reqState) entry(ctx context.Context, hd *headDoc) (*docEntry, error) {
	if hd.e != nil {
		return hd.e, nil
	}
	e, err := st.s.doc(ctx, st.p, hd.ns, hd.name, hd.rev)
	if err != nil {
		return nil, err
	}
	hd.e = e
	return e, nil
}

// fetchHeads reads the file metadata of live heads, and with docs their
// documents, FetchConcurrency at a time; heads whose rev is "" are read
// first (head). Resources that turn out not to be live, or that p may not
// read (a placement's item in a namespace its grant doesn't read, §B.3),
// are left out.
func (s *Server) fetchHeads(ctx context.Context, p *principal, items []headDoc, head func(context.Context, string, string) (*client.Head, error), docs bool) ([]headDoc, error) {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.opt.FetchConcurrency)
	out := make([]headDoc, len(items))
	got := make([]bool, len(items))
	for i, it := range items {
		g.Go(func() error {
			if it.rev == "" {
				h, err := head(gctx, it.ns, it.name)
				if hidden(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if h.State != client.Live {
					return nil
				}
				it.rev = h.ID
			}
			var err error
			if docs {
				if it.e, err = s.doc(gctx, p, it.ns, it.name, it.rev); err == nil {
					it.m = it.e.meta()
				}
			} else {
				it.m, err = s.meta(gctx, p, it.ns, it.name, it.rev)
			}
			if hidden(err) {
				return nil
			}
			if err != nil {
				return err
			}
			out[i], got[i] = it, true
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	live := out[:0]
	for i, it := range out {
		if got[i] {
			live = append(live, it)
		}
	}
	return live, nil
}

// hidden reports a read the core refuses or no longer serves: 403, 404
// or 410 (deleted since the listing).
func hidden(err error) bool {
	ae, ok := client.AsAPIError(err)
	return ok && (ae.Status == 403 || ae.Status == 404 || ae.Status == 410)
}

// liveHeads lists ns's live resources with p's grant (§7.4 /heads), with
// the time each head was written where the listing says.
func (s *Server) liveHeads(ctx context.Context, p *principal, ns string) ([]headDoc, error) {
	h, err := p.c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	items, err := p.c.Heads(ctx, ns, h.ID)
	if err != nil {
		return nil, err
	}
	out := make([]headDoc, 0, len(items))
	for _, it := range items {
		if it.Kind == "head" {
			hd := headDoc{ns: ns, name: it.Resource, rev: it.Target}
			hd.created, _ = time.Parse(time.RFC3339Nano, it.Created)
			out = append(out, hd)
		}
	}
	return out, nil
}
