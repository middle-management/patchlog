package dav

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// docEntry is a revision's document as served: rendered once, kept by
// revision id, which never changes what it names (§3.3).
type docEntry struct {
	value    any
	rendered []byte
	// created is the revision's creation time where known: for revisions
	// this server wrote, from the write's log entry (§7.1). Zero
	// otherwise: the core serves documents without it.
	created time.Time
	// sealed: the core served it sealed (application/jose, Addendum E),
	// which isn't rendered.
	sealed bool
}

// render is a document's canonical form (§3.1) indented by two spaces,
// with a trailing newline: keys sorted and numbers as JCS writes them, so
// a revision always reads as the same bytes and saving them unchanged is
// an empty diff.
func render(v any) []byte {
	var b bytes.Buffer
	if err := json.Indent(&b, jsonv.Canonical(v), "", "  "); err != nil {
		panic("dav: canonical JSON doesn't indent: " + err.Error())
	}
	b.WriteByte('\n')
	return b.Bytes()
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
			e = &docEntry{value: d.Value, rendered: render(d.Value)}
		}
		s.keep(k, e)
		return e, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*docEntry), nil
}

// keep caches a document under its key; the value counts twice its
// rendering.
func (s *Server) keep(k string, e *docEntry) {
	s.docMu.Lock()
	s.docs.Put(k, e, 3*len(e.rendered)+256)
	s.docMu.Unlock()
}

// modTime is a document's Last-Modified: its creation time where known,
// else when the principal was first shown it.
func (s *Server) modTime(p *principal, k string, e *docEntry) time.Time {
	if !e.created.IsZero() {
		return e.created
	}
	return p.firstSeen(k, s.opt.Now())
}

// nsInfo is what writes to a namespace need from its document: whether
// it is sealed or end-to-end (not served for writing here), and whether
// writes add a fresh $nonce (§C.7).
type nsInfo struct {
	sealed bool
	nonce  bool
	at     time.Time
}

// nsInfo reads ns's document with p's grant, at most every 30 seconds. A
// document p can't read, as under a grant limited to some resources,
// means a fresh $nonce on every write (client.NeedsNonce, §C.7).
func (s *Server) nsInfo(ctx context.Context, p *principal, ns string) nsInfo {
	now := s.opt.Now()
	p.mu.Lock()
	in, ok := p.ns[ns]
	p.mu.Unlock()
	if ok && now.Sub(in.at) < 30*time.Second {
		return in
	}
	in = nsInfo{at: now}
	h, err := p.c.NSHead(ctx, ns)
	var d *client.NSDoc
	if err == nil {
		d, err = p.c.NSDoc(ctx, ns, h.ID)
	}
	switch {
	case errors.Is(err, client.ErrNoKeys):
		in.sealed, in.nonce = true, true
	case err != nil:
		in.nonce = true
	default:
		enc, _ := d.Value["encryption"].(map[string]any)
		lv, _ := enc["level"].(string)
		in.sealed = lv == "sealed" || lv == "e2e"
		in.nonce = d.Value["nonce"] == "required"
	}
	p.mu.Lock()
	p.ns[ns] = in
	p.mu.Unlock()
	return in
}

// headDoc is a live resource's head and its document.
type headDoc struct {
	ns, name, rev string
	e             *docEntry
}

// fetchHeads reads the documents of live heads, FetchConcurrency at a
// time; heads whose rev is "" are read first (client.Head). Resources that
// turn out not to be live are left out.
func (s *Server) fetchHeads(ctx context.Context, p *principal, items []headDoc) ([]headDoc, error) {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.opt.FetchConcurrency)
	out := make([]headDoc, len(items))
	for i, it := range items {
		g.Go(func() error {
			if it.rev == "" {
				h, err := p.c.Head(gctx, it.ns, it.name)
				if err != nil {
					return err
				}
				if h.State != client.Live {
					return nil
				}
				it.rev = h.ID
			}
			e, err := s.doc(gctx, p, it.ns, it.name, it.rev)
			if err != nil {
				return err
			}
			it.e = e
			out[i] = it
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	live := out[:0]
	for _, it := range out {
		if it.e != nil {
			live = append(live, it)
		}
	}
	return live, nil
}

// liveHeads lists ns's live resources with p's grant (§7.4 /heads).
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
			out = append(out, headDoc{ns: ns, name: it.Resource, rev: it.Target})
		}
	}
	return out, nil
}
