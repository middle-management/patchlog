package dav

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/files"
)

// docEntry is a revision's document as served: rendered once, kept by
// revision id, which never changes what it names (§3.3).
type docEntry struct {
	value any
	// rendered is a JSON file's rendering (§H.1, files.Rendering); raw is
	// a raw file's blob reference instead (§7.8), and rendered nil. file
	// is its size and type as every tool lists them (files.Show, §H.3).
	rendered []byte
	raw      *rawRef
	file     files.Meta
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
	e := &docEntry{value: v, modified: modified, raw: rawRefOf(v, client.RawBlobOf(v))}
	e.file, e.rendered = files.Show(v)
	return e
}

// fileMeta is what a listing shows of a revision's file (§H.3), read from
// its document once and kept by revision id for good, apart from the
// documents (Server.metas), which take more room.
type fileMeta struct {
	files.Meta         // the reference's size and type, or the rendering's length and application/json
	raw        *rawRef // a raw file's reference; nil for a JSON file
	modified   time.Time
	sealed     bool
}

func (e *docEntry) meta() fileMeta {
	return fileMeta{Meta: e.file, raw: e.raw, modified: e.modified, sealed: e.sealed}
}

func docKey(ns, name, rev string) string { return ns + "/" + name + "@" + rev }

// doc returns ns/name at rev, from the cache or read with tk's client.
// Callers read the head (or a listing of heads) with tk's grant first, so
// a cached document is only handed to tokens that may read it.
func (s *Server) doc(ctx context.Context, tk *token, ns, name, rev string) (*docEntry, error) {
	k := docKey(ns, name, rev)
	s.docMu.Lock()
	e, ok := s.docs.Get(k)
	s.docMu.Unlock()
	if ok {
		return e, nil
	}
	// One read per token and revision at a time; another token's read
	// could fail where this one's wouldn't.
	v, err, _ := s.group.Do(tk.id+"|"+k, func() (any, error) {
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		d, err := tk.c.Doc(ctx, ns, name, rev)
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
func (s *Server) meta(ctx context.Context, tk *token, ns, name, rev string) (fileMeta, error) {
	s.docMu.Lock()
	m, ok := s.metas.Get(docKey(ns, name, rev))
	s.docMu.Unlock()
	if ok {
		return m, nil
	}
	e, err := s.doc(ctx, tk, ns, name, rev)
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

// nsInfo is what writes to a namespace need: what GET /ns/{ns}/principal
// says a writer needs (§7.4 writer, §H.7 "Limited grants"), which a grant
// limited to some resources learns though it can't read the namespace
// document: whether it is sealed or end-to-end (not offered here, §H.7),
// frozen, whether writes add a fresh $nonce (§C.7) and whether the
// namespace requires one, and the limits in force (§6.6, the deployment's
// defaults and maximums applied; 0 where not known); and, of a catalog,
// what its document says: its trust list (§B.3) and file tree (§H.2).
type nsInfo struct {
	sealed                bool
	frozen                bool // §8.4: it takes no writes, a DELETE neither
	nonce                 bool
	nonceRequired         bool
	trust                 []string
	files                 *treeFiles
	notTree               string // why a catalog's document makes no file tree, if it was read
	titled                bool   // a catalog's catalog.title is set: listings carry its items' titles (§B.5)
	readErr               error  // the core's refusal of a catalog's document to the token (a 401, 403, 404)
	patchSetSize, docSize int
	opsPerSet, blobSize   int
}

// writerAt is §7.4's writer block of a namespace as a token was given it,
// at at, or the core's refusal of it (err: a 401, 403, 404 or 410).
type writerAt struct {
	w   client.WriterInfo
	err error
	at  time.Time
}

// nsDocAt is what a namespace's document said to a token, at at.
type nsDocAt struct {
	trust   []string
	files   *treeFiles
	notTree string
	titled  bool
	readErr error
	at      time.Time
}

// treeFiles is a catalog's catalog.files (§H.2): the content namespace
// new files are created in, the folder node whose children are the
// tree's top level, and the schemas new folder and placement nodes
// carry as $schema ("" for none).
type treeFiles struct {
	ns, root, folder, placement string
}

// filesOf reads catalog.files from a namespace document's catalog
// object, or says why it makes no file tree.
func filesOf(cat map[string]any) (*treeFiles, string) {
	m, ok := cat["files"].(map[string]any)
	if !ok {
		return nil, "its namespace document has no catalog.files (§H.2, §7.4), so it isn't a file tree: its placements have no file names to show"
	}
	f := &treeFiles{}
	f.ns, _ = m["ns"].(string)
	f.root, _ = m["root"].(string)
	f.folder, _ = m["folder"].(string)
	f.placement, _ = m["placement"].(string)
	switch {
	case !client.ValidNSName(f.ns):
		return nil, fmt.Sprintf("its catalog.files.ns, %q, isn't a namespace name (§3.6)", f.ns)
	case !folderName(f.root):
		return nil, fmt.Sprintf("its catalog.files.root, %q, can't name a folder node: a resource name without a dot (§3.6, §B.2)", f.root)
	}
	return f, ""
}

// nsInfo returns what writes to ns need (nsInfo) as tk is given it:
// §7.4's writer block, asked at most every writerTTL, and a catalog's
// document, read at most every 30 seconds. Writer settings tk isn't given
// (GET /ns/{ns}/principal refused) mean a fresh $nonce on every write
// (client.NeedsNonce, §C.7).
func (s *Server) nsInfo(ctx context.Context, tk *token, ns string) nsInfo {
	in, _ := s.nsInfoErr(ctx, tk, ns)
	return in
}

// writerTTL is how long a token's writer block (§7.4, no-store) serves
// its writes: briefly, and never longer than the token is trusted
// without asking the core again (VerifyEvery). A refusal over one of its
// settings drops it sooner (davError.refresh).
func (s *Server) writerTTL() time.Duration { return min(30*time.Second, s.opt.VerifyEvery) }

// keepWriter keeps ns's writer block w, as tk was given it at now.
func (tk *token) keepWriter(ns string, w client.WriterInfo, now time.Time) {
	tk.mu.Lock()
	tk.writers[ns] = writerAt{w: w, at: now}
	tk.mu.Unlock()
}

// forgetNS drops what tk was given of ns (its writer block, its
// document), so the next nsInfo asks again.
func (tk *token) forgetNS(ns string) {
	tk.mu.Lock()
	delete(tk.writers, ns)
	delete(tk.docs, ns)
	tk.mu.Unlock()
}

// forgetWriters drops every writer block tk was given.
func (tk *token) forgetWriters() {
	tk.mu.Lock()
	clear(tk.writers)
	tk.mu.Unlock()
}

// transient reports a read that failed for now (a 429, a 5xx, no answer),
// whose failure isn't kept.
func transient(err error) bool {
	ae, isAPI := client.AsAPIError(err)
	return err != nil && (!isAPI || ae.Status == 429 || ae.Status >= 500)
}

// nsInfoErr is nsInfo, with the error of a read that failed for now
// (transient), which isn't kept.
func (s *Server) nsInfoErr(ctx context.Context, tk *token, ns string) (nsInfo, error) {
	now := s.opt.Now()
	tk.mu.Lock()
	wa, ok := tk.writers[ns]
	tk.mu.Unlock()
	if !ok || now.Sub(wa.at) >= s.writerTTL() {
		pi, err := tk.c.NSPrincipal(ctx, ns)
		switch {
		case transient(err):
			return nsInfo{nonce: true}, err
		case err != nil:
			wa = writerAt{err: err, at: now}
		default:
			wa = writerAt{w: pi.Writer, at: now}
		}
		tk.mu.Lock()
		tk.writers[ns] = wa
		tk.mu.Unlock()
	}
	in := nsInfo{nonce: true}
	if wa.err == nil {
		w := wa.w
		in.sealed = w.Level == "sealed" || w.Level == "e2e"
		in.nonceRequired = w.NonceRequired
		in.nonce = in.nonceRequired
		in.frozen = w.Frozen
		size := func(k string) int { n, _ := w.Size(k); return int(n) }
		in.patchSetSize, in.docSize = size("patchSetSize"), size("documentSize")
		in.opsPerSet, in.blobSize = size("opsPerSet"), size("blobSize")
	}
	if s.cats[ns] {
		d, err := s.nsDoc(ctx, tk, ns)
		if err != nil {
			return nsInfo{nonce: true}, err
		}
		in.trust, in.files, in.notTree, in.titled, in.readErr = d.trust, d.files, d.notTree, d.titled, d.readErr
	}
	return in, nil
}

// nsDoc returns what ns's document says, read with tk's grant at most
// every 30 seconds: a catalog's trust list and file tree, and whether tk
// reads it (readErr). A failure for now (transient) is the error.
func (s *Server) nsDoc(ctx context.Context, tk *token, ns string) (nsDocAt, error) {
	now := s.opt.Now()
	tk.mu.Lock()
	d, ok := tk.docs[ns]
	tk.mu.Unlock()
	if ok && now.Sub(d.at) < 30*time.Second {
		return d, nil
	}
	d = nsDocAt{at: now}
	h, err := tk.c.NSHead(ctx, ns)
	var doc *client.NSDoc
	if err == nil {
		doc, err = tk.c.NSDoc(ctx, ns, h.ID)
	}
	switch {
	case errors.Is(err, client.ErrNoKeys):
		// Sealed (§H.7): its writer block says so.
		d.readErr = err
	case transient(err):
		return nsDocAt{}, err
	case err != nil:
		d.readErr = err
	default:
		cat, _ := doc.Value["catalog"].(map[string]any)
		ts, _ := cat["trust"].([]any)
		for _, t := range ts {
			if t, ok := t.(string); ok {
				d.trust = append(d.trust, t)
			}
		}
		d.files, d.notTree = filesOf(cat)
		_, d.titled = cat["title"]
	}
	tk.mu.Lock()
	tk.docs[ns] = d
	tk.mu.Unlock()
	return d, nil
}

// headDoc is a live resource's head, the time it was written where a
// listing says (§7.4 created), its file's metadata, and, once read, its
// document. listed: m is the file metadata a tree service listed (§H.3),
// which shows the file but holds no blob id: reading the file reads its
// own.
type headDoc struct {
	ns, name, rev string
	created       time.Time
	m             fileMeta
	e             *docEntry
	listed        bool
}

// entry returns hd's document, read if it wasn't.
func (st *reqState) entry(ctx context.Context, hd *headDoc) (*docEntry, error) {
	if hd.e != nil {
		return hd.e, nil
	}
	e, err := st.s.doc(ctx, st.tk, hd.ns, hd.name, hd.rev)
	if err != nil {
		return nil, err
	}
	hd.e = e
	return e, nil
}

// fetchHeads reads the file metadata of live heads, and with docs their
// documents, FetchConcurrency at a time; heads whose rev is "" are read
// first (head). Resources that turn out not to be live, or that tk may not
// read (a placement's item in a namespace its grant doesn't read, §B.3),
// are left out.
func (s *Server) fetchHeads(ctx context.Context, tk *token, items []headDoc, head func(context.Context, string, string) (*client.Head, error), docs bool) ([]headDoc, error) {
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
				if it.e, err = s.doc(gctx, tk, it.ns, it.name, it.rev); err == nil {
					it.m = it.e.meta()
				}
			} else {
				it.m, err = s.meta(gctx, tk, it.ns, it.name, it.rev)
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

// liveHeads lists ns's live resources with tk's grant (§7.4 /heads), with
// the time each head was written where the listing says.
func (s *Server) liveHeads(ctx context.Context, tk *token, ns string) ([]headDoc, error) {
	h, err := tk.c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	items, err := tk.c.Heads(ctx, ns, h.ID)
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
