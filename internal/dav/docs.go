package dav

import (
	"context"
	"errors"
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
	// tree: a document of a file tree (§H.2), whose file is its content:
	// value, rendered, raw and file are content's (contentEntry), and whole
	// is the document; folder and name are its place, and isFolder says it
	// has no content. A document without a string folder and name has no
	// place (placed false), and is in no folder.
	tree, placed, isFolder bool
	whole                  any
	folder, name           string
}

// newEntry is the entry of document v, read or written at modified.
func newEntry(v any, modified time.Time) *docEntry {
	e := &docEntry{value: v, modified: modified, raw: rawRefOf(v, client.RawBlobOf(v))}
	e.file, e.rendered = files.Show(v)
	return e
}

// treeEntry is the entry of document v of a file tree (§H.2), read or
// written at modified: its file is content, of which "everything this
// addendum says of a file's document" holds, paths included; $nonce and
// $successor stay at the document's top level.
func treeEntry(v any, modified time.Time) *docEntry {
	m, _ := v.(map[string]any)
	content, has := m["content"]
	e := contentEntry(content, modified)
	e.tree, e.whole, e.isFolder = true, v, !has
	e.folder, _ = m["folder"].(string)
	e.name, _ = m["name"].(string)
	_, fok := m["folder"].(string)
	_, nok := m["name"].(string)
	e.placed = fok && nok
	if e.isFolder {
		e.value, e.raw, e.rendered = nil, nil, nil
	}
	return e
}

// contentEntry is the entry of a tree file's content: a raw file where it
// is a blob reference, else a JSON file whose rendering is content's own
// (§H.1, §H.2: the document's top-level $nonce and $successor aren't in
// it, as they aren't in content).
func contentEntry(content any, modified time.Time) *docEntry {
	e := &docEntry{value: content, modified: modified, tree: true, placed: true}
	if bid := client.RawBlobOf(content); bid != "" {
		e.raw = rawRefOf(content, bid)
	}
	e.file, e.rendered = files.Show(content)
	return e
}

// entryOf is the entry of document v of namespace ns as this server shows
// it: a tree's (treeEntry) or a flat namespace's (newEntry).
func (s *Server) entryOf(ns string, v any, modified time.Time) *docEntry {
	if s.trees[ns] {
		return treeEntry(v, modified)
	}
	return newEntry(v, modified)
}

// root is e's document as the core holds it: its whole document in a
// tree, else its value.
func (e *docEntry) root() any {
	if e.tree {
		return e.whole
	}
	return e.value
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
	st := state(ctx)
	if ok {
		// A read of the request's that failed stays its failure though
		// the document has come into the cache since, by another
		// request: every request it makes counts (§H.4 "Answers",
		// v0.86), and only its own, made again and answered, clears one.
		return e, nil
	}
	// One read per token and revision at a time; another token's read
	// could fail where this one's wouldn't.
	v, err, shared := s.group.Do(tk.id+"|"+k, func() (any, error) {
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
			e = s.entryOf(ns, d.Value, d.Modified)
		}
		s.keep(k, e)
		return e, nil
	})
	if err != nil {
		if st != nil && shared && failedRead(err) && !errors.Is(err, context.Canceled) {
			// The read may have been another request's, shared with this
			// one, which then made none of its own to see fail
			// (sawUpstream): its failure for now is this request's too
			// (§H.4 "Answers", v0.86), until the read is made again and
			// answered.
			if de, ok := upstream(err).(*davError); ok {
				st.upstreamFailed("GET "+k, de)
			}
		}
		return nil, err
	}
	if st != nil && !shared {
		// Its own read, answered: a failure it shared before is past.
		st.upstreamOK("GET " + k)
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
// namespace requires one, the limits in force (§6.6, the deployment's
// defaults and maximums applied; 0 where not known), and the verbs the
// grant allows there (can, nil where not known).
type nsInfo struct {
	can                   map[string]bool
	sealed                bool
	frozen                bool // §8.4: it takes no writes, a DELETE neither
	nonce                 bool
	nonceRequired         bool
	patchSetSize, docSize int
	opsPerSet, blobSize   int
	// tree: a file tree's (§H.2), whose files' patch sets are content's,
	// sent under /content, and whose documents are objects, which carry a
	// $nonce whatever their content (withNonce)
	tree bool
}

// writerAt is §7.4's writer block of a namespace as a token was given it,
// at at, or the core's refusal of it (err: a 401, 403, 404 or 410).
type writerAt struct {
	w   client.WriterInfo
	can []string // the verbs the grant allows there (§7.4 can); nil if not said
	err error
	at  time.Time
}

// nsInfo returns what writes to ns need (nsInfo) as tk is given it:
// §7.4's writer block, asked at most every writerTTL. Writer settings tk isn't given
// (GET /ns/{ns}/principal refused) mean a fresh $nonce on every write
// (client.NeedsNonce, §C.7).
func (s *Server) nsInfo(ctx context.Context, tk *token, ns string) nsInfo {
	in, err := s.nsInfoErr(ctx, tk, ns)
	if st := state(ctx); err != nil && st != nil && st.writes() && failedRead(err) {
		// What a request's writes need is among what its answer depends
		// on (§H.4 "Answers", v0.85): it fails before it writes
		// (saveInfo), a save as any other writing request. A request that
		// only reads fails too, since v0.86, when it answers: the read
		// that failed here is one it made (writeGuard, sawUpstream).
		st.unread.CompareAndSwap(nil, &err)
	}
	return in
}

// saveInfo is nsInfo of ns for st's token where the request writes: for
// a request that writes (writes: a save, a delete, a move, a copy, a new
// folder), a read of it that failed for now (failedRead), here or
// earlier in the request, of this namespace or of another (nsInfo), is
// the error, and the request fails before the write: a failed read of
// what the answer depends on fails it, and never counts as a refusal or
// as settings to go by (§H.4 "Answers", v0.85; before, a save's alone).
// A request that only reads goes on by the settings a fresh $nonce on
// every write stands for, as nsInfo does, and is answered with the
// failure all the same (errWriter; §H.4 "Answers", v0.86).
func (st *reqState) saveInfo(ctx context.Context, ns string) (nsInfo, error) {
	in, err := st.s.nsInfoErr(ctx, st.tk, ns)
	if !st.writes() {
		return in, nil
	}
	if err != nil && failedRead(err) {
		return in, upstream(err)
	}
	if e := st.unread.Load(); e != nil {
		return in, upstream(*e)
	}
	return in, nil
}

// writerTTL is how long a token's writer block (§7.4, no-store) serves
// its writes: briefly, and never longer than the token is trusted
// without asking the core again (VerifyEvery). A refusal over one of its
// settings drops it sooner (davError.refresh).
func (s *Server) writerTTL() time.Duration { return min(30*time.Second, s.opt.VerifyEvery) }

// keepWriter keeps ns's writer block and verbs, as tk was given them at
// now (pi, GET /ns/{ns}/principal).
func (tk *token) keepWriter(ns string, pi *client.PrincipalInfo, now time.Time) {
	tk.mu.Lock()
	tk.writers[ns] = writerOf(pi, now)
	tk.mu.Unlock()
}

// writerOf is what nsInfo keeps of principal answer pi, given at now.
func writerOf(pi *client.PrincipalInfo, now time.Time) writerAt {
	wa := writerAt{w: pi.Writer, at: now}
	if _, said := pi.Raw["can"].([]any); said {
		wa.can = append([]string{}, pi.Can...)
	}
	return wa
}

// forgetNS drops what tk was given of ns (its writer block), so the next
// nsInfo asks again.
func (tk *token) forgetNS(ns string) {
	tk.mu.Lock()
	delete(tk.writers, ns)
	tk.mu.Unlock()
}

// forgetWriters drops every writer block tk was given.
func (tk *token) forgetWriters() {
	tk.mu.Lock()
	clear(tk.writers)
	tk.mu.Unlock()
}

// transient reports a read that failed for now (a 408, a 429, a 5xx, no
// answer), whose failure isn't kept: it never counts as a refusal, for
// any request (§H.4 "Answers", v0.85; before, a 408 was kept like one but
// by a save).
func transient(err error) bool {
	ae, isAPI := client.AsAPIError(err)
	return err != nil && (!isAPI || ae.Status == 408 || ae.Status == 429 || ae.Status >= 500)
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
			return nsInfo{nonce: true, tree: s.trees[ns]}, err
		case err != nil:
			wa = writerAt{err: err, at: now}
		default:
			wa = writerOf(pi, now)
			tk.p.verifiedAs(ns, pi)
		}
		tk.mu.Lock()
		tk.writers[ns] = wa
		tk.mu.Unlock()
	}
	in := nsInfo{nonce: true, tree: s.trees[ns]}
	if wa.err == nil {
		w := wa.w
		in.sealed = w.Level == "sealed" || w.Level == "e2e"
		in.nonceRequired = w.NonceRequired
		in.nonce = in.nonceRequired
		in.frozen = w.Frozen
		size := func(k string) int { n, _ := w.Size(k); return int(n) }
		in.patchSetSize, in.docSize = size("patchSetSize"), size("documentSize")
		in.opsPerSet, in.blobSize = size("opsPerSet"), size("blobSize")
		if wa.can != nil {
			in.can = map[string]bool{}
			for _, v := range wa.can {
				in.can[v] = true
			}
		}
	}
	return in, nil
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
	items, _, err := tk.c.Unfiltered().Heads(ctx, ns, h.ID)
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
