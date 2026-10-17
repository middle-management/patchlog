// Package dav serves namespaces of a Patch Log deployment over WebDAV
// (RFC 4918), for file managers and editors: a prototype. It is an API
// consumer like the other services: it talks to the core only through its
// public HTTP API (internal/client) and keeps nothing but caches.
//
// Layout: / lists a directory per exposed namespace. A flat namespace's
// directory lists its live resources as {name}.json; a catalog (Addendum
// B) is a folder tree, folders as directories and placements as
// {ns}.{name}.json files holding the content document /r/{ns}/{name}.
//
// A file reads as the document's canonical JSON (§3.1) indented, so it is
// the same bytes for the same revision, whose id is its ETag. A save is a
// diff (merge.Diff) from the revision the saver was served to what it
// wrote, appended with If-Match on the head (§11 submit): edits others made
// since to other paths are kept, overlapping ones are a 409. Names that
// aren't documents (editor swap and backup files, .DS_Store, ._*) live in
// memory, per principal, so editors' save dances work.
//
// Two ways to authenticate: with a fixed grant (local mode, the WebDAV
// clients log in with a password of the server's), or as a gateway, where
// each request's Basic password is the grant sent upstream.
package dav

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/sync/singleflight"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/lru"
)

// Options configure a Server.
type Options struct {
	// Client talks to the core. In local mode it carries the grant every
	// request is made with (client.WithBearer); in gateway mode each
	// request's grant replaces its bearer.
	Client *client.Client
	// Namespaces are the flat namespaces served, each a directory of
	// {name}.json files.
	Namespaces []string
	// Catalogs are the catalog namespaces served as folder trees (Addendum
	// B).
	Catalogs []string
	// Gateway takes each request's Basic password as the grant sent
	// upstream as Authorization: Bearer; the user name is ignored.
	Gateway bool
	// Password is the Basic password of local mode (any user name).
	Password string
	// Realm names the WWW-Authenticate realm (default "patchlog").
	Realm string

	// FetchConcurrency bounds the document reads in flight to the core
	// (default 8).
	FetchConcurrency int
	// CacheBytes bounds the rendered documents kept by revision id
	// (default 64 MiB).
	CacheBytes int
	// MaxFileSize bounds a written file, buffered whole (default 16 MiB).
	MaxFileSize int
	// ScratchFiles and ScratchBytes bound one principal's scratch files
	// (default 256 and 32 MiB); ScratchTotal all principals' (default 256
	// MiB). ScratchIdle drops a scratch file untouched that long (default
	// an hour).
	ScratchFiles, ScratchBytes, ScratchTotal int
	ScratchIdle                              time.Duration
	// MaxPrincipals bounds the principals a gateway keeps state for, the
	// least recently seen dropped first (default 256).
	MaxPrincipals int
	// Retries bounds the resends of a write whose head moved (412,
	// default 5).
	Retries int
	// MaxRetryWait is the longest Retry-After of a 429 a write waits for
	// before answering 503 (default 2s).
	MaxRetryWait time.Duration

	Now  func() time.Time
	Logf func(format string, args ...any)
}

// Server is the WebDAV handler.
type Server struct {
	opt   Options
	flat  map[string]bool
	cats  map[string]bool
	start time.Time
	fs    *davFS

	local *principal // local mode

	mu           sync.Mutex
	principals   map[string]*principal // gateway mode, by grant hash
	lastSweep    time.Time
	scratchTotal atomic.Int64 // every principal's scratch bytes

	docMu sync.Mutex
	docs  lru.Cache[string, *docEntry] // by ns/name@rev
	sem   chan struct{}
	group singleflight.Group
}

// New returns a server for opt.
func New(opt Options) (*Server, error) {
	if opt.Client == nil {
		return nil, errors.New("dav: no client")
	}
	if !opt.Gateway && opt.Password == "" {
		return nil, errors.New("dav: local mode needs a password")
	}
	if len(opt.Namespaces)+len(opt.Catalogs) == 0 {
		return nil, errors.New("dav: no namespace to serve")
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&opt.FetchConcurrency, 8)
	def(&opt.CacheBytes, 64<<20)
	def(&opt.MaxFileSize, 16<<20)
	def(&opt.ScratchFiles, 256)
	def(&opt.ScratchBytes, 32<<20)
	def(&opt.ScratchTotal, 256<<20)
	def(&opt.MaxPrincipals, 256)
	def(&opt.Retries, 5)
	if opt.ScratchIdle <= 0 {
		opt.ScratchIdle = time.Hour
	}
	if opt.MaxRetryWait <= 0 {
		opt.MaxRetryWait = 2 * time.Second
	}
	if opt.Realm == "" {
		opt.Realm = "patchlog"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	s := &Server{opt: opt, flat: map[string]bool{}, cats: map[string]bool{}, principals: map[string]*principal{},
		sem: make(chan struct{}, opt.FetchConcurrency)}
	s.start = opt.Now()
	s.docs.MaxEntries, s.docs.MaxBytes = 1<<20, opt.CacheBytes
	for _, ns := range opt.Namespaces {
		if !client.ValidNSName(ns) {
			return nil, fmt.Errorf("dav: invalid namespace name %q", ns)
		}
		s.flat[ns] = true
	}
	for _, ns := range opt.Catalogs {
		if !client.ValidNSName(ns) {
			return nil, fmt.Errorf("dav: invalid namespace name %q", ns)
		}
		if s.flat[ns] {
			return nil, fmt.Errorf("dav: %s is both a namespace and a catalog", ns)
		}
		s.cats[ns] = true
	}
	s.fs = &davFS{s: s}
	if !opt.Gateway {
		s.local = s.newPrincipal("local", opt.Client)
	}
	return s, nil
}

// realm is the WWW-Authenticate challenge.
func (s *Server) realm() string { return fmt.Sprintf("Basic realm=%q, charset=\"UTF-8\"", s.opt.Realm) }

// namespaces lists the served namespaces, flat and catalogs, sorted.
func (s *Server) namespaces() []string {
	out := make([]string, 0, len(s.flat)+len(s.cats))
	for ns := range s.flat {
		out = append(out, ns)
	}
	for ns := range s.cats {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// ServeHTTP authenticates the request, then serves it with x/net/webdav
// over the principal's view.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, msg := s.authenticate(r)
	if p == nil {
		w.Header().Set("WWW-Authenticate", s.realm())
		http.Error(w, msg, http.StatusUnauthorized)
		return
	}
	st := &reqState{s: s, p: p, method: r.Method, path: slashClean(r.URL.Path), depth: r.Header.Get("Depth")}
	switch r.Method {
	case "PROPFIND":
		switch st.depth {
		case "":
			// RFC 4918 §9.1 makes a missing Depth infinity, which this
			// server doesn't walk (a catalog DAG can be large); listings
			// take one level.
			r.Header.Set("Depth", "1")
			st.depth = "1"
		case "infinity":
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>`)
			return
		}
	case "MOVE", "COPY":
		// RFC 4918 §10.6: no Overwrite header means T; x/net/webdav takes
		// it as F for MOVE.
		if r.Header.Get("Overwrite") == "" {
			r.Header.Set("Overwrite", "T")
		}
		if u, err := url.Parse(r.Header.Get("Destination")); err == nil && u.Path != "" {
			st.dst = slashClean(u.Path)
		}
	}
	h := &webdav.Handler{FileSystem: s.fs, LockSystem: p.locks, Logger: func(r *http.Request, err error) {
		if err != nil && !errors.Is(err, errNotExist) {
			s.opt.Logf("dav: %s %s: %v", r.Method, r.URL.Path, err)
		}
	}}
	h.ServeHTTP(&errWriter{ResponseWriter: w, st: st, realm: s.realm()}, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
}

// authenticate returns the request's principal, or nil and why not. Local
// mode compares the Basic password in constant time; gateway mode takes
// it as the grant, which must at least decode and not have expired (the
// core verifies it on every request).
func (s *Server) authenticate(r *http.Request) (*principal, string) {
	_, pw, ok := r.BasicAuth()
	if !ok {
		return nil, "authentication required"
	}
	if !s.opt.Gateway {
		a, b := sha256.Sum256([]byte(pw)), sha256.Sum256([]byte(s.opt.Password))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			return nil, "wrong password"
		}
		s.sweep()
		return s.local, ""
	}
	g, err := grant.Decode(pw, 64<<10)
	if err != nil {
		return nil, "the password must be a grant (Addendum C)"
	}
	now := s.opt.Now()
	for _, b := range g.Blocks {
		if b.Exp != nil && !now.Before(*b.Exp) {
			return nil, "the grant has expired"
		}
	}
	sum := sha256.Sum256([]byte(pw))
	id := hex.EncodeToString(sum[:16])
	s.mu.Lock()
	p := s.principals[id]
	if p == nil {
		p = s.newPrincipal(id, s.opt.Client.With(client.WithBearer(pw)))
		s.evictLocked()
		s.principals[id] = p
	}
	p.used = now
	s.mu.Unlock()
	s.sweep()
	return p, ""
}

// evictLocked drops the least recently seen principals, with their
// scratch files, to make room for one more.
func (s *Server) evictLocked() {
	for len(s.principals) >= s.opt.MaxPrincipals {
		var old *principal
		for _, p := range s.principals {
			if old == nil || p.used.Before(old.used) {
				old = p
			}
		}
		delete(s.principals, old.id)
		s.scratchTotal.Add(-int64(old.dropScratch()))
	}
}

// sweep drops idle scratch files, and idle principals of a gateway, at
// most once a minute.
func (s *Server) sweep() {
	now := s.opt.Now()
	s.mu.Lock()
	if now.Sub(s.lastSweep) < time.Minute {
		s.mu.Unlock()
		return
	}
	s.lastSweep = now
	ps := make([]*principal, 0, len(s.principals)+1)
	if s.local != nil {
		ps = append(ps, s.local)
	}
	for id, p := range s.principals {
		if now.Sub(p.used) > s.opt.ScratchIdle {
			delete(s.principals, id)
			s.scratchTotal.Add(-int64(p.dropScratch()))
			continue
		}
		ps = append(ps, p)
	}
	s.mu.Unlock()
	for _, p := range ps {
		s.scratchTotal.Add(-int64(p.expireScratch(now.Add(-s.opt.ScratchIdle))))
	}
}

// principal is what the server keeps for one upstream grant: its client,
// locks, scratch files and the revisions it was served. Nothing of it is
// shared with another principal.
type principal struct {
	id    string
	c     *client.Client
	locks webdav.LockSystem
	used  time.Time // under Server.mu

	mu      sync.Mutex
	scratch map[string]*scratchFile // by path
	sbytes  int
	served  lru.Cache[string, *served]   // by ns/name
	seen    lru.Cache[string, time.Time] // by ns/name@rev: first shown
	ns      map[string]nsInfo
}

func (s *Server) newPrincipal(id string, c *client.Client) *principal {
	p := &principal{id: id, c: c, locks: webdav.NewMemLS(), scratch: map[string]*scratchFile{}, ns: map[string]nsInfo{}, used: s.opt.Now()}
	p.served.MaxEntries, p.served.MaxBytes = 4096, 32<<20
	p.seen.MaxEntries = 65536
	return p
}

// served is what a principal last got or wrote for a document: the base
// its next save is diffed from. rev is the revision; doc, when set, is
// what it wrote, which differs from rev's document when the write merged
// others' edits.
type served struct {
	rev string
	doc any
}

func (p *principal) servedOf(ns, name string) *served {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, _ := p.served.Get(ns + "/" + name)
	return v
}

func (p *principal) setServed(ns, name string, v *served, cost int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.served.Put(ns+"/"+name, v, cost+64)
}

func (p *principal) forget(ns, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// lru has no delete: an entry without a revision means none.
	p.served.Put(ns+"/"+name, &served{}, 64)
}

// firstSeen is when the principal was first shown a revision whose
// creation time isn't known, its stand-in Last-Modified: later than any
// revision it saw before, so editors notice a change.
func (p *principal) firstSeen(key string, now time.Time) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.seen.Get(key); ok {
		return t
	}
	p.seen.Put(key, now, 1)
	return now
}

// reqState is one request's view, in its context: the principal, what
// the request is (MOVE and COPY destinations change what RemoveAll does),
// listings already read, and the error to answer with.
type reqState struct {
	s      *Server
	p      *principal
	method string
	path   string
	dst    string
	depth  string
	err    *davError

	lists  map[string]*listing  // by directory path
	graphs map[string]*catGraph // by catalog
}

type stateKey struct{}

func state(ctx context.Context) *reqState {
	st, _ := ctx.Value(stateKey{}).(*reqState)
	return st
}

// record keeps err for errWriter if it is a davError, and returns it.
// Another failure (no such file) leaves the answer to the handler. In
// local mode the core's 401 refuses the server's own grant, not the
// user's password, so it is a 502 rather than a new login prompt.
func (st *reqState) record(err error) error {
	if err == nil {
		return nil
	}
	var de *davError
	if !errors.As(err, &de) {
		st.err = nil
		return err
	}
	if de.status == http.StatusUnauthorized && !st.s.opt.Gateway {
		de = fail(http.StatusBadGateway, "the core refused this server's grant (-bearer): %s", de.msg)
	}
	st.err = de
	return err
}

// changed forgets what the request read, after it wrote.
func (st *reqState) changed() {
	st.lists, st.graphs = nil, nil
}

// slashClean is path.Clean of name rooted at /.
func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}
