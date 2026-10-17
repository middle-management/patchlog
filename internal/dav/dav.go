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
// the same bytes for the same revision, whose id is its ETag. A save is
// rebased (§11 submit): the edit from the version the saver had (the
// revision its If-Match names, else the closest of those it was served or
// wrote) to what it wrote, applied to the head with If-Match. Edits others
// made since to other paths are kept, overlapping ones are a 409. Names
// that aren't documents (editor swap and backup files, .DS_Store, ._*)
// live in memory, per principal, so editors' save dances work.
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
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
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
	// InflightBytes bounds the written files buffered at once, over every
	// request (default 8 times MaxFileSize; 503 beyond).
	InflightBytes int
	// ScratchFiles and ScratchBytes bound one grant root's scratch files
	// (default 256 and 32 MiB); ScratchTotal all of them (default 256
	// MiB). ScratchIdle drops a scratch file untouched that long, and a
	// gateway's principal idle that long (default an hour).
	ScratchFiles, ScratchBytes, ScratchTotal int
	ScratchIdle                              time.Duration
	// RecordBytes bounds the versions remembered as principals' bases (the
	// revisions they were served, the content they wrote), for every
	// principal together (default the larger of 128 MiB and 8 times
	// MaxFileSize). RecordIdle drops a document's versions untouched that
	// long (default a day). They outlive the principal's scratch files.
	RecordBytes int
	RecordIdle  time.Duration
	// MaxPrincipals bounds the principals a gateway keeps state for, the
	// least recently seen without a request in flight dropped first
	// (default 256); MaxPrincipalsPerRoot those of one grant root, its
	// authority block's kid and sub, so tokens attenuated from one grant
	// offline can't push out others' (default 8).
	MaxPrincipals, MaxPrincipalsPerRoot int
	// VerifyEvery is how often a gateway asks the core again whether a
	// principal's grant is accepted (default 5 minutes).
	VerifyEvery time.Duration
	// CatalogTTL is how long a principal's read of a catalog's tree serves
	// its requests, unless this server writes meanwhile (default 5s).
	CatalogTTL time.Duration
	// Retries bounds the resends of a write whose head moved (412,
	// default 5).
	Retries int
	// MaxRetryWait is the longest Retry-After of a 429 a write waits for
	// before answering 503 (default 2s).
	MaxRetryWait time.Duration

	Now  func() time.Time
	Logf func(format string, args ...any)
}

// maxXMLBody bounds a request body other than a PUT's (PROPFIND, PROPPATCH
// and LOCK carry XML; x/net/webdav decodes it whole).
const maxXMLBody = 1 << 20

// Server is the WebDAV handler.
type Server struct {
	opt   Options
	flat  map[string]bool
	cats  map[string]bool
	start time.Time
	fs    *davFS

	local *principal // local mode

	// gateway mode
	anon      *client.Client // without a grant
	checker   *grantcheck.Checker
	verifying singleflight.Group

	mu           sync.Mutex
	principals   map[string]*principal // gateway mode, by grant hash
	accounts     map[string]*account   // by grant root
	public       map[string]publicity  // by namespace
	lastSweep    time.Time
	scratchTotal atomic.Int64 // every principal's scratch bytes

	recMu   sync.Mutex
	records lru.Cache[string, []record]  // by principal and ns/name
	seen    lru.Cache[string, time.Time] // by principal and ns/name@rev: first shown

	docMu    sync.Mutex
	docs     lru.Cache[string, *docEntry] // by ns/name@rev
	sem      chan struct{}
	group    singleflight.Group
	inflight *semaphore.Weighted
	gen      atomic.Uint64 // writes through this server: catalog reads older are stale
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
	defDur := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&opt.FetchConcurrency, 8)
	def(&opt.CacheBytes, 64<<20)
	def(&opt.MaxFileSize, 16<<20)
	def(&opt.InflightBytes, 8*opt.MaxFileSize)
	def(&opt.ScratchFiles, 256)
	def(&opt.ScratchBytes, 32<<20)
	def(&opt.ScratchTotal, 256<<20)
	def(&opt.RecordBytes, max(128<<20, 8*opt.MaxFileSize))
	def(&opt.MaxPrincipals, 256)
	def(&opt.MaxPrincipalsPerRoot, 8)
	def(&opt.Retries, 5)
	defDur(&opt.ScratchIdle, time.Hour)
	defDur(&opt.RecordIdle, 24*time.Hour)
	defDur(&opt.VerifyEvery, 5*time.Minute)
	defDur(&opt.CatalogTTL, 5*time.Second)
	defDur(&opt.MaxRetryWait, 2*time.Second)
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
		accounts: map[string]*account{}, public: map[string]publicity{},
		sem: make(chan struct{}, opt.FetchConcurrency), inflight: semaphore.NewWeighted(int64(opt.InflightBytes))}
	s.start = opt.Now()
	s.docs.MaxEntries, s.docs.MaxBytes = 1<<20, opt.CacheBytes
	s.records.MaxEntries, s.records.MaxBytes = 1<<17, opt.RecordBytes
	s.seen.MaxEntries = 1 << 17
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
	if opt.Gateway {
		s.anon = opt.Client.With(client.WithBearer(""))
		s.checker = grantcheck.New(s.anon, grantcheck.WithClock(opt.Now))
	} else {
		s.local = s.newPrincipal("local", opt.Client, &account{root: "local"})
		s.local.verified = s.start
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
	p, de := s.authenticate(r)
	if de != nil {
		for k, v := range de.header {
			w.Header()[k] = v
		}
		if de.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", s.realm())
		}
		http.Error(w, de.msg, de.status)
		return
	}
	defer s.release(p)
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
			// A proxy that sets X-Forwarded-Host and passes its own Host
			// on: the client's Destination names the proxy's host, which
			// x/net/webdav refuses (502) as another server's.
			if u.Host != "" && u.Host != r.Host && u.Host == r.Header.Get("X-Forwarded-Host") {
				r.Header.Set("Destination", u.EscapedPath())
			}
		}
	case "PUT":
		// x/net/webdav ignores the preconditions of a PUT: If-None-Match:
		// * creates only, and the revision If-Match (or an If header's
		// entity tag) names is the base of the edit (§11 submit).
		st.noneMatch = r.Header.Get("If-None-Match") == "*"
		switch im := strings.TrimSpace(r.Header.Get("If-Match")); {
		case im == "*":
			st.matchAny = true
		case im != "":
			st.ifMatch = revOfETag(strings.TrimSpace(strings.Split(im, ",")[0]))
		default:
			st.ifMatch = ifHeaderETag(r.Header.Get("If"))
		}
	}
	if r.Body != nil {
		var body io.ReadCloser = r.Body
		if r.Method != "PUT" {
			body = http.MaxBytesReader(w, r.Body, maxXMLBody)
		}
		r.Body = &bodyReader{ReadCloser: body, st: st}
	}
	h := &webdav.Handler{FileSystem: s.fs, LockSystem: p.locks, Logger: func(r *http.Request, err error) {
		if err != nil && !errors.Is(err, errNotExist) {
			s.opt.Logf("dav: %s %s: %v", r.Method, r.URL.Path, err)
		}
	}}
	h.ServeHTTP(&errWriter{ResponseWriter: w, st: st, realm: s.realm()}, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
}

// bodyReader keeps the first error reading a request body: a PUT whose body
// was cut short isn't committed (x/net/webdav closes the file all the
// same).
type bodyReader struct {
	io.ReadCloser
	st *reqState
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF && b.st.bodyErr == nil {
		b.st.bodyErr = err
	}
	return n, err
}

// revOfETag is the revision an entity tag names: this server's tags are
// revision ids (§3.3), quoted.
func revOfETag(tag string) string {
	tag = strings.TrimPrefix(tag, "W/")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return ""
	}
	return tag[1 : len(tag)-1]
}

// ifHeaderETag is the first entity tag an If header (RFC 4918 §10.4)
// requires, as macOS and Windows send one beside their lock token.
func ifHeaderETag(h string) string {
	for i := 0; i < len(h); i++ {
		switch h[i] {
		case '<':
			if j := strings.IndexByte(h[i:], '>'); j > 0 {
				i += j
			}
		case '[':
			j := strings.IndexByte(h[i:], ']')
			if j < 0 {
				return ""
			}
			if !strings.HasSuffix(strings.TrimSpace(h[:i]), "Not") {
				if rev := revOfETag(h[i+1 : i+j]); rev != "" {
					return rev
				}
			}
			i += j
		}
	}
	return ""
}

// authenticate returns the request's principal, or the answer refusing
// it. Local mode compares the Basic password in constant time. Gateway
// mode takes it as the grant; nothing is kept for a grant before the core
// has accepted it (verify), again every VerifyEvery.
func (s *Server) authenticate(r *http.Request) (*principal, *davError) {
	_, pw, ok := r.BasicAuth()
	if !ok {
		return nil, fail(http.StatusUnauthorized, "authentication required")
	}
	if !s.opt.Gateway {
		a, b := sha256.Sum256([]byte(pw)), sha256.Sum256([]byte(s.opt.Password))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			return nil, fail(http.StatusUnauthorized, "wrong password")
		}
		s.sweep()
		return s.local, nil
	}
	g, err := grant.Decode(pw, 64<<10)
	if err != nil {
		return nil, fail(http.StatusUnauthorized, "the password must be a grant (Addendum C)")
	}
	now := s.opt.Now()
	for _, b := range g.Blocks {
		if b.Exp != nil && !now.Before(*b.Exp) {
			return nil, fail(http.StatusUnauthorized, "the grant has expired")
		}
	}
	sum := sha256.Sum256([]byte(pw))
	id := hex.EncodeToString(sum[:16])
	s.mu.Lock()
	if p := s.principals[id]; p != nil && now.Sub(p.verified) < s.opt.VerifyEvery {
		p.used = now
		p.inflight++
		s.mu.Unlock()
		s.sweep()
		return p, nil
	}
	s.mu.Unlock()

	c := s.opt.Client.With(client.WithBearer(pw))
	_, err, _ = s.verifying.Do(id, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		return nil, s.verify(ctx, c, g, pw)
	})
	p, de := s.admit(id, rootOf(g), c, err)
	if de != nil {
		return nil, de
	}
	s.sweep()
	return p, nil
}

// admit returns the principal of a grant (id, its root, its client) the
// core accepted, or refused with err: then what was kept for it goes
// (revoked, or its key withdrawn).
func (s *Server) admit(id, root string, c *client.Client, err error) (*principal, *davError) {
	now := s.opt.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.principals[id]
	if err != nil {
		var de *davError
		if !errors.As(err, &de) {
			de = fail(http.StatusBadGateway, "the grant couldn't be checked")
		}
		if de.status == http.StatusUnauthorized && p != nil && p.inflight == 0 {
			s.dropLocked(p)
		}
		return nil, de
	}
	if p == nil {
		if !s.makeRoomLocked(root) {
			return nil, &davError{status: http.StatusServiceUnavailable, msg: "too many users at once; try again",
				header: http.Header{"Retry-After": {"5"}}}
		}
		a := s.accounts[root]
		if a == nil {
			a = &account{root: root}
			s.accounts[root] = a
		}
		a.principals++
		p = s.newPrincipal(id, c, a)
		s.principals[id] = p
	}
	p.verified, p.used = now, now
	p.inflight++
	return p, nil
}

// rootOf is a grant's root: who its authority block was signed for, by
// which key. Tokens attenuated from one grant (Addendum C) share it.
func rootOf(g *grant.Grant) string {
	b := g.Blocks[0]
	return b.Kid + "\x00" + b.Sub
}

// release ends a request of p.
func (s *Server) release(p *principal) {
	if p == s.local {
		return
	}
	s.mu.Lock()
	p.inflight--
	s.mu.Unlock()
}

// publicity is whether a namespace is publicly readable, as last asked.
type publicity struct {
	public bool
	at     time.Time
}

// verify asks whether the core accepts grant g (token, sent by c) before a
// gateway keeps anything for it: a read of a served namespace the grant
// names. A namespace that isn't public answers 401 to a grant none of its
// keys verifies (§C.2); a public one ignores a bad grant on reads, so
// there the grant is verified as consumers verify them (grantcheck, with
// the keys of the namespace document, §C.6). One namespace accepting it is
// enough: another may not exist yet.
func (s *Server) verify(ctx context.Context, c *client.Client, g *grant.Grant, token string) error {
	var named []string
	for _, ns := range s.namespaces() {
		if g.NamesNS(ns) {
			named = append(named, ns)
		}
	}
	if len(named) == 0 {
		return fail(http.StatusUnauthorized, "the grant names none of the namespaces served here (%s)", strings.Join(s.namespaces(), ", "))
	}
	why := "no key of a namespace it names verifies it"
	for _, ns := range named {
		pub, err := s.isPublic(ctx, ns)
		if err != nil {
			return upstream(err)
		}
		if pub {
			_, err := s.checker.Verify(ctx, ns, token)
			var ae *grant.AuthError
			switch {
			case err == nil, errors.As(err, &ae) && ae.Status == http.StatusForbidden:
				// Verified; what the grant allows is the core's to decide.
				return nil
			case ae != nil:
				why = ae.Msg
				continue
			}
			return upstream(err)
		}
		_, err = c.NSHead(ctx, ns)
		ae, isAPI := client.AsAPIError(err)
		switch {
		case err == nil, client.IsNotFound(err):
			// 404: verified, without read here (§7 hides the rest).
			return nil
		case isAPI && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden):
			why = apiText(ae)
			continue
		}
		return upstream(err)
	}
	return fail(http.StatusUnauthorized, "the core doesn't accept the grant: %s", why)
}

// isPublic reports whether ns is read without a grant, asked of the core
// at most once a minute.
func (s *Server) isPublic(ctx context.Context, ns string) (bool, error) {
	now := s.opt.Now()
	s.mu.Lock()
	pi, ok := s.public[ns]
	s.mu.Unlock()
	if ok && now.Sub(pi.at) < time.Minute {
		return pi.public, nil
	}
	_, err := s.anon.NSHead(ctx, ns)
	switch {
	case err == nil:
		pi = publicity{public: true, at: now}
	case client.IsAuth(err), client.IsNotFound(err):
		pi = publicity{at: now}
	default:
		return false, err
	}
	s.mu.Lock()
	s.public[ns] = pi
	s.mu.Unlock()
	return pi.public, nil
}

// makeRoomLocked drops principals to make room for one more of root: the
// least recently seen of root's own beyond MaxPrincipalsPerRoot, then the
// least recently seen of all beyond MaxPrincipals; never one with a
// request in flight. False: there is no room.
func (s *Server) makeRoomLocked(root string) bool {
	if a := s.accounts[root]; a != nil && a.principals >= s.opt.MaxPrincipalsPerRoot {
		if !s.dropOldestLocked(func(p *principal) bool { return p.acct == a }) {
			return false
		}
	}
	for len(s.principals) >= s.opt.MaxPrincipals {
		if !s.dropOldestLocked(func(*principal) bool { return true }) {
			return false
		}
	}
	return true
}

func (s *Server) dropOldestLocked(which func(*principal) bool) bool {
	var old *principal
	for _, p := range s.principals {
		if p.inflight == 0 && which(p) && (old == nil || p.used.Before(old.used)) {
			old = p
		}
	}
	if old == nil {
		return false
	}
	s.dropLocked(old)
	return true
}

// dropLocked forgets principal p: its locks and scratch files (its
// records of what it was served stay, by principal, until they age out).
func (s *Server) dropLocked(p *principal) {
	delete(s.principals, p.id)
	s.scratchTotal.Add(-int64(p.dropScratch()))
	if p.acct.principals--; p.acct.principals <= 0 {
		delete(s.accounts, p.acct.root)
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
	for _, p := range s.principals {
		if p.inflight == 0 && now.Sub(p.used) > s.opt.ScratchIdle {
			s.dropLocked(p)
			continue
		}
		ps = append(ps, p)
	}
	s.mu.Unlock()
	for _, p := range ps {
		s.scratchTotal.Add(-int64(p.expireScratch(now.Add(-s.opt.ScratchIdle))))
	}
}

// account is what the principals of one grant root share: their number
// and the bounds on their scratch files. A root is signed by a key of a
// namespace's (Addendum C), so only its issuers make new ones; attenuating
// a grant offline makes a new token, a new principal, of the same root.
type account struct {
	root       string
	principals int // under Server.mu

	mu           sync.Mutex
	files, bytes int // scratch
}

// principal is what the server keeps for one upstream grant: its client,
// locks and scratch files. Nothing of it is shared with another
// principal; its records (records.go) are kept by its id.
type principal struct {
	id    string
	c     *client.Client
	locks webdav.LockSystem
	acct  *account

	// under Server.mu
	used, verified time.Time
	inflight       int

	mu      sync.Mutex
	scratch map[string]*scratchFile // by path
	sbytes  int
	dropped bool
	ns      map[string]nsInfo
	cats    map[string]*catGraph
}

func (s *Server) newPrincipal(id string, c *client.Client, a *account) *principal {
	return &principal{id: id, c: c, locks: webdav.NewMemLS(), acct: a, scratch: map[string]*scratchFile{},
		ns: map[string]nsInfo{}, cats: map[string]*catGraph{}, used: s.opt.Now()}
}

// reqState is one request's view, in its context: the principal, what
// the request is (MOVE and COPY destinations change what RemoveAll does,
// a PUT's preconditions what it writes), what it read already, and the
// error to answer with.
type reqState struct {
	s      *Server
	p      *principal
	method string
	path   string
	dst    string
	depth  string
	err    *davError

	ifMatch   string // the revision a PUT's If-Match or If header names
	matchAny  bool   // If-Match: *
	noneMatch bool   // If-None-Match: *
	bodyErr   error  // reading the request body failed
	noETag    bool   // the PUT's document isn't stored as sent: no validator (RFC 9110 §9.3.4)
	serve     *stagedServe

	lists  map[string]*listing     // by directory path
	graphs map[string]*catGraph    // by catalog
	heads  map[string]*client.Head // by ns/name
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
		de = &davError{status: http.StatusBadGateway, msg: "the core refused this server's grant (-bearer): " + de.msg, cause: de.cause}
	}
	st.err = de
	return de
}

// changed forgets what the request read, after it wrote, and makes other
// requests' catalog reads stale.
func (st *reqState) changed() {
	st.lists, st.graphs, st.heads = nil, nil, nil
	st.s.gen.Add(1)
}

// slashClean is path.Clean of name rooted at /.
func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}
