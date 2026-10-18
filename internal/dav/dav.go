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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
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
	// MaxFileSize); over it, the grant root keeping the most gives way
	// first. RecordIdle drops a document's versions untouched that long
	// (default a day). They outlive the principal's scratch files.
	RecordBytes int
	RecordIdle  time.Duration
	// MaxPrincipals bounds the principals a gateway keeps state for, the
	// least recently seen without a request in flight dropped first
	// (default 256); MaxPrincipalsPerRoot those of one grant root (the
	// namespace that verified it, its authority block's kid and sub), so
	// tokens attenuated from one grant offline can't push out others'
	// (default 8).
	MaxPrincipals, MaxPrincipalsPerRoot int
	// MaxLocks bounds one principal's locks (default 256), and four times
	// that one grant root's.
	MaxLocks int
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
// and LOCK carry XML, of a few hundred bytes from the clients): x/net/webdav
// decodes it whole, a value per element, and answers each property back,
// so a PROPPATCH of a mebibyte of empty properties took gigabytes. One over
// heavyBody is handled maxHeavy at a time over the server, once read.
const (
	maxXMLBody = 64 << 10
	heavyBody  = 4 << 10
	maxHeavy   = 4
)

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
	verifySem chan struct{} // verifications in flight
	refusedMu sync.Mutex
	refused   lru.Cache[string, time.Time] // grants the core refused lately, by hash

	mu           sync.Mutex
	principals   map[string]*principal // gateway mode, by grant hash
	accounts     map[string]*account   // by grant root
	public       map[string]publicity  // by namespace
	lastSweep    time.Time
	scratchTotal atomic.Int64 // every principal's scratch bytes

	recMu    sync.Mutex
	recRoots map[string]*recStore         // by grant root
	recBytes int                          // what every root's records cost
	recSeq   uint64                       // records made
	seen     lru.Cache[string, time.Time] // by principal and ns/name@rev: first shown

	docMu    sync.Mutex
	docs     lru.Cache[string, *docEntry] // by ns/name@rev
	sem      chan struct{}
	group    singleflight.Group
	inflight *semaphore.Weighted
	heavy    chan struct{} // requests with a body over heavyBody being handled
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
	def(&opt.MaxLocks, 256)
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
		accounts: map[string]*account{}, public: map[string]publicity{}, recRoots: map[string]*recStore{},
		sem: make(chan struct{}, opt.FetchConcurrency), inflight: semaphore.NewWeighted(int64(opt.InflightBytes)),
		heavy: make(chan struct{}, maxHeavy)}
	s.start = opt.Now()
	s.docs.MaxEntries, s.docs.MaxBytes = 1<<20, opt.CacheBytes
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
		s.verifySem = make(chan struct{}, maxVerifying)
		s.refused.MaxEntries = 1 << 12
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
	st := &reqState{s: s, p: p, method: r.Method, path: slashClean(r.URL.Path), depth: r.Header.Get("Depth"), hdr: r.Header}
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
	case "LOCK":
		// A lock lasts at most ScratchIdle (boundedLS), which the answer
		// says: x/net/webdav answers with the Timeout asked for.
		r.Header.Set("Timeout", lockTimeout(r.Header.Get("Timeout"), s.opt.ScratchIdle))
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
	case "PUT", "DELETE":
		// x/net/webdav ignores the preconditions of a PUT and a DELETE:
		// If-None-Match: * creates only, and the revision If-Match (or an
		// If header's entity tag) names is the base of the edit (§11
		// submit), or the revision a DELETE deletes. An If list of entity
		// tags only it would take for lock tokens, and fail (412): those
		// lists are this server's to check.
		if h := r.Header.Get("If"); h != "" {
			rest, tag := splitIf(h)
			if rest == "" {
				r.Header.Del("If")
			} else {
				r.Header.Set("If", rest)
			}
			st.ifMatch = tag
		}
		if r.Method == "PUT" {
			// The write that follows a document's move aside (vim's backup)
			// is the edit of it, even create-only (davfs2 then believes the
			// name free).
			aside := p.takeAside(st.path, s.opt.Now(), s.opt.ScratchIdle)
			st.noneMatch = r.Header.Get("If-None-Match") == "*" && !aside
		}
		switch im := strings.TrimSpace(r.Header.Get("If-Match")); {
		case im == "*":
			st.matchAny = true
		case im != "":
			st.ifMatch = revOfETag(strings.TrimSpace(strings.Split(im, ",")[0]))
		case st.ifMatch == "":
			st.ifMatch = ifHeaderETag(r.Header.Get("If"))
		}
	}
	switch {
	case r.Body != nil && r.Method == "PUT":
		r.Body = &bodyReader{ReadCloser: r.Body, st: st}
	case r.Body != nil:
		// Read whole first, so a slow body holds no slot.
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxXMLBody))
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			http.Error(w, fmt.Sprintf("a request body other than a PUT's is at most %d bytes", maxXMLBody), http.StatusRequestEntityTooLarge)
			return
		case err != nil:
			http.Error(w, "the request body didn't arrive whole", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		if len(b) > heavyBody {
			select {
			case s.heavy <- struct{}{}:
				defer func() { <-s.heavy }()
			case <-r.Context().Done():
				return
			}
		}
	}
	h := &webdav.Handler{FileSystem: s.fs, LockSystem: &boundedLS{LockSystem: p.locks, st: st}, Logger: func(r *http.Request, err error) {
		// Not logged: no such file, and a MKCOL of a directory that
		// exists (405), which rclone sends before every upload.
		if err != nil && !errors.Is(err, errNotExist) && !errors.Is(err, fs.ErrExist) {
			s.opt.Logf("dav: %s %s: %v", r.Method, r.URL.Path, err)
		}
	}}
	h.ServeHTTP(&errWriter{ResponseWriter: w, st: st, realm: s.realm()}, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
}

// answered keeps what the request's answer, status, says of the
// principal's saves for a DELETE that follows (refusedSaveFor). A PUT of
// a document's file refused without writing to the core is noted, but
// for one that put back the principal's own DELETE (undoOwnDelete), which
// a DELETE after it leaves deleted as the principal chose, and one a
// frozen namespace refused, which takes no DELETE either (§8.4). A DELETE
// done, or a GET of the file answered whole once the refusal is
// refusedSaveRead old, forgets them; a DELETE that found nothing (a
// refused create's cleanup) uses one up. It runs before the answer goes
// out, so the client's next request finds it.
func (st *reqState) answered(status int) {
	now := st.s.opt.Now()
	switch {
	case st.method == "PUT" && st.saveTo != "" && status >= 400:
		switch {
		case st.committed, st.undeleted:
		case st.saveDoc && st.err != nil && st.err.frozen:
			st.p.clearRefusedSave(st.saveTo)
		default:
			st.p.noteRefusedSave(st.saveTo, status, now)
		}
	case st.method == "DELETE" && status < 400:
		st.p.clearRefusedSave(st.path)
	case st.method == "DELETE" && status == http.StatusNotFound:
		st.p.takeRefusedSave(st.path, now)
	case st.method == "GET" && status == http.StatusOK:
		st.p.readAfterRefusedSave(st.path, now)
	}
}

// lockTimeout is a LOCK's Timeout header (RFC 4918 §10.7) within max: its
// first value, Infinite or none (infinite) as max.
func lockTimeout(h string, max time.Duration) string {
	limit := "Second-" + strconv.Itoa(int(max/time.Second))
	first := strings.TrimSpace(strings.Split(h, ",")[0])
	if n, ok := strings.CutPrefix(first, "Second-"); ok {
		if secs, err := strconv.ParseUint(n, 10, 32); err == nil && time.Duration(secs)*time.Second <= max {
			return first
		}
	}
	return limit
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

// splitIf takes out of an If header (RFC 4918 §10.4) its untagged lists
// that hold entity tags only (with the always true Not <DAV:no-lock>),
// and returns the rest and the first such entity tag's revision. One that
// doesn't parse is left whole, for x/net/webdav to refuse.
func splitIf(h string) (rest, rev string) {
	var keep []string
	i := 0
	skip := func() {
		for i < len(h) && (h[i] == ' ' || h[i] == '\t') {
			i++
		}
	}
	upto := func(c byte) (string, bool) {
		j := strings.IndexByte(h[i:], c)
		if j < 0 {
			return "", false
		}
		s := h[i : i+j+1]
		i += j + 1
		return s, true
	}
	for skip(); i < len(h); skip() {
		start := i
		tagged := false
		if h[i] == '<' {
			if _, ok := upto('>'); !ok {
				return h, ""
			}
			tagged = true
			skip()
		}
		if i >= len(h) || h[i] != '(' {
			return h, ""
		}
		i++
		tags, other := []string{}, false
		for skip(); i < len(h) && h[i] != ')'; skip() {
			not := false
			if strings.HasPrefix(h[i:], "Not") {
				not = true
				i += 3
				skip()
			}
			if i >= len(h) {
				return h, ""
			}
			switch h[i] {
			case '<':
				tok, ok := upto('>')
				if !ok {
					return h, ""
				}
				if !not || tok != "<DAV:no-lock>" {
					other = true
				}
			case '[':
				tag, ok := upto(']')
				if !ok {
					return h, ""
				}
				if not {
					other = true
				} else {
					tags = append(tags, tag[1:len(tag)-1])
				}
			default:
				return h, ""
			}
		}
		if i >= len(h) {
			return h, ""
		}
		i++
		if tagged || other || len(tags) == 0 {
			keep = append(keep, h[start:i])
			continue
		}
		if rev == "" {
			rev = revOfETag(tags[0])
		}
	}
	return strings.Join(keep, " "), rev
}

// authenticate returns the request's principal, or the answer refusing
// it. Local mode compares the Basic password in constant time. Gateway
// mode takes it as the grant; nothing is kept for a grant before the core
// has accepted it (verify), again every VerifyEvery. A grant refused is
// refused for refusedFor without asking again.
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
	s.refusedMu.Lock()
	at, refused := s.refused.Get(id)
	s.refusedMu.Unlock()
	if refused && now.Sub(at) < refusedFor {
		return nil, fail(http.StatusUnauthorized, "the core doesn't accept the grant")
	}

	c := s.opt.Client.With(client.WithBearer(pw))
	v, err, _ := s.verifying.Do(id, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		select {
		case s.verifySem <- struct{}{}:
		case <-ctx.Done():
			return "", &davError{status: http.StatusServiceUnavailable, msg: "too many logins at once; try again", header: http.Header{"Retry-After": {"5"}}}
		}
		defer func() { <-s.verifySem }()
		return s.verify(ctx, c, g, pw)
	})
	var de *davError
	if errors.As(err, &de) && de.status == http.StatusUnauthorized {
		s.refusedMu.Lock()
		s.refused.Put(id, now, 1)
		s.refusedMu.Unlock()
	}
	ns, _ := v.(string)
	named := map[string]bool{}
	for _, n := range s.namespaces() {
		named[n] = g.NamesNS(n)
	}
	p, de := s.admit(id, rootOf(ns, g), c, named, err)
	if de != nil {
		return nil, de
	}
	s.sweep()
	return p, nil
}

// maxVerifying bounds the grants being verified at once, maxVerifyNS the
// namespaces asked for one grant, and refusedFor how long a refused grant
// is refused without asking the core again.
const (
	maxVerifying = 8
	maxVerifyNS  = 3
	refusedFor   = 30 * time.Second
)

// admit returns the principal of a grant (id, its root, its client, the
// served namespaces it names) the core accepted, or refused with err:
// then what was kept for it goes (revoked, or its key withdrawn).
func (s *Server) admit(id, root string, c *client.Client, named map[string]bool, err error) (*principal, *davError) {
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
		p.named = named
		s.principals[id] = p
	}
	p.verified, p.used = now, now
	p.inflight++
	return p, nil
}

// rootOf is a grant's root: who its authority block was signed for, by
// which key of namespace ns, the one that verified it (a kid names a key
// of one namespace's document, §C.1). Tokens attenuated from one grant
// (Addendum C) share it.
func rootOf(ns string, g *grant.Grant) string {
	b := g.Blocks[0]
	return ns + "\x00" + b.Kid + "\x00" + b.Sub
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
// gateway keeps anything for it, in the served namespaces it names (the
// first maxVerifyNS of them), and returns the one that accepted it. One is
// enough: another may not exist yet.
func (s *Server) verify(ctx context.Context, c *client.Client, g *grant.Grant, token string) (string, error) {
	var named []string
	for _, ns := range s.namespaces() {
		if g.NamesNS(ns) {
			named = append(named, ns)
		}
	}
	if len(named) == 0 {
		var nss []string
		for _, b := range g.Blocks {
			nss = append(nss, b.NS...)
		}
		s.opt.Logf("dav: a grant for %q names none of the namespaces served (%q)", g.Blocks[0].Sub, nss)
		return "", fail(http.StatusUnauthorized, "the grant names none of the namespaces served here")
	}
	if len(named) > maxVerifyNS {
		named = named[:maxVerifyNS]
	}
	why := "no key of a namespace it names verifies it"
	for _, ns := range named {
		ok, reason, err := s.verifyIn(ctx, c, ns, token)
		if err != nil {
			return "", upstream(err)
		}
		if ok {
			return ns, nil
		}
		if reason != "" {
			why = reason
		}
	}
	return "", fail(http.StatusUnauthorized, "the core doesn't accept the grant: %s", why)
}

// verifyIn asks whether namespace ns accepts a grant (token, sent by c),
// or why not. A namespace that isn't public answers its gestures listing
// (§7.4, which needs only read, whatever the grant's rules say of
// resources) to a grant its keys verify, in scope, and allow read; it
// answers 401 to a grant none of its keys verifies, and 404 to the rest,
// as to a namespace it hides (§7), which isn't an acceptance. A public
// one ignores a bad grant on reads, so there the grant is verified as
// consumers verify them (grantcheck, with the keys of the namespace
// document, §C.6), key scope included. Whether ns is public is asked
// again when the answer may be out of date: after a private namespace
// accepted the grant (which a public one would, any grant), and after a
// public one's document couldn't verify it.
func (s *Server) verifyIn(ctx context.Context, c *client.Client, ns, token string) (bool, string, error) {
	pub, err := s.isPublic(ctx, ns, false)
	if err != nil {
		return false, "", err
	}
	fresh := false
	if !pub {
		if ok, why, err := s.askCore(ctx, c, ns); err != nil || !ok {
			return false, why, err
		}
		if pub, err = s.isPublic(ctx, ns, true); err != nil || !pub {
			return err == nil, "", err
		}
		fresh = true
	}
	_, err = s.checker.Verify(ctx, ns, token)
	var ae *grant.AuthError
	switch {
	case err == nil:
		return true, "", nil
	case !errors.As(err, &ae):
		return false, "", err
	case fresh:
		return false, ae.Msg, nil
	}
	if pub, err = s.isPublic(ctx, ns, true); err != nil || pub {
		return false, ae.Msg, err
	}
	return s.askCore(ctx, c, ns)
}

// askCore reads ns's gestures listing with c, for verifyIn.
func (s *Server) askCore(ctx context.Context, c *client.Client, ns string) (bool, string, error) {
	_, _, err := c.GesturesPage(ctx, ns, client.NewGesture(), "")
	ae, isAPI := client.AsAPIError(err)
	switch {
	case err == nil, client.IsNotOffered(err), client.IsPurged(err):
		// Answered after the read check: not offered in a sealed
		// namespace, a purged one gone.
		return true, "", nil
	case isAPI && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden):
		return false, apiText(ae), nil
	case isAPI && ae.Status == http.StatusNotFound:
		return false, fmt.Sprintf("%s doesn't let it read (a key's scope refuses it, or it lacks read there), or doesn't exist", ns), nil
	}
	return false, "", err
}

// isPublic reports whether ns is read without a grant, asked of the core
// at most once a minute, unless fresh.
func (s *Server) isPublic(ctx context.Context, ns string, fresh bool) (bool, error) {
	now := s.opt.Now()
	s.mu.Lock()
	pi, ok := s.public[ns]
	s.mu.Unlock()
	if ok && !fresh && now.Sub(pi.at) < time.Minute {
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
	s.recMu.Lock()
	s.sweepRecordsLocked(now)
	s.recMu.Unlock()
}

// account is what the principals of one grant root share: their number
// and the bounds on their scratch files. A root is signed by a key of a
// namespace's (Addendum C), so only its issuers make new ones; attenuating
// a grant offline makes a new token, a new principal, of the same root.
type account struct {
	root       string
	principals int // under Server.mu

	mu           sync.Mutex
	files, bytes int   // scratch
	locks        int   // its principals' locks
	inflight     int64 // bytes of written files being buffered
}

// hold reserves n bytes of written files being buffered, within max.
func (a *account) hold(n, max int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inflight+n > max {
		return false
	}
	a.inflight += n
	return true
}

func (a *account) release(n int64) {
	a.mu.Lock()
	a.inflight -= n
	a.mu.Unlock()
}

// rootInflight is how many bytes of written files one grant root's
// requests buffer at once: in a gateway, a share of InflightBytes, so
// one user's stalled uploads don't refuse everyone's writes.
func (s *Server) rootInflight() int64 {
	if !s.opt.Gateway {
		return int64(s.opt.InflightBytes)
	}
	return int64(max(s.opt.MaxFileSize, s.opt.InflightBytes/4))
}

// principal is what the server keeps for one upstream grant: its client,
// locks and scratch files. Nothing of it is shared with another
// principal; its records (records.go) are kept by its id.
type principal struct {
	id    string
	c     *client.Client
	locks webdav.LockSystem
	acct  *account
	// named: in a gateway, whether the grant names each served namespace
	// (§C.2); nil in local mode, whose grant the operator chose them for.
	named map[string]bool

	// under Server.mu
	used, verified time.Time
	inflight       int

	mu      sync.Mutex
	scratch map[string]*scratchFile // by path
	sbytes  int
	dropped bool
	ns      map[string]nsInfo
	cats    map[string]*catGraph
	locked  map[string]time.Time   // its locks' tokens, and when they expire
	deletes map[string]ownDelete   // by ns/name: its latest DELETEs
	aside   map[string]time.Time   // documents' paths moved aside to a backup, and when
	refused map[string]refusedSave // by document path: its refused saves lately
}

// setAside remembers that the principal moved the document at name aside
// (a backup's MOVE, which copies it): its client takes the name for free.
func (p *principal) setAside(name string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.aside {
		if len(p.aside) < maxDeletes {
			break
		}
		delete(p.aside, k)
	}
	p.aside[name] = now
}

// takeAside reports, once, whether the principal moved the document at
// name aside within idle.
func (p *principal) takeAside(name string, now time.Time, idle time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	at, ok := p.aside[name]
	delete(p.aside, name)
	return ok && now.Sub(at) <= idle
}

// ownDelete is a tombstone a principal's DELETE wrote.
type ownDelete struct {
	tomb string
	at   time.Time
}

// maxDeletes bounds the DELETEs a principal remembers.
const maxDeletes = 64

// noteDelete remembers that the principal tombstoned ns/name as tomb.
func (p *principal) noteDelete(ns, name, tomb string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.deletes) >= maxDeletes {
		var old string
		for k, d := range p.deletes {
			if old == "" || d.at.Before(p.deletes[old].at) {
				old = k
			}
		}
		delete(p.deletes, old)
	}
	p.deletes[ns+"/"+name] = ownDelete{tomb: tomb, at: now}
}

// ownDeleteUndo is how long after the principal's DELETE of a document a
// refused write of its name restores it as it was (undoOwnDelete): a
// save that deletes the original first writes the new version moments
// later (davfs2 within its upload delay, 10 seconds by default); one
// deleted before that stays deleted.
const ownDeleteUndo = 30 * time.Second

// deletedOwn reports whether tomb, ns/name's head, is the principal's own
// DELETE, within ownDeleteUndo of now; with tomb "", whether it deleted
// ns/name that lately.
func (p *principal) deletedOwn(ns, name, tomb string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.deletes[ns+"/"+name]
	return ok && now.Sub(d.at) <= ownDeleteUndo && (tomb == "" || d.tomb == tomb)
}

func (p *principal) forgetDelete(ns, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.deletes, ns+"/"+name)
}

// A refused save of a document's file (a PUT answered 4xx or 5xx that
// wrote nothing of it) makes the principal's next DELETE of the same path
// within refusedSaveFor a 409, once per refused save (at most
// maxRefusedCount pending), unless the principal read the file since (a
// GET answered 200, at least refusedSaveRead after the refusal): rclone
// deletes a file whose upload failed, a second after the failure
// (removeFailedCopy), and that DELETE would tombstone the document for
// every reader, or unplace the placement, because a save was refused. A
// DELETE naming the revision it deletes (If-Match) is deliberate and
// passes; so does the DELETE sent again. A refused MOVE or COPY onto the
// file sets none: rclone never deletes after one, and its next save
// without a cache (DELETE, then MOVE) would meet the guard instead.
const refusedSaveFor = 10 * time.Second

// refusedSaveRead is how old a refused save must be for a GET of the
// file to lift its guard: another program of the principal's reading the
// file in the second before rclone's DELETE isn't the principal's
// reload.
const refusedSaveRead = 2 * time.Second

// maxRefused bounds the paths a principal's refused saves are kept for,
// and maxRefusedCount the DELETEs one path's refuse: two clients' refused
// saves of it, each followed by its cleanup, without making a deliberate
// DELETE after a client's repeated refused saves (none of which deletes)
// take more than a few tries.
const (
	maxRefused      = 1024
	maxRefusedCount = 2
)

// maxRefusedPath bounds the path of a refused save kept for a PUT whose
// path couldn't be resolved (a catalog that couldn't be read).
const maxRefusedPath = 1024

// refusedSave is a path's refused saves: the latest's time and status,
// and how many DELETEs they still refuse.
type refusedSave struct {
	at     time.Time
	status int
	n      int
}

// noteRefusedSave remembers that a save of the document at path was
// refused (status) at now.
func (p *principal) noteRefusedSave(path string, status int, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, r := range p.refused {
		if now.Sub(r.at) > refusedSaveFor {
			delete(p.refused, k)
		}
	}
	r, ok := p.refused[path]
	if !ok && len(p.refused) >= maxRefused {
		var old string
		for k, r := range p.refused {
			if old == "" || r.at.Before(p.refused[old].at) {
				old = k
			}
		}
		delete(p.refused, old)
	}
	p.refused[path] = refusedSave{at: now, status: status, n: min(r.n+1, maxRefusedCount)}
}

// takeRefusedSave takes one DELETE's refusal from the principal's refused
// saves of the document at path within refusedSaveFor of now, saying how
// many more DELETEs they refuse.
func (p *principal) takeRefusedSave(path string, now time.Time) (r refusedSave, left int, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok = p.refused[path]
	if !ok || now.Sub(r.at) > refusedSaveFor {
		delete(p.refused, path)
		return r, 0, false
	}
	if r.n <= 1 {
		delete(p.refused, path)
		return r, 0, true
	}
	p.refused[path] = refusedSave{at: r.at, status: r.status, n: r.n - 1}
	return r, r.n - 1, true
}

// clearRefusedSave forgets the refused saves of the document at path.
func (p *principal) clearRefusedSave(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.refused, path)
}

// readAfterRefusedSave forgets the refused saves of the document at path
// that the principal read (a GET answered 200) at now, if the latest is
// at least refusedSaveRead old: the principal reloaded it.
func (p *principal) readAfterRefusedSave(path string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.refused[path]; ok && now.Sub(r.at) >= refusedSaveRead {
		delete(p.refused, path)
	}
}

func (s *Server) newPrincipal(id string, c *client.Client, a *account) *principal {
	return &principal{id: id, c: c, locks: webdav.NewMemLS(), acct: a, scratch: map[string]*scratchFile{},
		ns: map[string]nsInfo{}, cats: map[string]*catGraph{}, locked: map[string]time.Time{}, deletes: map[string]ownDelete{}, aside: map[string]time.Time{},
		refused: map[string]refusedSave{}, used: s.opt.Now()}
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

	hdr       http.Header // the request's
	ifMatch   string      // the revision a PUT's or DELETE's If-Match or If header names
	matchAny  bool        // If-Match: *
	noneMatch bool        // If-None-Match: *
	// placeholder: the PUT's preconditions found an empty placeholder
	// (scratch) at its document path, which exists for If-Match: *.
	placeholder bool
	bodyErr     error  // reading the request body failed
	noETag      bool   // the PUT's document isn't stored as sent: no validator (RFC 9110 §9.3.4)
	made        string // the revision commitDoc created or restored a document with
	serve       *stagedServe
	// saveTo is the document path a PUT writes, once resolved (or one in
	// a catalog that couldn't be read, maybe a placement's), and saveDoc
	// whether it is a flat namespace's document; committed: the request
	// wrote to the core (a revision, a catalog node), not counting a
	// restore of the principal's own DELETE as it was (undoOwnDelete),
	// which undeleted says it did.
	saveTo    string
	saveDoc   bool
	committed bool
	undeleted bool

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
