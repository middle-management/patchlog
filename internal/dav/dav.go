// Package dav serves namespaces of a Patch Log deployment over WebDAV
// (RFC 4918), for file managers and editors: a prototype. It is an API
// consumer like the other services: it talks to the core only through its
// public HTTP API (internal/client) and keeps nothing but caches.
//
// It follows Addendum H (files). Layout: / lists a directory per exposed
// namespace, but sealed and end-to-end ones, which need keys it doesn't
// hold (§H.7). A flat namespace's directory is the flat view (§H.2): a raw
// document (its root a blob reference, §7.8) as its resource name, any
// other as {name}.json; a catalog (Addendum B) with catalog.files is a
// file tree (§H.2), its folder nodes as directories and its placements as
// files holding their items, each named by its node's title.
//
// A raw file reads as its blob's bytes, typed by its name (§H.1); a JSON
// file as its rendering, the document's canonical JSON (§3.1) laid out,
// so it is the same bytes for the same revision, whose id is its ETag. A
// save is rebased (§11.3, §H.4): the edit from the version the saver had
// (the revision its If-Match names, else the closest of those it was
// served or wrote) to what it wrote, applied to the head with If-Match.
// Edits others made since to other paths are kept, overlapping ones are a
// 409; a raw file has no paths, so any change of its bytes since is one.
// Editors' and systems' own files (swap and backup files, .DS_Store, ._*,
// §H.6) live in memory, per principal, so editors' save dances work.
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
	// Namespaces are the flat namespaces served, each a directory of its
	// files (§H.2 "Flat view").
	Namespaces []string
	// Catalogs are the catalog namespaces served as file trees (§H.2),
	// each with catalog.files in its namespace document.
	Catalogs []string
	// CaseSensitive compares the names of a tree's siblings after NFC
	// only; by default they are compared after Unicode case folding too
	// (§H.2 "Siblings"), as the file systems of macOS and Windows, whose
	// clients can't hold two names that differ only in case, compare them.
	CaseSensitive bool
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
	// (default 64 MiB); the files' sizes and types are kept apart
	// (maxMetas).
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

// maxMetas bounds the files' metadata kept by revision id (fileMeta, a
// few dozen bytes each), so a listing reads each revision's document once
// though the documents don't fit CacheBytes.
const maxMetas = 1 << 18

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
	metas    lru.Cache[string, fileMeta]  // by ns/name@rev
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
	s.metas.MaxEntries = maxMetas
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
	// Whatever an answer holds (a file, a listing, an error repeating a
	// name the client sent), no page of this origin, which holds the
	// users' credentials, runs it, nor does a browser take it for another
	// type (§H.6 "Raw bytes").
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
	if r.Method == http.MethodPost {
		// x/net/webdav answers a POST as a GET, without the headers a
		// served file gets (open): a cross-site form would run a writer's
		// .html in this origin. No WebDAV client posts.
		w.Header().Set("Allow", allowed)
		http.Error(w, "POST isn't a WebDAV method here; files are read with GET and written with PUT", http.StatusMethodNotAllowed)
		return
	}
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
	st := &reqState{s: s, p: p, method: r.Method, path: slashClean(r.URL.Path), depth: r.Header.Get("Depth"), hdr: r.Header, resp: w.Header()}
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
		if r.Method == "PUT" && r.Header.Get("Content-Range") != "" {
			// x/net/webdav would write the range as the whole file.
			http.Error(w, "a PUT with Content-Range (a partial write) isn't taken: send the whole file (§H.4); nothing was written", http.StatusBadRequest)
			return
		}
		st.ctype = r.Header.Get("Content-Type")
		// x/net/webdav ignores the preconditions of a PUT and a DELETE:
		// If-None-Match: * creates only, and the revision If-Match (its
		// first value), or failing that the If header (ifHeaderETag),
		// names is the base of the edit (§H.4), or the revision a DELETE
		// deletes. An If list of entity tags only it would take for lock
		// tokens, and fail (412): those lists are this server's to check.
		ifTag := ifHeaderETag(r.Header.Get("If"), st.path)
		if h := r.Header.Get("If"); h != "" {
			if rest := splitIf(h); rest == "" {
				r.Header.Del("If")
			} else {
				r.Header.Set("If", rest)
			}
		}
		if r.Method == "PUT" {
			// The write that follows a document's move aside (vim's backup)
			// is the edit of it, even create-only (davfs2 then believes the
			// name free).
			aside := p.takeAside(st.path, s.opt.Now())
			st.noneMatch = r.Header.Get("If-None-Match") == "*" && !aside
		}
		switch im := strings.TrimSpace(r.Header.Get("If-Match")); {
		case im == "*":
			st.matchAny = true
		case im != "":
			st.ifMatch = revOfETag(strings.TrimSpace(strings.Split(im, ",")[0]))
		default:
			st.ifMatch = ifTag
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

// allowed are the methods served (RFC 9110 §10.2.1 Allow).
const allowed = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"

// answered keeps what the request's answer, status, says of the
// principal's saves for a DELETE that follows (refusedSaveFor): a PUT of
// a file, or a MOVE onto an existing one (onto), refused without writing
// to the core sets a guard, but for one that put back the principal's own
// DELETE (undoOwnDelete), which a DELETE after it leaves deleted as the
// principal chose, and one a frozen namespace refused, which takes no
// DELETE either (§8.4); a DELETE that found nothing (a refused create's
// cleanup) uses one up. A GET finding a file gone (404) is the reload a
// refused save over someone else's delete asked for (tombBase). It runs
// before the answer goes out, so the client's next request finds it.
func (st *reqState) answered(status int) {
	now := st.s.opt.Now()
	guardOn := ""
	switch {
	case st.method == "PUT":
		guardOn = st.saveTo
	case st.method == "MOVE":
		guardOn = st.onto
	}
	switch {
	case guardOn != "" && status >= 400:
		if !st.committed && !st.undeleted && (st.err == nil || !st.err.frozen) {
			st.p.noteRefusedSave(guardOn, status, now)
		}
	case st.method == "DELETE" && status == http.StatusNotFound:
		st.p.takeRefusedSave(st.path, now)
	case st.method == "GET" && status == http.StatusNotFound:
		for _, g := range st.gone {
			st.s.reloaded(st.p, g.ns, g.name)
		}
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

// ifHeaderETag is the revision an If header (RFC 4918 §10.4) names as a
// save's base (§H.4), as macOS and Windows send one beside their lock
// token: the first entity tag, not negated with Not, of the first list
// that applies to this resource, reqPath, and holds one. An untagged list
// applies to the request's resource; a tagged one to the resource its tag
// names, and the lists after a tag are its own until the next.
func ifHeaderETag(h, reqPath string) string {
	applies := true
	for i := 0; i < len(h); i++ {
		switch h[i] {
		case '<':
			j := strings.IndexByte(h[i:], '>')
			if j < 0 {
				return ""
			}
			u, err := url.Parse(h[i+1 : i+j])
			applies = err == nil && slashClean(u.Path) == reqPath
			i += j
		case '(':
			j := strings.IndexByte(h[i:], ')')
			if j < 0 {
				return ""
			}
			list := h[i+1 : i+j]
			i += j
			if !applies {
				continue
			}
			if rev := listETag(list); rev != "" {
				return rev
			}
		}
	}
	return ""
}

// listETag is the revision of the first entity tag not negated with Not
// among the conditions of one If list.
func listETag(list string) string {
	for i := 0; i < len(list); i++ {
		switch list[i] {
		case '<':
			j := strings.IndexByte(list[i:], '>')
			if j < 0 {
				return ""
			}
			i += j
		case '[':
			j := strings.IndexByte(list[i:], ']')
			if j < 0 {
				return ""
			}
			if !strings.HasSuffix(strings.TrimSpace(list[:i]), "Not") {
				if rev := revOfETag(list[i+1 : i+j]); rev != "" {
					return rev
				}
			}
			i += j
		}
	}
	return ""
}

// splitIf takes out of an If header (RFC 4918 §10.4) its lists of entity
// tags (with the always true Not <DAV:no-lock>), tagged or not: they hold
// no lock token, which is all x/net/webdav checks (a list without one
// always fails there, 412), and they are this server's to read
// (ifHeaderETag). It returns the rest; one that doesn't parse is left
// whole, for x/net/webdav to refuse.
func splitIf(h string) string {
	var out []string
	tag, said := "", "" // the lists' resource tag, and the last one kept
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
		if h[i] == '<' {
			t, ok := upto('>')
			if !ok {
				return h
			}
			tag = t
			skip()
		}
		if i >= len(h) || h[i] != '(' {
			return h
		}
		start := i
		i++
		tags, other := 0, false
		for skip(); i < len(h) && h[i] != ')'; skip() {
			not := false
			if strings.HasPrefix(h[i:], "Not") {
				not = true
				i += 3
				skip()
			}
			if i >= len(h) {
				return h
			}
			switch h[i] {
			case '<':
				tok, ok := upto('>')
				if !ok {
					return h
				}
				if !not || tok != "<DAV:no-lock>" {
					other = true
				}
			case '[':
				if _, ok := upto(']'); !ok {
					return h
				}
				tags++
			default:
				return h
			}
		}
		if i >= len(h) {
			return h
		}
		i++
		if other || tags == 0 {
			// A list after a tag is that tag's (RFC 4918 §10.4.2): kept
			// so, if the list that carried the tag is taken out.
			if tag != said {
				out, said = append(out, tag), tag
			}
			out = append(out, h[start:i])
		}
	}
	return strings.Join(out, " ")
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
	locked  map[string]time.Time  // its locks' tokens, and when they expire
	deletes map[string]ownDelete  // by ns/name: its latest DELETEs
	trees   map[string]treeDelete // by path: the files of trees its latest DELETEs removed
	aside   map[string]time.Time  // documents' paths moved aside to a backup, and when
	guards  map[string][]guard    // by document path: its refused saves' guards, oldest first
	nguards int
	own     lru.Cache[string, bool] // by ns/name@id: the tombstones and restores it wrote
}

// maxOwn bounds the tombstones and restores a principal remembers having
// written (ownEntry).
const maxOwn = 1 << 12

// markOwn remembers that the principal wrote entry id of ns/name, a
// tombstone or a restore: one between a save's base and the head is no
// delete or restore by someone else (§11.3, §H.4).
func (p *principal) markOwn(ns, name, id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.own.Put(ns+"/"+name+"@"+id, true, 1)
}

// ownEntry reports whether the principal wrote entry id of ns/name, as
// far as it remembers (markOwn): one it forgot counts as someone else's,
// which a save from before refuses (a reload settles it).
func (p *principal) ownEntry(ns, name, id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.own.Get(ns + "/" + name + "@" + id)
	return ok
}

// asideFor is how soon after the principal moved a document aside to a
// scratch name its create-only PUT of the document is taken as an edit
// (§H.5 "Move to a scratch name", "within a few seconds"): vim on davfs2
// moves the original aside when it saves, and davfs2 uploads the new
// version when its upload delay (10 seconds by default) is over.
const asideFor = 30 * time.Second

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
// name aside within asideFor.
func (p *principal) takeAside(name string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	at, ok := p.aside[name]
	delete(p.aside, name)
	return ok && now.Sub(at) <= asideFor
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

// treeDelete is a file of a tree a principal's DELETE removed (§H.5): its
// placement node in catalog cat, in folder parent, and its tombstone; its
// item, and the item's tombstone if the DELETE deleted it too.
type treeDelete struct {
	cat, node, nodeTomb, parent string
	itemNS, itemName, itemTomb  string
	at                          time.Time
}

// noteTreeDelete remembers that the principal's DELETE of path removed
// file d.
func (p *principal) noteTreeDelete(path string, d treeDelete, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.trees) >= maxDeletes {
		var old string
		for k, t := range p.trees {
			if old == "" || t.at.Before(p.trees[old].at) {
				old = k
			}
		}
		delete(p.trees, old)
	}
	d.at = now
	p.trees[path] = d
}

// treeDeleted returns the file of a tree the principal's DELETE of path
// removed within ownDeleteUndo of now.
func (p *principal) treeDeleted(path string, now time.Time) (treeDelete, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.trees[path]
	return d, ok && now.Sub(d.at) <= ownDeleteUndo
}

func (p *principal) forgetTreeDelete(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.trees, path)
}

// A refused save of a file (a PUT, or a MOVE onto an existing file,
// answered 4xx or 5xx without writing to the core) sets a guard (§H.6):
// the principal's DELETE of the same path within refusedSaveFor is a 409,
// once per refusal, and two refusals never share one. rclone deletes a
// file whose upload failed, a second after the failure
// (removeFailedCopy), whatever refused it, and that DELETE would
// tombstone the document for every reader, or delete a tree's file,
// because a save was refused. A guard ends only by time: a read of the
// file doesn't lift it (another program's GET is no reload), nor does
// another program's write, or a DELETE that passed. A DELETE naming the
// revision it deletes (If-Match, or an If header's entity tag) is
// deliberate and passes, the guards left as they are, as does one in a
// frozen namespace, which the core refuses anyway (§8.4); one that finds
// nothing (a refused create's cleanup) uses one up. A refused plain MOVE
// (to a new name) or COPY sets none, nor does a write whose refusal undid
// the principal's own DELETE (undoOwnDelete), whose cleanup DELETE then
// leaves the file deleted as the principal chose, nor a refusal of a
// frozen namespace's.
const refusedSaveFor = 10 * time.Second

// maxGuards bounds a principal's guards over all paths, sized for many
// uploads refused at once (80 parallel uploads once exhausted a small
// table and tombstoned 16 files, §H.6); over it, the oldest goes.
const maxGuards = 4096

// maxRefusedPath bounds the path of a refused save kept for a PUT whose
// path couldn't be resolved (a tree that couldn't be read).
const maxRefusedPath = 1024

// guard is a refused save's guard: when, and its status.
type guard struct {
	at     time.Time
	status int
}

// noteRefusedSave sets a guard on the file at path: a save of it was
// refused (status) at now.
func (p *principal) noteRefusedSave(path string, status int, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireGuardsLocked(now)
	for p.nguards >= maxGuards {
		old := ""
		for k, gs := range p.guards {
			if old == "" || gs[0].at.Before(p.guards[old][0].at) {
				old = k
			}
		}
		p.dropGuardLocked(old)
	}
	p.guards[path] = append(p.guards[path], guard{at: now, status: status})
	p.nguards++
}

// expireGuardsLocked drops the guards older than refusedSaveFor.
func (p *principal) expireGuardsLocked(now time.Time) {
	for k, gs := range p.guards {
		for len(gs) > 0 && now.Sub(gs[0].at) > refusedSaveFor {
			gs = gs[1:]
			p.nguards--
		}
		if len(gs) == 0 {
			delete(p.guards, k)
		} else {
			p.guards[k] = gs
		}
	}
}

// dropGuardLocked drops path's oldest guard.
func (p *principal) dropGuardLocked(path string) {
	gs := p.guards[path]
	if len(gs) <= 1 {
		delete(p.guards, path)
	} else {
		p.guards[path] = gs[1:]
	}
	if len(gs) > 0 {
		p.nguards--
	}
}

// takeRefusedSave uses up the oldest guard on the file at path within
// refusedSaveFor of now, saying how many more are left.
func (p *principal) takeRefusedSave(path string, now time.Time) (g guard, left int, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireGuardsLocked(now)
	gs := p.guards[path]
	if len(gs) == 0 {
		return guard{}, 0, false
	}
	p.dropGuardLocked(path)
	return gs[0], len(gs) - 1, true
}

// guarded reports whether the file at path has a guard within
// refusedSaveFor of now.
func (p *principal) guarded(path string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireGuardsLocked(now)
	return len(p.guards[path]) > 0
}

func (s *Server) newPrincipal(id string, c *client.Client, a *account) *principal {
	p := &principal{id: id, c: c, locks: webdav.NewMemLS(), acct: a, scratch: map[string]*scratchFile{},
		ns: map[string]nsInfo{}, cats: map[string]*catGraph{}, locked: map[string]time.Time{}, deletes: map[string]ownDelete{},
		trees: map[string]treeDelete{}, aside: map[string]time.Time{}, guards: map[string][]guard{}, used: s.opt.Now()}
	p.own.MaxEntries = maxOwn
	return p
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
	resp      http.Header // the answer's
	ifMatch   string      // the revision a PUT's or DELETE's If-Match or If header names
	matchAny  bool        // If-Match: *
	noneMatch bool        // If-None-Match: *
	// placeholder: the PUT's preconditions found an empty placeholder
	// (scratch) at its document path, which exists for If-Match: *.
	placeholder bool
	bodyErr     error    // reading the request body failed
	ctype       string   // the type a written raw file was uploaded as (fileType): a PUT's Content-Type, a copy's source's
	copySrc     *blobSrc // the blob of the raw file a COPY or MOVE copies, whose id the copy keeps
	wroteTo     string   // the ns/name commitRev wrote last
	noETag      bool     // the PUT's document isn't stored as sent: no validator (RFC 9110 §9.3.4)
	serve       *stagedServe
	// saveTo is the document path a PUT writes, once resolved (or one in
	// a tree that couldn't be read), and saveDoc whether it is a flat
	// namespace's document; committed: the request wrote to the core (a
	// revision, a catalog node), not counting a restore of the
	// principal's own DELETE as it was (undoOwnDelete), which undeleted
	// says it did.
	saveTo    string
	saveDoc   bool
	committed bool
	undeleted bool
	// onto is the existing file a MOVE saves into (§H.5), whose refusal
	// sets a guard (§H.6); gone, a document a GET found the core has
	// gone (tombBase).
	onto string
	gone []stagedServe

	lists  map[string]*listing     // by directory path
	graphs map[string]*catGraph    // by catalog
	dirs   map[string]*treeDir     // by catalog/folder node
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
	st.lists, st.graphs, st.dirs, st.heads = nil, nil, nil, nil
	st.s.gen.Add(1)
}

// slashClean is path.Clean of name rooted at /.
func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}
