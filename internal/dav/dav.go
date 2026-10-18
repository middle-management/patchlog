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
// §H.6) live in memory, per user, so editors' save dances work.
//
// Two ways to authenticate: with a fixed grant (local mode, the WebDAV
// clients log in with a password of the server's), or as a gateway, where
// each request's Basic password is the grant sent upstream. State (bases,
// scratch files, locks, guards) is kept per user (§H.7): in a gateway,
// the root sub and kid GET /ns/{ns}/principal names for a grant, so every
// token of one person is one user; in local mode, everyone is one. What
// may hold what one token read (scratch files, locks, dead properties) is
// kept apart for a token narrowed offline (scope).
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
	"slices"
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
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
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
	// TreeService is the base URL of the tree service (§B.5) following
	// the catalogs served, such as http://tree:8082, and TreeServices
	// that of a catalog with its own, by catalog. A tree's folder is then
	// listed from the tree service's children listing, read with the
	// request's grant, which the tree service filters by (§H.3, §H.7,
	// §B.11.5), with the file metadata it adds; without one, from the
	// catalog's node documents read from the core, the fallback for
	// deployments without a tree service (treesvc.go).
	TreeService  string
	TreeServices map[string]string
	// TreeWait bounds how long a listing waits for the tree service to
	// reach the user's own writes through this server (?min=, §B.5),
	// before the folder is listed from the node documents (default 3s).
	TreeWait time.Duration
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
	// (maxMetas). It bounds, apart too, the catalogs' graphs and the
	// folders' listings kept by token (views).
	CacheBytes int
	// MaxFileSize bounds a written JSON file and a scratch file, buffered
	// whole (default 16 MiB).
	MaxFileSize int
	// MaxRawSize bounds a written raw file (§H.1), buffered whole (default
	// 64 MiB, the core's default blobSize, §6.6; a namespace's smaller
	// blobSize refuses one before it is uploaded).
	MaxRawSize int
	// InflightBytes bounds the written files buffered at once, over every
	// request (default the larger of 8 times MaxFileSize and twice
	// MaxRawSize; 503 beyond).
	InflightBytes int
	// ScratchFiles and ScratchBytes bound one user's scratch files
	// (default 256 and 32 MiB); ScratchTotal all of them (default 256
	// MiB). ScratchIdle drops a scratch file untouched that long, and a
	// gateway's user idle that long (default an hour).
	ScratchFiles, ScratchBytes, ScratchTotal int
	ScratchIdle                              time.Duration
	// RecordBytes bounds the versions remembered as users' bases (the
	// revisions they were served, the content they wrote), for every user
	// together (default the larger of 128 MiB and 8 times MaxFileSize);
	// over it, the user keeping the most gives way first. RecordIdle drops
	// a document's versions untouched that long (default a day). They
	// outlive the user's scratch files.
	RecordBytes int
	RecordIdle  time.Duration
	// MaxPrincipals bounds the users a gateway keeps state for (§H.7), the
	// least recently seen without a request in flight dropped first
	// (default 256); MaxTokensPerPrincipal the tokens it keeps for one
	// user (re-minted, attenuated offline), the least recently used
	// without a request in flight dropped first, to be verified again
	// when it comes back (default 8), and the narrowings (scopes) whose
	// scratch files and locks it keeps for one user, likewise.
	MaxPrincipals, MaxTokensPerPrincipal int
	// MaxLocks bounds one user's locks (default 256).
	MaxLocks int
	// VerifyEvery is how often a gateway asks the core again whether a
	// token's grant is accepted (default 5 minutes): at least as often as
	// edge grants expire (§H.7, §C.5.2), at most edge.MaxGrantTTL, which
	// bounds how long a revoked grant still reaches its user's scratch
	// files. Writers' settings (§7.4 writer) are kept for no longer.
	VerifyEvery time.Duration
	// CatalogTTL is how long a token's read of a catalog's tree serves its
	// requests, unless this server writes meanwhile (default 5s).
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

	local *token // local mode: the one bearer, the one user

	// gateway mode
	anon      *client.Client // without a grant
	verifying singleflight.Group
	verifySem chan struct{} // verifications in flight
	refusedMu sync.Mutex
	refused   lru.Cache[string, refusal] // grants the core refused lately, by hash

	mu           sync.Mutex
	tokens       map[string]*token           // gateway mode, by grant hash
	principals   map[string]*principal       // gateway mode, by user (userKey)
	kidNS        lru.Cache[string, []string] // gateway mode, by root kid and sub: the served namespaces that accepted a grant of them, first first (verify)
	idUsers      idUsers                     // gateway mode: who each token was verified as last, kept past the token (admit)
	lastSweep    time.Time
	scratchTotal atomic.Int64 // every user's scratch bytes

	opMu     sync.Mutex
	opKeys   []client.OperatorKey // the deployment's operator keys (operatorKeys), read at opAt
	opAt     time.Time
	opRetry  time.Time // after a failed read, not read again before
	opErr    error     // the failed read, while none was read
	opFlight singleflight.Group

	viewMu sync.Mutex
	views  lru.Cache[string, tokenView] // by token id: catalogs' graphs and folders it read (views)

	recMu    sync.Mutex
	recRoots map[string]*recStore         // by user
	recBytes int                          // what every user's records cost
	recSeq   uint64                       // records made
	seen     lru.Cache[string, time.Time] // by user and ns/name@rev: first shown

	docMu    sync.Mutex
	docs     lru.Cache[string, *docEntry] // by ns/name@rev
	metas    lru.Cache[string, fileMeta]  // by ns/name@rev
	sem      chan struct{}
	group    singleflight.Group
	inflight *semaphore.Weighted
	heavy    chan struct{} // requests with a body over heavyBody being handled
	gen      atomic.Uint64 // writes through this server: catalog reads older are stale
	ts       treeShared    // the tree service's client, and the catalogs' settings
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
	def(&opt.MaxRawSize, max(64<<20, opt.MaxFileSize))
	def(&opt.InflightBytes, max(8*opt.MaxFileSize, 2*opt.MaxRawSize))
	def(&opt.ScratchFiles, 256)
	def(&opt.ScratchBytes, 32<<20)
	def(&opt.ScratchTotal, 256<<20)
	def(&opt.RecordBytes, max(128<<20, 8*opt.MaxFileSize))
	def(&opt.MaxPrincipals, 256)
	def(&opt.MaxTokensPerPrincipal, 8)
	def(&opt.MaxLocks, 256)
	def(&opt.Retries, 5)
	defDur(&opt.ScratchIdle, time.Hour)
	defDur(&opt.RecordIdle, 24*time.Hour)
	defDur(&opt.VerifyEvery, 5*time.Minute)
	defDur(&opt.CatalogTTL, 5*time.Second)
	defDur(&opt.MaxRetryWait, 2*time.Second)
	defDur(&opt.TreeWait, 3*time.Second)
	if opt.VerifyEvery > edge.MaxGrantTTL {
		return nil, fmt.Errorf("dav: VerifyEvery %v is longer than edge grants live (%v): a gateway re-checks a grant at least as often as they expire (§H.7, §C.5.2)", opt.VerifyEvery, edge.MaxGrantTTL)
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
	s := &Server{opt: opt, flat: map[string]bool{}, cats: map[string]bool{}, tokens: map[string]*token{},
		principals: map[string]*principal{}, recRoots: map[string]*recStore{},
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
	if err := s.ts.init(&s.opt); err != nil {
		return nil, err
	}
	opt.Client = s.opt.Client
	s.anon = opt.Client.With(client.WithBearer(""))
	s.views.MaxEntries, s.views.MaxBytes = 1<<16, opt.CacheBytes
	if opt.Gateway {
		s.verifySem = make(chan struct{}, maxVerifying)
		s.refused.MaxEntries = 1 << 12
		s.kidNS.MaxEntries, s.kidNS.MaxBytes = 1<<12, 1<<16
		s.idUsers.init(maxIDUsers, maxIDsPerUser)
	} else {
		s.local = s.newToken("local", opt.Client, s.newScopeLocked(s.newPrincipal("local"), ""), nil)
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
// over the user's view.
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
	tk, de := s.authenticate(r)
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
	defer s.release(tk)
	sc := tk.sc
	st := &reqState{s: s, tk: tk, p: tk.p, sc: sc, method: r.Method, path: slashClean(r.URL.Path), depth: r.Header.Get("Depth"), hdr: r.Header, resp: w.Header()}
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
			aside := tk.p.takeAside(st.path, s.opt.Now())
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
			http.Error(w, fmt.Sprintf("too large: a request body other than a PUT's is at most %d bytes (a PROPFIND, PROPPATCH or LOCK body)", maxXMLBody), http.StatusRequestEntityTooLarge)
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
	h := &webdav.Handler{FileSystem: s.fs, LockSystem: &boundedLS{LockSystem: sc.locks, st: st}, Logger: func(r *http.Request, err error) {
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
	case (st.method == "DELETE" || st.method == "MOVE") && status < 300:
		st.sc.unlockUnder(st.path, now)
		to := ""
		if st.method == "MOVE" {
			to = st.dst
		}
		st.sc.moveProps(st.path, to)
	case st.method == "GET" && status == http.StatusNotFound:
		for _, g := range st.gone {
			st.s.reloaded(st.p, g.ns, g.name, st.tk.id)
		}
		st.s.forgetPath(st.p, st.path)
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

// authenticate returns the request's token, or the answer refusing it.
// Local mode compares the Basic password in constant time. Gateway mode
// takes it as the grant: nothing is kept for a grant before the core has
// accepted it (verify), and it is asked again every VerifyEvery. A grant
// refused is refused for refusedFor without asking again.
func (s *Server) authenticate(r *http.Request) (*token, *davError) {
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
	prev := ""
	if tk := s.tokens[id]; tk != nil {
		if !tk.verified.IsZero() && now.Sub(tk.verified) < s.opt.VerifyEvery {
			s.useLocked(tk, now)
			s.mu.Unlock()
			s.sweep()
			return tk, nil
		}
		prev = tk.vns
	} else if u, ok := s.idUsers.get(id); ok {
		// Dropped since (idle, or to make room): verified again in the
		// same order, and seen to have become someone else (admit).
		prev = u.vns
	}
	s.mu.Unlock()
	s.refusedMu.Lock()
	rf, refused := s.refused.Get(id)
	s.refusedMu.Unlock()
	if refused && now.Sub(rf.at) < refusedFor {
		return nil, rf.err
	}

	c := s.opt.Client.With(client.WithBearer(pw))
	v, err, _ := s.verifying.Do(id, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		select {
		case s.verifySem <- struct{}{}:
		case <-ctx.Done():
			return nil, &davError{status: http.StatusServiceUnavailable, msg: "too many logins at once; try again", header: http.Header{"Retry-After": {"5"}}}
		}
		defer func() { <-s.verifySem }()
		return s.verify(ctx, c, g, prev)
	})
	var de *davError
	if errors.As(err, &de) && refusedStatus(de.status) {
		s.refusedMu.Lock()
		s.refused.Put(id, refusal{err: de, at: now}, 1)
		s.refusedMu.Unlock()
	}
	named := map[string]bool{}
	for _, n := range s.namespaces() {
		named[n] = g.NamesNS(n)
	}
	vd, _ := v.(*verdict)
	skey, chain := scopeOf(g)
	tk, de := s.admit(id, c, named, skey, chain, vd, err)
	if de != nil {
		return nil, de
	}
	s.sweep()
	return tk, nil
}

// maxVerifying bounds the grants being verified at once, maxVerifyNS the
// namespaces asked for one grant, and refusedFor how long a refused grant
// is refused without asking the core again.
const (
	maxVerifying = 8
	maxVerifyNS  = 3
	refusedFor   = 30 * time.Second
)

// kidSub is kidNS's key for a root block's kid and sub.
func kidSub(kid, sub string) string { return kid + "\x00" + sub }

// refusal is a grant's refusal (verify), and when.
type refusal struct {
	err *davError
	at  time.Time
}

// refusedStatus reports a refusal of verify that is the grant's answer
// for refusedFor: 401 (no namespace accepts it), 410 and 404 (the one
// that verified it is purged, or absent).
func refusedStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusGone || status == http.StatusNotFound
}

// verdict is the core's acceptance of a grant (verify): the served
// namespace that accepted it, and its answer there (§7.4).
type verdict struct {
	ns   string
	info *client.PrincipalInfo
}

// verify asks whether the core accepts grant g (sent by c), before a
// gateway keeps anything for it: GET /ns/{ns}/principal (§7.4) in the
// served namespaces it names, the first maxVerifyNS of them, until one
// accepts it. Only the ns check and verification apply there (§C.2 item
// 1), the key's scope included, no verb and no rule, so a grant limited
// to some resources, or without read, is accepted too (§H.7 "Limited
// grants"); and a public namespace answers it as any other, though its
// reads ignore a bad grant (§7). One namespace is enough: another may not
// exist yet, or not trust the key. A 401 there is a grant that can't be
// used; a 410, a namespace purged once the grant verified (§8.5); a 404,
// one that doesn't exist, to an operator grant (§C.4). Accepted nowhere,
// the grant is refused with the first of 410 and 404 that it met (§H.4
// "Answers"), else 401.
//
// The namespace that accepts a grant is part of its user (userKey), so
// the order they are asked in keeps a person one user: first prev, the
// one that accepted this token before, then those that accepted a grant
// of its root kid and sub, first first (kidNS), then the rest, sorted. A
// namespace created later, or given the key later, that sorts first then
// doesn't make the same token, or the same person's next one, someone
// else, with none of their records, scratch files or locks. kids are
// per namespace document and free-form (§C.1), so the record is by kid
// and sub, not kid alone, which another namespace's key named alike
// (another person's) would take first; and since a namespace's key may
// mint grants for any sub, it keeps every served namespace that accepted
// one, never dropping the first for a later one: one that accepted a
// grant for the same kid and sub first, but that this grant doesn't name
// or that refuses it, doesn't stand for the person's, and namespaces
// accepting the kid and sub later (a stranger's, whose key is named
// alike, or the person's own single-namespace grants) don't push the
// person's out. Only served namespaces are asked, so a record holds at
// most those (and kidNS's bounds count them). The preferred namespaces
// don't count against maxVerifyNS.
//
// A grant an operator key signed (§C.4) authorizes nothing this server
// does, and is refused (401) where /principal accepts it
// (operatorSigned): its root kid may name a namespace's key too, and
// /principal, which verifies it against the operator keys, names that
// kid, so it would be taken for that key's user, and reach their scratch
// files. One the namespace's own keys verify (an operator who listed
// its key there, §C.4) is the namespace's, as the core serves it. Where
// the namespace doesn't exist, its 404 is the answer, as the core's to an
// operator grant.
func (s *Server) verify(ctx context.Context, c *client.Client, g *grant.Grant, prev string) (*verdict, error) {
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
		return nil, fail(http.StatusUnauthorized, "the grant names none of the namespaces served here")
	}
	kid, rk := g.Blocks[0].Kid, kidSub(g.Blocks[0].Kid, g.Blocks[0].Sub)
	s.mu.Lock()
	recorded, _ := s.kidNS.Get(rk)
	s.mu.Unlock()
	var order []string
	for _, ns := range append([]string{prev}, recorded...) {
		if ns != "" && slices.Contains(named, ns) && !slices.Contains(order, ns) {
			order = append(order, ns)
		}
	}
	rest := 0
	for _, ns := range named {
		if !slices.Contains(order, ns) && rest < maxVerifyNS {
			order = append(order, ns)
			rest++
		}
	}
	why, purged, absent := "no key of a namespace it names verifies it", "", ""
	for _, ns := range order {
		info, err := c.NSPrincipal(ctx, ns)
		ae, isAPI := client.AsAPIError(err)
		switch {
		case err == nil:
			switch op, err := s.operatorSigned(ctx, c, g, ns); {
			case err != nil:
				return nil, err
			case op:
				return nil, fail(http.StatusUnauthorized, "the grant is signed by an operator key (kid %q), which authorizes creating namespaces and forced purges (§C.4), nothing this server does: log in with a grant from a key a namespace's document lists", kid)
			}
			s.mu.Lock()
			if nss, _ := s.kidNS.Get(rk); !slices.Contains(nss, ns) {
				nss = append(slices.Clip(nss), ns)
				s.kidNS.Put(rk, nss, len(nss))
			}
			s.mu.Unlock()
			return &verdict{ns: ns, info: info}, nil
		case client.IsPurged(err):
			if purged == "" {
				purged = ns
			}
		case isAPI && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden):
			why = apiText(ae)
		case isAPI && ae.Status == http.StatusNotFound:
			if absent == "" {
				absent = ns
			}
		default:
			return nil, upstream(err)
		}
	}
	switch {
	case purged != "":
		return nil, fail(http.StatusGone, "namespace %s was purged (§8.5), and no other namespace your grant names here accepts it", purged)
	case absent != "":
		return nil, fail(http.StatusNotFound, "namespace %s doesn't exist (§7.4), and no other namespace your grant names here accepts it", absent)
	}
	return nil, fail(http.StatusUnauthorized, "the core doesn't accept the grant: %s", why)
}

// operatorKeysFor is how long the deployment's operator keys, as read
// (operatorKeys), are used before they are read again; they are served
// cacheable for minutes (§C.4). After a failed read they aren't read
// again for operatorKeysRetry, or operatorKeysRetryNone while none was
// read (the core is asked of each grant meanwhile, operatorSigned).
const (
	operatorKeysFor       = 5 * time.Minute
	operatorKeysRetry     = 30 * time.Second
	operatorKeysRetryNone = 5 * time.Second
)

// operatorSigned reports whether an operator key signed grant g (§C.4),
// accepted by namespace ns's /principal, and the core doesn't serve it as
// ns's own: an operator key of the deployment's history (operatorKeys)
// whose kid is g's root kid, and under whose public key g's signature
// chain verifies. kids are never reused there, but a namespace
// document's key may carry an operator key's kid (kids are free-form):
// only the signature tells which of them signed g. And the core verifies
// a grant against the namespace's keys before the operator's
// (core/principal.go), so one signed by an operator key the namespace
// also lists under that kid (namespaceSigned) is the namespace's grant,
// served as any other. While the key set can't be read, the core is
// asked that of every grant (namespaceSigned).
func (s *Server) operatorSigned(ctx context.Context, c *client.Client, g *grant.Grant, ns string) (bool, error) {
	keys, err := s.operatorKeys(ctx)
	if err != nil {
		own, nerr := s.namespaceSigned(ctx, c, g, ns)
		if nerr != nil {
			return false, err
		}
		return !own, nil
	}
	for _, k := range keys {
		if k.Kid == g.Blocks[0].Kid && g.SignedBy(k.Pub) {
			own, err := s.namespaceSigned(ctx, c, g, ns)
			return !own, err
		}
	}
	return false, nil
}

// namespaceSigned reports whether namespace ns's own keys verify grant g,
// which c sends: an ordinary request under it is then served (§C.2 item
// 1), where under an operator grant it is 401 (§C.4). The namespace's
// head read with g: a 401 is a grant no key of ns verifies; any other
// refusal (403, 404 for a grant limited to some resources, 410) comes
// after verification. A public namespace's reads ignore a grant (§7):
// there its document, which anyone reads, says whether a key it lists
// under g's root kid signed g; read without a grant, it tells a public
// namespace from another.
func (s *Server) namespaceSigned(ctx context.Context, c *client.Client, g *grant.Grant, ns string) (bool, error) {
	h, err := c.NSHead(ctx, ns)
	switch ae, isAPI := client.AsAPIError(err); {
	case err == nil:
	case isAPI && ae.Status == http.StatusUnauthorized:
		return false, nil
	case isAPI && ae.Status < 500 && ae.Status != http.StatusTooManyRequests:
		return true, nil
	default:
		return false, upstream(err)
	}
	d, err := s.anon.NSDoc(ctx, ns, h.ID)
	switch ae, isAPI := client.AsAPIError(err); {
	case err == nil:
	case isAPI && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound):
		// Not public: the head read with g verified it.
		return true, nil
	default:
		return false, upstream(err)
	}
	if d.Value["read"] != "public" {
		return true, nil
	}
	keys, err := grant.ParseKeys(d.Value["keys"])
	if err != nil {
		return false, nil
	}
	for _, k := range keys {
		if k.Kid == g.Blocks[0].Kid && g.SignedBy(k.Pub) {
			return true, nil
		}
	}
	return false, nil
}

// operatorKeys returns the deployment's operator key history (§C.4), read
// without a grant at most operatorKeysFor ago. A read older is made once
// for every verification asking meanwhile (opFlight), outside opMu, while
// those with keys read before use them; one that fails leaves those in
// use and isn't tried again for operatorKeysRetry. With none read yet it
// is an error, also for operatorKeysRetryNone without reading again, and
// operatorSigned asks the core instead, rather than take an operator's
// grant for a user's. The core answers its key set 200, an empty set when
// it has none: any other answer, a 404 included (a proxy that doesn't
// route /.well-known), is a failed read.
func (s *Server) operatorKeys(ctx context.Context) ([]client.OperatorKey, error) {
	now := s.opt.Now()
	s.opMu.Lock()
	keys, at, retry, last := s.opKeys, s.opAt, s.opRetry, s.opErr
	s.opMu.Unlock()
	fresh := !at.IsZero() && now.Sub(at) < operatorKeysFor
	if fresh || now.Before(retry) {
		if at.IsZero() {
			return nil, last
		}
		return keys, nil
	}
	ch := s.opFlight.DoChan("op", func() (any, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		keys, err := s.anon.OperatorKeys(rctx)
		now := s.opt.Now()
		s.opMu.Lock()
		defer s.opMu.Unlock()
		if err == nil {
			s.opKeys, s.opAt, s.opRetry, s.opErr = keys, now, time.Time{}, nil
			return keys, nil
		}
		if !s.opAt.IsZero() {
			s.opt.Logf("dav: the deployment's operator keys couldn't be read again (%v); those read at %v are used", err, s.opAt)
			s.opRetry = now.Add(operatorKeysRetry)
			return s.opKeys, nil
		}
		s.opRetry, s.opErr = now.Add(operatorKeysRetryNone), upstream(err)
		return nil, s.opErr
	})
	if !at.IsZero() {
		// Read again in the background: these serve meanwhile.
		return keys, nil
	}
	select {
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.([]client.OperatorKey), nil
	case <-ctx.Done():
		return nil, &davError{status: http.StatusServiceUnavailable, msg: "the deployment's operator keys are being read; try again", header: http.Header{"Retry-After": {"5"}}}
	}
}

// userKey is who the state of a grant the core accepted (v) is kept for
// (§H.7): the root sub and kid GET /ns/{ns}/principal named, never the
// token, so every token of one person (minted again, attenuated offline)
// is one user; with the namespace whose key verified it, since a kid
// names a key of one namespace's document (§C.1), and the same kid in
// another served namespace may be anyone's key, minting grants for the
// same sub. verify asks the namespaces in an order that keeps it so.
func userKey(v *verdict) string {
	return v.ns + "\x00" + v.info.Kid + "\x00" + v.info.Sub
}

// idUser is who a token was verified as last (idUsers): its user
// (userKey), the namespace that verified it and its issuer there (the
// namespace and the root kid), kept past the token itself, which goes
// when idle for VerifyEvery (sweep) or to make room, so that coming back
// it is verified in the same order, and seen to have become someone else.
type idUser struct{ user, vns, issuer string }

// issuerKey is the key that minted the grant v the core accepted: the
// verifying namespace and the root block's kid, userKey without the sub.
func issuerKey(v *verdict) string { return v.ns + "\x00" + v.info.Kid }

// maxIDUsers bounds the token ids idUsers keeps, maxIDsPerUser those of
// one user.
const (
	maxIDUsers    = 1 << 14
	maxIDsPerUser = 1 << 8
)

// idUsers is who each token id was verified as last (idUser), within
// maxIDUsers over every user and maxIDsPerUser a user, the user's least
// recently verified going first. Narrowing is offline and free, and each
// narrowing is a new token id the core accepts, and the holder of a
// served namespace's key mints grants for any sub, each another user:
// over maxIDUsers, the verifying namespace keeping the most ids gives
// way, within it the issuer (kid) keeping the most, the least recently
// verified of equals, and within that issuer its least recently verified
// id. So one user's logins push out only that user's ids, and one key
// holder's, for however many subs it mints or kids it adds to its
// namespace, only its own, not those that let another person's token,
// dropped while idle and coming back as someone else, be seen to switch
// (admit): served namespaces are the operator's choice, and a
// namespace's keys the issuers it trusts with its subs. Under Server.mu.
type idUsers struct {
	ids     map[string]idUser
	users   map[string]*lru.Cache[string, struct{}] // by user: its token ids
	issuers map[string]*lru.Cache[string, struct{}] // by issuer: its token ids
	nss     map[string]*idGroup                     // by verifying namespace
	seq     uint64
	max     int
	perUser int
}

// idGroup is the ids a verifying namespace keeps (n), by issuer (of),
// or an issuer's, and when one was last verified (seq).
type idGroup struct {
	n, seq uint64
	of     map[string]*idGroup
}

// init empties x, to keep at most all token ids, perUser of a user.
func (x *idUsers) init(all, perUser int) {
	*x = idUsers{max: all, perUser: perUser, ids: map[string]idUser{},
		users: map[string]*lru.Cache[string, struct{}]{}, issuers: map[string]*lru.Cache[string, struct{}]{},
		nss: map[string]*idGroup{}}
}

// get returns who token id was verified as last.
func (x *idUsers) get(id string) (idUser, bool) {
	u, ok := x.ids[id]
	return u, ok
}

// put records that token id was verified as u.
func (x *idUsers) put(id string, u idUser) {
	if old, ok := x.ids[id]; ok && old != u {
		x.drop(id)
	}
	x.seq++
	ns := x.nss[u.vns]
	if ns == nil {
		ns = &idGroup{of: map[string]*idGroup{}}
		x.nss[u.vns] = ns
	}
	is := ns.of[u.issuer]
	if is == nil {
		is = &idGroup{}
		ns.of[u.issuer] = is
	}
	ns.seq, is.seq = x.seq, x.seq
	if _, ok := x.ids[id]; ok {
		x.users[u.user].Get(id)
		x.issuers[u.issuer].Get(id)
		return
	}
	x.ids[id] = u
	ns.n++
	is.n++
	ic := x.issuers[u.issuer]
	if ic == nil {
		ic = &lru.Cache[string, struct{}]{MaxEntries: x.max + 1}
		x.issuers[u.issuer] = ic
	}
	ic.Put(id, struct{}{}, 1)
	uc := x.users[u.user]
	if uc == nil {
		uc = &lru.Cache[string, struct{}]{MaxEntries: x.perUser}
		uc.OnEvict = func(id string, _ struct{}) { x.drop(id) }
		x.users[u.user] = uc
	}
	uc.Put(id, struct{}{}, 1)
	for len(x.ids) > x.max {
		x.evict()
	}
}

// evict drops the least recently verified id of the issuer keeping the
// most ids in the verifying namespace keeping the most.
func (x *idUsers) evict() {
	ns := mostOf(x.nss)
	if ns == "" {
		return
	}
	if ic := x.issuers[mostOf(x.nss[ns].of)]; ic != nil {
		if id, _, _, ok := ic.RemoveOldest(); ok {
			x.drop(id)
		}
	}
}

// mostOf returns the key of the group of gs keeping the most ids, the
// least recently verified of equals.
func mostOf(gs map[string]*idGroup) string {
	best := ""
	for k, g := range gs {
		if b := gs[best]; b == nil || g.n > b.n || g.n == b.n && g.seq < b.seq {
			best = k
		}
	}
	return best
}

// drop forgets token id.
func (x *idUsers) drop(id string) {
	u, ok := x.ids[id]
	if !ok {
		return
	}
	delete(x.ids, id)
	if c := x.users[u.user]; c != nil {
		if c.Remove(id); c.Len() == 0 {
			delete(x.users, u.user)
		}
	}
	if c := x.issuers[u.issuer]; c != nil {
		if c.Remove(id); c.Len() == 0 {
			delete(x.issuers, u.issuer)
		}
	}
	ns := x.nss[u.vns]
	if ns == nil {
		return
	}
	if is := ns.of[u.issuer]; is != nil {
		if is.n--; is.n == 0 {
			delete(ns.of, u.issuer)
		}
	}
	if ns.n--; ns.n == 0 {
		delete(x.nss, u.vns)
	}
}

// admit returns the token of a grant (id, its client, the served
// namespaces it names, its narrowing skey and chain, scopeOf) the core
// accepted (v), its user's state made only now, or refused with err: then
// the token goes, and its user's other tokens are asked again at their
// next request, since what refused it (a revoked root, a key withdrawn)
// may refuse them too. The user's state stays: only a token the core
// accepts reaches it, each asked again every VerifyEvery, and it is that
// person's, whose grant minted again finds it (§H.7); it goes when idle
// (ScratchIdle, RecordIdle) or to make room (MaxPrincipals), as any
// user's.
func (s *Server) admit(id string, c *client.Client, named map[string]bool, skey, chain string, v *verdict, err error) (*token, *davError) {
	now := s.opt.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tk := s.tokens[id]
	if err != nil {
		var de *davError
		if !errors.As(err, &de) {
			de = fail(http.StatusBadGateway, "the grant couldn't be checked")
		}
		if refusedStatus(de.status) && tk != nil {
			for o := range tk.p.toks {
				o.verified = time.Time{}
			}
			s.dropTokenLocked(tk)
		}
		return nil, de
	}
	key := userKey(v)
	p := s.principals[key]
	if p == nil {
		if !s.makeRoomLocked() {
			return nil, &davError{status: http.StatusServiceUnavailable, msg: "too many users at once; try again",
				header: http.Header{"Retry-After": {"5"}}}
		}
		p = s.newPrincipal(key)
		s.principals[key] = p
	}
	// Verified again as someone else: the namespace that accepted it
	// before refuses it now, and another accepts it. That user's records
	// don't hold what this token's client may have open, so its saves
	// without a base are refused until it reloads, rather than rebased on
	// the head (§H.4); whether the token is still kept or went meanwhile
	// (idUsers). Marked once it is admitted as that user, as idUsers is
	// then: a token refused room meanwhile (503) is seen to switch again
	// at its retry, and marks nothing before.
	was := ""
	if tk != nil {
		was = tk.p.id
	} else if u, ok := s.idUsers.get(id); ok {
		was = u.user
	}
	if tk != nil && tk.p != p {
		s.dropTokenLocked(tk)
		tk = nil
	}
	if tk == nil {
		if !s.tokenRoomLocked(p) {
			return nil, &davError{status: http.StatusServiceUnavailable, msg: "too many of your logins at once; try again",
				header: http.Header{"Retry-After": {"5"}}}
		}
		sc := p.scopes[skey]
		if sc == nil {
			if full := s.scopeRoomLocked(p, chain); full != "" {
				return nil, &davError{status: http.StatusServiceUnavailable,
					msg:    fmt.Sprintf("%s each keep temporary files or locks, or are busy; try again once one of them is idle", full),
					header: http.Header{"Retry-After": {"60"}}}
			}
			sc = s.newScopeLocked(p, skey)
			sc.chain = chain
		}
		tk = s.newToken(id, c, sc, named)
		s.tokens[id] = tk
		p.toks[tk] = true
	}
	if was != "" && was != key {
		s.loseRecords(was, p, id)
	}
	s.idUsers.put(id, idUser{user: key, vns: v.ns, issuer: issuerKey(v)})
	tk.verified, tk.vns = now, v.ns
	tk.keepWriter(v.ns, v.info.Writer, now)
	s.useLocked(tk, now)
	return tk, nil
}

// useLocked counts a request of tk's, now.
func (s *Server) useLocked(tk *token, now time.Time) {
	tk.used, tk.p.used, tk.sc.used = now, now, now
	tk.inflight++
	tk.p.inflight++
	tk.sc.inflight++
}

// release ends a request of tk's.
func (s *Server) release(tk *token) {
	if tk == s.local {
		return
	}
	s.mu.Lock()
	tk.inflight--
	tk.p.inflight--
	tk.sc.inflight--
	s.mu.Unlock()
}

// makeRoomLocked drops users to make room for one more: the least
// recently seen of all beyond MaxPrincipals, never one with a request in
// flight. False: there is no room.
func (s *Server) makeRoomLocked() bool {
	for len(s.principals) >= s.opt.MaxPrincipals {
		var old *principal
		for _, p := range s.principals {
			if p.inflight == 0 && (old == nil || p.used.Before(old.used)) {
				old = p
			}
		}
		if old == nil {
			return false
		}
		s.dropPrincipalLocked(old)
	}
	return true
}

// tokenRoomLocked drops p's tokens to make room for one more: the least
// recently used beyond MaxTokensPerPrincipal, never one with a request in
// flight, which is verified again when it comes back. False: there is no
// room.
func (s *Server) tokenRoomLocked(p *principal) bool {
	for len(p.toks) >= s.opt.MaxTokensPerPrincipal {
		var old *token
		for tk := range p.toks {
			if tk.inflight == 0 && (old == nil || tk.used.Before(old.used)) {
				old = tk
			}
		}
		if old == nil {
			return false
		}
		s.dropTokenLocked(old)
	}
	return true
}

// scopeRoomLocked drops one of p's scopes to make room for one more of
// chain (scopeOf): the least recently used of its pool beyond
// MaxTokensPerPrincipal that holds no scratch file or lock and has no
// request in flight (dead properties, cosmetic, may go with it). Tokens
// as issued are one pool; tokens narrowed offline a pool per chain, the
// token their narrowing started from (its first narrowing block), and at
// most MaxTokensPerPrincipal chains, a new one making room by dropping
// other chains' scopes alike. It returns who keeps the room, or "" once
// there is room. A scope with content isn't dropped to make room:
// narrowing is offline and free, and whoever holds a token of the user's
// (a delegate, the user's own devices) would drop the editor's swap
// files, backup copies and locks with a few new narrowings; those can't
// make room among the scopes of tokens as issued, and a delegate's, which
// only extend its own chain (a narrowing can't drop a block), fill only
// that chain's pool, not the user's other narrowed tokens' (their phone's
// read-only token, another delegate's): only a holder of a token as
// issued starts a chain.
func (s *Server) scopeRoomLocked(p *principal, chain string) string {
	now := s.opt.Now()
	max := s.opt.MaxTokensPerPrincipal
	for {
		n := 0
		others := map[string]bool{} // other chains
		var old, other *scope
		for _, sc := range p.scopes {
			idle := sc.inflight == 0 && !sc.holds(now)
			switch {
			case sc.chain == chain:
				n++
				if idle && (old == nil || sc.used.Before(old.used)) {
					old = sc
				}
			case chain != "" && sc.chain != "":
				others[sc.chain] = true
				if idle && (other == nil || sc.used.Before(other.used)) {
					other = sc
				}
			}
		}
		switch {
		case n >= max && old == nil && chain == "":
			return fmt.Sprintf("your %d other logins as issued", max)
		case n >= max && old == nil:
			return fmt.Sprintf("your %d other logins narrowed offline from the same token", max)
		case n >= max:
			s.dropScopeLocked(old)
		case n == 0 && chain != "" && len(others) >= max && other == nil:
			return fmt.Sprintf("logins narrowed offline from %d other tokens of yours", max)
		case n == 0 && chain != "" && len(others) >= max:
			s.dropScopeLocked(other)
		default:
			return ""
		}
	}
}

// dropTokenLocked forgets token tk: its next request is verified again.
// Its user's state stays. A request of it still in flight finishes.
func (s *Server) dropTokenLocked(tk *token) {
	if s.tokens[tk.id] == tk {
		delete(s.tokens, tk.id)
	}
	delete(tk.p.toks, tk)
}

// dropScopeLocked forgets scope sc of a user: its locks and scratch
// files, and its tokens, verified again at their next request.
func (s *Server) dropScopeLocked(sc *scope) {
	for tk := range sc.p.toks {
		if tk.sc == sc {
			s.dropTokenLocked(tk)
		}
	}
	sc.p.mu.Lock()
	delete(sc.p.scopes, sc.key)
	sc.p.mu.Unlock()
	s.scratchTotal.Add(-int64(sc.drop()))
}

// dropPrincipalLocked forgets user p: its tokens, and its scopes' locks
// and scratch files (its records of what it was served stay, by user,
// until they age out).
func (s *Server) dropPrincipalLocked(p *principal) {
	delete(s.principals, p.id)
	for tk := range p.toks {
		s.dropTokenLocked(tk)
	}
	for _, sc := range p.scopes {
		s.dropScopeLocked(sc)
	}
}

// sweep drops idle scratch files, and a gateway's idle tokens (unused for
// VerifyEvery, verified again if they come back), users and scopes
// (ScratchIdle), at most once a minute.
func (s *Server) sweep() {
	now := s.opt.Now()
	s.mu.Lock()
	if now.Sub(s.lastSweep) < time.Minute {
		s.mu.Unlock()
		return
	}
	s.lastSweep = now
	for _, tk := range s.tokens {
		if tk.inflight == 0 && now.Sub(tk.used) > s.opt.VerifyEvery {
			s.dropTokenLocked(tk)
		}
	}
	ps := make([]*principal, 0, len(s.principals)+1)
	if s.local != nil {
		ps = append(ps, s.local.p)
	}
	for _, p := range s.principals {
		if p.inflight == 0 && now.Sub(p.used) > s.opt.ScratchIdle {
			s.dropPrincipalLocked(p)
			continue
		}
		for _, sc := range p.scopes {
			if sc.inflight == 0 && now.Sub(sc.used) > s.opt.ScratchIdle {
				s.dropScopeLocked(sc)
			}
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

// hold reserves n bytes of written files being buffered for p, within
// max.
func (p *principal) hold(n, max int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held+n > max {
		return false
	}
	p.held += n
	return true
}

func (p *principal) unhold(n int64) {
	p.mu.Lock()
	p.held -= n
	p.mu.Unlock()
}

// userInflight is how many bytes of written files one user's requests
// buffer at once: in a gateway, a share of InflightBytes, so one user's
// stalled uploads don't refuse everyone's writes.
func (s *Server) userInflight() int64 {
	if !s.opt.Gateway {
		return int64(s.opt.InflightBytes)
	}
	return int64(max(s.opt.MaxFileSize, s.opt.MaxRawSize, s.opt.InflightBytes/4))
}

// token is one bearer: in a gateway, a grant the core verified (verify),
// with the client sending it, the served namespaces it names, the
// namespace that verified it, and what was read with it, since another
// token of the same user may read less (attenuated offline): writers'
// settings and namespace documents (nsInfo); its catalogs' graphs and the
// folders a tree service listed to it are kept by its id (views). What is
// kept for its user is in its principal, shared by every token of the
// user (§H.7), and in its principal's scope for its narrowing (scopeOf).
type token struct {
	id string
	c  *client.Client
	p  *principal
	sc *scope // of p, for the grant's narrowing
	// named: in a gateway, whether the grant names each served namespace
	// (§C.2); nil in local mode, whose grant the operator chose them for.
	named map[string]bool

	// under Server.mu; verified zero: ask the core again at the next
	// request; vns, the namespace whose GET /ns/{ns}/principal accepted
	// it last (verdict), asked first when it is verified again
	used, verified time.Time
	inflight       int
	vns            string

	mu      sync.Mutex
	writers map[string]writerAt // by namespace: §7.4's writer block
	docs    map[string]nsDocAt  // by namespace: what its document says
}

func (s *Server) newToken(id string, c *client.Client, sc *scope, named map[string]bool) *token {
	return &token{id: id, c: c, p: sc.p, sc: sc, named: named, used: s.opt.Now(), writers: map[string]writerAt{}, docs: map[string]nsDocAt{}}
}

// principal is a user as the server keeps state for them (§H.7): their
// guards, recent deletes and moves aside, the writes their tree listings
// wait for and the bytes their uploads buffer, within bounds, and, by
// narrowing, their scopes; their records (records.go) are kept by its id,
// apart and for longer. In a gateway, every token the core verified as
// theirs (userKey) shares it; in local mode, there is one.
type principal struct {
	id string // userKey; "local" in local mode

	// under Server.mu
	used     time.Time
	inflight int             // requests in flight, over its tokens
	toks     map[*token]bool // its tokens kept

	ts treeSvc // its writes its tree listings wait for (treesvc.go)

	mu      sync.Mutex
	held    int64                 // bytes of written files being buffered (hold)
	scopes  map[string]*scope     // by scopeOf; membership under Server.mu too
	deletes map[string]ownDelete  // by ns/name: its latest DELETEs
	trees   map[string]treeDelete // by path: the files of trees its latest DELETEs removed
	aside   map[string]time.Time  // documents' paths moved aside to a backup, and when
	guards  map[string][]guard    // by document path: its refused saves' guards, oldest first
	nguards int
}

// scope is what a principal keeps for its tokens of one narrowing
// (scopeOf), which may hold what one token read: their scratch files,
// locks (their owners' XML) and dead properties, within the principal's
// bounds, over its scopes. Tokens the issuer minted for the user with
// the same rights share one, whatever their times; one minted with less
// (another ns, can, roles or rules: a grant limited to some resources,
// §C.5.1) or narrowed offline (another ns, can, rules, or a via: a
// delegate) has its own, so a scratch file one wrote, such as a
// document's backup copy (§H.5) or an editor's swap file holding its
// text, is never served to a token that may read less (§H.6 "served
// only to that user"). What holds no content (guards, deletes, moves
// aside, records) stays the user's.
type scope struct {
	p     *principal
	key   string
	chain string // its grants' narrowing chain, "" as issued (scopeOf)
	locks webdav.LockSystem

	// under Server.mu
	used     time.Time
	inflight int

	// under p.mu
	scratch map[string]*scratchFile // by path
	sbytes  int
	dropped bool
	locked  map[string]heldLock // by token: its locks
	props   map[string]*propSet // by path: its dead properties (PROPPATCH)
	pbytes  int                 // what props cost
}

// scopeOf is the narrowing of grant g that its token's scope is kept by,
// and its chain, "" without narrowing blocks: a digest of what limits
// what g may read (§C.1): the root block's ns, can, roles and rules, and groups and
// attrs, which rules may test, without its kid and sub (the user's,
// userKey), nbf, exp and at, which bound only when or as of when it is
// used, and enc and signers, which don't limit reads; then each
// narrowing block without nbf and exp, leaving out blocks that hold
// nothing else. A token the issuer mints again with the same rights is
// in the same scope (§H.7 "a reminted token is the same person"); one it
// limited to some resources (rules on /resource, §C.5.1) isn't. ns, can,
// roles and groups are sets (§C.1, §C.2: tested by containment and
// intersection), so they are digested sorted and without duplicates: the
// same rights listed in another order (an issuer building them from a
// set) are the same scope. The chain is the digest up to the first
// narrowing block that holds something: the token the narrowings started
// from, which a delegate's further narrowings keep (scopeRoomLocked).
func scopeOf(g *grant.Grant) (string, string) {
	h := sha256.New()
	write := func(raw map[string]any, skip ...string) bool {
		m := make(map[string]any, len(raw))
		for k, v := range raw {
			if !slices.Contains(skip, k) {
				m[k] = v
				if slices.Contains(setMembers, k) {
					m[k] = asSet(v)
				}
			}
		}
		if len(m) == 0 {
			return false
		}
		h.Write(jsonv.Canonical(m))
		h.Write([]byte{0})
		return true
	}
	write(g.Blocks[0].Raw, "kid", "sub", "nbf", "exp", "at", "enc", "signers")
	chain := ""
	for _, b := range g.Blocks[1:] {
		if write(b.Raw, "nbf", "exp") && chain == "" {
			chain = hex.EncodeToString(h.Sum(nil)[:16])
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), chain
}

// setMembers are the block members scopeOf digests as sets.
var setMembers = []string{"ns", "can", "roles", "groups"}

// asSet returns v, a list of strings, sorted and without duplicates; any
// other value as it is.
func asSet(v any) any {
	arr, ok := v.([]any)
	if !ok {
		return v
	}
	ss := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return v
		}
		ss = append(ss, s)
	}
	slices.Sort(ss)
	ss = slices.Compact(ss)
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
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

func (s *Server) newPrincipal(id string) *principal {
	return &principal{id: id, toks: map[*token]bool{}, scopes: map[string]*scope{}, deletes: map[string]ownDelete{},
		trees: map[string]treeDelete{}, aside: map[string]time.Time{}, guards: map[string][]guard{}, used: s.opt.Now()}
}

// newScopeLocked makes p's scope key.
func (s *Server) newScopeLocked(p *principal, key string) *scope {
	sc := &scope{p: p, key: key, locks: webdav.NewMemLS(), used: s.opt.Now(), scratch: map[string]*scratchFile{},
		locked: map[string]heldLock{}, props: map[string]*propSet{}}
	p.mu.Lock()
	p.scopes[key] = sc
	p.mu.Unlock()
	return sc
}

// reqState is one request's view, in its context: the token and its
// user, what the request is (MOVE and COPY destinations change what RemoveAll does,
// a PUT's preconditions what it writes), what it read already, and the
// error to answer with.
type reqState struct {
	s      *Server
	tk     *token
	p      *principal // tk's user
	sc     *scope     // tk's scope of p
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
	fresh  map[string]bool         // by catalog: its graph was read by the request (freshGraph)
	dirs   map[string]*treeDir     // by catalog/folder node
	heads  map[string]*client.Head // by ns/name
	// byNodes: catalogs whose paths the request resolves from their node
	// documents, a tree service's listing having disagreed (resolveCatalog)
	byNodes map[string]bool
}

type stateKey struct{}

func state(ctx context.Context) *reqState {
	st, _ := ctx.Value(stateKey{}).(*reqState)
	return st
}

// record keeps err for errWriter if it is a davError, and returns it.
// Another failure (no such file) leaves the answer to the handler. In
// local mode the core's 401 refuses the server's own grant, not the
// user's password, so it is a 502 rather than a new login prompt; in a
// gateway it refuses the token (revoked since it was verified), which is
// verified again at its next request. A refusal over a writer's settings
// (frozen, a nonce, a limit, §7.4 writer) drops the token's, read again
// for the next write.
func (st *reqState) record(err error) error {
	if err == nil {
		return nil
	}
	var de *davError
	if !errors.As(err, &de) {
		st.err = nil
		return err
	}
	if de.refresh {
		st.tk.forgetWriters()
	}
	switch {
	case de.status == http.StatusUnauthorized && !st.s.opt.Gateway:
		de = &davError{status: http.StatusBadGateway, msg: "the core refused this server's grant (-bearer): " + de.msg, cause: de.cause}
	case de.status == http.StatusUnauthorized:
		st.s.mu.Lock()
		st.tk.verified = time.Time{}
		st.s.mu.Unlock()
	}
	st.err = de
	return de
}

// changed forgets what the request read, after it wrote, and makes other
// requests' catalog reads stale.
func (st *reqState) changed() {
	st.lists, st.graphs, st.fresh, st.dirs, st.heads = nil, nil, nil, nil, nil
	st.s.gen.Add(1)
}

// slashClean is path.Clean of name rooted at /.
func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}
