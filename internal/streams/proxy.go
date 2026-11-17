package streams

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Options configure a Proxy.
type Options struct {
	// Client reaches the core as the proxy: with the proxy's grant as its
	// bearer, or an X-Author for a core with authentication disabled.
	Client *client.Client
	// Grant is the proxy's own grant, the token Client sends: each
	// caller's read grant is narrowed from it (J.3). It must allow create,
	// append, read and purge in NS. Empty only over a core with
	// authentication disabled, where callers get no grant.
	Grant string
	// NS is the namespace the streams are kept in (default "streams").
	NS string
	// CallerNS is the namespace a caller's grant is verified in: the core
	// says there who the bearer is (GET /ns/{ns}/principal, §7.4), which
	// needs the grant to name that namespace. Required unless the core
	// has authentication disabled, where the caller is its X-Author.
	CallerNS string
	// PublicURL is the core's base URL as callers reach it, for the url
	// and log of an answer (default Client.BaseURL()).
	PublicURL string
	// Upstreams is the allowlist: URL prefixes (scheme, host and a path
	// prefix) a caller's Upstream-URL must fall under. Empty refuses all.
	Upstreams []string
	// Flush is the least time between two appends to a stream (J.2;
	// default 200ms).
	Flush time.Duration
	// TTL is how long a stream's read grants live from its creation; the
	// sweeper purges a closed stream once it is that old (J.4; default
	// 24h).
	TTL time.Duration
	// IdleTimeout closes a stream with no append for that long with
	// "timeout" (J.2; default 2m).
	IdleTimeout time.Duration
	// SweepInterval is how often Run sweeps the namespace (default a
	// quarter of the lesser of IdleTimeout and TTL, between 1s and 1m).
	SweepInterval time.Duration
	// StateFile, if set, holds the names of the open stream resources, so
	// a proxy started again closes them with "error" (J.2 Restarts).
	StateFile string
	// MaxRequestBody bounds the request body forwarded upstream (default
	// 1 MiB).
	MaxRequestBody int64
	// MaxSegments bounds the resources one upstream response may fill: a
	// stream about to pass documentSize continues in the next (J.1), and
	// the read grant names all of them (default 8).
	MaxSegments int
	// MaxStreams bounds the streams carried at once (J.2 Pace; default
	// 64).
	MaxStreams int
	// HTTPClient calls upstream (default one without a timeout that
	// follows no redirects).
	HTTPClient *http.Client
	// Now is the clock (default time.Now).
	Now func() time.Time
	// Logf logs (default: nothing). Neither the upstream URL nor any
	// request header is ever logged.
	Logf func(format string, args ...any)
}

// Proxy is a stream proxy: an http.Handler for its callers (POST /streams,
// GET /healthz), the writers of the streams it carries, and the sweeper.
type Proxy struct {
	opt   Options
	c     *client.Client
	grant *grant.Grant // nil with authentication disabled
	allow []*url.URL

	authDisabled bool
	nonce        bool
	docSize      int // documentSize of the namespace
	setSize      int // patchSetSize
	opsPerSet    int
	maxChunk     int // most bytes of a chunk
	maxEnc       int // and most as a canonical JSON string, without its quotes
	maxPending   int // most bytes read from upstream and not yet appended, as JSON

	ctx    context.Context // cancelled by Close: streams wind down
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	open  map[string]*stream // by current resource name
	known map[string]known   // what the sweeper learnt of a resource
	// reserved counts the requests that hold a slot of MaxStreams for a
	// stream whose resource is being created.
	reserved int
	closed   bool
}

// reserve is the room kept in a stream document for what ends it: closed
// with an error or next, an abort, and the encoding around them.
const reserve = 640

// maxError bounds closed.error.
const maxError = 200

// New checks the namespace and the proxy's grant against the core, closes
// the streams a previous run left open (StateFile) and returns the proxy.
// Call Run for the sweeper and Close to stop.
func New(ctx context.Context, opt Options) (*Proxy, error) {
	if opt.Client == nil {
		return nil, errors.New("streams: no client")
	}
	if opt.NS == "" {
		opt.NS = "streams"
	}
	if !client.ValidNSName(opt.NS) {
		return nil, fmt.Errorf("streams: invalid namespace name %q", opt.NS)
	}
	if opt.Flush <= 0 {
		opt.Flush = 200 * time.Millisecond
	}
	if opt.TTL <= 0 {
		opt.TTL = 24 * time.Hour
	}
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 2 * time.Minute
	}
	if opt.SweepInterval <= 0 {
		opt.SweepInterval = min(max(min(opt.IdleTimeout, opt.TTL)/4, time.Second), time.Minute)
	}
	if opt.MaxRequestBody <= 0 {
		opt.MaxRequestBody = 1 << 20
	}
	if opt.MaxSegments <= 0 {
		opt.MaxSegments = 8
	}
	if opt.MaxStreams <= 0 {
		opt.MaxStreams = 64
	}
	if opt.HTTPClient == nil {
		opt.HTTPClient = &http.Client{}
	}
	// A redirect would leave the allowlist, with the caller's upstream
	// credentials: the 3xx is kept as the stream instead.
	hc := *opt.HTTPClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	opt.HTTPClient = &hc
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.PublicURL == "" {
		opt.PublicURL = opt.Client.BaseURL()
	}
	opt.PublicURL = strings.TrimRight(opt.PublicURL, "/")
	p := &Proxy{opt: opt, c: opt.Client, open: map[string]*stream{}, known: map[string]known{}}
	for _, a := range opt.Upstreams {
		u, err := url.Parse(a)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("streams: upstream prefix %q: want http(s)://host[/path], without user, query or fragment", a)
		}
		p.allow = append(p.allow, u)
	}

	var err error
	if p.authDisabled, err = p.c.AuthDisabled(ctx); err != nil {
		return nil, fmt.Errorf("streams: reaching the core: %w", err)
	}
	pi, err := p.c.NSPrincipal(ctx, opt.NS)
	if err != nil {
		if client.IsNotFound(err) {
			return nil, fmt.Errorf("streams: namespace %s does not exist, or the proxy's grant doesn't name it: %w", opt.NS, err)
		}
		return nil, fmt.Errorf("streams: the proxy's grant in namespace %s: %w", opt.NS, err)
	}
	for _, verb := range []string{"create", "append", "read", "purge"} {
		if !pi.HasVerb(verb) {
			return nil, fmt.Errorf("streams: the proxy's grant does not allow %s in namespace %s (J.1 needs create, append, read and purge)", verb, opt.NS)
		}
	}
	switch pi.Writer.Level {
	case "sealed":
		return nil, fmt.Errorf("streams: namespace %s is sealed: signing each reader a root grant with its enc (J.4 Encryption) is not implemented", opt.NS)
	case "e2e":
		return nil, fmt.Errorf("streams: namespace %s is end-to-end encrypted, where the abort rule can't be judged (J.4): a stream proxy doesn't work there", opt.NS)
	}
	if pi.Writer.Frozen {
		return nil, fmt.Errorf("streams: namespace %s is frozen", opt.NS)
	}
	if pi.Writer.SignaturesRequired {
		return nil, fmt.Errorf("streams: namespace %s requires signatures, which the proxy doesn't write", opt.NS)
	}
	p.nonce = pi.Writer.NonceRequired
	size := func(key string, def int64) int {
		if n, ok := pi.Writer.Size(key); ok && n > 0 {
			return int(n)
		}
		return int(def)
	}
	p.docSize, p.setSize, p.opsPerSet = size("documentSize", 1<<20), size("patchSetSize", 256<<10), size("opsPerSet", 1000)
	valueSize := size("valueSize", 64<<10)
	// valueSize measures a string as canonical JSON, quotes and escapes
	// included (§6.6), where a control character is six bytes. A chunk
	// stays far below it (J.1): half at most by that measure, 16 KiB of
	// text, and small enough for a patch set and for four to a segment.
	p.maxEnc = min(valueSize/2, (p.setSize-1024)/2, (p.docSize-reserve-256)/4) - 2
	p.maxChunk = min(16<<10, p.maxEnc)
	p.maxPending = 2 * p.setSize
	if p.maxEnc < 6*64 || p.opsPerSet < 8 {
		return nil, fmt.Errorf("streams: namespace %s's limits are too small for streams (documentSize %d, patchSetSize %d, valueSize %d, opsPerSet %d)",
			opt.NS, p.docSize, p.setSize, valueSize, p.opsPerSet)
	}

	if !p.authDisabled {
		if opt.Grant == "" {
			return nil, errors.New("streams: the proxy's grant is needed to narrow read grants from (J.3)")
		}
		if p.grant, err = grant.Decode(opt.Grant, 0); err != nil {
			return nil, fmt.Errorf("streams: the proxy's grant: %w", err)
		}
		if !p.grant.HasProof() {
			return nil, errors.New("streams: the proxy's grant is sealed or has no proof, so it can't be narrowed for readers (J.3)")
		}
		if opt.CallerNS == "" {
			return nil, errors.New("streams: no caller namespace: the core verifies a caller's grant in a namespace the grant names")
		}
		if !client.ValidNSName(opt.CallerNS) {
			return nil, fmt.Errorf("streams: invalid caller namespace name %q", opt.CallerNS)
		}
		// A namespace anyone may read serves its documents without a
		// grant, whatever a read grant's rules say (§2.1): every stream
		// would be public. The configuration must say otherwise, and a
		// proxy that can't read it doesn't start.
		read, err := p.readMode(ctx)
		if err != nil {
			return nil, fmt.Errorf("streams: the configuration of namespace %s can't be read to check that its reads need a grant (J.1): %w", opt.NS, err)
		}
		if read != "grant" {
			return nil, fmt.Errorf("streams: namespace %s has read: %q, so anyone could read every stream; streams need a namespace with read: \"grant\" (J.1)", opt.NS, read)
		}
		if exp := grantExp(p.grant); !exp.IsZero() && exp.Before(opt.Now().Add(opt.TTL)) {
			opt.Logf("streams: the proxy's grant expires %s, sooner than a read grant's ttl of %s: read grants end with it", exp.Format(time.RFC3339), opt.TTL)
		}
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	if err := p.recover(ctx); err != nil {
		p.cancel()
		return nil, err
	}
	return p, nil
}

// readMode is the namespace document's read member in force: "grant"
// when it has none (§6.5).
func (p *Proxy) readMode(ctx context.Context) (string, error) {
	h, err := p.c.NSHead(ctx, p.opt.NS)
	if err != nil {
		return "", err
	}
	d, err := p.c.NSDoc(ctx, p.opt.NS, h.ID)
	if err != nil {
		return "", err
	}
	switch v := d.Value["read"].(type) {
	case nil:
		return "grant", nil
	case string:
		return v, nil
	}
	return "", errors.New("its read member is not a string")
}

// grantExp is the earliest exp of a grant's blocks.
func grantExp(g *grant.Grant) time.Time {
	var exp time.Time
	for _, b := range g.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	return exp
}

// Run sweeps the namespace every SweepInterval until ctx ends or the proxy
// is closed.
func (p *Proxy) Run(ctx context.Context) {
	t := time.NewTicker(p.opt.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.ctx.Done():
			return
		case <-t.C:
			if err := p.Sweep(ctx); err != nil && ctx.Err() == nil {
				p.opt.Logf("streams: sweep: %v", err)
			}
		}
	}
}

// Close stops the proxy: the upstream requests of its open streams are
// cancelled and the streams closed with "error", as upstream can't be
// resumed (J.2). It waits for them until ctx ends.
func (p *Proxy) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Open is how many streams the proxy carries now.
func (p *Proxy) Open() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.open)
}

// ServeHTTP serves the caller-facing API.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			httpError(w, 405, "method_not_allowed", "GET /healthz")
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ok", "open": p.Open()})
	case "/streams":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			httpError(w, 405, "method_not_allowed", "POST /streams")
			return
		}
		p.start(w, r)
	default:
		httpError(w, 404, "not_found", "the stream proxy serves POST /streams and GET /healthz; streams are read from the core")
	}
}

// Answer is the body of a POST /streams answer.
type Answer struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Log   string `json:"log"`
	Grant string `json:"grant,omitempty"`
	Exp   string `json:"exp"`
}

func httpError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"code": code, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

// caller is who asks: the principal the core takes the bearer for.
type caller struct {
	sub string // the root block's sub, or the X-Author
	key string // thumbprint of the key that signed the grant, "" without authentication
}

// whois asks the core who the request's bearer is. A core with
// authentication disabled has no grants: the caller is its X-Author.
func (p *Proxy) whois(r *http.Request) (caller, int, string) {
	if p.authDisabled {
		a := strings.TrimSpace(r.Header.Get("X-Author"))
		if a == "" {
			return caller{}, 401, "the core has authentication disabled: name the caller in X-Author"
		}
		return caller{sub: a}, 0, ""
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok = strings.TrimSpace(tok); !ok || tok == "" {
		return caller{}, 401, "Authorization: Bearer with the caller's grant is required"
	}
	// The server's verdict, not the token's own claim (client.Principal
	// only decodes): the grant is verified in the caller namespace.
	pi, err := p.c.With(client.WithBearer(tok), client.WithAuthor("")).NSPrincipal(r.Context(), p.opt.CallerNS)
	switch {
	case client.IsAuth(err):
		return caller{}, 401, "the core does not accept the caller's grant in namespace " + p.opt.CallerNS
	case client.IsNotFound(err), client.IsGone(err):
		return caller{}, 401, "the caller's grant can't be verified in namespace " + p.opt.CallerNS
	case err != nil:
		return caller{}, 502, "the core could not be asked about the caller's grant"
	case pi.Sub == "":
		return caller{}, 401, "the caller's grant names no principal"
	}
	return caller{sub: pi.Sub, key: pi.Key}, 0, ""
}

// allowed reports whether u falls under an allowlist prefix: the same
// scheme and host, and the prefix's path up to a segment boundary.
func (p *Proxy) allowed(u *url.URL) bool {
	if u.User != nil || u.Fragment != "" || u.Host == "" || u.Opaque != "" {
		return false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	for _, a := range p.allow {
		if !strings.EqualFold(a.Scheme, u.Scheme) || !strings.EqualFold(a.Host, u.Host) {
			continue
		}
		ap := a.Path
		if ap == "" || ap == "/" {
			return true
		}
		if path == ap || strings.HasPrefix(path, strings.TrimSuffix(ap, "/")+"/") {
			return true
		}
	}
	return false
}

var idEnc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// keyedID derives a stream id from the namespace, the caller and its Request-Key, so a
// repeated request finds its stream (J.1 Names): 160 bits of a sha-256 in
// base32, a name of §3.6.
func keyedID(ns string, c caller, requestKey string) string {
	h := sha256.New()
	for _, s := range []string{"patchlog-streams/2", ns, c.key, c.sub, requestKey} {
		fmt.Fprintf(h, "%d:%s,", len(s), s)
	}
	return idEnc.EncodeToString(h.Sum(nil)[:20])
}

func validMethod(m string) bool {
	if m == "" || len(m) > 32 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if c := m[i]; c < 'A' || c > 'Z' {
			return false
		}
	}
	return m != "CONNECT" && m != "TRACE"
}

const headerPrefix = "Upstream-Header-"

// start is POST /streams: it creates the stream resource, starts upstream
// in the background and answers once the resource exists.
func (p *Proxy) start(w http.ResponseWriter, r *http.Request) {
	who, status, msg := p.whois(r)
	if status != 0 {
		if status == 401 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			httpError(w, status, "unauthenticated", msg)
		} else {
			httpError(w, status, "unavailable", msg)
		}
		return
	}
	raw := r.Header.Get("Upstream-URL")
	if raw == "" {
		httpError(w, 400, "bad_input", "Upstream-URL is required")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		httpError(w, 400, "bad_input", "Upstream-URL must be an http or https URL")
		return
	}
	if !p.allowed(u) {
		httpError(w, 403, "forbidden", "Upstream-URL is not under an allowed upstream prefix")
		return
	}
	method := r.Header.Get("Upstream-Method")
	if method == "" {
		method = http.MethodPost
	}
	if !validMethod(method) {
		httpError(w, 400, "bad_input", "Upstream-Method must be an HTTP method in capitals")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.opt.MaxRequestBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			httpError(w, 413, "limit", fmt.Sprintf("the request body is larger than %d bytes", p.opt.MaxRequestBody))
		} else {
			httpError(w, 400, "bad_input", "the request body could not be read")
		}
		return
	}
	hdr := http.Header{}
	for name, vals := range r.Header {
		if len(name) > len(headerPrefix) && strings.EqualFold(name[:len(headerPrefix)], headerPrefix) {
			hdr[http.CanonicalHeaderKey(name[len(headerPrefix):])] = vals
		}
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		hdr.Set("Content-Type", ct)
	}
	if a := r.Header.Get("Upstream-Authorization"); a != "" {
		hdr.Set("Authorization", a)
	}

	id := seal.NewNonce() // 128 random bits in base32, a name of §3.6
	if key := r.Header.Get("Request-Key"); key != "" {
		if len(key) > 1024 {
			httpError(w, 400, "bad_input", "Request-Key is longer than 1024 bytes")
			return
		}
		id = keyedID(p.opt.NS, who, key)
	}

	// A new stream needs a slot of MaxStreams, taken here, before its
	// resource exists, and held until the stream is carried or the
	// request turns out not to start one.
	keyed := r.Header.Get("Request-Key") != ""
	reserved := false
	defer func() {
		if reserved {
			p.mu.Lock()
			p.reserved--
			p.mu.Unlock()
		}
	}()
	p.mu.Lock()
	switch {
	case p.closed:
		p.mu.Unlock()
		httpError(w, 503, "unavailable", "the proxy is shutting down")
		return
	case p.open[id] != nil:
		// Ours and running: the create below answers that it exists.
	case len(p.open)+p.reserved < p.opt.MaxStreams:
		p.reserved++
		reserved = true
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	exists := false
	if !reserved {
		// No slot. A keyed request may still be for a stream that
		// exists, which needs none.
		if keyed {
			if h, err := p.c.Head(ctx, p.opt.NS, id); err == nil && h.State == client.Live {
				exists = true
			}
		}
		if !exists {
			w.Header().Set("Retry-After", "1")
			httpError(w, 503, "busy", fmt.Sprintf("the proxy carries %d streams, its most", p.opt.MaxStreams))
			return
		}
	}

	// J.2 step 1: create before calling upstream. 201 is a new stream;
	// 200 (the same create, retried) or 412 means it exists; 410 that it
	// was removed.
	gen := map[string]any{"upstream": map[string]any{"method": method}, "chunks": []any{}}
	if p.nonce {
		gen["$nonce"] = seal.NewNonce()
	}
	// The caller's connection doesn't matter to any of this (ctx): a
	// resource created is a stream started.
	var res *client.WriteResult
	var err2 error
	if !exists {
		res, err2 = p.create(ctx, id, gen)
	}
	err = err2
	var created time.Time
	isNew := false
	switch {
	case exists:
	case err == nil && res.Status == 201:
		isNew = true
		created = entryTime(res.Entry, p.opt.Now())
	case err == nil:
		created = entryTime(res.Entry, time.Time{})
	case client.IsStale(err):
	case client.IsGone(err):
		httpError(w, 410, "gone", "the stream was removed")
		return
	case client.IsRateLimited(err):
		w.Header().Set("Retry-After", "1")
		httpError(w, 503, "busy", "the core limits the proxy's writes; try again")
		return
	default:
		p.opt.Logf("streams: creating %s: %v", id, err)
		httpError(w, 502, "unavailable", "the stream could not be created in the core")
		return
	}
	if created.IsZero() {
		// An existing stream whose genesis the answer didn't carry: its
		// first log entry says when it was created.
		var exact bool
		if created, exact, err = p.createdAt(ctx, id, ""); err != nil {
			if client.IsGone(err) {
				httpError(w, 410, "gone", "the stream was removed")
				return
			}
			p.opt.Logf("streams: reading %s: %v", id, err)
			httpError(w, 502, "unavailable", "the stream could not be read from the core")
			return
		}
		if !exact {
			// Its history was pruned, the genesis with it (§8.6): a
			// grant counted from anything later would outlive the ones
			// handed out before, and the stream's purge.
			httpError(w, 409, "pruned", "the stream's history was pruned, so when it was created is not known: no further read grant is made for it")
			return
		}
	}
	exp := created.Add(p.opt.TTL)
	if !isNew && !p.opt.Now().Before(exp) {
		httpError(w, 410, "gone", "the stream's read grants have expired; it is about to be purged")
		return
	}
	ans := Answer{ID: id, URL: p.opt.PublicURL + "/r/" + p.opt.NS + "/" + id}
	ans.Log = ans.URL + "/log"
	if p.grant != nil {
		if ge := grantExp(p.grant); !ge.IsZero() && ge.Before(exp) {
			exp = ge
		}
		tok, err := p.readGrant(id, who.sub, exp)
		if err != nil {
			p.opt.Logf("streams: narrowing the grant for %s: %v", id, err)
			if isNew {
				p.abandon(id, res.ID, "the proxy could not make a read grant")
			}
			httpError(w, 500, "internal", "the read grant could not be made")
			return
		}
		ans.Grant = tok
	}
	ans.Exp = exp.UTC().Format(time.RFC3339)
	if !isNew {
		writeJSON(w, 200, ans)
		return
	}
	s := &stream{p: p, id: id, name: id, head: res.ID, created: created, method: method,
		size: len(jsonv.Canonical(jsonv.FromGo(gen))), metaSent: false, abortSig: make(chan struct{}, 1)}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.abandon(id, res.ID, "the proxy shut down")
		httpError(w, 503, "unavailable", "the proxy is shutting down")
		return
	}
	p.open[id] = s
	p.reserved--
	reserved = false
	p.saveStateLocked()
	p.wg.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wg.Done()
		s.run(u.String(), hdr, body)
	}()
	w.Header().Set("Location", ans.URL)
	writeJSON(w, 201, ans)
}

// create creates a stream resource, once more after a 429's Retry-After.
func (p *Proxy) create(ctx context.Context, name string, doc map[string]any) (*client.WriteResult, error) {
	res, err := p.c.CreateDoc(ctx, p.opt.NS, name, doc)
	if ae, ok := client.AsAPIError(err); ok && ae.Status == 429 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(max(ae.RetryAfter, 50*time.Millisecond), 5*time.Second)):
		}
		res, err = p.c.CreateDoc(ctx, p.opt.NS, name, doc)
	}
	return res, err
}

// abandon closes a stream that was created but never started.
func (p *Proxy) abandon(name, head, why string) {
	p.abandonWith(name, head, &Closed{Reason: ReasonError, Error: why})
}

// closeOps is the patch set that sets closed.
func (p *Proxy) closeOps(c *Closed) []any {
	ops := []any{map[string]any{"op": "add", "path": "/closed", "value": c.value()}}
	if p.nonce {
		ops = append(ops, map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
	}
	return ops
}

func entryTime(e *client.LogEntry, def time.Time) time.Time {
	if e != nil {
		if t, err := time.Parse(time.RFC3339, e.Created); err == nil {
			return t
		}
	}
	return def
}

// createdAt is when resource name was created: its genesis entry's
// created, which is exact. Where the history was pruned, the genesis with
// it (§8.6), it is the head's time instead, not exact but no earlier:
// good for purging no sooner than due, not for a grant's exp. head ""
// reads the current head first.
func (p *Proxy) createdAt(ctx context.Context, name, head string) (t time.Time, exact bool, err error) {
	if head == "" {
		h, err := p.c.Head(ctx, p.opt.NS, name)
		if err != nil {
			return time.Time{}, false, err
		}
		if h.State != client.Live {
			return time.Time{}, false, &client.APIError{Status: 410, Code: "gone", Method: "GET", Path: "/r/" + p.opt.NS + "/" + name}
		}
		head = h.ID
	}
	es, _, err := p.c.LogPage(ctx, p.opt.NS, name, head, "")
	if client.IsPruned(err) || (err == nil && len(es) > 0 && es[0].Parent != "") {
		d, err := p.c.Doc(ctx, p.opt.NS, name, head)
		if err != nil {
			return time.Time{}, false, err
		}
		if d.Modified.IsZero() {
			return time.Time{}, false, fmt.Errorf("streams: %s: its history is pruned and its head has no time", name)
		}
		// Last-Modified is to the second, rounded down.
		return d.Modified.Add(time.Second), false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if len(es) == 0 {
		return time.Time{}, false, fmt.Errorf("streams: %s has no log entries", name)
	}
	if t, err = time.Parse(time.RFC3339, es[0].Created); err != nil {
		return time.Time{}, false, fmt.Errorf("streams: %s: created %q: %w", name, es[0].Created, err)
	}
	return t, true, nil
}

// readGrant narrows the proxy's grant for a caller (J.3): via names the
// caller, the rules fix the stream's resources and allow appends only
// within /abort. Where J.3 fixes /resource to the id alone, this names the
// id and its continuations, the resources a stream closed with "size"
// carries on in (J.1), which the reader must be able to follow.
func (p *Proxy) readGrant(id, callerSub string, exp time.Time) (string, error) {
	var resource any = map[string]any{"op": "test", "path": "/resource", "value": id}
	if p.opt.MaxSegments > 1 {
		names := make([]any, p.opt.MaxSegments)
		for i := range names {
			names[i] = SegmentName(id, i)
		}
		resource = map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": names}}
	}
	g, err := p.grant.Narrow(map[string]any{
		// The proxy's grant may name other namespaces too: the reader's
		// names this one alone (§C.1), or the names fixed below would
		// be readable in each.
		"ns":  []any{p.opt.NS},
		"via": callerSub,
		"can": []any{"read", "append"},
		"exp": exp.UTC().Format(time.RFC3339),
		"rules": []any{
			resource,
			map[string]any{
				"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "append"}},
				"then": []any{map[string]any{"op": "writes", "within": []any{"/abort"}}},
			},
		},
	})
	if err != nil {
		return "", err
	}
	return g.Encode(), nil
}
