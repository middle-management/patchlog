// Package clienttest runs an in-process Patch Log server (internal/core +
// internal/server over httptest) for tests of API consumers, with helpers
// for keys and grants.
package clienttest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/server"
	"github.com/middle-management/patchlog/internal/testenv"

	"net/http/httptest"
)

// Origin is the origin every test server publishes at GET /.
const Origin = "https://cms.example"

// Clock is an injectable clock for the engine.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Options configure a test server.
type Options struct {
	// Auth enables authentication with a generated operator key.
	Auth bool
	// LongPoll is the long-poll interval (default 300ms, to keep tests fast).
	LongPoll time.Duration
	// Start is the engine clock's start time (default 2026-10-04T12:00:00Z).
	// Use RealClock for tests that need grants valid against time.Now.
	Start time.Time
	// RealClock uses time.Now instead of an injectable clock.
	RealClock bool
	// KeyStore enables encryption (Addendum E): at-rest, sealed and e2e
	// namespaces need one.
	KeyStore core.KeyStore
	// Archiver stores pruning archives (§8.6); nil means none. The
	// retention loop is off either way.
	Archiver core.Archiver
	// LogPageSize is the deployment's log page size (§6.6): log ranges,
	// long-polls and /heads answer at most this many entries (§7.1
	// Paging). Zero means PATCHLOG_TEST_LOG_PAGE_SIZE (testenv), else the
	// default, 1000.
	LogPageSize int
	// Wrap, if set, wraps the server's handler, e.g. to change state
	// between two requests of a flow.
	Wrap func(http.Handler) http.Handler
}

// Server is a running test server.
type Server struct {
	URL         string
	Engine      *core.Engine
	HTTP        *httptest.Server
	Clock       *Clock // nil with RealClock
	OperatorKey ed25519.PrivateKey
	auth        bool
}

type nopPurger struct{}

func (nopPurger) PurgeTags([]string) {}

// New starts a server on an in-memory database (or a fresh Postgres one,
// see pgtest); it stops with the test.
func New(t testing.TB, opt Options) *Server {
	t.Helper()
	if opt.LongPoll == 0 {
		opt.LongPoll = 300 * time.Millisecond
	}
	if opt.Start.IsZero() {
		opt.Start = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	}
	o := core.Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), Origin: Origin, AuthDisabled: !opt.Auth, LongPollInterval: opt.LongPoll, Purger: nopPurger{}, KeyStore: opt.KeyStore,
		Archiver: opt.Archiver, RetentionInterval: -1}
	if opt.LogPageSize > 0 {
		o.Maximums = core.DefaultLimits()
		o.Maximums.LogPageSize = opt.LogPageSize
	}
	testenv.Apply(&o)
	s := &Server{auth: opt.Auth}
	if !opt.RealClock {
		s.Clock = &Clock{t: opt.Start}
		o.Now = s.Clock.Now
	}
	if opt.Auth {
		pub, priv := grant.GenerateKey()
		ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": pub, "can": []any{"*"}}}))
		if err != nil {
			t.Fatal(err)
		}
		o.OperatorKeys = ks
		s.OperatorKey = priv
	}
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	s.Engine = e
	var h http.Handler = server.New(e)
	if opt.Wrap != nil {
		h = opt.Wrap(h)
	}
	s.HTTP = httptest.NewServer(CountPages(h))
	s.URL = s.HTTP.URL
	t.Cleanup(func() {
		s.HTTP.CloseClientConnections()
		s.HTTP.Close()
		e.Close()
	})
	return s
}

// pagesServed counts log range answers that continued (X-Log-Next).
var pagesServed atomic.Int64

// CountPages wraps a server's handler to count the log range answers it
// serves that continue on another page (X-Log-Next, §7.1), for Paged.
// Servers from New are wrapped already.
func CountPages(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		// The header map outlives the answer.
		if w.Header().Get("X-Log-Next") != "" {
			pagesServed.Add(1)
		}
	})
}

// Paged runs a test's flows with a log page size of n (§6.6): every test
// server they start (New, or a handler wrapped by CountPages and an engine
// set up with testenv.Apply) answers at most n entries per log range page,
// so every client on the way must follow X-Log-Next (§7.1 Paging). It
// fails unless some range did span pages.
func Paged(t *testing.T, n int, run func(*testing.T)) {
	t.Helper()
	t.Setenv(testenv.LogPageSizeEnv, strconv.Itoa(n))
	before := pagesServed.Load()
	run(t)
	if !t.Failed() && pagesServed.Load() == before {
		t.Fatalf("no log range spanned pages of %d", n)
	}
}

// Now is the engine's current time.
func (s *Server) Now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// AuthProxy returns the URL of a proxy to the server whose GET / says
// "auth": mode (§1, §7), as the same deployment restarted in that mode
// would, e.g. "grants" for a development server's database served with
// authentication on. Everything else passes through unchanged.
func (s *Server) AuthProxy(t testing.TB, mode string) string {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	// The server's own pool, not http.DefaultTransport's, whose idle
	// connections any test server closing closes.
	rp.Transport = s.HTTP.Client().Transport
	rp.ModifyResponse = func(r *http.Response) error {
		if r.Request.URL.Path != "/" || r.StatusCode != 200 {
			return nil
		}
		var m map[string]any
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		m["auth"] = mode
		b, _ = json.Marshal(m)
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
		return nil
	}
	p := httptest.NewServer(rp)
	t.Cleanup(p.Close)
	return p.URL
}

// Client returns a client for the server. Without Auth, the server says
// at GET / that authentication is disabled (§1, client.AuthDisabled).
func (s *Server) Client(t testing.TB, opts ...client.Option) *client.Client {
	t.Helper()
	c, err := client.New(s.URL, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// OperatorGrant mints a grant with the operator key allowing the creation
// of namespace ns (§C.4).
func (s *Server) OperatorGrant(t testing.TB, ns string) string {
	return Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"config"},
		"exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
}

// Key is a namespace signing key.
type Key struct {
	Kid  string
	Pub  string
	Priv ed25519.PrivateKey
}

// NewKey generates a key pair.
func NewKey(kid string) Key {
	pub, priv := grant.GenerateKey()
	return Key{kid, pub, priv}
}

// Entry is the key's namespace-document entry with verbs can.
func (k Key) Entry(can ...string) map[string]any {
	c := make([]any, len(can))
	for i, x := range can {
		c[i] = x
	}
	return map[string]any{"kid": k.Kid, "alg": "ed25519", "pub": k.Pub, "can": c}
}

// Grant mints a root grant signed by k for sub on namespaces ns with verbs
// can, valid for an hour from now; extra fields are merged into the block.
func (k Key) Grant(t testing.TB, now time.Time, sub string, ns []string, can []string, extra ...map[string]any) string {
	t.Helper()
	root := map[string]any{"kid": k.Kid, "sub": sub, "ns": toAny(ns), "exp": now.Add(time.Hour).Format(time.RFC3339)}
	if can != nil {
		root["can"] = toAny(can)
	}
	for _, x := range extra {
		for kk, v := range x {
			root[kk] = v
		}
	}
	return Mint(t, k.Priv, root)
}

// Mint signs a root block.
func Mint(t testing.TB, priv ed25519.PrivateKey, root map[string]any) string {
	t.Helper()
	g, err := grant.Mint(root, priv)
	if err != nil {
		t.Fatal(err)
	}
	return g.Encode()
}

func toAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
