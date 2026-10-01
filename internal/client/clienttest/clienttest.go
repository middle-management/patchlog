// Package clienttest runs an in-process Patch Log server (internal/core +
// internal/server over httptest) for tests of API consumers, with helpers
// for keys and grants.
package clienttest

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/server"

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
}

// Server is a running test server.
type Server struct {
	URL         string
	Engine      *core.Engine
	HTTP        *httptest.Server
	Clock       *Clock // nil with RealClock
	OperatorKey ed25519.PrivateKey
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
	o := core.Options{Path: pgtest.DB(t), Origin: Origin, AuthDisabled: !opt.Auth, LongPollInterval: opt.LongPoll, Purger: nopPurger{}, KeyStore: opt.KeyStore,
		Archiver: opt.Archiver, RetentionInterval: -1}
	s := &Server{}
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
	s.HTTP = httptest.NewServer(server.New(e))
	s.URL = s.HTTP.URL
	t.Cleanup(func() {
		s.HTTP.CloseClientConnections()
		s.HTTP.Close()
		e.Close()
	})
	return s
}

// Now is the engine's current time.
func (s *Server) Now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// Client returns a client for the server.
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
