package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// Remote branches of a source that is end-to-end from its creation
// (Addendum E Levels, §G.5.2): the fixture the v0.26.1 hardening tests of
// remote bases run on since v0.78 cut sources raised to e2e.

// v081Source is A, with namespace m e2e from its creation: x and y written
// as sealed ops under m#1 (key k1), and at, A's head after them.
type v081Source struct {
	a      *tenv
	kA     keyPair
	root   func() string
	k1     []byte
	x1, y1 string
	at     string
}

func newV081Source(t *testing.T, opts ...envOpt) *v081Source {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, append([]envOpt{withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning}, opts...)...)
	a.opPriv = aPriv
	s := &v081Source{a: a, kA: newKey("admin"), k1: seal.NewKey()}
	a.mkNS("m", e2eDoc(map[string]any{"read": "grant", "keys": []any{s.kA.entry("*")}}))
	s.root = func() string { return a.grant(s.kA, "user:root", []string{"m"}, allVerbs) }
	s.x1 = s.write("x", "", addRoot(map[string]any{"v": 1.0}))
	s.y1 = s.write("y", "", addRoot(map[string]any{"v": 2.0}))
	s.at = a.nsHead("m", s.root())
	return s
}

// write writes patches to m's name on parent as a sealed op under m#1,
// and returns the new revision's id.
func (s *v081Source) write(name, parent string, patches []any) string {
	s.a.t.Helper()
	r := s.a.writeRaw("m", name, parent, sealed(s.a.t, s.k1, "m#1", "m", name, parent, patches), s.root())
	expect(s.a.t, r, 201)
	return etagOf(r)
}

// newV081B is B, reaching A at url with a grant on m for read and export,
// with more options for B.
func newV081B(t *testing.T, s *v081Source, url string, opts ...envOpt) *tenv {
	t.Helper()
	rt := &route{url: url, bearer: s.a.grant(s.kA, "svc:b", []string{"m"}, []string{"read", "export"})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, append([]envOpt{withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning}, opts...)...)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	return b
}

// v081Remote creates remote branch name of A's m at s.at on b, e2e as
// its source, and returns a reader's grant there.
func v081Remote(t *testing.T, b *tenv, s *v081Source, name string) (keyPair, string) {
	t.Helper()
	kB := newKey("badmin")
	expect(t, b.mkRemote(name, remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	return kB, b.grant(kB, "user:reader", []string{name}, []string{"read"})
}

// v077Answer is a canned answer of the proxy in front of A.
type v077Answer struct {
	from   int // from the from-th request for the path on
	status int
	body   string
}

// v077Proxy fronts A, answering each path in answers as it says from its
// from-th request on, and everything else as A does. set replaces answers.
type v077Proxy struct {
	mu      sync.Mutex
	answers map[string]v077Answer
	seen    map[string]int
	srv     *httptest.Server
}

func newV077Proxy(t *testing.T, a *tenv, answers map[string]v077Answer) *v077Proxy {
	t.Helper()
	p := &v077Proxy{answers: answers, seen: map[string]int{}}
	target, _ := url.Parse(a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		p.mu.Lock()
		p.seen[key]++
		n := p.seen[key]
		ans, ok := p.answers[key]
		p.mu.Unlock()
		if ok && n >= ans.from {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ans.status)
			w.Write([]byte(ans.body))
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *v077Proxy) set(answers map[string]v077Answer) {
	p.mu.Lock()
	p.answers = answers
	p.mu.Unlock()
}

// count is how many requests the proxy has seen for key ("GET /path").
func (p *v077Proxy) count(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen[key]
}

const v077Forbidden = `{"code":"forbidden","message":"not for this grant"}`
