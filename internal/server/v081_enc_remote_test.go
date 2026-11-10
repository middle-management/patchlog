package server

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
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

// newV081Pruned is a v081Source whose x A pruned at x2 below at, with its
// snapshot: x1, x2 (the horizon) and x3, at after x3.
func newV081Pruned(t *testing.T) (s *v081Source, x2, x3, snap string) {
	t.Helper()
	s = newV081Source(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	x2 = s.write("x", s.x1, ops(op("replace", "/v", 2.0)))
	x3 = s.write("x", x2, ops(op("replace", "/v", 3.0)))
	s.a.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(s.k1, "m#1", "m", "x", x2, map[string]any{"v": 2.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, s.a.prune("m", "x", map[string]any{"horizon": x2, "snapshot": snap}, s.root()), 200)
	s.at = s.a.nsHead("m", s.root())
	return s, x2, x3, snap
}

// E2E-6 (§G.5.2 E3 sources, §7.1; scenario 66, FED-24): creating a remote
// branch of an E3 source A pruned below at mirrors A's snapshot at its
// horizon, verbatim. B answers /rev itself: the horizon is A's JWE, pl.ns
// naming A's namespace; a later revision is 404 not_offered with that
// horizon, never 502, and B doesn't ask A again.
func TestV081RemoteMirrorsSnapshot(t *testing.T) {
	t.Parallel()
	s, x2, x3, snap := newV081Pruned(t)
	p := newV077Proxy(t, s.a, nil)
	b := newV081B(t, s, p.srv.URL)
	_, g := v081Remote(t, b, s, "r")
	before := p.count("GET /r/m/x/rev/"+x2) + p.count("GET /r/m/x/rev/"+x3)
	r := b.get("/r/r/x/rev/"+x2, g)
	if r.Code != 200 || string(r.Body) != snap || r.H.Get("Content-Type") != seal.ContentType {
		t.Fatalf("B at A's horizon: %d %v %.200s", r.Code, r.H, r.Body)
	}
	if h, err := seal.ParseHeader(string(r.Body)); err != nil || h.PL["ns"] != "m" {
		t.Fatalf("pl %v %v", h, err)
	}
	p.set(map[string]v077Answer{"GET /r/m/x/rev/" + x3: {1, 502, `{"code":"upstream"}`}})
	r = b.get("/r/r/x/rev/"+x3, g)
	expectCode(t, r, 404, "not_offered")
	if r.Str("horizon") != x2 {
		t.Fatalf("B at a later id: %s", r.Body)
	}
	if after := p.count("GET /r/m/x/rev/"+x2) + p.count("GET /r/m/x/rev/"+x3); after != before {
		t.Fatalf("B asked A %d times at read time", after-before)
	}
	// The log from the horizon is A's ciphertext.
	expect(t, b.get("/r/r/x/rev/"+x3+"/log?since="+x2, g), 200)
}

// E2E-6 at a tombstone horizon T with parent P (§E.3.1): B learns P from
// A's not_offered (last), checks that T is P's tombstone, and mirrors A's
// snapshot at P, which it serves there; a later revision names T and P.
func TestV081RemoteMirrorsTombstoneSnapshot(t *testing.T) {
	t.Parallel()
	s := newV081Source(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	x2 := s.write("x", s.x1, ops(op("replace", "/v", 2.0)))
	tomb := s.a.del("m", "x", x2, s.root())
	l := etagOf(s.a.writeRaw("m", "x", tomb, "[]", s.root()))
	s.a.clock.Advance(10 * time.Minute)
	snap, _ := seal.SealSnapshot(s.k1, "m#1", "m", "x", x2, map[string]any{"v": 2.0})
	expect(t, s.a.prune("m", "x", map[string]any{"horizon": tomb, "snapshot": snap}, s.root()), 200)
	s.at = s.a.nsHead("m", s.root())
	b := newV081B(t, s, s.a.srv.URL)
	_, g := v081Remote(t, b, s, "r")
	if r := b.get("/r/r/x/rev/"+x2, g); r.Code != 200 || string(r.Body) != snap {
		t.Fatalf("B at P: %d %.200s", r.Code, r.Body)
	}
	expect(t, b.get("/r/r/x/rev/"+tomb, g), 410)
	r := b.get("/r/r/x/rev/"+l, g)
	expectCode(t, r, 404, "not_offered")
	if r.Str("horizon") != tomb || r.Str("last") != x2 {
		t.Fatalf("B at a later id: %s", r.Body)
	}
}

// E2E-6 against a hostile A (v0.26.1 C4, C-M; formerly the pending
// pre-raise sealings' strict-JWE, cap and redirect tests): B takes A's
// snapshot only as a strict compact JWE (no CR or LF inside a segment),
// within its cap, served 200 (a redirect isn't followed) and bound to A's
// horizon. Anything else is a creation 502 upstream, and nothing is kept.
func TestV081RemoteSnapshotHostile(t *testing.T) {
	t.Parallel()
	s, x2, _, snap := newV081Pruned(t)
	parts := strings.Split(snap, ".")
	inflated := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3][:4] + "\r\n" + parts[3][4:] + "." + parts[4]
	other, _ := seal.SealSnapshot(s.k1, "m#1", "m", "x", s.x1, map[string]any{"v": 1.0})
	foreign, _ := seal.SealSnapshot(s.k1, "q#1", "q", "x", x2, map[string]any{"v": 2.0})
	var hit int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	t.Cleanup(target.Close)
	for name, serve := range map[string]func(w http.ResponseWriter){
		"CR/LF in a segment": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", seal.ContentType)
			w.Write([]byte(inflated))
		},
		"over the cap": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", seal.ContentType)
			w.Write([]byte(parts[0] + "..." + strings.Repeat("A", 3<<20) + "." + parts[4]))
		},
		"another revision's": func(w http.ResponseWriter) { w.Header().Set("Content-Type", seal.ContentType); w.Write([]byte(other)) },
		"another namespace's": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", seal.ContentType)
			w.Write([]byte(foreign))
		},
		"a redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", target.URL+"/x")
			w.WriteHeader(http.StatusFound)
		},
		"not jose": func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/json"); w.Write([]byte(snap)) },
	} {
		t.Run(name, func(t *testing.T) {
			tg, _ := url.Parse(s.a.srv.URL)
			rp := httputil.NewSingleHostReverseProxy(tg)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/r/m/x/rev/"+x2 {
					serve(w)
					return
				}
				rp.ServeHTTP(w, r)
			}))
			t.Cleanup(front.Close)
			b := newV081B(t, s, front.URL)
			kB := newKey("badmin")
			r := b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
			expectCode(t, r, 502, "upstream")
			// Nothing was kept: the name is free (not 412).
			expectCode(t, b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 502, "upstream")
		})
	}
	if hit != 0 {
		t.Fatalf("B followed A's redirect %d times", hit)
	}
}

// E2E-6, an honest A with a large snapshot (formerly
// TestV0261HonestLargeAtCreation): B's cap takes a snapshot of a document
// of this deployment's maximum size class.
func TestV081RemoteSnapshotHonestLarge(t *testing.T) {
	t.Parallel()
	s := newV081Source(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	unit := "é<>&\"\\\t 😀abc"
	big := map[string]any{}
	for i := 0; i < 8; i++ {
		big[fmt.Sprint("k", i)] = strings.Repeat(unit, (48<<10)/len(unit))
	}
	x2 := s.write("x", s.x1, ops(op("replace", "/v", 2.0)))
	s.a.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(s.k1, "m#1", "m", "x", x2, big)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, s.a.prune("m", "x", map[string]any{"horizon": x2, "snapshot": snap}, s.root()), 200)
	s.at = s.a.nsHead("m", s.root())
	b := newV081B(t, s, s.a.srv.URL)
	_, g := v081Remote(t, b, s, "r")
	if r := b.get("/r/r/x/rev/"+x2, g); r.Code != 200 || string(r.Body) != snap {
		t.Fatalf("B at A's horizon: %d, %d bytes", r.Code, len(r.Body))
	}
}

// E2E-6 (§8.3, §8.5; formerly TestV0261PreRaisePurgeDeletesShadowSealings):
// B's purge of the resource, or of the remote branch, deletes the
// snapshot it mirrored.
func TestV081RemotePurgeDeletesMirroredSnapshot(t *testing.T) {
	t.Parallel()
	s, x2, x3, _ := newV081Pruned(t)
	var path string
	b := newV081B(t, s, s.a.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
	kB, g := v081Remote(t, b, s, "r")
	kQ, _ := v081Remote(t, b, s, "q")
	db, pg := v0261DB(t, path)
	count := func(branch string) int {
		return v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots s JOIN resources r ON r.res = s.res JOIN namespaces n ON n.ns = r.ns WHERE n.name = '~`+branch+`'`)
	}
	if count("r") != 1 || count("q") != 1 {
		t.Fatalf("mirrored snapshots: r %d, q %d", count("r"), count("q"))
	}
	admin := b.grant(kB, "user:admin", []string{"r"}, allVerbs)
	expect(t, b.purge("r", "x", x3, admin), 204)
	if count("r") != 0 {
		t.Fatal("the resource purge kept the mirrored snapshot")
	}
	expect(t, b.get("/r/r/x/rev/"+x2, g), 410)
	adminQ := b.grant(kQ, "user:admin", []string{"q"}, allVerbs)
	expect(t, b.patchNS("q", ops(op("add", "/frozen", true)), adminQ), 201)
	expect(t, b.do(req{method: "POST", path: "/ns/q/purge", ifMatch: b.nsHead("q", adminQ), bearer: adminQ}), 204)
	if count("q") != 0 {
		t.Fatal("the namespace purge kept the mirrored snapshot")
	}
}

// E2E-7 (§G.5.2, §G.3; Addendum E Levels): a source a pre-v0.78 deployment
// raised to e2e before at (simulated with LegacyE2ERaiseForTests on A)
// isn't e2e from its creation: creation is 502 upstream, and B keeps no
// shadow and no keys.
func TestV081RemoteRaisedSourceRefused(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withLegacyE2ERaise)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := a.grant(kA, "user:root", []string{"m"}, allVerbs)
	a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), root), 201)
	s := &v081Source{a: a, kA: kA, root: func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }, at: a.nsHead("m", root)}
	var path string
	b := newV081B(t, s, a.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
	kB := newKey("badmin")
	r := b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
	expectCode(t, r, 502, "upstream")
	if !strings.Contains(r.Str("message"), "e2e from its creation") {
		t.Fatalf("refusal %s", r.Body)
	}
	db, pg := v0261DB(t, path)
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM epoch_keys`); n != 0 {
		t.Fatalf("%d epoch keys on B", n)
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM namespaces WHERE name LIKE '~%'`); n != 0 {
		t.Fatalf("%d shadows on B", n)
	}
}

// v0.26.1 C1, C3 (formerly TestV0261FetchSealedLogBounds, whose pre-raise
// log paging v0.78 cut): a hostile A that pages the log B mirrors from its
// horizon for ever, an empty page with a fresh X-Log-Next each time,
// doesn't hold creation: it ends within FollowTimeout, 502 upstream.
func TestV081RemoteSnapshotLogPagingBounded(t *testing.T) {
	t.Parallel()
	s, x2, x3, _ := newV081Pruned(t)
	var pages atomic.Int64
	tg, _ := url.Parse(s.a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(tg)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/r/m/x/rev/"+x3+"/log" && r.URL.Query().Get("since") != "" {
			n := pages.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Log-Next", fmt.Sprintf("%s%d", x2, n))
			w.Write([]byte("[]"))
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	b := newV081B(t, s, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = 2 * time.Second })
	kB := newKey("badmin")
	start := time.Now()
	r := b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
	el := time.Since(start)
	t.Logf("creation after %v and %d pages: %d %.200s", el, pages.Load(), r.Code, r.Body)
	if el > 4*time.Second || pages.Load() == 0 {
		t.Fatalf("creation took %v over %d pages", el, pages.Load())
	}
	if r.Code != 502 {
		t.Fatalf("creation: %d %s, want 502", r.Code, r.Body)
	}
}
