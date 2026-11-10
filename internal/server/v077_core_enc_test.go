package server

import (
	"bytes"
	"context"
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

// V77-01 (v0.77): a remote branch of an E3 source raised from sealed
// stores and serves the source's sealings of content from before the raise
// only once it has opened and verified them (§G.3 Creating one, §G.5.2 E3
// sources).

// v077Raised is A, with namespace m sealed, then raised to e2e: x, y and
// w written before the raise, and z referencing a blob, with their first
// revisions, and the raise's ns_id.
type v077Raised struct {
	a                   *tenv
	kA                  keyPair
	root                func() string
	x1, y1, w1, z1, bid string
	data                []byte
	raised              string
}

func newV077Raised(t *testing.T) *v077Raised {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	r := &v077Raised{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
	r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
	r.x1 = a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), r.root())
	r.y1 = a.wr("m", "y", "", withNonce(addRoot(map[string]any{"v": 2.0})), r.root())
	r.w1 = a.wr("m", "w", "", withNonce(addRoot(map[string]any{"v": 3.0})), r.root())
	r.data = []byte("z's blob from before the raise")
	r.bid = a.upload("m", "z", "text/plain", r.data, r.root())
	r.z1 = a.wr("m", "z", "", withNonce(addRoot(map[string]any{"b": ref(r.bid, "text/plain", len(r.data), "")})), r.root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
	r.raised = a.nsHead("m", r.root())
	return r
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

// newV077B is B, whose remote endpoint for A is the proxy, with a grant on
// A that gets A's keys of the epochs before its raise (enc, nbf).
func newV077B(t *testing.T, r *v077Raised, p *v077Proxy) *tenv {
	t.Helper()
	bJWK, bID, _ := seal.GenerateRecipient()
	var mu sync.Mutex
	id := bID
	rt := &route{url: p.srv.URL, bearer: r.a.grant(r.kA, "svc:b", []string{"m"}, []string{"read", "export"},
		map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	return b
}

const v077Forbidden = `{"code":"forbidden","message":"not for this grant"}`

// §G.3 Creating one, §G.5.2 E3 sources: A's /keys refuses B's grant the
// keys of the epochs before its raise, or omits them, so B can't open A's
// sealings of that content: creation is 422, as for a base B can't read.
// Before v0.77 B created the branch and served A's bytes it had checked
// only by shape. B's client asks A's /keys first for the keys that open
// A's sealed namespace documents; the second request is the one for the
// pre-raise keys (fetchPreRaiseKeys).
func TestV077EncPreRaiseNoKeyIs422(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	for what, ans := range map[string]v077Answer{
		"refused": {2, http.StatusForbidden, v077Forbidden},
		"omitted": {2, http.StatusOK, `{"level":"e2e","epoch":2,"keys":[]}`},
	} {
		p := newV077Proxy(t, r.a, map[string]v077Answer{"POST /ns/m/keys": ans})
		b := newV077B(t, r, p)
		kB := newKey("badmin")
		res := b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
		if res.Code != 422 || res.Str("code") != "invalid" {
			t.Fatalf("%s: %d %s, want 422 invalid", what, res.Code, res.Body)
		}
	}
	// A transient failure of A's /keys is no answer: 502, never 422.
	p := newV077Proxy(t, r.a, map[string]v077Answer{"POST /ns/m/keys": {2, http.StatusRequestTimeout, `{"message":"slow"}`}})
	b := newV077B(t, r, p)
	kB := newKey("badmin")
	res := b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
	expectCode(t, res, 502, "upstream")
}

// §G.5.2 E3 sources, §G.3 Reading through (scenario 72): A's sealings B
// couldn't fetch at creation, refused (403), answered 503 or 429, answer
// 502 upstream on B. Once a sync fetches, opens and verifies them, B
// stores and serves A's bytes; where A answers 410 pruned, B answers 410
// pruned with A's horizon from then on, and post-raise reads are
// unaffected. Before v0.77 nothing fetched them again: they stayed 502.
func TestV077EncPreRaiseSealingsAfterCreation(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	// x's document is read once, for A's sealing; w's log and z's blob
	// sealing are read once to mirror w's chain (fetchChain) and z's blob
	// (fetchBlobs), then again for A's sealings.
	zBlob := blobPath("m", "z", r.bid) + "/e/1"
	wLog := "/r/m/w/rev/" + r.w1 + "/log"
	p := newV077Proxy(t, r.a, map[string]v077Answer{
		"GET /r/m/x/rev/" + r.x1: {1, http.StatusServiceUnavailable, `{"message":"down"}`},
		"GET " + wLog:            {2, http.StatusForbidden, v077Forbidden},
		"GET " + zBlob:           {2, http.StatusTooManyRequests, `{"message":"later"}`},
	})
	b := newV077B(t, r, p)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	xPath, wPath, zPath := "/r/r/x/rev/"+r.x1, "/r/r/w/rev/"+r.w1+"/log", blobPath("r", "z", r.bid)+"/e/1"
	for _, path := range []string{xPath, wPath, zPath} {
		res := b.get(path, g)
		expectCode(t, res, 502, "upstream")
		if res.Str("origin") != originA {
			t.Fatalf("%s: %s, want origin %s", path, res.Body, originA)
		}
	}
	// A sync while A still refuses changes nothing.
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	expectCode(t, b.get(xPath, g), 502, "upstream")

	// A serves x's document and z's blob sealing again, and has pruned
	// w's history: w has a revision w2 past the branch's at (e2e: the
	// server checks kid and pl only), A's horizon, which A keeps (§8.6).
	// v0.26.1: a horizon is a revision after the pruned one, w1 itself
	// never being A's honest horizon for w1's entry.
	wr := r.a.writeRaw("m", "w", r.w1, sealed(t, seal.NewKey(), "m#2", "m", "w", r.w1, ops(op("replace", "/v", 4.0))), r.root())
	expect(t, wr, 201)
	w2 := etagOf(wr)
	p.set(map[string]v077Answer{"GET " + wLog: {1, http.StatusGone, `{"code":"pruned","horizon":"` + w2 + `","message":"pruned"}`}})
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	ra, rb := r.a.get("/r/m/x/rev/"+r.x1, r.root()), b.get(xPath, g)
	expect(t, ra, 200)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("x's document after the sync: %d %.160s, want A's bytes %.120s", rb.Code, rb.Body, ra.Body)
	}
	ra, rb = r.a.get(zBlob, r.root()), b.get(zPath, g)
	expect(t, ra, 200)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("z's blob sealing after the sync: %d %.160s, want A's bytes", rb.Code, rb.Body)
	}
	res := b.get(wPath, g)
	expectCode(t, res, 410, "pruned")
	if res.Str("horizon") != w2 {
		t.Fatalf("w's log: %s, want A's horizon %s", res.Body, w2)
	}
	// Pruned isn't final here (v0.26.1): w2, past the branch's at, is a
	// horizon A could fabricate (its log verifies only that A can chain
	// it), so B asks again after its backoff, and stores A's sealing once
	// A serves it. Until then, 410 stands.
	p.set(nil)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	expectCode(t, b.get(wPath, g), 410, "pruned")
	b.clock.Advance(5 * time.Minute)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	ra, rb = r.a.get(wLog, r.root()), b.get(wPath, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("w's log once A serves it again: %d %.160s, want A's bytes", rb.Code, rb.Body)
	}
	// What A served at creation is A's bytes throughout.
	ra, rb = r.a.get("/r/m/y/rev/"+r.y1, r.root()), b.get("/r/r/y/rev/"+r.y1, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("y's document: %d %.120s, want A's bytes", rb.Code, rb.Body)
	}
}

// v077PrunedW is A, with namespace m sealed and w's entries w1 and w2
// written before its raise to e2e, behind a proxy that answers the ranges
// of w's log from genesis, from the from-th such request on, with status
// (0: as A does): 403, or 410 pruned with horizon w2, as A would once it
// pruned w1's patch set (§7.1). Every other request, a range since w1
// included, goes to A, which serves it.
type v077PrunedW struct {
	a                  *tenv
	kA                 keyPair
	root               func() string
	w1, w2, raised     string
	proxy              *httptest.Server
	mu                 sync.Mutex
	status, from, seen int
}

func newV077PrunedW(t *testing.T) *v077PrunedW {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	x := &v077PrunedW{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{x.kA.entry("*")}}))
	x.root = func() string { return a.grant(x.kA, "user:root", []string{"m"}, allVerbs) }
	x.w1 = a.wr("m", "w", "", withNonce(addRoot(map[string]any{"v": 1.0})), x.root())
	x.w2 = a.wr("m", "w", x.w1, withNonce([]any{op("replace", "/v", 2.0)}), x.root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), x.root()), 201)
	x.raised = a.nsHead("m", x.root())
	target, _ := url.Parse(a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	x.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && (r.URL.Path == "/r/m/w/rev/"+x.w1+"/log" || r.URL.Path == "/r/m/w/rev/"+x.w2+"/log") &&
			r.URL.Query().Get("since") == "" {
			x.mu.Lock()
			x.seen++
			st := x.status
			if x.seen < x.from {
				st = 0
			}
			x.mu.Unlock()
			body := v077Forbidden
			if st == http.StatusGone {
				body = `{"code":"pruned","horizon":"` + x.w2 + `","message":"pruned"}`
			}
			if st != 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(st)
				w.Write([]byte(body))
				return
			}
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(x.proxy.Close)
	return x
}

// answer sets the proxy's answer for w's ranges from genesis.
func (x *v077PrunedW) answer(status, from int) {
	x.mu.Lock()
	x.status, x.from, x.seen = status, from, 0
	x.mu.Unlock()
}

// b is B, created from A through the proxy, and a reader's grant there.
func (x *v077PrunedW) b(t *testing.T) (*tenv, string) {
	t.Helper()
	bJWK, bID, _ := seal.GenerateRecipient()
	var mu sync.Mutex
	id := bID
	rt := &route{url: x.proxy.URL, bearer: x.a.grant(x.kA, "svc:b", []string{"m"}, []string{"read", "export"},
		map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", x.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	return b, b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
}

// check is B's answers once A has pruned w1 alone: w2's own range is A's
// bytes, and w1's 410 pruned with A's horizon.
func (x *v077PrunedW) check(t *testing.T, b *tenv, g string) {
	t.Helper()
	w2Only := "/rev/" + x.w2 + "/log?since=" + x.w1
	ra, rb := x.a.get("/r/m/w"+w2Only, x.root()), b.get("/r/r/w"+w2Only, g)
	expect(t, ra, 200)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("w2's own range on B: %d %.200s, want A's bytes, which A still serves", rb.Code, rb.Body)
	}
	res := b.get("/r/r/w/rev/"+x.w1+"/log", g)
	expectCode(t, res, 410, "pruned")
	if res.Str("horizon") != x.w2 {
		t.Fatalf("w1's range on B: %s, want A's horizon %s", res.Body, x.w2)
	}
}

// §G.5.2 E3 sources ("410 where A has pruned it"), §7.1: once A has pruned
// w1's patch set, its log of w from genesis is 410 pruned, though its
// range since w1 still serves w2's entry. A sync asks for each entry that
// 410 leaves pending again, in a range of its own: w1's is 410, so w1 is
// pruned on B for good; w2's is served, so B stores A's sealing of it once
// it has opened and verified it. Before, the whole range's 410 marked w2
// pruned too, and B answered w2's own range 410 though A served it.
func TestV077EncPreRaisePrunedRangeAfterCreation(t *testing.T) {
	t.Parallel()
	x := newV077PrunedW(t)
	// Creation reads w's log from genesis twice, to mirror its chain and
	// for A's sealings; the second is refused, so both entries are pending.
	x.answer(http.StatusForbidden, 2)
	b, g := x.b(t)
	expectCode(t, b.get("/r/r/w/rev/"+x.w2+"/log?since="+x.w1, g), 502, "upstream")
	x.answer(http.StatusGone, 1)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	x.check(t, b, g)
}

// The same at creation (§G.3 Creating one, §G.5.2): A's log of w from
// genesis is 410 pruned when B asks for A's sealings; w2's own range is
// served, so B stores its sealing at once, and only w1 is pruned.
func TestV077EncPreRaisePrunedRangeAtCreation(t *testing.T) {
	t.Parallel()
	x := newV077PrunedW(t)
	x.answer(http.StatusGone, 2)
	b, g := x.b(t)
	x.check(t, b, g)
}
