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
	// w's history.
	p.set(map[string]v077Answer{"GET " + wLog: {1, http.StatusGone, `{"code":"pruned","horizon":"` + r.w1 + `","message":"pruned"}`}})
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
	if res.Str("horizon") != r.w1 {
		t.Fatalf("w's log: %s, want A's horizon %s", res.Body, r.w1)
	}
	// Pruned is final: A serving it again changes nothing.
	p.set(nil)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	expectCode(t, b.get(wPath, g), 410, "pruned")
	// What A served at creation is A's bytes throughout.
	ra, rb = r.a.get("/r/m/y/rev/"+r.y1, r.root()), b.get("/r/r/y/rev/"+r.y1, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("y's document: %d %.120s, want A's bytes", rb.Code, rb.Body)
	}
}
