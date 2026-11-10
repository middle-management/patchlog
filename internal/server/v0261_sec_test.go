package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v0.26.1: a remote branch's pending pre-raise sealings (V77-01) against a
// hostile remote base A (security review of v0.26.0, C1-C5, C-M, C-B,
// C-E).

// count is how many requests the proxy has seen for key ("GET /path").
func (p *v077Proxy) count(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen[key]
}

// newV0261B is newV077B with more options for B.
func newV0261B(t *testing.T, r *v077Raised, proxyURL string, opts ...envOpt) *tenv {
	t.Helper()
	bJWK, bID, _ := seal.GenerateRecipient()
	var mu sync.Mutex
	id := bID
	rt := &route{url: proxyURL, bearer: r.a.grant(r.kA, "svc:b", []string{"m"}, []string{"read", "export"},
		map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, append([]envOpt{withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)),
		withEncTuning, withBlobTuning}, opts...)...)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	return b
}

// v0261Remote creates remote branch name of A's m on b, and returns a
// reader's grant there.
func v0261Remote(t *testing.T, b *tenv, r *v077Raised, name string) (keyPair, string) {
	t.Helper()
	kB := newKey("badmin")
	expect(t, b.mkRemote(name, remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	return kB, b.grant(kB, "user:reader", []string{name}, []string{"read"})
}

// C1: A's log of a pending entry, asked for at every sync, paged as long
// as A named a new X-Log-Next (fetchSealedLog). A answering 200 [] with a
// fresh X-Log-Next every time kept SyncRemotes, sequential over every
// remote branch on the follower's goroutine, in that loop for ever: one
// sync asked A for some 40,000 pages in 3 s. X-Log-Next must now name an
// entry of the range, on the page, after the page's since: one page, and
// the sync returns at once.
func TestV0261PreRaiseLogPagingUnbounded(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	p := newV077Proxy(t, r.a, map[string]v077Answer{})
	wLog := "/r/m/w/rev/" + r.w1 + "/log"
	// Creation: w's log is read twice, for the chain, then for A's
	// sealings; refuse the second so w1's entry is pending.
	p.set(map[string]v077Answer{"GET " + wLog: {2, http.StatusForbidden, v077Forbidden}})
	b := newV077B(t, r, p)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)

	// Now A pages for ever: a 200 empty page, with a new X-Log-Next each time.
	var pages atomic.Int64
	// Serve the paging answer from the proxy's own server.
	inner := p.srv.Config.Handler
	p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" && req.URL.Path == wLog {
			n := pages.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Log-Next", "p"+strconv.FormatInt(n, 10))
			w.WriteHeader(200)
			w.Write([]byte("[]"))
			return
		}
		inner.ServeHTTP(w, req)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	err := b.e.SyncRemotes(ctx)
	el := time.Since(start)
	t.Logf("SyncRemotes returned after %v (%d log pages asked of A): %v", el, pages.Load(), err)
	if n := pages.Load(); n > 1000 || ctx.Err() != nil {
		t.Fatalf("one sync asked A for %d pages of w's log and ran until the deadline (%v): paging is unbounded", n, el)
	}
	// Bounded by w's chain, of one entry: one page, and a sync that
	// finishes at once.
	if n := pages.Load(); n < 1 || n > 2 || el > 2*time.Second {
		t.Fatalf("one sync asked A for %d pages of w's log in %v, want 1 or 2, quickly", n, el)
	}
	// The same with an X-Log-Next that is an entry of w's range but not on
	// the page, or one that doesn't move forward: one page each.
	for _, next := range []string{r.w1, ""} {
		pages.Store(0)
		p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == "GET" && req.URL.Path == wLog {
				pages.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if next != "" {
					w.Header().Set("X-Log-Next", next)
				} else {
					w.Header().Set("X-Log-Next", req.URL.Query().Get("since")+"x")
				}
				w.WriteHeader(200)
				w.Write([]byte("[]"))
				return
			}
			inner.ServeHTTP(w, req)
		})
		b.clock.Advance(5 * time.Hour) // past any backoff
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := b.e.SyncRemotes(ctx)
		late := ctx.Err()
		cancel()
		if n := pages.Load(); n < 1 || n > 2 || late != nil {
			t.Fatalf("X-Log-Next %q: %d pages of w's log asked for (%v)", next, n, err)
		}
	}
	p.srv.Config.Handler = inner
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	expectCode(t, b.get("/r/r/w/rev/"+r.w1+"/log", g), 502, "upstream")
}

// v0261Paged is A with namespace m sealed and w's entries w1…w5 written
// before its raise to e2e, and a log page size of 2, so that each range of
// w's log from genesis takes three pages.
type v0261Paged struct {
	*v077Raised
	w []string
}

func newV0261Paged(t *testing.T) *v0261Paged {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning, withLogPageSize(2))
	a.opPriv = aPriv
	r := &v077Raised{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
	r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
	x := &v0261Paged{v077Raised: r}
	prev := ""
	for i := 1; i <= 5; i++ {
		var ps []any
		if prev == "" {
			ps = withNonce(addRoot(map[string]any{"v": 1.0}))
		} else {
			ps = withNonce([]any{op("replace", "/v", float64(i))})
		}
		prev = a.wr("m", "w", prev, ps, r.root())
		x.w = append(x.w, prev)
	}
	r.w1 = x.w[0]
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
	r.raised = a.nsHead("m", r.root())
	return x
}

// An honest A paging w's log (its page size is 2, so five pre-raise entries
// take three pages): at creation, and at a sync after A refused it there,
// B reads every page and stores A's sealing of each entry, as A serves
// them. The bounds of C1 refuse nothing A honestly serves.
func TestV0261PreRaiseHonestPaging(t *testing.T) {
	t.Parallel()
	x := newV0261Paged(t)
	last := x.w[len(x.w)-1]
	wLog := "/r/m/w/rev/" + last + "/log"
	check := func(b *tenv, g string) {
		t.Helper()
		for i, id := range x.w {
			path := "/rev/" + id + "/log"
			if i > 0 {
				path += "?since=" + x.w[i-1]
			}
			ra, rb := x.a.get("/r/m/w"+path, x.root()), b.get("/r/r/w"+path, g)
			expect(t, ra, 200)
			if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
				t.Fatalf("w's entry %d on B: %d %.200s, want A's bytes %.120s", i+1, rb.Code, rb.Body, ra.Body)
			}
		}
	}
	t.Run("creation", func(t *testing.T) {
		p := newV077Proxy(t, x.a, nil)
		b := newV077B(t, x.v077Raised, p)
		_, g := v0261Remote(t, b, x.v077Raised, "r")
		if n := p.count("GET " + wLog); n < 6 {
			t.Fatalf("A was asked for %d pages of w's log, want 3 for the chain and 3 for its sealings", n)
		}
		check(b, g)
	})
	t.Run("sync", func(t *testing.T) {
		// The chain takes three pages; refuse the fourth on, A's sealings.
		p := newV077Proxy(t, x.a, map[string]v077Answer{"GET " + wLog: {4, http.StatusForbidden, v077Forbidden}})
		b := newV077B(t, x.v077Raised, p)
		_, g := v0261Remote(t, b, x.v077Raised, "r")
		expectCode(t, b.get("/r/r/w/rev/"+x.w[0]+"/log", g), 502, "upstream")
		p.set(nil)
		before := p.count("GET " + wLog)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		if n := p.count("GET " + wLog); n-before < 3 {
			t.Fatalf("the sync asked A for %d pages of w's log, want 3", n-before)
		}
		check(b, g)
	})
}

// C2: A's 410 for a pending sealing counted as final "pruned" on any body
// with code "pruned", and its horizon, any string of any size, was stored
// and served by B for good (pendingAnswer, preRaiseUnfetched). A horizon
// is now taken only if it is a revision of that resource's mirrored chain
// at or after the pending revision; any other 410 is refused, not final:
// 502 upstream, asked again.
func TestV0261PreRaisePrunedHorizonUnvalidated(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
	b := newV077B(t, r, p)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")

	big := "not-a-revision-" + strings.Repeat("A", 8<<20)
	p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + big + `"}`}})
	before := p.count("GET " + xDoc)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	if p.count("GET "+xDoc) == before {
		t.Fatalf("the sync didn't ask A for x's document")
	}
	res := b.get("/r/r/x/rev/"+r.x1, g)
	hz := res.Str("horizon")
	t.Logf("B: %d, %d-byte body, horizon of %d bytes, Cache-Control %q", res.Code, len(res.Body), len(hz), res.H.Get("Cache-Control"))
	if res.Code == 410 {
		if _, err := ids.Parse(hz); err != nil {
			t.Fatalf("B answers x's document 410 pruned for good with A's horizon of %d bytes, not a revision id (%.40q...)", len(hz), hz)
		}
	}
	expectCode(t, res, 502, "upstream")
	// A revision id that isn't in x's chain (y's), and none: refused too.
	for _, hz := range []string{`"horizon":"` + r.y1 + `",`, ``} {
		b.clock.Advance(5 * time.Hour)
		p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned",` + hz + `"message":"pruned"}`}})
		before := p.count("GET " + xDoc)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		if p.count("GET "+xDoc) == before {
			t.Fatalf("%s: the sync didn't ask A for x's document", hz)
		}
		g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
		expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
	}
	// x's own revision isn't A's horizon for its own document, which A
	// keeps at its horizon (§8.6): refused (v0.26.1, where v0.26.0 took
	// it).
	b.clock.Advance(5 * time.Hour)
	p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + r.x1 + `"}`}})
	before = p.count("GET " + xDoc)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	if p.count("GET "+xDoc) == before {
		t.Fatalf("the sync didn't ask A for x's document")
	}
	g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
	// A revision after it, past the branch's at, which A's log verifies:
	// 410 (not final, being past at: TestV0261ForgedPastHorizonWhileRegistered).
	x2 := v0261After(t, r, "x", r.x1)
	b.clock.Advance(5 * time.Hour)
	p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + x2 + `"}`}})
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	res = b.get("/r/r/x/rev/"+r.x1, g)
	expectCode(t, res, 410, "pruned")
	if res.Str("horizon") != x2 {
		t.Fatalf("x's document: %s, want horizon %s", res.Body, x2)
	}
}

// v0261After writes a revision of name after parent on r's A, past its
// raise to e2e (the server checks the sealed op's kid and pl only), and
// returns its id.
func v0261After(t *testing.T, r *v077Raised, name, parent string) string {
	t.Helper()
	wr := r.a.writeRaw("m", name, parent, sealed(t, seal.NewKey(), "m#2", "m", name, parent, ops(op("replace", "/v", 9.0))), r.root())
	expect(t, wr, 201)
	return etagOf(wr)
}

// The same at creation: a 410 whose horizon isn't in the chain leaves the
// sealing pending as refused, never pruned.
func TestV0261PreRaisePrunedHorizonAtCreation(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"junk"}`}})
	b := newV077B(t, r, p)
	_, g := v0261Remote(t, b, r, "r")
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
}

// After x is purged on the branch, its pre-raise URLs answer as purged,
// never with A's pruned horizon.
func TestV0261PreRaisePrunedRowAfterPurge(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	// A's horizon is a revision after x1 (v0.26.1: never x1 itself), one
	// past the branch's at, which A's log verifies.
	x2 := v0261After(t, r, "x", r.x1)
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + x2 + `"}`}})
	b := newV077B(t, r, p)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 410, "pruned")
	root := b.grant(kB, "user:root", []string{"r"}, allVerbs)
	res := b.purge("r", "x", r.x1, root)
	t.Logf("purge: %d %s", res.Code, res.Body)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	for _, path := range []string{"/r/r/x/rev/" + r.x1, "/r/r/x/rev/" + r.x1 + "/log", "/r/r/x"} {
		res := b.get(path, g)
		t.Logf("%s: %d %s", path, res.Code, res.Body)
		if res.Str("code") == "pruned" {
			t.Fatalf("%s after the purge: %s", path, res.Body)
		}
	}
}

// C4: a pending sealing was fetched at every sync with rawGet, which
// followed A's redirects anywhere: a blind SSRF at every sync, with B's
// grant forwarded to another port of A's host. A 3xx is now no answer:
// the target is never asked.
func TestV0261PreRaiseRedirectFollowed(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
	b := newV077B(t, r, p)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)

	var hits, asked atomic.Int64
	var auth atomic.Value
	auth.Store("")
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		auth.Store(req.Header.Get("Authorization"))
		w.WriteHeader(404)
	}))
	t.Cleanup(other.Close)
	port := other.Listener.Addr().(*net.TCPAddr).Port
	for _, host := range []string{"localhost", "127.0.0.1"} {
		hits.Store(0)
		asked.Store(0)
		auth.Store("")
		target := "http://" + host + ":" + strconv.Itoa(port) + "/internal/metadata"
		inner := p.srv.Config.Handler
		p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == "GET" && req.URL.Path == xDoc {
				asked.Add(1)
				http.Redirect(w, req, target, http.StatusFound)
				return
			}
			inner.ServeHTTP(w, req)
		})
		for i := 0; i < 3; i++ {
			b.clock.Advance(5 * time.Hour) // past any backoff
			b.e.SyncRemotes(context.Background())
		}
		p.srv.Config.Handler = inner
		a, _ := auth.Load().(string)
		t.Logf("redirect to %s: hit %d times over 3 syncs, Authorization forwarded: %v", host, hits.Load(), a != "")
		if asked.Load() == 0 {
			t.Fatalf("the syncs didn't ask A for x's document")
		}
		if hits.Load() > 0 {
			t.Errorf("B followed A's redirect to %s at every sync (%d hits, Authorization forwarded: %v)", target, hits.Load(), a != "")
		}
	}
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
}

// C3: A's real sealing of x's document padded with trailing whitespace
// opened (openPreSealing trims) but was stored untrimmed and served by B
// at that size. B now stores the trimmed sealing, A's bytes as A serves
// them, and reads no more than a sealing's cap of A's answer.
func TestV0261PreRaisePaddedSealingStored(t *testing.T) {
	t.Parallel()
	for _, pad := range []int{1 << 10, 8 << 20} {
		r := newV077Raised(t)
		xDoc := "/r/m/x/rev/" + r.x1
		p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
		b := newV077B(t, r, p)
		kB := newKey("badmin")
		expect(t, b.mkRemote("r", remoteGenesis("m", r.raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
		g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
		real := r.a.get(xDoc, r.root())
		expect(t, real, 200)
		padded := string(real.Body) + strings.Repeat(" ", pad)
		p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusOK, padded}})
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		res := b.get("/r/r/x/rev/"+r.x1, g)
		t.Logf("pad %d: B serves x's document: %d, %d bytes (A's sealing is %d bytes)", pad, res.Code, len(res.Body), len(real.Body))
		if res.Code == 200 && len(res.Body) > len(real.Body)+64 {
			t.Fatalf("B stored and serves A's sealing padded to %d bytes", len(res.Body))
		}
		if pad == 1<<10 && (res.Code != 200 || !bytes.Equal(res.Body, real.Body)) {
			t.Fatalf("pad %d: B serves x's document %d %.120s, want A's bytes", pad, res.Code, res.Body)
		}
	}
}

// C3, for log entries: each sealing in a log page is a JSON string, which
// A can pad too. B stores each trimmed.
func TestV0261PreRaisePaddedLogEntryStored(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	wLog := "/r/m/w/rev/" + r.w1 + "/log"
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + wLog: {2, http.StatusForbidden, v077Forbidden}})
	b := newV077B(t, r, p)
	_, g := v0261Remote(t, b, r, "r")
	real := r.a.get(wLog, r.root())
	expect(t, real, 200)
	var page []string
	if err := json.Unmarshal(real.Body, &page); err != nil || len(page) != 1 {
		t.Fatalf("A's page of w's log: %v %s", err, real.Body)
	}
	padded, _ := json.Marshal([]string{page[0] + strings.Repeat(" ", 4<<10)})
	p.set(map[string]v077Answer{"GET " + wLog: {1, http.StatusOK, string(padded)}})
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	res := b.get("/r/r/w/rev/"+r.w1+"/log", g)
	if res.Code != 200 || !bytes.Equal(res.Body, real.Body) {
		t.Fatalf("w's log on B: %d %d bytes, want A's %d bytes", res.Code, len(res.Body), len(real.Body))
	}
}

// v0261DB opens the database at path (withFileDB), and says whether it is
// Postgres, whose placeholders are $n.
func v0261DB(t *testing.T, path string) (*sql.DB, bool) {
	t.Helper()
	driver, dsn := "sqlite", sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)")
	if strings.HasPrefix(path, "postgres") {
		driver, dsn = "pgx", pgtest.DSN(path)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, driver == "pgx"
}

func v0261Count(t *testing.T, db *sql.DB, pg bool, q string, args ...any) int {
	t.Helper()
	if pg {
		for i := 1; strings.Contains(q, "?"); i++ {
			q = strings.Replace(q, "?", "$"+strconv.Itoa(i), 1)
		}
	}
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// C5: rows of remote_pending_sealings, with the name, pl, horizon and
// sha256 of the content, outlived a purge of their resource or of the
// branch, and so did the shadow's stored copies of A's sealings (sealed,
// blob_epochs), which purgeResource deleted for the branch's own namespace
// only. A purge now deletes them all.
func TestV0261PreRaisePurgeDeletesShadowSealings(t *testing.T) {
	t.Parallel()
	for _, what := range []string{"resource", "namespace"} {
		r := newV077Raised(t)
		xDoc := "/r/m/x/rev/" + r.x1
		zDoc := "/r/m/z/rev/" + r.z1
		p := newV077Proxy(t, r.a, map[string]v077Answer{
			"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + r.x1 + `"}`},
			"GET " + zDoc: {1, http.StatusForbidden, v077Forbidden},
		})
		var path string
		b := newV0261B(t, r, p.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
		kB, _ := v0261Remote(t, b, r, "r")
		db, pg := v0261DB(t, path)
		shadowRows := func(table, name string) int {
			return v0261Count(t, db, pg, `SELECT COUNT(*) FROM `+table+` s JOIN namespaces n ON n.ns = s.ns WHERE n.name LIKE '~%' AND s.name = ?`, name)
		}
		// x's document pruned and z's refused are pending; their entries
		// and z's blob sealing are stored in the shadow.
		for _, name := range []string{"x", "z"} {
			if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM remote_pending_sealings WHERE name = ?`, name); n != 1 {
				t.Fatalf("%s: %d pending rows for %s, want 1", what, n, name)
			}
			if shadowRows("sealed", name) == 0 {
				t.Fatalf("%s: no sealing of %s's stored in its shadow", what, name)
			}
		}
		if shadowRows("blob_epochs", "z") == 0 {
			t.Fatalf("%s: z's blob sealing isn't stored in its shadow", what)
		}
		root := b.grant(kB, "user:root", []string{"r"}, allVerbs)
		switch what {
		case "resource":
			expect(t, b.purge("r", "x", r.x1, root), 204)
			expect(t, b.purge("r", "z", r.z1, root), 204)
		default:
			b.purgeNSAs("r", root)
		}
		for _, name := range []string{"x", "z"} {
			if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM remote_pending_sealings WHERE name = ?`, name); n != 0 {
				t.Errorf("%s purge: %d rows of remote_pending_sealings for %s remain", what, n, name)
			}
			for _, table := range []string{"sealed", "blob_epochs"} {
				if n := shadowRows(table, name); n != 0 {
					t.Errorf("%s purge: %d rows of %s for %s remain in its shadow", what, n, table, name)
				}
			}
		}
	}
}

// C-B: a refused sealing was asked for again at every sync, with no
// backoff. Now, past the sync after it was recorded and the one after its
// first failed retry, it waits a minute, doubling at each failure.
func TestV0261PreRaiseRetryBackoff(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
	b := newV077B(t, r, p)
	_, g := v0261Remote(t, b, r, "r")
	asked := func() int { return p.count("GET " + xDoc) }
	sync := func() {
		t.Helper()
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
	if n := asked(); n != 1 {
		t.Fatalf("creation asked A %d times for x's document", n)
	}
	for range 10 {
		sync()
	}
	if n := asked(); n != 3 {
		t.Fatalf("10 syncs at once asked A for x's document %d times in all, want 3", n)
	}
	// Due a minute after the second failed retry, two after the third.
	b.clock.Advance(time.Minute)
	sync()
	sync()
	if n := asked(); n != 4 {
		t.Fatalf("a minute later: asked %d times, want 4", n)
	}
	b.clock.Advance(time.Minute)
	sync()
	if n := asked(); n != 4 {
		t.Fatalf("a minute after the third failed retry: asked %d times, want 4", n)
	}
	b.clock.Advance(time.Minute)
	sync()
	if n := asked(); n != 5 {
		t.Fatalf("two minutes after the third failed retry: asked %d times, want 5", n)
	}
	// Once A serves it and it is due, it is stored.
	p.set(nil)
	b.clock.Advance(4 * time.Minute)
	sync()
	ra, rb := r.a.get(xDoc, r.root()), b.get("/r/r/x/rev/"+r.x1, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("x's document once due and served: %d %.120s", rb.Code, rb.Body)
	}
}

// C-M: rawGet read up to 1 GiB of any answer, error or not. It now reads a
// small error body, and no more than a sealing's cap of a 200.
func TestV0261PreRaiseReadCaps(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusForbidden, http.StatusOK} {
		r := newV077Raised(t)
		xDoc := "/r/m/x/rev/" + r.x1
		p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
		b := newV077B(t, r, p)
		_, g := v0261Remote(t, b, r, "r")
		var written atomic.Int64
		inner := p.srv.Config.Handler
		p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == "GET" && req.URL.Path == xDoc {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				chunk := bytes.Repeat([]byte(" "), 64<<10)
				for written.Load() < 256<<20 {
					n, err := w.Write(chunk)
					written.Add(int64(n))
					if err != nil {
						return
					}
				}
				return
			}
			inner.ServeHTTP(w, req)
		})
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		p.srv.Config.Handler = inner
		t.Logf("%d: A wrote %d bytes before B stopped reading", status, written.Load())
		if written.Load() == 0 {
			t.Fatalf("%d: the sync didn't ask A for x's document", status)
		}
		if written.Load() >= 64<<20 {
			t.Fatalf("%d: B read %d bytes of A's answer for one sealing", status, written.Load())
		}
		expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
	}
}

// v0261Epochs is A with m sealed, z's blob referenced by z1 under epoch 1
// and by z2 under epoch 2, then raised to e2e.
func newV0261Epochs(t *testing.T) (*v077Raised, string) {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	r := &v077Raised{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
	r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
	r.x1 = a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), r.root())
	r.data = []byte("z's blob under two epochs")
	r.bid = a.upload("m", "z", "text/plain", r.data, r.root())
	r.z1 = a.wr("m", "z", "", withNonce(addRoot(map[string]any{"b": ref(r.bid, "text/plain", len(r.data), ""), "v": 1.0})), r.root())
	a.clock.Advance(time.Minute)
	expect(t, a.patchNS("m", ops(op("add", "/encryption/epoch", 2.0)), r.root()), 201)
	z2 := a.wr("m", "z", r.z1, withNonce([]any{op("replace", "/v", 2.0)}), r.root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 3.0})), r.root()), 201)
	r.raised = a.nsHead("m", r.root())
	return r, z2
}

// C-E: pendingPruned matched a blob's pending row whatever its epoch, so a
// blob A pruned under one epoch answered 410 under another, which A only
// refused: 502 is owed there.
func TestV0261PreRaisePrunedBlobEpoch(t *testing.T) {
	t.Parallel()
	r, z2 := newV0261Epochs(t)
	e1, e2 := blobPath("m", "z", r.bid)+"/e/1", blobPath("m", "z", r.bid)+"/e/2"
	p := newV077Proxy(t, r.a, map[string]v077Answer{
		"GET " + e1: {1, http.StatusGone, `{"code":"pruned","horizon":"` + z2 + `"}`},
		"GET " + e2: {2, http.StatusForbidden, v077Forbidden}, // the first mirrors the blob (fetchBlobs)
	})
	b := newV077B(t, r, p)
	_, g := v0261Remote(t, b, r, "r")
	if p.count("GET "+e1) == 0 || p.count("GET "+e2) == 0 {
		t.Fatalf("creation asked for z's blob under epoch 1 %d times, under 2 %d times", p.count("GET "+e1), p.count("GET "+e2))
	}
	res := b.get(blobPath("r", "z", r.bid)+"/e/1", g)
	expectCode(t, res, 410, "pruned")
	if res.Str("horizon") != z2 {
		t.Fatalf("z's blob under epoch 1: %s, want horizon %s", res.Body, z2)
	}
	expectCode(t, b.get(blobPath("r", "z", r.bid)+"/e/2", g), 502, "upstream")
}

// C1: a base that doesn't answer held SyncRemotes, which follows bases one
// after another on the follower's goroutine, for ever: production's HTTP
// client has no timeout, and the follower's context no deadline. Each
// base's step now has one (RemoteOptions.FollowTimeout), and fetching its
// pending sealings half of it, so the other bases are still followed. A
// hang where the branch follows the base's log (GET /ns/m), or fetches a
// pending sealing again (x's document). An origin has one FollowTimeout
// per sync: once spent, its other branches wait for the next.
func TestV0261FollowDeadline(t *testing.T) {
	t.Parallel()
	for _, hang := range []string{"/ns/m", "/r/m/x/rev/"} {
		r := newV077Raised(t)
		xDoc := "/r/m/x/rev/" + r.x1
		p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
		// In front of the proxy: once armed, the first GET of the path
		// hangs until B gives up; the rest go to the proxy.
		var armed, hung atomic.Bool
		release := make(chan struct{})
		target, _ := url.Parse(p.srv.URL)
		rp := httputil.NewSingleHostReverseProxy(target)
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			path := hang
			if hang != "/ns/m" {
				path = xDoc
			}
			if req.Method == "GET" && req.URL.Path == path && armed.Load() && hung.CompareAndSwap(false, true) {
				select {
				case <-req.Context().Done():
				case <-release:
				case <-time.After(30 * time.Second):
				}
				return
			}
			rp.ServeHTTP(w, req)
		}))
		t.Cleanup(front.Close)
		t.Cleanup(func() { close(release) })
		b := newV0261B(t, r, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = 3 * time.Second })
		_, g1 := v0261Remote(t, b, r, "r1")
		_, g2 := v0261Remote(t, b, r, "r2")
		p.set(nil)
		armed.Store(true)
		start := time.Now()
		err := b.e.SyncRemotes(context.Background())
		el := time.Since(start)
		t.Logf("%s: SyncRemotes after %v: %v", hang, el, err)
		// A hang reading the log spends the origin's FollowTimeout: its
		// other branch is skipped; one fetching a pending sealing, half
		// of it, which leaves the other branch time.
		skipped := err != nil && strings.Contains(err.Error(), "skipped")
		if el > 6*time.Second || !hung.Load() || err == nil || skipped != (hang == "/ns/m") {
			t.Fatalf("%s: SyncRemotes took %v (hung: %v), error %v", hang, el, hung.Load(), err)
		}
		// The next sync follows both.
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("%s: second sync: %v", hang, err)
		}
		c1, c2 := b.get("/r/r1/x/rev/"+r.x1, g1).Code, b.get("/r/r2/x/rev/"+r.x1, g2).Code
		if c1 != 200 || c2 != 200 {
			t.Fatalf("%s: x's document on r1: %d, on r2: %d after the next sync; want 200", hang, c1, c2)
		}
	}
}

// C2: rows that v0.26.0 recorded 410 pruned with any horizon A named:
// before migration 015 (due 0), or during an upgrade, settling a row this
// version recorded (due other than updated). One whose horizon isn't a
// revision of the chain after its own is served 502, never with that
// horizon, and is asked for again (pendingFixes); one whose horizon is
// stays 410 pruned for good.
func TestV0261PreRaiseLegacyPrunedRows(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	// y2, after y1, is in the branch's chain: its at is after it.
	y2 := v0261After(t, r, "y", r.y1)
	r.raised = r.a.nsHead("m", r.root())
	xDoc, yDoc := "/r/m/x/rev/"+r.x1, "/r/m/y/rev/"+r.y1
	p := newV077Proxy(t, r.a, map[string]v077Answer{
		"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden},
		"GET " + yDoc: {1, http.StatusForbidden, v077Forbidden},
	})
	var path string
	b := newV0261B(t, r, p.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
	_, g := v0261Remote(t, b, r, "r")
	db, pg := v0261DB(t, path)
	// y's as recorded before migration 015 (due 0); x's as a v0.26.0
	// instance settles a row this version recorded during an upgrade:
	// answer, horizon and updated, its due kept.
	for name, set := range map[string]string{
		"x": `horizon = '` + strings.Repeat("A", 1<<10) + `', updated = updated + 1`,
		"y": `horizon = '` + y2 + `', due = 0, tries = 0`,
	} {
		res, err := db.Exec(`UPDATE remote_pending_sealings SET answer = 'pruned', ` + set + ` WHERE name = '` + name + `' AND kind = 'doc'`)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("%s: %d pending rows of its document", name, n)
		}
	}
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
	// A serves both now: x's is asked for again and stored, y's isn't,
	// its row kept pruned for good (due set). (y1's document isn't served
	// from the branch, y having an e2e revision since: X-E2e fold.)
	p.set(nil)
	for range 2 {
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
	ra, rb := r.a.get(xDoc, r.root()), b.get("/r/r/x/rev/"+r.x1, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("x's document: %d %.160s, want A's bytes", rb.Code, rb.Body)
	}
	if p.count("GET "+yDoc) != 1 {
		t.Fatalf("y's document, pruned for good, was asked for %d times", p.count("GET "+yDoc))
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM remote_pending_sealings WHERE name = 'y' AND kind = 'doc' AND answer = 'pruned' AND horizon = ? AND due > 0`, y2); n != 1 {
		t.Fatalf("y's row: %d kept pruned with horizon %s", n, y2)
	}
}

// C3: a sealing a sync asks for again is bounded as creation bounds it, by
// the content B mirrored (jweFor), not by B's own maximums: an honest A's
// sealing of a document larger than B's documentSize, which creation
// would take, is taken at a sync too.
func TestV0261PreRaiseRetryHonestLarge(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	r := &v077Raised{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
	r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
	big := map[string]any{}
	for i := range 5 {
		big[strconv.Itoa(i)] = strings.Repeat("x", 40<<10)
	}
	r.x1 = a.wr("m", "x", "", withNonce(addRoot(big)), r.root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
	r.raised = a.nsHead("m", r.root())
	xDoc := "/r/m/x/rev/" + r.x1
	p := newV077Proxy(t, a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
	small := func(o *core.Options) {
		for _, l := range []*core.Limits{&o.Limits, &o.Maximums} {
			l.DocumentSize, l.PatchSetSize, l.ValueSize, l.BlobsPerDocument = 64<<10, 64<<10, 16<<10, 100
		}
	}
	b := newV0261B(t, r, p.srv.URL, small)
	_, g := v0261Remote(t, b, r, "r")
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
	p.set(nil)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	ra, rb := a.get(xDoc, r.root()), b.get("/r/r/x/rev/"+r.x1, g)
	expect(t, ra, 200)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("x's document (%d bytes at A) after the sync: %d %.160s", len(ra.Body), rb.Code, rb.Body)
	}
}

// v0261Inflate inserts n newlines into the ciphertext segment of a compact
// JWE: base64 decoding ignores CR and LF (encoding/base64, also Strict), so
// it still opens, under the same header and AAD, without A needing the key
// to re-seal; TrimSpace (trimJWE) leaves it, being inside.
func v0261Inflate(t *testing.T, jwe string, n int) string {
	t.Helper()
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 || len(parts[3]) < 2 {
		t.Fatalf("not a compact JWE: %.80q", jwe)
	}
	ct := parts[3][:1] + strings.Repeat("\n", n) + parts[3][1:]
	return strings.Join([]string{parts[0], parts[1], parts[2], ct, parts[4]}, ".")
}

// v0.26.1 review (C3 incomplete): a sealing B asks A for again at a
// sync is bounded only by caps.jwe (2 × the deployment's largest document
// or patch set + 64 KiB), not by the size of the content B mirrored
// (jweFor, which creation uses), and is stored as A serves it once it
// opens. A pads it inside the JWE, where trimJWE doesn't reach, and B
// stores and serves it at that size for good.
func TestV0261RetryStoresInflatedSealing(t *testing.T) {
	t.Parallel()
	t.Run("document", func(t *testing.T) {
		r := newV077Raised(t)
		xDoc := "/r/m/x/rev/" + r.x1
		p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
		b := newV077B(t, r, p)
		_, g := v0261Remote(t, b, r, "r")
		real := r.a.get(xDoc, r.root())
		expect(t, real, 200)
		inflated := v0261Inflate(t, string(real.Body), 1<<20)
		p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusOK, inflated}})
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		res := b.get("/r/r/x/rev/"+r.x1, g)
		t.Logf("B serves x's document: %d, %d bytes (A's sealing is %d bytes)", res.Code, len(res.Body), len(real.Body))
		if res.Code == 200 && len(res.Body) > len(real.Body)+64 {
			t.Fatalf("B stored and serves A's sealing of x's document (%d bytes of content) inflated to %d bytes", len(real.Body), len(res.Body))
		}
	})
	t.Run("log entry", func(t *testing.T) {
		r := newV077Raised(t)
		wLog := "/r/m/w/rev/" + r.w1 + "/log"
		p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + wLog: {2, http.StatusForbidden, v077Forbidden}})
		b := newV077B(t, r, p)
		_, g := v0261Remote(t, b, r, "r")
		real := r.a.get(wLog, r.root())
		expect(t, real, 200)
		var page []string
		if err := json.Unmarshal(real.Body, &page); err != nil || len(page) != 1 {
			t.Fatalf("A's page of w's log: %v %s", err, real.Body)
		}
		inflated, _ := json.Marshal([]string{v0261Inflate(t, page[0], 1<<20)})
		p.set(map[string]v077Answer{"GET " + wLog: {1, http.StatusOK, string(inflated)}})
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		res := b.get("/r/r/w/rev/"+r.w1+"/log", g)
		t.Logf("B serves w's log: %d, %d bytes (A's is %d bytes)", res.Code, len(res.Body), len(real.Body))
		if res.Code == 200 && len(res.Body) > len(real.Body)+64 {
			t.Fatalf("B stored and serves A's sealing of w's entry inflated to %d bytes", len(res.Body))
		}
	})
}

// v0.26.1 review: the size bounds at creation (jweFor of the mirrored
// entry or document) against an honest A with large entries and
// documents, padded or not, and strings JSON escapes: every sealing is
// stored, nothing left pending.
func TestV0261HonestLargeAtCreation(t *testing.T) {
	t.Parallel()
	for _, pad := range []bool{false, true} {
		t.Run(fmt.Sprint("pad=", pad), func(t *testing.T) {
			var aPriv ed25519.PrivateKey
			a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
			a.opPriv = aPriv
			r := &v077Raised{a: a, kA: newKey("admin")}
			doc := sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}})
			if pad {
				doc["encryption"].(map[string]any)["pad"] = true
			}
			a.mkNS("m", doc)
			r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
			// Strings JSON escapes or holds as multi-byte UTF-8.
			unit := "é<>&\"\\\t 😀abc"
			val := func(i int) string { return fmt.Sprint(i) + strings.Repeat(unit, (48<<10)/len(unit)-2) }
			var revs []string
			prev := ""
			k := 0
			for w := 0; w < 5; w++ {
				var ps []any
				if prev == "" {
					root := map[string]any{}
					for j := 0; j < 3; j++ {
						root[fmt.Sprint("k", k)] = val(k)
						k++
					}
					ps = withNonce(addRoot(root))
				} else {
					for j := 0; j < 3; j++ {
						ps = append(ps, op("add", fmt.Sprint("/k", k), val(k)))
						k++
					}
					ps = withNonce(ps)
				}
				prev = a.wr("m", "x", prev, ps, r.root())
				revs = append(revs, prev)
			}
			r.x1 = revs[0]
			a.clock.Advance(time.Hour)
			expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
			r.raised = a.nsHead("m", r.root())

			p := newV077Proxy(t, a, nil)
			var path string
			b := newV0261B(t, r, p.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
			_, g := v0261Remote(t, b, r, "r")
			db, pg := v0261DB(t, path)
			if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM remote_pending_sealings`); n != 0 {
				var kinds []string
				rows, _ := db.Query(`SELECT kind, ref, answer FROM remote_pending_sealings`)
				for rows != nil && rows.Next() {
					var a, b, c string
					rows.Scan(&a, &b, &c)
					kinds = append(kinds, a+" "+b+" "+c)
				}
				t.Errorf("an honest A's sealings of large content: %d left pending at creation: %v", n, kinds)
			}
			for i, id := range revs {
				log := "/rev/" + id + "/log"
				if i > 0 {
					log += "?since=" + revs[i-1]
				}
				for _, pth := range []string{"/rev/" + id, log} {
					ra, rb := a.get("/r/m/x"+pth, r.root()), b.get("/r/r/x"+pth, g)
					if ra.Code != 200 || rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
						t.Errorf("%s: A %d (%d bytes), B %d %.160s", pth, ra.Code, len(ra.Body), rb.Code, rb.Body)
					}
				}
			}
		})
	}
}

// v0.26.1 review (dead rows): creation takes a blob sealing's 410
// pruned if its horizon is at or after the first revision referencing the
// blob under any epoch (prunedIn, firstRef), but the row is recorded at
// the first revision referencing it under that epoch (storePreSealings),
// and pendingPruned/horizonIn check against that. A horizon in between is
// recorded "pruned" with due set (never re-validated: only due 0 is),
// served 502 (horizonIn fails), and never asked for again (pendingRows
// skips pruned rows with due <> 0): 502 for good, even once A serves it.
func TestV0261BlobPrunedRowDead(t *testing.T) {
	t.Parallel()
	r, _ := newV0261Epochs(t)
	e2 := blobPath("m", "z", r.bid) + "/e/2"
	p := newV077Proxy(t, r.a, map[string]v077Answer{
		// The first mirrors the blob (fetchBlobs); the second is A's sealing.
		"GET " + e2: {2, http.StatusGone, `{"code":"pruned","horizon":"` + r.z1 + `"}`},
	})
	b := newV077B(t, r, p)
	kB, g := v0261Remote(t, b, r, "r")
	res := b.get(blobPath("r", "z", r.bid)+"/e/2", g)
	t.Logf("after creation: %d %s", res.Code, res.Body)
	p.set(nil) // A serves it now
	before := p.count("GET " + e2)
	for range 4 {
		b.clock.Advance(5 * time.Hour)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
	g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	res = b.get(blobPath("r", "z", r.bid)+"/e/2", g)
	t.Logf("after 4 syncs over 20 h: %d %.200s; A asked %d times", res.Code, res.Body, p.count("GET "+e2)-before)
	if res.Code == 502 && p.count("GET "+e2) == before {
		t.Fatalf("z's blob under epoch 2: 502 for good, its row recorded pruned with a horizon horizonIn rejects, never asked for again")
	}
}

// v0.26.1 review (C2 fix too narrow): §8.6 lets A prune past the `at`
// of a remote branch whose registration has expired, or that never
// registered (-remote-register is off by default): only local branches'
// and registered remote branches' `at` is protected. A's honest 410
// pruned then names a horizon after B's `at`: a revision of x's chain at A
// that the shadow never mirrors. horizonIn accepts only revisions of the
// mirrored chain, so B records the answer as a refusal and answers 502
// upstream for good (asked again every 4 h, for ever), where §G.3/§G.5.2
// owe "410 where A has pruned it".
func TestV0261HonestPrunedPastAt(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
	b := newV077B(t, r, p)
	kB, g := v0261Remote(t, b, r, "r")
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")

	// A writes x past B's at (e2e: the server checks kid and pl only),
	// and later prunes x below it: x1's document is gone at A.
	wr := r.a.writeRaw("m", "x", r.x1, sealed(t, seal.NewKey(), "m#2", "m", "x", r.x1, ops(op("replace", "/v", 9.0))), r.root())
	expect(t, wr, 201)
	x2 := etagOf(wr)
	p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + x2 + `"}`}})
	for range 3 {
		b.clock.Advance(5 * time.Hour)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
	if p.count("GET "+xDoc) < 2 {
		t.Fatalf("the syncs didn't ask A for x's document")
	}
	g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	res := b.get("/r/r/x/rev/"+r.x1, g)
	t.Logf("B: %d %s", res.Code, res.Body)
	if res.Code != 410 {
		t.Fatalf("A pruned x1's document (horizon %s, a revision of x after the branch's at); B answers %d %s, want 410 pruned", x2, res.Code, res.Body)
	}
}

// The same at creation: A has written x past the branch's at and pruned
// below it, so its 410 for x1's document names x2, which B's mirror lacks
// and A's log verifies after B's head: 410 pruned with that horizon. A
// horizon A's log doesn't verify after the head (an id of y's) is a
// refusal.
func TestV0261PreRaisePrunedPastAtCreation(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	wr := r.a.writeRaw("m", "x", r.x1, sealed(t, seal.NewKey(), "m#2", "m", "x", r.x1, ops(op("replace", "/v", 9.0))), r.root())
	expect(t, wr, 201)
	x2 := etagOf(wr)
	xDoc := "/r/m/x/rev/" + r.x1
	for hz, want := range map[string]int{x2: 410, r.y1: 502} {
		p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + hz + `"}`}})
		b := newV077B(t, r, p)
		_, g := v0261Remote(t, b, r, "r")
		res := b.get("/r/r/x/rev/"+r.x1, g)
		if res.Code != want || want == 410 && res.Str("horizon") != x2 {
			t.Fatalf("horizon %s: %d %s, want %d", hz, res.Code, res.Body, want)
		}
		// Past at, it isn't final: once A serves x1's document again, a
		// sync after its backoff stores it.
		p.set(nil)
		b.clock.Advance(5 * time.Minute)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		ra, rb := r.a.get(xDoc, r.root()), b.get("/r/r/x/rev/"+r.x1, g)
		if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
			t.Fatalf("horizon %s: x1's document once A serves it: %d %.160s", hz, rb.Code, rb.Body)
		}
	}
}

// v0.26.1 review (horizonIn takes rv.seq >= the sealing's revision): a
// real A, sealed, pruned at H, still serves H's document and H's own log
// entry (§8.6 keeps H's document and drops only the patch sets before H),
// so an honest 410 pruned for a sealing of revision R never names R
// itself: its horizon is strictly after R. horizonIn accepts R, so A can
// get B to answer 410 for good for the branch's head as of at, content an
// honest A never answers 410 for with that horizon.
func TestV0261PrunedHorizonStrictlyAfter(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	x2 := a.wr("m", "x", x1, withNonce([]any{op("replace", "/v", 2.0)}), root())
	x3 := a.wr("m", "x", x2, withNonce([]any{op("replace", "/v", 3.0)}), root())
	a.clock.Advance(time.Hour) // past the retry window
	res := a.prune("m", "x", map[string]any{"horizon": x2}, root())
	t.Logf("prune at x2: %d %s", res.Code, res.Body)
	expect(t, res, 200)
	for _, c := range []struct {
		path string
		want int
	}{
		{"/r/m/x/rev/" + x1, 410},
		{"/r/m/x/rev/" + x2, 200},
		{"/r/m/x/rev/" + x2 + "/log?since=" + x1, 200},
		{"/r/m/x/rev/" + x3 + "/log?since=" + x2, 200},
	} {
		r := a.get(c.path, root())
		t.Logf("%s: %d %.120s", c.path, r.Code, r.Body)
		if r.Code != c.want {
			t.Errorf("%s: %d, want %d", c.path, r.Code, c.want)
		}
	}
}

// v0.26.1 review (C4 incomplete): rawGet no longer follows A's
// redirects, but two other requests a sync makes to A still do, with B's
// grant: sealedAt (followLog, after A refuses the namespace log) and
// postRegistration (RemoteOptions.Register, at every sync until
// registered; a 307 replays the POST and its body).
func TestV0261RedirectsOutsideRawGet(t *testing.T) {
	t.Parallel()
	for _, step := range []string{"sealedAt", "postRegistration"} {
		for _, host := range []string{"localhost", "127.0.0.1"} {
			t.Run(step+"/"+host, func(t *testing.T) {
				r := newV077Raised(t)
				p := newV077Proxy(t, r.a, nil)
				var opts []envOpt
				if step == "postRegistration" {
					opts = append(opts, func(o *core.Options) { o.Remote.Register = true })
				}
				b := newV0261B(t, r, p.srv.URL, opts...)
				v0261Remote(t, b, r, "r")

				var hits atomic.Int64
				var auth, method, body atomic.Value
				auth.Store("")
				method.Store("")
				body.Store("")
				other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					hits.Add(1)
					auth.Store(req.Header.Get("Authorization"))
					method.Store(req.Method)
					bs, _ := io.ReadAll(req.Body)
					body.Store(string(bs))
					w.WriteHeader(404)
				}))
				t.Cleanup(other.Close)
				target := "http://" + host + ":" + strconv.Itoa(other.Listener.Addr().(*net.TCPAddr).Port) + "/internal/metadata"
				inner := p.srv.Config.Handler
				p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					switch {
					case step == "sealedAt" && req.Method == "GET" && req.URL.Path == "/ns/m":
						// A head B hasn't followed yet, whose log A refuses.
						w.Header().Set("ETag", `"`+r.x1+`"`)
						w.WriteHeader(http.StatusFound)
						return
					case step == "sealedAt" && req.Method == "GET" && req.URL.Path == "/ns/m/rev/"+r.x1+"/log":
						w.WriteHeader(http.StatusForbidden)
						io.WriteString(w, v077Forbidden)
						return
					case step == "sealedAt" && req.Method == "GET" && req.URL.Path == "/ns/m/rev/"+r.x1:
						http.Redirect(w, req, target, http.StatusFound)
						return
					case step == "postRegistration" && req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/branches"):
						http.Redirect(w, req, target, http.StatusTemporaryRedirect)
						return
					}
					inner.ServeHTTP(w, req)
				})
				if step == "postRegistration" {
					// Past RenewBefore of the registration made at creation.
					b.clock.Advance(25 * 24 * time.Hour)
				}
				for i := 0; i < 3; i++ {
					b.clock.Advance(5 * time.Hour)
					err := b.e.SyncRemotes(context.Background())
					t.Logf("sync %d: %v", i, err)
				}
				a, _ := auth.Load().(string)
				t.Logf("redirect to %s: hit %d times over 3 syncs, last %s, Authorization forwarded: %v, body %q", target, hits.Load(), method.Load(), a != "", body.Load())
				if hits.Load() > 0 {
					t.Errorf("%s: B followed A's redirect to %s (%d hits over 3 syncs, method %s, Authorization forwarded: %v)", step, target, hits.Load(), method.Load(), a != "")
				}
			})
		}
	}
}

// v0.26.1 review (C1 bound is per branch, not per origin): one hostile
// A that every remote branch of it follows drips its answer to the log
// read (GET /ns/m) until B gives up costs each branch's step the whole
// FollowTimeout, one after another: k branches of A hold SyncRemotes, and
// every other base after them, for k × FollowTimeout per sync (10 min
// each by default, the sync interval being 5 min).
func TestV0261StallPerBranch(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	p := newV077Proxy(t, r.a, nil)
	var armed atomic.Bool
	target, _ := url.Parse(p.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if armed.Load() && req.Method == "GET" && req.URL.Path == "/ns/m" {
			// Slow drip: headers at once, then a byte at a time.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			for {
				select {
				case <-req.Context().Done():
					return
				case <-time.After(100 * time.Millisecond):
					if _, err := w.Write([]byte(" ")); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		}
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(front.Close)
	const timeout = time.Second
	b := newV0261B(t, r, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = timeout })
	const k = 4
	for i := 0; i < k; i++ {
		v0261Remote(t, b, r, "r"+string(rune('a'+i)))
	}
	armed.Store(true)
	start := time.Now()
	err := b.e.SyncRemotes(context.Background())
	el := time.Since(start)
	t.Logf("SyncRemotes with %d branches of one dripping A: %v (FollowTimeout %v): %.200v", k, el, timeout, err)
	if el >= time.Duration(k)*timeout {
		t.Fatalf("one origin's %d branches held the sync %v: %d × FollowTimeout", k, el, k)
	}
}

// v0.26.1 review: creation (fetchRemote, with the request's context)
// has no deadline of its own: A dripping one pending sealing's answer
// within its cap holds the creating request as long as it likes, past
// FollowTimeout. Here A gives up after 4 s.
func TestV0261CreationNoDeadline(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	p := newV077Proxy(t, r.a, nil)
	target, _ := url.Parse(p.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	const drip = 4 * time.Second
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" && req.URL.Path == "/r/m/x/rev/"+r.x1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			end := time.After(drip)
			for {
				select {
				case <-req.Context().Done():
					return
				case <-end:
					return
				case <-time.After(100 * time.Millisecond):
					if _, err := w.Write([]byte(" ")); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		}
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(front.Close)
	b := newV0261B(t, r, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = time.Second })
	start := time.Now()
	v0261Remote(t, b, r, "r")
	el := time.Since(start)
	t.Logf("creation took %v with FollowTimeout 1s", el)
	if el >= drip {
		t.Fatalf("creation took %v: A's drip held it past FollowTimeout", el)
	}
}

// C2, item 3 of the review: A really prunes x past the branch's at, at a
// revision written after it, with a snapshot (§8.6, §E.3.1). Where the
// horizon is the child of B's head x1, A's range since x1 is served and
// verifies: 410 pruned with A's horizon. Where a revision lies between
// them, A's range since x1 is itself pruned, so the horizon can't be
// verified to follow B's head: 502 upstream, as for a refusal.
func TestV0261PreRaiseRealPrunePastAt(t *testing.T) {
	t.Parallel()
	for _, past := range []int{1, 2} {
		t.Run(strconv.Itoa(past), func(t *testing.T) {
			r := newV0261Raised(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
			xDoc := "/r/m/x/rev/" + r.x1
			p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
			b := newV077B(t, r, p)
			kB, _ := v0261Remote(t, b, r, "r")
			hz := r.x1
			for range past {
				hz = v0261After(t, r, "x", hz)
			}
			r.a.clock.Advance(10 * time.Minute) // past the retry window
			snap, err := seal.SealSnapshot(seal.NewKey(), "m#2", "m", "x", hz, map[string]any{"v": 9.0})
			if err != nil {
				t.Fatal(err)
			}
			expect(t, r.a.prune("m", "x", map[string]any{"horizon": hz, "snapshot": snap}, r.root()), 200)
			res := r.a.get(xDoc, r.root())
			expectCode(t, res, 410, "pruned")
			if res.Str("horizon") != hz {
				t.Fatalf("A: x1's document: %s, want horizon %s", res.Body, hz)
			}
			p.set(nil)
			b.clock.Advance(5 * time.Hour)
			if err := b.e.SyncRemotes(context.Background()); err != nil {
				t.Logf("sync: %v", err)
			}
			g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
			res = b.get("/r/r/x/rev/"+r.x1, g)
			switch past {
			case 1:
				expectCode(t, res, 410, "pruned")
				if res.Str("horizon") != hz {
					t.Fatalf("B: %s, want horizon %s", res.Body, hz)
				}
			default:
				expectCode(t, res, 502, "upstream")
			}
		})
	}
}

// newV0261Raised is newV077Raised's A, x and y only, with more options for
// A.
func newV0261Raised(t *testing.T, opts ...envOpt) *v077Raised {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, append([]envOpt{withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning}, opts...)...)
	a.opPriv = aPriv
	r := &v077Raised{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
	r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
	r.x1 = a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), r.root())
	r.y1 = a.wr("m", "y", "", withNonce(addRoot(map[string]any{"v": 2.0})), r.root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
	r.raised = a.nsHead("m", r.root())
	return r
}

// v0.26.1 review, round 3 (efb5aca, "put creation's fetch from a
// remote base under FollowTimeout"): only fetchRemote runs under it. After
// the branch is written, creation registers it with A (RegisterRemote,
// with -remote-register) and reads the deeper bases' documents
// (readChainAtCreation), both with the request's own context, which has no
// deadline: A dripping its answer to the registration holds the creating
// request as long as it likes. Here A gives up after 4 s.
func TestV0261CreationRegistrationNoDeadline(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	p := newV077Proxy(t, r.a, nil)
	target, _ := url.Parse(p.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	const drip = 4 * time.Second
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/ns/m/branches" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			end := time.After(drip)
			for {
				select {
				case <-req.Context().Done():
					return
				case <-end:
					return
				case <-time.After(100 * time.Millisecond):
					if _, err := w.Write([]byte(" ")); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		}
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(front.Close)
	b := newV0261B(t, r, front.URL, func(o *core.Options) {
		o.Remote.FollowTimeout = time.Second
		o.Remote.Register = true
	})
	start := time.Now()
	v0261Remote(t, b, r, "r")
	el := time.Since(start)
	t.Logf("creation took %v with FollowTimeout 1s", el)
	if el >= drip {
		t.Fatalf("creation took %v: A's drip of the registration held it past FollowTimeout", el)
	}
}

// v0.26.1 review, round 3 (88b5a96, "one FollowTimeout per remote
// origin"): baseStep marks an origin late only when a step's own deadline
// expires (or its error is DeadlineExceeded); nothing adds up the time an
// origin's steps take. TestV0261StallPerBranch's A drips until B gives up;
// this A drips the same answer and stops a little before FollowTimeout
// (0.8 of it), so no step runs out of time, none of A's bases is skipped,
// and k branches of A still hold the sync k × 0.8 × FollowTimeout, every
// other origin's bases waiting behind them. (A's answer is a 503, after
// which the step asks A nothing else.)
func TestV0261StallJustUnderDeadline(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	p := newV077Proxy(t, r.a, nil)
	const timeout = time.Second
	var armed atomic.Bool
	target, _ := url.Parse(p.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if armed.Load() && req.Method == "GET" && req.URL.Path == "/ns/m" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			end := time.After(timeout * 8 / 10)
			for {
				select {
				case <-req.Context().Done():
					return
				case <-end:
					return
				case <-time.After(100 * time.Millisecond):
					if _, err := w.Write([]byte(" ")); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		}
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(front.Close)
	b := newV0261B(t, r, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = timeout })
	const k = 4
	for i := 0; i < k; i++ {
		v0261Remote(t, b, r, "r"+string(rune('a'+i)))
	}
	armed.Store(true)
	start := time.Now()
	err := b.e.SyncRemotes(context.Background())
	el := time.Since(start)
	t.Logf("SyncRemotes with %d branches of one A answering just under FollowTimeout: %v (FollowTimeout %v): %.300v", k, el, timeout, err)
	if el >= 2*timeout {
		t.Fatalf("one origin's %d branches held the sync %v (%.1f × FollowTimeout), none of them skipped: the per-origin budget only counts a step that runs out of time",
			k, el, float64(el)/float64(timeout))
	}
}

// v0.26.1 review, round 3 (b345cfe): verifyHorizonPast proves
// only that A can produce a hash chain from B's head to the horizon, which
// A always can (ids are unkeyed hashes): one fabricated entry, the
// tombstone of B's head, suffices, and the 410 is then final (due =
// updated). Here B registered with A at creation (§G.3), so §8.6 forbids
// A any horizon past x's head as of at, and A's real server still serves
// x1's document: only its answer to B's sync lies. (Observation: B can't
// refuse such a horizon soundly while registered either, since A may have
// pruned before B registered.)
func TestV0261ForgedPastHorizonWhileRegistered(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc := "/r/m/x/rev/" + r.x1
	x1, err := ids.Parse(r.x1)
	if err != nil {
		t.Fatal(err)
	}
	hz := ids.Tombstone(x1).String()
	forged := `[{"id":"` + hz + `","parent":"` + r.x1 + `","kind":"tombstone"}]`
	// At creation A refuses x1's document: it stays pending.
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
	b := newV0261B(t, r, p.srv.URL, func(o *core.Options) { o.Remote.Register = true })
	kB, _ := v0261Remote(t, b, r, "r")
	br := r.a.get("/ns/m/branches", r.root())
	t.Logf("A's /ns/m/branches: %d %.300s", br.Code, br.Body)
	if !strings.Contains(string(br.Body), originB) {
		t.Fatalf("B didn't register with A: %s", br.Body)
	}
	// At the sync, with the registration standing, A answers 410 with a
	// fabricated horizon past x1, and the one-entry log that "verifies" it.
	p.set(map[string]v077Answer{
		"GET " + xDoc:                   {1, http.StatusGone, `{"code":"pruned","horizon":"` + hz + `"}`},
		"GET /r/m/x/rev/" + hz + "/log": {1, http.StatusOK, forged},
	})
	b.clock.Advance(5 * time.Hour)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	if res := r.a.get(xDoc, r.root()); res.Code != 200 {
		t.Fatalf("A: x1's document: %d", res.Code)
	}
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	res := b.get("/r/r/x/rev/"+r.x1, g)
	t.Logf("B: x1's document: %d %s", res.Code, res.Body)
	// Decision: B may answer 410 with such a horizon (it can't tell it
	// from an honest one), but not for good: the row is asked for again
	// after its backoff, and once A serves the sealing, B stores and
	// serves it.
	p.set(nil)
	for range 3 {
		b.clock.Advance(5 * time.Hour)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
	g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	ra, rb := r.a.get(xDoc, r.root()), b.get("/r/r/x/rev/"+r.x1, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("B answers %d %.200s for x1's document after A served it again, past the 410 with the horizon A fabricated (%s): "+
			"that 410 was final", rb.Code, rb.Body, hz)
	}
}

// v0.26.1 final review (C-I1/C-I4, cross-origin): originBudget gives each origin a
// deadline one FollowTimeout after its FIRST base's step starts, in wall
// time. Bases are shuffled across origins, so when an honest origin's
// base comes before a stalling origin's, the stall (one FollowTimeout of
// the other origin's) is charged to the honest origin too: its bases
// after the stall are skipped, though it spent almost none of its own
// time. Here origin A (honest, three branches) and origin C (one branch
// whose namespace log hangs until B gives up): A's bases are skipped
// "having run out of time" in about half the syncs. Only the origin's own
// steps should count against its budget. (Should-fix: no base is starved
// for good, the order being shuffled at each sync, but another origin's
// stall delays an honest origin's purges; catchUpChainReads shares
// originBudget.)
func TestV0261BudgetChargedForOtherOrigin(t *testing.T) {
	t.Parallel()
	const originC = "https://c.example"
	a := newEnv(t, withOrigin(originA))
	c := newEnv(t, withOrigin(originC))
	for _, e := range []*tenv{a, c} {
		e.mkNS("m", map[string]any{"read": "public"})
		e.create("m", "x", map[string]any{"v": 1.0}, "alice")
	}
	var armed atomic.Bool
	target, _ := url.Parse(c.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if armed.Load() && req.Method == "GET" && req.URL.Path == "/ns/m" {
			<-req.Context().Done() // until B gives up
			return
		}
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(front.Close)
	const timeout = time.Second
	b := newEnv(t, withOrigin(originB), func(o *core.Options) {
		o.Remote = core.RemoteOptions{FollowInterval: -1, FollowTimeout: timeout, Resolve: func(origin string) (core.RemoteEndpoint, error) {
			switch origin {
			case originA:
				return core.RemoteEndpoint{BaseURL: a.srv.URL, OriginURL: a.srv.URL, HTTPClient: httpClient}, nil
			case originC:
				return core.RemoteEndpoint{BaseURL: front.URL, OriginURL: front.URL, HTTPClient: httpClient}, nil
			}
			return core.RemoteEndpoint{}, fmt.Errorf("unknown origin %s", origin)
		}}
	})
	for i, origin := range []string{originA, originA, originA, originC} {
		src := a
		if origin == originC {
			src = c
		}
		at := src.nsHead("m")
		g := addRoot(map[string]any{"read": "public", "base": map[string]any{"origin": origin, "ns": "m", "at": at, "chain": []any{"m"}}})
		expect(t, b.mkRemote(fmt.Sprintf("r%d", i), g), 201)
	}
	count := func(syncs int) (skipped int) {
		for range syncs {
			err := b.e.SyncRemotes(context.Background())
			if err != nil && strings.Contains(err.Error(), originA+" having run out of time") {
				skipped++
			}
		}
		return skipped
	}
	// Control: with C answering, no base of A is ever skipped.
	if n := count(4); n > 0 {
		t.Fatalf("control: %s's bases skipped in %d of 4 syncs with no stall", originA, n)
	}
	armed.Store(true)
	const syncs = 10
	skipped := count(syncs)
	t.Logf("%d of %d syncs skipped bases of the honest origin %s, which answers at once, for %s's stall", skipped, syncs, originA, originC)
	if skipped > 0 {
		t.Fatalf("%s's bases were skipped in %d of %d syncs, charged with the FollowTimeout another origin (%s) spent", originA, skipped, syncs, originC)
	}
}

// newFCSameEpoch is A's sealed namespace m with z's blob referenced by two
// revisions under the same epoch 1, z1 and z2 (and z3 after), then raised
// to e2e (epoch 2): B's branch mirrors all three, z1 the first to
// reference the blob under epoch 1, z2 the last but one.
func newFCSameEpoch(t *testing.T, raise bool) (*v077Raised, string, string) {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	r := &v077Raised{a: a, kA: newKey("admin")}
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
	r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
	r.x1 = a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), r.root())
	r.data = []byte("z's blob, referenced twice under epoch 1")
	r.bid = a.upload("m", "z", "text/plain", r.data, r.root())
	r.z1 = a.wr("m", "z", "", withNonce(addRoot(map[string]any{"b": ref(r.bid, "text/plain", len(r.data), ""), "v": 1.0})), r.root())
	z2 := a.wr("m", "z", r.z1, withNonce([]any{op("replace", "/v", 2.0)}), r.root())
	z3 := a.wr("m", "z", z2, withNonce([]any{op("replace", "/v", 3.0)}), r.root())
	a.clock.Advance(time.Hour)
	if raise {
		expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
		r.raised = a.nsHead("m", r.root())
	}
	return r, z2, z3
}

// fcSyncs runs n syncs of b, each after its clock moves past the longest
// backoff (maxPendingBackoff, 4 h).
func fcSyncs(t *testing.T, b *tenv, n int) {
	t.Helper()
	for range n {
		b.clock.Advance(5 * time.Hour)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
}

// v0.26.1 final review (C-I3, should-fix: "410 pruned only where owed"; not a
// regression, v0.26.0 took any horizon as final, and A gains only
// finality over withholding, B's 410 being no-store): B takes
// A's 410 pruned for a blob's sealing under epoch e as final where its
// horizon is a mirrored revision after the FIRST revision referencing the
// blob under e (prunedIn with firstRef at creation; horizonIn with the
// row's rev_seq at a sync). §E.2.2 (SPEC "Epochs": "An epoch whose
// referencing revisions were all pruned answers 410"), and openSealedBlob,
// owe that 410 only once EVERY revision of e referencing it is below the
// horizon, and §8.6 keeps the horizon's own document. Here z1, z2 and z3
// all reference the blob under epoch 1; a real A pruned at z2 (and even at
// z3) still serves …/e/1 (the control). A that answers B 410 pruned with
// horizon z2 for …/e/1 gets B to answer 410 for it for good: never asked
// again, even once A serves it.
func TestV0261BlobPrunedHorizonBeforeLastReference(t *testing.T) {
	t.Parallel()
	t.Run("control: a real A pruned at z2 serves the blob under epoch 1", func(t *testing.T) {
		r, z2, z3 := newFCSameEpoch(t, false)
		e1 := blobPath("m", "z", r.bid) + "/e/1"
		expect(t, r.a.get(e1, r.root()), 200)
		for _, hz := range []string{z2, z3} {
			expect(t, r.a.prune("m", "z", map[string]any{"horizon": hz}, r.root()), 200)
			expect(t, r.a.get("/r/m/z/rev/"+r.z1, r.root()), 410)
			if res := r.a.get(e1, r.root()); res.Code != 200 {
				t.Fatalf("pruned at %s: …/e/1 %d %s", hz, res.Code, res.Body)
			}
		}
	})
	for _, at := range []string{"creation", "sync"} {
		t.Run("lie at "+at, func(t *testing.T) {
			r, z2, _ := newFCSameEpoch(t, true)
			e1 := blobPath("m", "z", r.bid) + "/e/1"
			lie := v077Answer{2, http.StatusGone, `{"code":"pruned","horizon":"` + z2 + `"}`} // the first mirrors the blob (fetchBlobs)
			p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + e1: lie})
			if at == "sync" {
				p.set(map[string]v077Answer{"GET " + e1: {2, http.StatusForbidden, v077Forbidden}})
			}
			b := newV077B(t, r, p)
			kB, g := v0261Remote(t, b, r, "r")
			if at == "sync" {
				expectCode(t, b.get(blobPath("r", "z", r.bid)+"/e/1", g), 502, "upstream")
				p.set(map[string]v077Answer{"GET " + e1: {1, lie.status, lie.body}})
				fcSyncs(t, b, 1)
				g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
			}
			res := b.get(blobPath("r", "z", r.bid)+"/e/1", g)
			t.Logf("B, after A's 410 with horizon z2: %d %s", res.Code, res.Body)
			p.set(nil) // A serves it
			before := p.count("GET " + e1)
			fcSyncs(t, b, 3)
			g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
			ra, rb := r.a.get(e1, r.root()), b.get(blobPath("r", "z", r.bid)+"/e/1", g)
			expect(t, ra, 200)
			if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
				t.Fatalf("z's blob under epoch 1, which z2 and z3 still reference: B answers %d %.160s for good (A asked %d times since); "+
					"A's 410 pruned with horizon z2 was taken as final", rb.Code, rb.Body, p.count("GET "+e1)-before)
			}
		})
	}
}

// v0.26.1 final review (C-I3, same class): §8.6 keeps, when the horizon H is a
// tombstone, "the last live document". A real A that deleted x (tombstone
// x2) and pruned at x2 still serves x1's document (the control; x1's own
// log range is 410). B takes A's 410 pruned for x1's document with horizon
// x2 as final, since x2 is a mirrored revision after x1: 410 for good.
// (Should-fix, as TestV0261BlobPrunedHorizonBeforeLastReference; the same
// holds for a blob the last live document references: a real A pruned at
// a tombstone still serves it.) x1's log entry is owed 410 there, so the
// exception is for documents and blobs only.
func TestV0261DocPrunedAtTombstone(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, raise bool) (*v077Raised, string) {
		var aPriv ed25519.PrivateKey
		a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
		a.opPriv = aPriv
		r := &v077Raised{a: a, kA: newKey("admin")}
		a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{r.kA.entry("*")}}))
		r.root = func() string { return a.grant(r.kA, "user:root", []string{"m"}, allVerbs) }
		r.x1 = a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), r.root())
		del := a.write("DELETE", "m", "x", r.x1, nil, r.root())
		expect(t, del, 200)
		a.clock.Advance(time.Hour)
		if raise {
			expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), r.root()), 201)
			r.raised = a.nsHead("m", r.root())
		}
		return r, del.Str("tombstone")
	}
	t.Run("control: a real A pruned at the tombstone serves x1's document", func(t *testing.T) {
		r, x2 := setup(t, false)
		expect(t, r.a.prune("m", "x", map[string]any{"horizon": x2}, r.root()), 200)
		expect(t, r.a.get("/r/m/x/rev/"+r.x1+"/log", r.root()), 410)
		expect(t, r.a.get("/r/m/x/rev/"+r.x1, r.root()), 200)
	})
	for _, at := range []string{"creation", "sync"} {
		t.Run("lie at "+at, func(t *testing.T) {
			r, x2 := setup(t, true)
			xDoc := "/r/m/x/rev/" + r.x1
			lie := v077Answer{1, http.StatusGone, `{"code":"pruned","horizon":"` + x2 + `"}`}
			p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: lie})
			if at == "sync" {
				p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden}})
			}
			b := newV077B(t, r, p)
			kB, g := v0261Remote(t, b, r, "r")
			if at == "sync" {
				expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
				p.set(map[string]v077Answer{"GET " + xDoc: lie})
				fcSyncs(t, b, 1)
				g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
			}
			res := b.get("/r/r/x/rev/"+r.x1, g)
			t.Logf("B, after A's 410 with horizon x2: %d %s", res.Code, res.Body)
			p.set(nil)
			before := p.count("GET " + xDoc)
			fcSyncs(t, b, 3)
			g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
			ra, rb := r.a.get(xDoc, r.root()), b.get("/r/r/x/rev/"+r.x1, g)
			expect(t, ra, 200)
			if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
				t.Fatalf("x1's document, the last live one before the tombstone x2: B answers %d %.160s for good (A asked %d times since); "+
					"A's 410 pruned with horizon x2 was taken as final", rb.Code, rb.Body, p.count("GET "+xDoc)-before)
			}
		})
	}
}
