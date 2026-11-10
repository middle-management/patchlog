package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
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
	// x's own revision is a horizon in its chain: final, as before.
	b.clock.Advance(5 * time.Hour)
	p.set(map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + r.x1 + `"}`}})
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("sync: %v", err)
	}
	g = b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	res = b.get("/r/r/x/rev/"+r.x1, g)
	expectCode(t, res, 410, "pruned")
	if res.Str("horizon") != r.x1 {
		t.Fatalf("x's document: %s, want horizon %s", res.Body, r.x1)
	}
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
	p := newV077Proxy(t, r.a, map[string]v077Answer{"GET " + xDoc: {1, http.StatusGone, `{"code":"pruned","horizon":"` + r.x1 + `"}`}})
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
// pending sealing again (x's document).
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
		if el > 15*time.Second || !hung.Load() || err == nil {
			t.Fatalf("%s: SyncRemotes took %v (hung: %v), error %v", hang, el, hung.Load(), err)
		}
		c1, c2 := b.get("/r/r1/x/rev/"+r.x1, g1).Code, b.get("/r/r2/x/rev/"+r.x1, g2).Code
		if c1+c2 != 200+502 {
			t.Fatalf("%s: x's document on r1: %d, on r2: %d; want one base followed (200) past the other's deadline (502)", hang, c1, c2)
		}
	}
}

// C2: rows that v0.26.0 recorded 410 pruned (due 0) with any horizon A
// named. One whose horizon isn't a revision of the chain at or after its
// own is served 502, never with that horizon, and is asked for again
// (pendingFixes); one whose horizon is stays 410 pruned for good.
func TestV0261PreRaiseLegacyPrunedRows(t *testing.T) {
	t.Parallel()
	r := newV077Raised(t)
	xDoc, yDoc := "/r/m/x/rev/"+r.x1, "/r/m/y/rev/"+r.y1
	p := newV077Proxy(t, r.a, map[string]v077Answer{
		"GET " + xDoc: {1, http.StatusForbidden, v077Forbidden},
		"GET " + yDoc: {1, http.StatusForbidden, v077Forbidden},
	})
	var path string
	b := newV0261B(t, r, p.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
	_, g := v0261Remote(t, b, r, "r")
	db, _ := v0261DB(t, path)
	for name, hz := range map[string]string{"x": strings.Repeat("A", 1<<10), "y": r.y1} {
		res, err := db.Exec(`UPDATE remote_pending_sealings SET answer = 'pruned', horizon = '` + hz + `', due = 0, tries = 0 WHERE name = '` + name + `' AND kind = 'doc'`)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("%s: %d pending rows of its document", name, n)
		}
	}
	expectCode(t, b.get("/r/r/x/rev/"+r.x1, g), 502, "upstream")
	res := b.get("/r/r/y/rev/"+r.y1, g)
	expectCode(t, res, 410, "pruned")
	if res.Str("horizon") != r.y1 {
		t.Fatalf("y's document: %s, want horizon %s", res.Body, r.y1)
	}
	// A serves both now: x's is asked for again and stored, y's isn't.
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
	expectCode(t, b.get("/r/r/y/rev/"+r.y1, g), 410, "pruned")
}
