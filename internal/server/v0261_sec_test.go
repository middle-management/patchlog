package server

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v0.26.1: a remote branch against a hostile remote base A (security
// review of v0.26.0, C1-C5, C-M, C-B, C-E). v0.78 cut the pending
// pre-raise sealings these were first found through; the rules that
// remain are held here on a source that is e2e from its creation
// (v081Source), and the snapshot-mirroring tests of v081_enc_remote_test.go.

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

// C1: a base that doesn't answer held SyncRemotes, which follows bases one
// after another on the follower's goroutine, for ever: production's HTTP
// client has no timeout, and the follower's context no deadline. Each
// base's step now has one (RemoteOptions.FollowTimeout), so the other
// bases are still followed. A hang where the branch follows the base's
// log (GET /ns/m). An origin has one FollowTimeout per sync: once spent,
// its other branches wait for the next, which follows both.
func TestV0261FollowDeadline(t *testing.T) {
	t.Parallel()
	s := newV081Source(t)
	// In front of A: once armed, the first GET of the log hangs until B
	// gives up; the rest go to A.
	var armed, hung atomic.Bool
	release := make(chan struct{})
	target, _ := url.Parse(s.a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" && req.URL.Path == "/ns/m" && armed.Load() && hung.CompareAndSwap(false, true) {
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
	b := newV081B(t, s, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = 3 * time.Second })
	_, g1 := v081Remote(t, b, s, "r1")
	_, g2 := v081Remote(t, b, s, "r2")
	// A purges y (§8.5), which each branch follows (§G.3).
	expect(t, s.a.purge("m", "y", s.y1, s.root()), 204)
	armed.Store(true)
	start := time.Now()
	err := b.e.SyncRemotes(context.Background())
	el := time.Since(start)
	t.Logf("SyncRemotes after %v: %v", el, err)
	// The hang spends the origin's FollowTimeout: its other branch is
	// skipped.
	if el > 6*time.Second || !hung.Load() || err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Fatalf("SyncRemotes took %v (hung: %v), error %v", el, hung.Load(), err)
	}
	// The next sync follows both.
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Logf("second sync: %v", err)
	}
	for _, c := range []struct{ ns, g string }{{"r1", g1}, {"r2", g2}} {
		if r := b.get("/r/"+c.ns+"/y/rev/"+s.y1+"/log", c.g); r.Code != 410 {
			t.Fatalf("y's purge on %s after the next sync: %d %s; want 410", c.ns, r.Code, r.Body)
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
				s := newV081Source(t)
				p := newV077Proxy(t, s.a, nil)
				var opts []envOpt
				if step == "postRegistration" {
					opts = append(opts, func(o *core.Options) { o.Remote.Register = true })
				}
				b := newV081B(t, s, p.srv.URL, opts...)
				v081Remote(t, b, s, "r")

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
						w.Header().Set("ETag", `"`+s.x1+`"`)
						w.WriteHeader(http.StatusFound)
						return
					case step == "sealedAt" && req.Method == "GET" && req.URL.Path == "/ns/m/rev/"+s.x1+"/log":
						w.WriteHeader(http.StatusForbidden)
						io.WriteString(w, v077Forbidden)
						return
					case step == "sealedAt" && req.Method == "GET" && req.URL.Path == "/ns/m/rev/"+s.x1:
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
	s := newV081Source(t)
	var armed atomic.Bool
	target, _ := url.Parse(s.a.srv.URL)
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
	b := newV081B(t, s, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = timeout })
	const k = 4
	for i := 0; i < k; i++ {
		v081Remote(t, b, s, "r"+string(rune('a'+i)))
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
// has no deadline of its own: A dripping its answer to one of creation's
// reads within its cap holds the creating request as long as it likes,
// past FollowTimeout. Here A drips x's log for 4 s: creation gives up at
// FollowTimeout, 502 upstream.
func TestV0261CreationNoDeadline(t *testing.T) {
	t.Parallel()
	s := newV081Source(t)
	target, _ := url.Parse(s.a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	const drip = 4 * time.Second
	var dripped atomic.Bool
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" && strings.HasPrefix(req.URL.Path, "/r/m/x/rev/") && strings.HasSuffix(req.URL.Path, "/log") {
			dripped.Store(true)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte("["))
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
	b := newV081B(t, s, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = time.Second })
	start := time.Now()
	kB := newKey("badmin")
	r := b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
	el := time.Since(start)
	t.Logf("creation took %v with FollowTimeout 1s: %d %s", el, r.Code, r.Body)
	if !dripped.Load() {
		t.Fatal("creation didn't read x's log")
	}
	if el >= drip {
		t.Fatalf("creation took %v: A's drip held it past FollowTimeout", el)
	}
	expectCode(t, r, 502, "upstream")
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
	s := newV081Source(t)
	target, _ := url.Parse(s.a.srv.URL)
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
	b := newV081B(t, s, front.URL, func(o *core.Options) {
		o.Remote.FollowTimeout = time.Second
		o.Remote.Register = true
	})
	start := time.Now()
	v081Remote(t, b, s, "r")
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
	s := newV081Source(t)
	const timeout = time.Second
	var armed atomic.Bool
	target, _ := url.Parse(s.a.srv.URL)
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
	b := newV081B(t, s, front.URL, func(o *core.Options) { o.Remote.FollowTimeout = timeout })
	const k = 4
	for i := 0; i < k; i++ {
		v081Remote(t, b, s, "r"+string(rune('a'+i)))
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

// v0.26.1 review, round 3 (b345cfe): A can always produce a hash chain
// from B's head to a horizon (ids are unkeyed hashes): one fabricated
// entry, the tombstone of B's head, suffices. Here B registered with A at
// creation (§G.3), so §8.6 forbids A any horizon past x's head as of at,
// and A's real server still serves x1's log entry: only its answers to B
// after creation lie, 410 pruned with that horizon and the one-entry log
// that "verifies" it. Since v0.78 B mirrors the whole of an E3 source's
// chain at creation and answers its reads from that (§G.5.2), so such a
// horizon never reaches what B serves: B doesn't ask A for x again.
func TestV0261ForgedPastHorizonWhileRegistered(t *testing.T) {
	t.Parallel()
	s := newV081Source(t)
	x1, err := ids.Parse(s.x1)
	if err != nil {
		t.Fatal(err)
	}
	hz := ids.Tombstone(x1).String()
	forged := `[{"id":"` + hz + `","parent":"` + s.x1 + `","kind":"tombstone"}]`
	xLog := "/r/m/x/rev/" + s.x1 + "/log"
	p := newV077Proxy(t, s.a, nil)
	b := newV081B(t, s, p.srv.URL, func(o *core.Options) { o.Remote.Register = true })
	kB, _ := v081Remote(t, b, s, "r")
	br := s.a.get("/ns/m/branches", s.root())
	if !strings.Contains(string(br.Body), originB) {
		t.Fatalf("B didn't register with A: %s", br.Body)
	}
	p.set(map[string]v077Answer{
		"GET /r/m/x/rev/" + s.x1:        {1, http.StatusGone, `{"code":"pruned","horizon":"` + hz + `"}`},
		"GET " + xLog:                   {1, http.StatusGone, `{"code":"pruned","horizon":"` + hz + `"}`},
		"GET /r/m/x/rev/" + hz + "/log": {1, http.StatusOK, forged},
	})
	before := p.count("GET "+xLog) + p.count("GET /r/m/x/rev/"+s.x1)
	for range 3 {
		b.clock.Advance(5 * time.Hour)
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
	}
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})
	ra, rb := s.a.get(xLog, s.root()), b.get("/r/r/x/rev/"+s.x1+"/log", g)
	same := func(a, b *resp) bool {
		ea, eb := a.Arr(), b.Arr()
		if len(ea) != 1 || len(eb) != 1 {
			return false
		}
		ma, mb := ea[0].(map[string]any), eb[0].(map[string]any)
		return ma["id"] == mb["id"] && jsonv.Equal(jsonv.FromGo(ma["patches"]), jsonv.FromGo(mb["patches"]))
	}
	if ra.Code != 200 || rb.Code != 200 || !same(ra, rb) {
		t.Fatalf("x1's log entry: A %d %s, B %d %s; want B to serve what it mirrored", ra.Code, ra.Body, rb.Code, rb.Body)
	}
	if after := p.count("GET "+xLog) + p.count("GET /r/m/x/rev/"+s.x1); after != before {
		t.Fatalf("B asked A for x1 %d times after creation", after-before)
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
				return core.RemoteEndpoint{BaseURL: a.srv.URL, HTTPClient: httpClient}, nil
			case originC:
				return core.RemoteEndpoint{BaseURL: front.URL, HTTPClient: httpClient}, nil
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
// revisions under the same epoch 1, z1 and z2 (and z3 after).
func newFCSameEpoch(t *testing.T) (a *tenv, root func() string, bid, z1, z2, z3 string) {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a = newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root = func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	data := []byte("z's blob, referenced twice under epoch 1")
	bid = a.upload("m", "z", "text/plain", data, root())
	z1 = a.wr("m", "z", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), ""), "v": 1.0})), root())
	z2 = a.wr("m", "z", z1, withNonce([]any{op("replace", "/v", 2.0)}), root())
	z3 = a.wr("m", "z", z2, withNonce([]any{op("replace", "/v", 3.0)}), root())
	a.clock.Advance(time.Hour)
	return a, root, bid, z1, z2, z3
}

// v0.26.1 final review (C-I3, "410 pruned only where owed"): §E.2.2
// ("Epochs": "An epoch whose referencing revisions were all pruned answers
// 410") owes that 410 only once EVERY revision of e referencing a blob is
// below the horizon, and §8.6 keeps the horizon's own document. Here z1,
// z2 and z3 all reference the blob under epoch 1; A pruned at z2 (and even
// at z3) still serves …/e/1. (v0.78 cut the remote branches' pending
// pre-raise sealings that took A's 410 for it as final.)
func TestV0261BlobPrunedHorizonBeforeLastReference(t *testing.T) {
	t.Parallel()
	a, root, bid, z1, z2, z3 := newFCSameEpoch(t)
	e1 := blobPath("m", "z", bid) + "/e/1"
	expect(t, a.get(e1, root()), 200)
	for _, hz := range []string{z2, z3} {
		expect(t, a.prune("m", "z", map[string]any{"horizon": hz}, root()), 200)
		expect(t, a.get("/r/m/z/rev/"+z1, root()), 410)
		if res := a.get(e1, root()); res.Code != 200 {
			t.Fatalf("pruned at %s: …/e/1 %d %s", hz, res.Code, res.Body)
		}
	}
}

// v0.26.1 final review (C-I3, same class): §8.6 keeps, when the horizon H
// is a tombstone, "the last live document". A that deleted x (tombstone
// x2) and pruned at x2 still serves x1's document; x1's own log range is
// 410. (v0.78 cut the remote branches' pending pre-raise sealings that took
// A's 410 for it as final.)
func TestV0261DocPrunedAtTombstone(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	del := a.write("DELETE", "m", "x", x1, nil, root())
	expect(t, del, 200)
	a.clock.Advance(time.Hour)
	expect(t, a.prune("m", "x", map[string]any{"horizon": del.Str("tombstone")}, root()), 200)
	expect(t, a.get("/r/m/x/rev/"+x1+"/log", root()), 410)
	expect(t, a.get("/r/m/x/rev/"+x1, root()), 200)
}
