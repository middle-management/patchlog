package index_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// v82Gate holds the index's reads that match picks until open is closed.
type v82Gate struct {
	base  http.RoundTripper
	match func(*http.Request) bool
	open  chan struct{}
}

func (g *v82Gate) RoundTrip(r *http.Request) (*http.Response, error) {
	if g.match(r) {
		select {
		case <-g.open:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return g.base.RoundTrip(r)
}

// TestV082StoppedMemberKeepsServedTrust (SVC-08; §B.11.9 Where, v0.82: "a
// purged catalog's catalog.trust is the last one the origin stored or the
// service read"; §A.4): the index serves matches and cat-season, which
// was purged before it started. Until its own follower has reached
// cat-season, visibility reads cat-season through a follower of its own
// (memberAtGone), which the reconciler stops once the index holds
// cat-season's checkpoint. Here that follower is still at its bootstrap,
// so never met the purge, when the index applies cat-season's log, its
// purge-ns last, and records the trust its documents gave. The follower
// stopped, forgetting what it held leaves that trust alone: matches is
// covered and dark, and li, a partial reader, gets a g: marker and no
// hits. Before, cat-season, whose document is still read at its head,
// counted as live there, and its trust was forgotten with the follower's
// checkpoint, after the last entry that would record it again: li was 403
// with no marker for good, in the runs where the reconciler stopped the
// follower after cat-season's purge-ns committed and before the follower
// met the purge itself (TestV082PurgedCatalogMetPurged failed so, one run
// in twenty).
func TestV082StoppedMemberKeepsServedTrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	rd := clienttest.NewKey("rd")
	e := rd.Entry("read")
	e["rules"] = []any{v77TypeRule}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/keys/-", "value": e}}))
	li := rd.Grant(t, w.s.Now(), "user:li", []string{"matches"}, []string{"read"}, map[string]any{"groups": []any{"fans"}, "roles": []any{"reader"}})
	v82PurgeNS(w, "cat-season")

	// The index's own follower of cat-season reads nothing of its state
	// until the gate opens: its log, heads and events. Its head and its
	// documents, which coverage and the grant checker read, pass.
	gate := &v82Gate{base: http.DefaultTransport, open: make(chan struct{}), match: func(r *http.Request) bool {
		p := r.URL.Path
		return strings.HasPrefix(p, "/ns/cat-season/") && (strings.HasSuffix(p, "/log") || strings.HasSuffix(p, "/heads") || strings.HasSuffix(p, "/events"))
	}}
	var openOnce sync.Once
	open := func() { openOnce.Do(func() { close(gate.open) }) }
	// stops counts the times the reconciler stopped the follower for
	// visibility; purgesThen are the purges of idx:cat-season as it last
	// did, before it forgot what that follower held, which purges it
	// once more.
	var (
		x          *svc
		mu         sync.Mutex
		stops      int
		purgesThen int
		member     context.Context // the follower for visibility last started
	)
	x = startSvcWith(t, w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", []string{"schemas", "cat-season", "matches"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "cat-season"}, untyped: true, now: w.s.Now, noRun: true, hc: &http.Client{Transport: gate}},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
			logf := o.Logf
			o.Logf = func(f string, a ...any) {
				logf(f, a...)
				if strings.Contains(f, "is no longer read by the coverage") && len(a) == 1 && a[0] == "cat-season" {
					n := members76Purges(x, "idx:cat-season")
					mu.Lock()
					stops, purgesThen = stops+1, n
					mu.Unlock()
				}
			}
		})
	// The follower for visibility never gets past its bootstrap: it holds
	// no checkpoint and never meets the purge.
	x.ix.OnMemberBootstrap(func(ctx context.Context, m string) {
		if m == "cat-season" {
			mu.Lock()
			member = ctx
			mu.Unlock()
			<-ctx.Done()
		}
	})
	x.ix.SetMinWait(20 * time.Millisecond) // for a follower that holds no checkpoint
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { x.ix.Run(rctx); close(done) }()
	t.Cleanup(func() { open(); cancel(); <-done })

	x.caughtUp("matches")
	// cat-season not reached and its follower for visibility without a
	// checkpoint: li is behind, never answered. Her query starts that
	// follower; the reconciler stops it whenever it runs, as cat-season is
	// one the index serves, so it is started until one stays, the
	// reconciler having nothing left to run for until the gate opens.
	var running context.Context
	var stopsThen int
	waitFor(t, "a follower for visibility of cat-season that stays", func() bool {
		if r := x.raw("/matches", li); r.status != 503 {
			t.Fatalf("li before the index reached cat-season: %d %v, want 503", r.status, r.body)
		}
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		running, stopsThen = member, stops
		mu.Unlock()
		return running != nil && running.Err() == nil
	})

	open()
	waitFor(t, "the index applies cat-season's purge", func() bool {
		for _, b := range x.batches() {
			if b.NS == "cat-season" && b.Coalesce().PurgedNS {
				return true
			}
		}
		return false
	})
	// Applying it runs the reconciler, which stops the follower and
	// forgets what it held.
	select {
	case <-running.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the reconciler never stopped cat-season's follower for visibility")
	}
	waitFor(t, "the index forgets what cat-season's follower for visibility held", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return stops > stopsThen && members76Purges(x, "idx:cat-season") > purgesThen
	})

	if n := must(x.ix.ExecForTest(ctx, `UPDATE catalog_trust SET trust = trust WHERE ns = 'cat-season'`)); n != 1 {
		t.Errorf("the index holds %d catalog.trust of cat-season once its follower for visibility stopped, want the one its own follower recorded", n)
	}
	x.ix.ExpireGrantChecks()
	q := x.raw("/matches", li)
	if q.status != 302 || !strings.HasPrefix(q.header.Get("Location"), "/matches/g/") {
		t.Fatalf("li's query: %d %s %v, want a redirect under her g: marker", q.status, q.header.Get("Location"), q.body)
	}
	if r := x.follow("/matches", li); r.status != 200 || len(resources(r.body)) != 0 {
		t.Errorf("li where cat-season is purged: %d %v, want no hits", r.status, r.body)
	}
}
