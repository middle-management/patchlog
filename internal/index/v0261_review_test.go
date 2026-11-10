package index_test

// Regression tests from the independent review of the v0.26.1 index fixes.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// TestV0261WidenPending503: pr is private (its genesis recorded in
// ns_conf as not public) and is made public; the index hasn't applied the
// widening yet (its follower is held), while the grant checker, which
// reads the live head, already reads pr as public. pr is public only once
// the index has applied it (publicFor): meanwhile an anonymous query of
// pr is 401 (not 503, as e75beac had it, its read check and its re-check
// once gen is taken disagreeing), a grant holder reads it as a private
// namespace, and an anonymous /_refs over pr and pub answers with pub's
// hits, leaving pr out. Once applied, pr is answered anonymously.
func TestV0261WidenPending503(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	for _, ns := range []string{"pub", "schemas"} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	}
	nss := []string{"pr", "pub", "schemas"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", nss, []string{"read", "create", "config"})))
	sch := must(w.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{"title": map[string]any{"type": "string"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"$schema": ref, "title": "a", "related": []any{"/r/target/x"}}))
	must(w.CreateDoc(ctx, "pub", "p", map[string]any{"$schema": ref, "title": "p", "related": []any{"/r/target/x"}}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	var hold atomic.Bool
	held, release := make(chan struct{}), make(chan struct{})
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr", "pub"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			rec := o.OnApply
			o.OnApply = func(b *follow.Batch) {
				rec(b)
				if b.NS == "pr" && hold.CompareAndSwap(true, false) {
					close(held)
					<-release // pr's follower waits here
				}
			}
		})
	x.caughtUp("pr")
	x.caughtUp("pub")
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	if r := x.raw("/pr?limit=5", ""); r.status != 401 {
		t.Fatalf("anonymous /pr while private: %d %v", r.status, r.body)
	}
	if got := refsAllHits(x.follow(refs, "").body); got != "pub/p" {
		t.Fatalf("anonymous /_refs while pr is private: %s", got)
	}
	hold.Store(true)
	must(w.CreateDoc(ctx, "pr", "b", map[string]any{"$schema": ref, "title": "b"}))
	<-held
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "public"}}))
	time.Sleep(20 * time.Millisecond) // past the harness's CheckerTTL (1 ms): the checker reads pr's head, public
	r := x.raw("/pr?limit=6", "")
	t.Logf("anonymous /pr, made public, the widening not applied yet: %d %v", r.status, r.body)
	if r.status != 401 {
		t.Errorf("anonymous /pr, public at its head, the widening not applied yet: %d %v, want 401", r.status, r.body)
	}
	rg := k.Grant(t, s.Now(), "user:r", []string{"pr"}, []string{"read"})
	if g := x.raw("/pr?limit=6", rg); g.status != 302 || !strings.HasPrefix(g.header.Get("Location"), "/pr/g/") {
		t.Errorf("a grant holder's /pr meanwhile: %d %q %v, want a redirect to its gs", g.status, g.header.Get("Location"), g.body)
	} else if f := x.raw(g.header.Get("Location"), rg); f.status != 200 {
		t.Errorf("a grant holder's %s meanwhile: %d %v", g.header.Get("Location"), f.status, f.body)
	}
	rr := x.follow(refs+"&limit=6", "")
	t.Logf("anonymous /_refs meanwhile: %d %v", rr.status, rr.body)
	if got := refsAllHits(rr.body); rr.status != 200 || got != "pub/p" {
		t.Errorf("anonymous /_refs over pr and pub while pr's widening is pending: %d %q, want 200 with pub/p alone", rr.status, got)
	}
	close(release)
	x.caughtUp("pr")
	if r := x.follow("/pr?limit=7", ""); r.status != 200 {
		t.Errorf("anonymous /pr once the widening is applied: %d %v", r.status, r.body)
	}
}

// TestV0261SnapshotRebuildNoNarrowPurge (gap 2): the index serves
// pr, public, and its anonymous result is handed out with public immutable
// caching, tagged idx:pr. While the index is down pr is made private; the
// index is rebuilt. Replayed from the log (the default), the narrowing is
// applied again and purges idx:pr (§A.1). Bootstrapped from a snapshot
// (follow.WithSnapshot, an Options.FollowOptions a library user may pass),
// no config entry is applied, ns_conf is empty, and idx:pr is never
// purged: the CDN keeps serving the public copies.
func TestV0261SnapshotRebuildNoNarrowPurge(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("snapshot=%v", snapshot), func(t *testing.T) {
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
			must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public then"}))
			ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
			db := filepath.Join(t.TempDir(), "i.db")
			x1 := startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
			x1.caughtUp("pr")
			p := x1.raw("/pr?limit=5", "")
			f := x1.raw(p.header.Get("Location"), "")
			if f.status != 200 || !strings.Contains(f.header.Get("Cache-Control"), "public") || !strings.Contains(f.header.Get("Cache-Tag"), "idx:pr") {
				t.Fatalf("public result: %d %q %q", f.status, f.header.Get("Cache-Control"), f.header.Get("Cache-Tag"))
			}
			x1.stop()
			must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
			x2 := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, rebuild: true, now: s.Now},
				func(o *indexOpts) {
					if snapshot {
						o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot())
					}
				})
			x2.caughtUp("pr")
			x2.appliedUpTo(must(w.NSHead(ctx, "pr")).ID)
			got := x2.purgesSoFar()
			t.Logf("purges after the rebuild: %s", got)
			if !strings.Contains(got, "idx:pr") {
				t.Errorf("pr made private while the index was down, rebuilt (snapshot=%v): idx:pr never purged (%s); the CDN's public copies of %s stay", snapshot, got, p.header.Get("Location"))
			}
		})
	}
}

// v0261HookPurger calls f with every purge's tags, after the svc records
// them: purgeKept calls PurgeTags once kept results are dropped, before a
// member's checkpoint is published (memberHandler.Apply's reach).
type v0261HookPurger struct {
	next index.Purger
	f    func([]string)
}

func (p v0261HookPurger) PurgeTags(tags []string) { p.next.PurgeTags(tags); p.f(tags) }

// TestV0261MemberPurgeWindow (gap 1): the index serves matches and
// covers it through cat-season, a member. A placement in cat-season,
// matches.shared, is purged: memberHandler.Apply commits, drops kept
// results tagged idx:cat-season, and only then publishes the member's new
// checkpoint (reach), and later tells the checker (Observe). li, a fan,
// asks in between (from PurgeTags). Is an answer computed there, at the
// member's position before the purge, kept with shared, and served after?
func TestV0261MemberPurgeWindow(t *testing.T) {
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	var armed atomic.Bool
	type seen struct {
		loc  string
		ptr  resp
		hits string
	}
	got := make(chan seen, 1)
	var li string
	ev := must(edge.New([]byte("s3cret"), "", ""))
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	w.x = startSvcWith(t, w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
			o.Purger = v0261HookPurger{next: o.Purger, f: func(tags []string) {
				if !slices.Contains(tags, "idx:cat-season") || !armed.CompareAndSwap(true, false) {
					return
				}
				done := make(chan seen, 1)
				go func() {
					var sn seen
					sn.ptr = w.x.raw("/matches", li)
					sn.loc = sn.ptr.header.Get("Location")
					if sn.ptr.status == 302 {
						sn.hits = strings.Join(resources(w.x.raw(sn.loc, li).body), ",")
					}
					done <- sn
				}()
				select {
				case sn := <-done:
					got <- sn
				case <-time.After(5 * time.Second):
					got <- seen{loc: "timeout"}
				}
			}}
		})
	w.x.caughtUp("matches")
	li = w.reader("user:li", []any{"fans"})
	loc0, _, _ := w.pointer("/matches", li)
	if got := strings.Join(resources(w.x.search(loc0, li)), ","); got != "derby,shared" {
		t.Fatalf("li sees %s, want derby,shared", got)
	}
	armed.Store(true)
	h := must(w.admin.Head(ctx, "cat-season", "matches.shared"))
	must(w.admin.Purge(ctx, "cat-season", "matches.shared", h.ID, false))
	sn := <-got
	t.Logf("li in the window: %d Location=%q hits=%q", sn.ptr.status, sn.loc, sn.hits)
	waitFor(t, "cat-season followed to its head", func() bool { return w.x.ix.Members()["cat-season"] == w.head("cat-season") })
	if sn.loc == "" || sn.loc == "timeout" {
		return
	}
	if loc2, _, _ := w.pointer("/matches", li); loc2 == sn.loc {
		t.Logf("the window's answer is at the post-purge at: the pre-purge position wasn't exercised")
	}
	r := w.x.raw(sn.loc, li)
	after := strings.Join(resources(r.body), ",")
	t.Logf("li GET %s after the purge: %d hits=%q kept=%v", sn.loc, r.status, after, w.x.ix.KeptHas(sn.loc))
	if r.status == 200 && strings.Contains(after, "shared") {
		t.Errorf("li's answer computed in the member's purge window, showing the purged placement's item, served after the purge: %s %q", sn.loc, after)
	}
}

// TestV0261StaleCheckerAfterNarrowing (F1's guard for I1): pr is made
// private and the index has applied it, but the grant checker reloads pr
// from a stale head pointer (a cache or a lagging replica in front of the
// core: the head before the narrowing, public). The checker's head is
// not after the index's checkpoint in pr's chain (stillPublic), so an
// anonymous query is not answered from it: no result is computed in the
// public URL space, kept or served. Trusting the checker whenever it
// disagrees with ns_conf would serve pr's hits publicly here.
func TestV0261StaleCheckerAfterNarrowing(t *testing.T) {
	ctx := context.Background()
	var capture, replay atomic.Bool
	var replayed atomic.Int32
	var mu sync.Mutex
	var stale *httptest.ResponseRecorder
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/ns/pr" {
				h.ServeHTTP(rw, r)
				return
			}
			mu.Lock()
			st := stale
			mu.Unlock()
			if replay.Load() && st != nil {
				replayed.Add(1)
				for k, v := range st.Header() {
					rw.Header()[k] = v
				}
				rw.WriteHeader(st.Code)
				rw.Write(st.Body.Bytes())
				return
			}
			if capture.Load() {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				mu.Lock()
				stale = rec
				mu.Unlock()
				for k, v := range rec.Header() {
					rw.Header()[k] = v
				}
				rw.WriteHeader(rec.Code)
				rw.Write(rec.Body.Bytes())
				return
			}
			h.ServeHTTP(rw, r)
		})
	}})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second })
	x.caughtUp("pr")
	capture.Store(true)
	must(w.NSHead(ctx, "pr"))
	capture.Store(false)
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	must(w.CreateDoc(ctx, "pr", "b", map[string]any{"title": "written while private"}))
	x.appliedUpTo(x.caughtUp("pr"))
	replay.Store(true)
	x.ix.ExpireGrantChecks() // the checker reloads pr now, from the stale head
	r := x.raw("/pr?limit=9", "")
	loc := r.header.Get("Location")
	var at resp
	if r.status == 302 && strings.HasPrefix(loc, "/pr/at/") {
		at = x.raw(loc, "")
	}
	replay.Store(false)
	t.Logf("anonymous /pr, the checker's head stale (%d replayed): %d Location=%q; %d", replayed.Load(), r.status, loc, at.status)
	if r.status == 200 || at.status == 200 {
		t.Errorf("pr, private, answered to an anonymous reader from a stale head: %d %v / %d %v", r.status, r.body, at.status, at.body)
	}
	if strings.HasPrefix(loc, "/pr/at/") && x.ix.KeptHas(loc) {
		t.Errorf("a result of pr, private, kept under the public URL %s", loc)
	}
}
