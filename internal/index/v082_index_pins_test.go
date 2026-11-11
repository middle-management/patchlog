package index_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V82-05 (v0.82): clauses the index already met, pinned (SVC-08, SVC-14i,
// SVC-16, SVC-17i), and the exchange's reading of the authentication mode.

// v82Start starts an index of w following nss, as v75x.start does, with a
// grant that reads every namespace of all.
func v82Start(w *v75x, branches bool, all []string, nss ...string) *svc {
	w.t.Helper()
	ev := must(edge.New([]byte("s3cret"), "", ""))
	x := startSvcWith(w.t, w.s.Client(w.t, client.WithBearer(w.k.Grant(w.t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(w.t.TempDir(), "i.db"), ns: nss, untyped: true, branches: branches, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		})
	for _, ns := range nss {
		x.caughtUp(ns)
	}
	return x
}

// v82Answer is one answer, redirects not followed: what a reader can tell
// two requests apart by.
type v82Answer struct {
	status int
	loc    string
	cache  string
	tags   string
	body   string
}

// v82Get asks path with the Authorization header auth ("" for none) and
// follows redirects with it, returning each answer.
func v82Get(t *testing.T, x *svc, path, auth string) []v82Answer {
	t.Helper()
	var out []v82Answer
	for range 5 {
		req := must(http.NewRequest("GET", x.http.URL+path, nil))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		r := must(noFollow.Do(req))
		b := must(io.ReadAll(r.Body))
		r.Body.Close()
		out = append(out, v82Answer{r.StatusCode, r.Header.Get("Location"), r.Header.Get("Cache-Control"), r.Header.Get("Cache-Tag"), string(b)})
		if r.StatusCode != 302 {
			return out
		}
		path = r.Header.Get("Location")
	}
	t.Fatalf("%s: too many redirects", path)
	return nil
}

// TestV082PublicIgnoresGrant (SVC-14i; §A.4 Public namespaces, v0.82: "a
// query of one ignores any grant and is answered as one without it (§7
// step 1)"; CONFORMANCE SVC-11, scenario 118 at the index): a query of
// public schemas, its redirect included, and /_refs of an index that
// follows only public namespaces, answer a request carrying a grant with
// a block rule on /now, an expired grant, a malformed one, one over
// grantSize or an Authorization that isn't Bearer, byte for byte as they
// answer one without credentials: never 401, 403 or 413.
func TestV082PublicIgnoresGrant(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	x := v82Start(w, false, []string{"schemas"}, "schemas")
	now := w.s.Now()
	auths := map[string]string{
		"a /now rule": "Bearer " + w.k.Grant(t, now, "user:li", []string{"schemas"}, []string{"read"},
			map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}}),
		"expired":       "Bearer " + w.k.Grant(t, now, "user:li", []string{"schemas"}, []string{"read"}, map[string]any{"exp": now.Add(-time.Hour).Format(time.RFC3339)}),
		"another ns":    "Bearer " + w.k.Grant(t, now, "user:li", []string{"matches"}, []string{"read"}),
		"malformed":     "Bearer not-a-grant",
		"oversized":     "Bearer " + strings.Repeat("A", 20000),
		"not Bearer":    "Basic eDp5",
		"empty Bearer":  "Bearer ",
		"a valid grant": "Bearer " + w.k.Grant(t, now, "user:li", []string{"schemas"}, []string{"read"}),
	}
	for _, path := range []string{"/schemas", "/schemas?limit=1", "/_refs?to=" + url.QueryEscape("/r/target/x")} {
		anon := v82Get(t, x, path, "")
		if last := anon[len(anon)-1]; len(anon) < 2 || last.status != 200 || !strings.HasPrefix(last.cache, "public") {
			t.Fatalf("%s without credentials: %+v", path, anon)
		}
		for name, auth := range auths {
			got := v82Get(t, x, path, auth)
			if len(got) != len(anon) {
				t.Errorf("%s with %s: %+v, want as without credentials: %+v", path, name, got, anon)
				continue
			}
			for i := range got {
				if got[i] != anon[i] {
					t.Errorf("%s with %s, hop %d: %+v, want as without credentials: %+v", path, name, i, got[i], anon[i])
				}
			}
		}
	}
}

// TestV082NonBearerIsMalformed (SVC-17i; §C.8: any Authorization that
// isn't a Bearer grant is a malformed grant): on a private namespace's
// query, on /_refs of an index following only private namespaces and at
// the exchange, Authorization: Basic x is 401, as a request with no
// usable grant, and never read as a request without Authorization, which
// could be answered under a cookie.
func TestV082NonBearerIsMalformed(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	prefixes, cookies := d.exchange(d.reader(d.k1))
	for _, path := range []string{"/docs", prefixes["docs"], "/_refs?to=" + url.QueryEscape("/r/docs/schema"), prefixes["_refs"] + "?to=" + url.QueryEscape("/r/docs/schema")} {
		req := must(http.NewRequest("GET", d.x.http.URL+path, nil))
		req.Header.Set("Authorization", "Basic eDp5")
		for _, c := range cookies {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		r := must(noFollow.Do(req))
		r.Body.Close()
		if r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s with Authorization: Basic and the reader's cookies: %d, want 401", path, r.StatusCode)
		}
	}
	req := must(http.NewRequest("POST", d.x.http.URL+"/edge-grants", nil))
	req.Header.Set("Authorization", "Basic eDp5")
	r := must(noFollow.Do(req))
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Errorf("the exchange with Authorization: Basic: %d, want 401", r.StatusCode)
	}
}

// TestV082BranchOfBranchNoMarker (SVC-17i; §A.4 gs, v0.82: no marker
// where {ns} "is a catalog (§B.6) or its catalogs, or that of any local
// base in its chain at the base's head or as of the at it is read through
// at, names one"; scenario 121): matches-r7a is a branch of matches-r7, a
// branch of covered matches, and neither branch's own document names a
// catalog. A partial reader of matches-r7a has no marker there: her query
// and her exchange are 403, and /_refs shows her nothing of it, never the
// hits her rules alone allow. An unrestricted reader reads it.
func TestV082BranchOfBranchNoMarker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	all := []string{"schemas", "cat-season", "matches", "matches-r7", "matches-r7a"}
	admin := w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "user:root", all, []string{"read", "create", "append", "config", "branch"})))
	must(admin.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	must(admin.PatchConfig(ctx, "matches-r7", must(admin.NSHead(ctx, "matches-r7")).Config, []any{map[string]any{"op": "remove", "path": "/catalogs"}}))
	must(admin.CreateBranch(ctx, "matches-r7", client.BranchRequest{Name: "matches-r7a"}))
	for _, b := range []string{"matches-r7", "matches-r7a"} {
		if doc := must(admin.NSDoc(ctx, b, must(admin.NSHead(ctx, b)).ID)).Value; doc["catalogs"] != nil || doc["catalog"] != nil {
			t.Fatalf("%s's own document names a catalog: %v", b, doc)
		}
	}
	x := v82Start(w, true, all, "matches")
	x.caughtUp("matches-r7")
	x.caughtUp("matches-r7a")
	fan := w.reader("user:fan", []any{"fans"}, "matches-r7a")
	if r := x.raw("/matches-r7a", fan); r.status != 403 || r.header.Get("Location") != "" {
		t.Errorf("a partial reader's query of matches-r7a: %d %v, want 403 with no marker", r.status, r.body)
	}
	if r := p37Do(t, x, "POST", "/edge-grants", fan, "", nil, ""); r.status != 403 || len(r.cookies) != 0 {
		t.Errorf("her exchange: %d %v, want 403", r.status, r.body)
	}
	if r := x.follow("/_refs?to="+url.QueryEscape("/r/target/x"), fan); r.status == 200 && len(resources(r.body)) > 0 {
		t.Errorf("/_refs: %d %v, want nothing of matches-r7a", r.status, r.body)
	}
	root := w.k.Grant(t, w.s.Now(), "user:root", []string{"matches-r7a"}, []string{"read"})
	if got := strings.Join(resources(x.search("/matches-r7a", root)), ","); got != "derby,opener,secret,shared" {
		t.Errorf("an unrestricted reader of matches-r7a sees %s", got)
	}
}

// v82RootFails is a core whose GET / answers status while it is set, and
// says authentication is disabled while off is.
type v82RootFails struct {
	status atomic.Int32
	off    atomic.Bool
}

func (f *v82RootFails) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			h.ServeHTTP(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		switch st := int(f.status.Load()); {
		case st != 0:
			rw.WriteHeader(st)
			rw.Write([]byte(`{"code":"x","message":"x"}`))
		case f.off.Load():
			rw.Write([]byte(`{"spec":"0.82","auth":"disabled","origin":"` + clienttest.Origin + `"}`))
		default:
			h.ServeHTTP(rw, r)
		}
	})
}

// TestV082AuthModeNeverFromEarlierRead (SVC-16; §B.11.9 Where, v0.82: "a
// service learns whether authentication is on from the origin's GET /
// (§7), never from an earlier read. While it can't, it answers a request
// that coverage decides, once the reader's grant verifies, 503 (behind)
// where the cause is transient, else 502 (upstream)"; scenario 126): the
// index has read the root and answered li, a partial reader of covered
// matches. Once GET / fails with a 5xx, her query and /_refs are 503
// behind with Retry-After, and with a lasting 4xx 502 upstream, under her
// grant and under her cookie, never answered under the mode read
// earlier; neither names a namespace; a grant that doesn't verify is 401
// first, and a request with no credentials 401. An unrestricted reader,
// whom coverage doesn't decide, is answered throughout.
func TestV082AuthModeNeverFromEarlierRead(t *testing.T) {
	t.Parallel()
	f := &v82RootFails{}
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: f.wrap}))
	w.x = w.start(false, "matches")
	li := w.reader("user:li", []any{"fans"})
	root := w.k.Grant(t, w.s.Now(), "user:root", []string{"matches"}, []string{"read"})
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	prefix, cookies := v081Exchange(t, w.x, li, "matches")
	if got := strings.Join(resources(w.x.search("/matches", li)), ","); got != "derby,shared" {
		t.Fatalf("li while the root is read: %s", got)
	}
	for _, c := range []struct {
		root, want int
		code       string
	}{{500, 503, "behind"}, {503, 503, "behind"}, {404, 502, "upstream"}, {403, 502, "upstream"}} {
		f.status.Store(int32(c.root))
		time.Sleep(5 * time.Millisecond) // the index's CheckerTTL
		w.x.ix.ExpireGrantChecks()
		answers := map[string]resp{"/matches": w.x.raw("/matches", li), "/_refs": w.x.raw(refs, li)}
		under, _ := p37Follow(t, w.x, prefix, cookies, "")
		answers["the cookie"] = under.resp
		for what, r := range answers {
			if r.status != c.want || r.body["code"] != c.code || r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s while GET / answers %d: %d %v, want %d %s", what, c.root, r.status, r.body, c.want, c.code)
			}
			if c.want == 503 && r.header.Get("Retry-After") == "" {
				t.Errorf("%s while GET / answers %d: no Retry-After", what, c.root)
			}
			if m, _ := r.body["message"].(string); strings.Contains(m, "matches") || strings.Contains(m, "cat-season") {
				t.Errorf("%s while GET / answers %d: names a namespace: %q", what, c.root, m)
			}
		}
		for what, tok := range map[string]string{"a grant that doesn't verify": "not-a-grant", "no credentials": ""} {
			if r := w.x.raw("/matches", tok); r.status != 401 {
				t.Errorf("%s while GET / answers %d: %d %v, want 401 first", what, c.root, r.status, r.body)
			}
		}
		if r := w.x.raw("/matches", root); r.status != 302 {
			t.Errorf("an unrestricted reader while GET / answers %d: %d %v", c.root, r.status, r.body)
		}
	}
	f.status.Store(0)
	time.Sleep(5 * time.Millisecond)
	if got := strings.Join(resources(w.x.search("/matches", li)), ","); got != "derby,shared" {
		t.Errorf("li once the root is read again: %s", got)
	}
}

// TestV082ExchangeReadsAuthMode (SVC-16; §B.11.9 Where, v0.82: "never
// from an earlier read"; §C.5): the exchange is 404 not_offered while the
// core runs with authentication disabled, as its root says now. An index
// that minted edge grants while authentication was on mints none once
// the root says it is disabled, and mints again once it is on. Before
// v0.82 the exchange read the root once and kept its answer.
func TestV082ExchangeReadsAuthMode(t *testing.T) {
	t.Parallel()
	f := &v82RootFails{}
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: f.wrap}))
	w.x = w.start(false, "matches")
	root := w.k.Grant(t, w.s.Now(), "user:root", []string{"matches"}, []string{"read"})
	if r := p37Do(t, w.x, "POST", "/edge-grants", root, "", nil, ""); r.status != 200 {
		t.Fatalf("the exchange with authentication on: %d %v", r.status, r.body)
	}
	f.off.Store(true)
	time.Sleep(5 * time.Millisecond) // the index's CheckerTTL
	if r := p37Do(t, w.x, "POST", "/edge-grants", root, "", nil, ""); r.status != 404 || r.body["code"] != "not_offered" || len(r.cookies) != 0 {
		t.Errorf("the exchange once the root says authentication is disabled: %d %v, want 404 not_offered", r.status, r.body)
	}
	f.off.Store(false)
	time.Sleep(5 * time.Millisecond)
	if r := p37Do(t, w.x, "POST", "/edge-grants", root, "", nil, ""); r.status != 200 {
		t.Errorf("the exchange once authentication is on again: %d %v", r.status, r.body)
	}
}

// v82PurgeNS freezes ns and purges it (§8.5).
func v82PurgeNS(w *v75x, ns string) {
	w.t.Helper()
	ctx := context.Background()
	must(w.admin.PatchConfig(ctx, ns, must(w.admin.NSHead(ctx, ns)).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purger := w.s.Client(w.t, client.WithBearer(w.k.Grant(w.t, w.s.Now(), "user:root", []string{ns}, []string{"purge-ns"})))
	must(purger.PurgeNamespace(ctx, ns, w.head(ns)))
}

// TestV082PurgedCatalogMetPurged (SVC-08; §B.11.9 Where, v0.82: "a
// purged catalog's catalog.trust is the last one the origin stored or the
// service read; one a service never read counts as no catalog"): an
// index that starts once cat-season is purged reads the trust of the
// document the origin still stores for it, with its first checkpoint,
// whether it serves the catalog or follows it only for visibility. So
// matches is covered and dark: li, a partial reader through a key that
// needs no at, gets a g: marker and no hits at her query, at /_refs and
// under her cookie, never the documents her rules alone allow, which are
// all of them. Before v0.82 the follower of a catalog met purged never
// marked it so: li got 502 for good, and the follower was restarted in a
// loop. (TestV0261SnapshotRefreshesTrust pins the 403 of a trust never
// read, TestV077PurgedCatalogDark the catalog purged while followed.)
func TestV082PurgedCatalogMetPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	rd := clienttest.NewKey("rd")
	e := rd.Entry("read")
	e["rules"] = []any{v77TypeRule}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/keys/-", "value": e}}))
	li := rd.Grant(t, w.s.Now(), "user:li", []string{"matches"}, []string{"read"}, map[string]any{"groups": []any{"fans"}, "roles": []any{"reader"}})
	v82PurgeNS(w, "cat-season")
	for name, nss := range map[string][]string{"not followed": {"matches"}, "followed": {"matches", "cat-season"}} {
		x := v82Start(w, false, []string{"schemas", "cat-season", "matches"}, nss[0])
		if len(nss) > 1 {
			x = startSvcWith(t, x.core, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, untyped: true, now: w.s.Now},
				func(o *indexOpts) {
					o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
				})
			x.caughtUp("matches")
		}
		// Until the follower of the catalog has met its purge, a read of
		// its state is behind or refused upstream: never an answer.
		waitFor(t, "the index learns cat-season is purged", func() bool {
			x.ix.ExpireGrantChecks()
			return x.raw("/matches", li).status < 500
		})
		q := x.raw("/matches", li)
		if q.status != 302 || !strings.HasPrefix(q.header.Get("Location"), "/matches/g/") {
			t.Fatalf("%s: li's query: %d %s %v, want a redirect under her g: marker", name, q.status, q.header.Get("Location"), q.body)
		}
		for _, path := range []string{"/matches", "/_refs?to=" + url.QueryEscape("/r/target/x")} {
			if r := x.follow(path, li); r.status != 200 || len(resources(r.body)) != 0 {
				t.Errorf("%s: li at %s where the index met the catalog purged: %d %v, want no hits", name, path, r.status, r.body)
			}
		}
		prefix, cookies := v081Exchange(t, x, li, "matches")
		if !strings.HasPrefix(q.header.Get("Location"), prefix+"/at/") {
			t.Errorf("%s: her exchange gives %s, her query redirects to %s", name, prefix, q.header.Get("Location"))
		}
		if got, _ := p37Follow(t, x, prefix, cookies, ""); got.status != 200 || len(p37Hits(got.body)) != 0 {
			t.Errorf("%s: under her cookie: %d %v, want no hits", name, got.status, got.body)
		}
	}
}

// TestV082PurgedMemberRolesCountForNoFolder (SVC-08; §B.11.9 Where,
// v0.82: "a purged namespace's roles count for no catalog's folders";
// scenario 123 at the index): fan, a partial reader of the catalog
// cat-season, sees its nodes only through matches's role reader, which
// her group has at root. Once matches is purged, its roles count for no
// folder: she sees no folder and no placement of cat-season, at her
// query, at /_refs and under the cookie she held.
func TestV082PurgedMemberRolesCountForNoFolder(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	x := w.start(false, "cat-season", "matches")
	fan := w.catReader("user:fan", "fans")
	if got := strings.Join(resources(x.search("/cat-season", fan)), ","); got != "matches.derby,matches.shared" {
		t.Fatalf("fan sees %s of cat-season before the purge, want the placements matches's role shows her", got)
	}
	prefix, cookies := v081Exchange(t, x, fan, "cat-season")
	v82PurgeNS(w, "matches")
	waitFor(t, "the index applies matches's purge", func() bool {
		for _, b := range x.batches() {
			if b.NS == "matches" && b.Coalesce().PurgedNS {
				return true
			}
		}
		return false
	})
	x.ix.ExpireGrantChecks()
	under, _ := p37Follow(t, x, prefix, cookies, "")
	for what, r := range map[string]resp{"her query": x.follow("/cat-season", fan), "/_refs": x.follow("/_refs?to="+url.QueryEscape("/r/cat-season/root"), fan), "her cookie": under.resp} {
		if r.status == 200 && len(resources(r.body)) > 0 || r.status >= 500 {
			t.Errorf("%s once matches is purged: %d %v, want nothing of cat-season", what, r.status, r.body)
		}
	}
}

// TestV082CatalogPurgedWhileDown (SVC-08; §B.11.9 Where; §A.1: "purge
// idx:{ns} from the service's own cache and drop kept results"): the
// index follows cat-season only for visibility and has answered li, who
// sees derby and shared through it. While the index is down cat-season
// is purged; restarted on the same database, its follower of cat-season
// meets the purge without a purge-ns batch to apply. It purges
// idx:cat-season all the same, and li, her matches still covered through
// the trust the index read, gets no hits, at her query and at the at URL
// she was answered at before, never what the purged catalog showed her.
func TestV082CatalogPurgedWhileDown(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	db := filepath.Join(t.TempDir(), "i.db")
	x1 := v0261Start(w, db, false, false, "matches")
	li := w.reader("user:li", []any{"fans"})
	r := x1.raw("/matches", li)
	at := r.header.Get("Location")
	if got := strings.Join(resources(x1.search("/matches", li)), ","); r.status != 302 || got != "derby,shared" {
		t.Fatalf("li before the purge: %d %s", r.status, got)
	}
	x1.stop()
	v82PurgeNS(w, "cat-season")
	x := v0261Start(w, db, false, false, "matches")
	waitFor(t, "the index learns cat-season is purged", func() bool {
		x.ix.ExpireGrantChecks()
		return x.raw("/matches", li).status < 500 && members76Purges(x, "idx:cat-season") > 0
	})
	for _, path := range []string{"/matches", at} {
		if r := x.follow(path, li); r.status != 200 || len(resources(r.body)) != 0 {
			t.Errorf("li at %s once cat-season was purged while the index was down: %d %v, want no hits", path, r.status, r.body)
		}
	}
}
