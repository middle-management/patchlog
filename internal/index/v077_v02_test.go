package index_test

import (
	"context"
	"fmt"
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
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V77-02 (v0.77): the index's markers, scope cookies, coverage, exchange
// 410, /_refs, purges before serving, upstream errors and judged-once
// epochs (§A.1, §A.4, §B.11.9, §C.4, §E.2.6).

// TestV077MembersBehindNamesNone (FSVC-12; §A.4 Private namespaces: a
// partial reader is answered "503 (behind, §B.5) until it has reached
// each"; /principal hides catalog.trust, §7.4): before cat-season's
// follower holds its first checkpoint, li's 503 at /matches and at /_refs
// doesn't name cat-season. Before v0.77 its body did.
func TestV077MembersBehindNamesNone(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	x, _ := members76Start(t, w, filepath.Join(t.TempDir(), "i.db"), func(ctx context.Context, m string) {
		if m == "cat-season" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	})
	x.ix.SetMinWait(50 * time.Millisecond)
	w.x = x
	x.caughtUp("matches")
	li := w.reader("user:li", []any{"fans"})
	for _, path := range []string{"/matches", "/_refs?to=%2Fr%2Ftarget%2Fx"} {
		r := x.raw(path, li)
		if r.status != 503 || r.body["code"] != "behind" || strings.Contains(r.body["message"].(string), "cat-season") {
			t.Errorf("%s before cat-season's first checkpoint: %d %v", path, r.status, r.body)
		}
	}
}

// TestV077HeadPointerDropsOpaqueAfter (FSVC-8, index part; §A.4: "A
// redirect from a head pointer or to another at ... keeps an after naming
// a resource, applied to the new result, and drops an opaque one, starting
// again"): GET /matches?q=…&after=<an opaque next> is a 302 whose Location
// has no after; with a resource-naming after, it keeps it. Before v0.77
// the head pointer passed an opaque after on.
func TestV077HeadPointerDropsOpaqueAfter(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	w.doc(t, "a1", w.match, map[string]any{"title": "word one"})
	w.doc(t, "a2", w.match, map[string]any{"title": "word two"})
	cur := s.caughtUp("matches")
	b := s.search("/matches?limit=1&q=word", "")
	next, _ := b["next"].(string)
	if next == "" {
		t.Fatalf("no next: %v", b)
	}
	r := s.raw("/matches?after="+url.QueryEscape(next)+"&limit=1&q=word", "")
	if loc := r.header.Get("Location"); r.status != 302 || loc != "/matches/at/"+cur+"?limit=1&q=word" {
		t.Errorf("head pointer with an opaque after: %d %s", r.status, loc)
	}
	r = s.raw("/matches?after=1&limit=1&sort=%2Ftitle", "")
	if loc := r.header.Get("Location"); r.status != 302 || loc != "/matches/at/"+cur+"?limit=1&sort=%2Ftitle" {
		t.Errorf("head pointer with sort's opaque after: %d %s", r.status, loc)
	}
	r = s.raw("/matches?after=a1&limit=1", "")
	if loc := r.header.Get("Location"); r.status != 302 || loc != "/matches/at/"+cur+"?after=a1&limit=1" {
		t.Errorf("head pointer with an after naming a resource: %d %s", r.status, loc)
	}
}

// v77docs is an uncovered private namespace docs (it names no catalog and
// is none) whose keys k1 and k2 have the same scope rules, testing
// /resource by type, so their grants read docs in part; its role reader
// lists read. docs holds a, b and secret. One index follows it, minting
// edge grants of its own.
type v77docs struct {
	t             *testing.T
	s             *clienttest.Server
	admin, k1, k2 clienttest.Key
	w             *client.Client
	x             *svc
}

var v77TypeRule = map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}

func newV77Docs(t *testing.T) *v77docs {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	d := &v77docs{t: t, s: s, admin: clienttest.NewKey("admin"), k1: clienttest.NewKey("k1"), k2: clienttest.NewKey("k2")}
	entry := func(k clienttest.Key) map[string]any {
		e := k.Entry("read")
		e["rules"] = []any{v77TypeRule}
		return e
	}
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{d.admin.Entry("*"), entry(d.k1), entry(d.k2)},
		"roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}}))
	d.w = s.Client(t, client.WithBearer(d.admin.Grant(t, s.Now(), "user:root", []string{"docs"}, []string{"read", "create", "append", "config"})))
	sch := must(d.w.CreateDoc(ctx, "docs", "schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	for _, n := range []string{"a", "b", "secret"} {
		must(d.w.CreateDoc(ctx, "docs", n, map[string]any{"$schema": "/r/docs/schema/rev/" + sch.ID, "title": "word " + n}))
	}
	ev := must(edge.New([]byte("s3cret"), "", ""))
	d.x = startSvcWith(t, s.Client(t, client.WithBearer(d.admin.Grant(t, s.Now(), "svc:indexer", []string{"docs"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"docs"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		})
	d.x.caughtUp("docs")
	return d
}

// reader is k's grant for user:li with the role reader.
func (d *v77docs) reader(k clienttest.Key) string {
	return k.Grant(d.t, d.s.Now(), "user:li", []string{"docs"}, []string{"read"}, map[string]any{"roles": []any{"reader"}})
}

// patch applies ops to docs' document and waits for the index.
func (d *v77docs) patch(ops ...any) {
	d.t.Helper()
	ctx := context.Background()
	must(d.w.PatchConfig(ctx, "docs", must(d.w.NSHead(ctx, "docs")).Config, ops))
	d.x.caughtUp("docs")
	d.x.ix.ExpireGrantChecks()
}

// exchange exchanges token and returns its prefixes, by kind (the
// namespace, or "_refs"), and its cookies.
func (d *v77docs) exchange(token string) (map[string]string, []*http.Cookie) {
	d.t.Helper()
	r := p37Do(d.t, d.x, "POST", "/edge-grants", token, "", nil, "")
	if r.status != 200 {
		d.t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	prefixes := map[string]string{}
	for _, p := range r.body["prefixes"].([]any) {
		prefixes[strings.Split(p.(string), "/")[1]] = p.(string)
	}
	return prefixes, r.cookies
}

// TestV077ScopeMarkerKey (FSVC-1; §A.4 Across namespaces: the scope
// marker's "digest covering the rules that limit it there ..., the
// /principal values they refer to and its key's key: string (§B.11.9
// gs)"; CONFORMANCE Grant scope 66): grants through k1 and k2, whose
// rules are the same, are redirected to different /docs/g/{gs}, and the
// exchange gives them different prefixes. Before v0.77 both shared one.
func TestV077ScopeMarkerKey(t *testing.T) {
	t.Parallel()
	d := newV77Docs(t)
	g1, g2 := d.reader(d.k1), d.reader(d.k2)
	loc1, loc2 := d.x.raw("/docs?q=word", g1).header.Get("Location"), d.x.raw("/docs?q=word", g2).header.Get("Location")
	if !strings.HasPrefix(loc1, "/docs/g/") || !strings.HasPrefix(loc2, "/docs/g/") || strings.Split(loc1, "/")[3] == strings.Split(loc2, "/")[3] {
		t.Errorf("k1's and k2's readers: %s and %s, want different gs", loc1, loc2)
	}
	for _, g := range []string{g1, g2} {
		if got := strings.Join(resources(d.x.search("/docs?q=word", g)), ","); got != "a,b,secret" {
			t.Errorf("hits %s", got)
		}
	}
	p1, _ := d.exchange(g1)
	p2, _ := d.exchange(g2)
	if p1["docs"] == "" || p1["docs"] == p2["docs"] || p1["_refs"] == p2["_refs"] {
		t.Errorf("prefixes %v and %v, want different", p1, p2)
	}
}

// TestV077ScopeCookieEnds (FSVC-2; §A.4: "a cookie is 403 until the
// reader exchanges again ... where a marker's key, rules or roles would
// end a gs cookie (§B.11.9 gs)"; scenarios 66 and 121): li's cookie for
// its scope marker in docs, through k1 with the role reader, is 403 at
// /docs/g/{gs} and at /_refs once docs (a) removes k1, (b) changes k1's
// pub, (c) narrows reader's rules, or (d) drops read from reader; a
// change to an unrelated role leaves it read. Before v0.77 it read on
// under the old rules until it expired.
func TestV077ScopeCookieEnds(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		op    func(d *v77docs) map[string]any
		holds bool
	}{
		{"k1 removed", func(d *v77docs) map[string]any {
			return map[string]any{"op": "remove", "path": "/keys/1"}
		}, false},
		{"k1's pub changed", func(d *v77docs) map[string]any {
			return map[string]any{"op": "replace", "path": "/keys/1/pub", "value": clienttest.NewKey("k1").Pub}
		}, false},
		{"reader narrowed", func(d *v77docs) map[string]any {
			return map[string]any{"op": "add", "path": "/roles/reader/rules", "value": []any{
				map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "secret"}}}}
		}, false},
		{"reader without read", func(d *v77docs) map[string]any {
			return map[string]any{"op": "replace", "path": "/roles/reader/can", "value": []any{"create"}}
		}, false},
		{"another role added", func(d *v77docs) map[string]any {
			return map[string]any{"op": "add", "path": "/roles/other", "value": map[string]any{"can": []any{"read"}}}
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newV77Docs(t)
			prefixes, cookies := d.exchange(d.reader(d.k1))
			refs := prefixes["_refs"] + "?to=" + url.QueryEscape("/r/docs/schema")
			for _, p := range []string{prefixes["docs"] + "?q=word", refs} {
				if got, _ := p37Follow(t, d.x, p, cookies, ""); got.status != 200 {
					t.Fatalf("%s under the cookie: %d %v", p, got.status, got.body)
				}
			}
			d.patch(c.op(d))
			for _, p := range []string{prefixes["docs"] + "?q=word", refs} {
				got, _ := p37Follow(t, d.x, p, cookies, "")
				if c.holds && got.status != 200 || !c.holds && got.status != 403 {
					t.Errorf("%s under the cookie after the change: %d %v", p, got.status, got.body)
				}
			}
		})
	}
}

// TestV077PurgedCatalogDark (FSVC-4; §B.11.9 Where: "an end-to-end
// catalog, which the origin can't read, or a purged one, makes nothing
// visible"; scenario 115): once cat-season, matches' only trusted
// catalog, is purged, matches stays covered: li's query is redirected to
// /matches/g/{gs}/at/{at} under her g: marker, and answered with no hits,
// cat-season out of at. Before v0.77 matches became uncovered, and li got
// the hits her rules allow.
func TestV077PurgedCatalogDark(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans"})
	if got := strings.Join(resources(w.x.search("/matches", li)), ","); got != "derby,shared" {
		t.Fatalf("li sees %s before the purge", got)
	}
	purger := w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "user:root", []string{"cat-season"}, []string{"purge-ns"})))
	must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(purger.PurgeNamespace(ctx, "cat-season", w.head("cat-season")))
	waitFor(t, "the index learns cat-season is purged", func() bool {
		w.x.ix.ExpireGrantChecks()
		r := w.x.raw("/matches", li)
		return r.status == 302 && strings.Contains(r.header.Get("Location"), "/g/") && w.x.ix.Members()["cat-season"] == ""
	})
	r := w.x.raw("/matches", li)
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.HasPrefix(loc, "/matches/g/") || !strings.Contains(loc, "/at/") {
		t.Fatalf("li's pointer after the purge: %d %s %v", r.status, loc, r.body)
	}
	b := w.x.search(loc, li)
	if len(resources(b)) != 0 {
		t.Errorf("li sees %v after the purge, want none", resources(b))
	}
	if ns := v75Namespaces(t, b); ns["cat-season"] != "" || ns["matches"] != w.x.ix.Checkpoint("matches") {
		t.Errorf("namespaces %v, want matches alone", ns)
	}
}

// TestV077AuthDisabledUncovers (FSVC-5; §B.11.9 Where: "It covers, only
// while authentication is on (§1), a namespace that trusts a catalog";
// §A.4 follows coverage): against a core running with authentication
// disabled, matches, which trusts cat-season, isn't covered: a partial
// reader gets no g: marker, and, matches naming a catalog, no marker at
// all (403, FSVC-3). Before v0.77 the index covered it whatever the core
// said.
func TestV077AuthDisabledUncovers(t *testing.T) {
	t.Parallel()
	// The core's root says whether authentication is disabled (§1, §7);
	// the rest of it runs with grants, so the setup can still be made.
	var off atomic.Bool
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" && off.Load() {
				rw.Header().Set("Content-Type", "application/json")
				rw.Write([]byte(`{"spec":"0.77","auth":"disabled","origin":"` + clienttest.Origin + `"}`))
				return
			}
			h.ServeHTTP(rw, r)
		})
	}}))
	w.x = w.start(false, "matches")
	li := w.reader("user:li", []any{"fans"})
	if r := w.x.raw("/matches", li); r.status != 302 || !strings.Contains(r.header.Get("Location"), "/g/") {
		t.Fatalf("li with authentication on: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	_, gs, _ := w.pointer("/matches", li)
	off.Store(true)
	time.Sleep(5 * time.Millisecond) // the index's CheckerTTL
	if r := w.x.raw("/matches", li); r.status != 403 {
		t.Errorf("li with authentication disabled: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	off.Store(false)
	time.Sleep(5 * time.Millisecond)
	if _, again, _ := w.pointer("/matches", li); again != gs {
		t.Errorf("li once authentication is on again: gs %s, want %s", again, gs)
	}
}

// TestV077NoMarkerShapes (FSVC-3; §A.4: "where it doesn't [cover] but
// {ns} is neither sealed nor end-to-end and is a catalog (§B.6) or its
// catalogs, or a local base's, names one, a partial reader has none";
// scenarios 101, 113, 114, 119, 122): a partial reader gets 403, never the
// hits its rules allow, and /_refs shows nothing of the namespace, in
// matches once cat-season no longer trusts it, in the matches-r7 branch
// once matches edits catalog-01's maxTtl, and in cat-season, followed,
// once nothing trusts it. Before v0.77 each was read by rules alone.
func TestV077NoMarkerShapes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	t.Run("matches", func(t *testing.T) {
		t.Parallel()
		w := newV75X(t, false)
		must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config,
			[]any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
		w.x.ix.ExpireGrantChecks()
		fan := w.reader("user:fan", []any{"fans"})
		if r := w.x.raw("/matches?q=derby", fan); r.status != 403 {
			t.Errorf("/matches: %d %v", r.status, r.body)
		}
		if r := w.x.follow(refs, fan); r.status == 200 && len(resources(r.body)) > 0 {
			t.Errorf("/_refs: %d %v", r.status, r.body)
		}
		if r := p37Do(t, w.x, "POST", "/edge-grants", fan, "", nil, ""); r.status != 403 {
			t.Errorf("exchange: %d %v", r.status, r.body)
		}
	})
	t.Run("matches-r7", func(t *testing.T) {
		t.Parallel()
		w := cover76Branch(t)
		fan := w.reader("user:fan", []any{"fans"}, "matches-r7")
		if r := w.x.raw("/matches-r7", fan); r.status != 302 {
			t.Fatalf("covered: %d %v", r.status, r.body)
		}
		w.patchKeys(func(keys []any) []any { keys[1].(map[string]any)["maxTtl"] = "PT14M"; return keys })
		if r := w.x.raw("/matches-r7", fan); r.status != 403 {
			t.Errorf("/matches-r7 once uncovered: %d %v", r.status, r.body)
		}
	})
	t.Run("cat-season", func(t *testing.T) {
		t.Parallel()
		w := newV75X(t, false)
		x := w.start(false, "cat-season", "matches")
		must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config,
			[]any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
		x.caughtUp("cat-season")
		x.ix.ExpireGrantChecks()
		fan := w.catReader("user:fan", "fans")
		if r := x.raw("/cat-season", fan); r.status != 403 {
			t.Errorf("/cat-season once nothing trusts it: %d %v", r.status, r.body)
		}
	})
}

// TestV077NoMarkerCookie (FSVC-3, cookies): a scope cookie for docs,
// issued while docs named no catalog, is 403 once docs names one in its
// catalogs (one that doesn't trust it back, so docs stays uncovered),
// at /docs/g/{gs} and under /_refs. Before v0.77 it read on by rules
// alone.
func TestV077NoMarkerCookie(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newV77Docs(t)
	op := d.s.Client(t, client.WithBearer(d.s.OperatorGrant(t, "cat")))
	must(op.CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{d.admin.Entry("*")}, "catalog": map[string]any{"trust": []any{}}}))
	prefixes, cookies := d.exchange(d.reader(d.k1))
	refs := prefixes["_refs"] + "?to=" + url.QueryEscape("/r/docs/schema")
	for _, p := range []string{prefixes["docs"], refs} {
		if got, _ := p37Follow(t, d.x, p, cookies, ""); got.status != 200 {
			t.Fatalf("%s under the cookie: %d %v", p, got.status, got.body)
		}
	}
	d.patch(map[string]any{"op": "add", "path": "/catalogs", "value": map[string]any{"cat": map[string]any{"place": []any{}}}})
	for _, p := range []string{prefixes["docs"], refs} {
		if got, _ := p37Follow(t, d.x, p, cookies, ""); got.status != 403 {
			t.Errorf("%s once docs names cat: %d %v", p, got.status, got.body)
		}
	}
	if r := d.x.raw("/docs", d.reader(d.k1)); r.status != 403 {
		t.Errorf("the grant once docs names cat: %d %v", r.status, r.body)
	}
}

// TestV077ExchangePurgedOnly (FSVC-6; §A.4 Coverage: "Only a reader who
// may see none of the namespaces gets 401 or 403, or, where every
// namespace its grant names is purged and the grant verifies in each,
// 410 as §C.5.2 gives it"): once pb is purged, a grant naming pb and the
// public pub, or pb and schemas, which the index doesn't follow, is
// refused 403 at the exchange, not 410; one naming pb alone is 410 with
// ns and head, at the exchange and, where the index follows no public
// namespace every reader sees, at /_refs. Before v0.77 the first two were
// 410, and /_refs answered 200 with nothing.
func TestV077ExchangePurgedOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := p37Setup(t, svcedge.DefaultExchangeRate)
	op := w.s.Client(t, client.WithBearer(w.admin.Grant(t, w.s.Now(), "user:root", []string{"pb"}, []string{"read", "config", "purge-ns"})))
	must(op.PatchConfig(ctx, "pb", must(op.NSHead(ctx, "pb")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	head := must(op.PurgeNamespace(ctx, "pb", must(op.NSHead(ctx, "pb")).ID))
	onlyPB := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pb"}, []string{"read"})
	waitFor(t, "the index to apply the purge of pb", func() bool {
		w.x.ix.ExpireGrantChecks()
		return w.x.raw("/pb", onlyPB).status == 410
	})
	for _, nss := range [][]string{{"pb", "pub"}, {"pb", "schemas"}} {
		g := w.issuer.Grant(t, w.s.Now(), "user:amy", nss, []string{"read"})
		if r := p37Do(t, w.x, "POST", "/edge-grants", g, "", nil, ""); r.status != 403 || len(r.cookies) != 0 {
			t.Errorf("exchange naming %v: %d %v", nss, r.status, r.body)
		}
	}
	if r := p37Do(t, w.x, "POST", "/edge-grants", onlyPB, "", nil, ""); r.status != 410 || r.body["ns"] != "pb" || r.body["head"] != head {
		t.Errorf("exchange naming pb alone: %d %v", r.status, r.body)
	}
	// /_refs: every reader sees the public pub there, so the answer is
	// pub's; an index following pa and pb alone answers 410.
	if r := w.x.raw("/_refs?to="+url.QueryEscape("/r/target/x"), onlyPB); r.status != 302 {
		t.Errorf("/_refs naming pb alone, pub followed: %d %v", r.status, r.body)
	}
	x := startSvc(t, w.s.Client(t, client.WithBearer(w.admin.Grant(t, w.s.Now(), "svc:indexer", []string{"pa", "pb"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pa", "pb"}, untyped: true, now: w.s.Now})
	x.caughtUp("pa")
	waitFor(t, "the second index to reach pb's purge", func() bool { x.ix.ExpireGrantChecks(); return x.raw("/pb", onlyPB).status == 410 })
	if r := x.raw("/_refs?to="+url.QueryEscape("/r/target/x"), onlyPB); r.status != 410 || r.body["code"] != "purged" || r.body["ns"] != "pb" || r.body["head"] != head {
		t.Errorf("/_refs naming pb alone: %d %v", r.status, r.body)
	}
	// A grant naming every namespace ("*") names no set of them: never 410.
	star := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"*"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "none"}}})
	if r := p37Do(t, w.x, "POST", "/edge-grants", star, "", nil, ""); r.status == 410 {
		t.Errorf("exchange naming *: %d %v", r.status, r.body)
	}
}

// TestV077RefsBaseEarliest (FSVC-7; §A.4 Answers: "one that branches read
// only as of different ats at the earliest"): r7a and r7b are branches of
// matches-r7 cut at X and at a later Y whose ns_id sorts before X's; a
// partial reader of both, who doesn't read matches-r7 itself, gets a
// /_refs answer listing matches-r7 at X, the earliest in its chain.
// Before v0.77 it was listed at the lower by bytes, Y.
func TestV077RefsBaseEarliest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	must(w.admin.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	var points []string
	for i := range 6 {
		w.put("matches-r7", fmt.Sprintf("n%d", i), w.page("new", "cup"))
		points = append(points, w.head("matches-r7"))
	}
	x, y := "", ""
	for i := 0; i < len(points) && x == ""; i++ {
		for j := i + 1; j < len(points); j++ {
			if points[j] < points[i] {
				x, y = points[i], points[j]
				break
			}
		}
	}
	if x == "" {
		t.Skip("every later point sorts after the earlier ones") // 1 in 720
	}
	brancher := w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "user:root", []string{"matches-r7", "r7a", "r7b"}, []string{"read", "branch"})))
	must(brancher.CreateBranch(ctx, "matches-r7", client.BranchRequest{Name: "r7a", At: x}))
	must(brancher.CreateBranch(ctx, "matches-r7", client.BranchRequest{Name: "r7b", At: y}))
	all := []string{"schemas", "cat-season", "matches", "matches-r7", "r7a", "r7b"}
	w.x = startSvc(t, w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true, branches: true, now: w.s.Now})
	for _, ns := range []string{"matches", "matches-r7", "r7a", "r7b"} {
		w.x.caughtUp(ns)
	}
	fan := w.reader("user:fan", []any{"fans"}, "r7a", "r7b")
	r := w.x.follow("/_refs?to="+url.QueryEscape("/r/target/x"), fan)
	if r.status != 200 {
		t.Fatalf("/_refs: %d %v", r.status, r.body)
	}
	ns := v75Namespaces(t, r.body)
	if ns["matches-r7"] != x || ns["r7a"] == "" || ns["r7b"] == "" {
		t.Errorf("namespaces %v, want matches-r7 at %s (r7a's), not %s (r7b's)", ns, x, y)
	}
}

// TestV077PurgeBeforeServe (FSVC-9; §A.1: a purge drops kept results,
// "serving or keeping none computed from what was read before it";
// scenario 117): a result computed at its at from rows read before derby's
// purge commits is neither served nor kept: the request is redirected to
// the at after the purge, whose answer doesn't show derby, and the old at
// URL is redirected too. Before v0.77 that page was served once.
func TestV077PurgeBeforeServe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	whole := w.k.Grant(t, w.s.Now(), "user:whole", []string{"matches"}, []string{"read"})
	_, gs, at := w.pointer("/matches?q=shared", whole)
	var once atomic.Bool
	w.x.ix.OnAnswerRead(func() {
		if once.CompareAndSwap(false, true) {
			must(w.admin.Purge(ctx, "matches", "derby", must(w.admin.Head(ctx, "matches", "derby")).ID, false))
			w.x.caughtUp("matches")
		}
	})
	old := "/matches/g/" + gs + "/at/" + at + "?q=derby"
	r := w.x.raw(old, whole)
	if !once.Load() {
		t.Fatal("the answer was never computed")
	}
	if r.status == 200 {
		t.Fatalf("GET %s: served the page read before the purge: %v", old, r.body)
	}
	if r.status != 302 || strings.Contains(r.header.Get("Location"), "/at/"+at+"?") {
		t.Errorf("GET %s: %d %q, want a redirect to the at after the purge", old, r.status, r.header.Get("Location"))
	}
	if b := w.x.search(r.header.Get("Location"), whole); len(resources(b)) != 0 {
		t.Errorf("after the purge: %v", b)
	}
	if r := w.x.raw(old, whole); r.status != 302 {
		t.Errorf("GET %s again: %d %v, want a redirect: nothing kept there", old, r.status, r.body)
	}
}

// TestV077RefsPurgeBeforeServe (FSVC-9 at /_refs; scenario 117): li's
// /_refs answer, read before matches.derby's placement in cat-season is
// purged, is computed again with her views after the purge, never served
// as read: it shows shared alone. Before v0.77 it was retried with the
// views read before the purge, and served on the last try.
func TestV077RefsPurgeBeforeServe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans"})
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	if got := refsAllHits(w.x.follow(refs, li).body); got != "matches/derby matches/shared" {
		t.Fatalf("before the purge: %s", got)
	}
	// The at URL of another query, whose answer isn't kept: computed and
	// served at once, were it not for the purge.
	p := w.x.raw(refs, li)
	loc := p.header.Get("Location")
	if p.status != 302 {
		t.Fatalf("pointer: %d %v", p.status, p.body)
	}
	at := strings.SplitN(loc, "?", 2)[0] + "?limit=7&to=" + url.QueryEscape("/r/target/x")
	var once atomic.Bool
	w.x.ix.OnRefsRead(func() {
		if once.CompareAndSwap(false, true) {
			must(w.admin.Purge(ctx, "cat-season", "matches.derby", must(w.admin.Head(ctx, "cat-season", "matches.derby")).ID, false))
			waitFor(t, "the purge in cat-season to be applied", func() bool {
				return w.x.ix.Members()["cat-season"] == w.head("cat-season")
			})
		}
	})
	r := w.x.raw(at, li)
	if !once.Load() {
		t.Fatalf("the answer was never computed: %d %v", r.status, r.body)
	}
	if r.status == 200 && refsAllHits(r.body) != "matches/shared" {
		t.Fatalf("GET %s: served the answer read before the purge: %v", at, r.body)
	}
	if r = w.x.follow(at, li); r.status != 200 || refsAllHits(r.body) != "matches/shared" {
		t.Errorf("after the purge: %d %v", r.status, r.body)
	}
}

// TestV077EpochJudgedOnce (ENC-5; §E.2.6 Per-entry sealing: kid "naming
// the epoch the revision it derives from is served under (§E.2.2), at E3
// the one a prune's snapshot of that revision would carry (§E.3.1),
// judged once, when the service first seals a value derived from it"): in
// e-b, an e2e branch of the e2e namespace e, r's head is e's op read
// through, whose kid names no epoch of e-b (pending). The first answer
// that seals it judges it under e-b's epoch then; after e-b rotates and
// moves on, a new answer still seals r under that epoch, beside s,
// written after the rotation, under the new one. Before v0.77 r took the
// epoch current at each answer.
func TestV077EpochJudgedOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "public", "keys": []any{admin.Entry("*")},
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	idxJWK, idxPriv, _ := seal.GenerateRecipient()
	nss := []string{"e", "e-b", "schemas"}
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", nss, []string{"read", "create", "append", "config", "branch"}, map[string]any{"enc": adminJWK})))
	ad := ac.E2E(adminPriv)
	sch := must(ac.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	must(ad.InitKeyring(ctx, "e", idxPriv.PublicKey()))
	must(ad.CreateDocSealed(ctx, "e", "r", map[string]any{"$schema": ref, "title": "zq r", "related": []any{"/r/target/x"}}))
	must(ac.CreateBranch(ctx, "e", client.BranchRequest{Name: "e-b"}))
	must(ad.InitKeyring(ctx, "e-b", idxPriv.PublicKey()))
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}, map[string]any{"enc": idxJWK})),
		client.WithKeyringSenders(adminPriv.PublicKey()))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, branches: true, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	x.caughtUp("e-b")
	// Judged first by a /_refs answer, read back by every later one.
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	before := p37Kids(t, x.fetch(refs, "").body)["e-b/r"]
	if before != "e-b#1" {
		t.Fatalf("e-b/r's kid before the rotation: %q", before)
	}
	e := must(ad.RotateEpoch(ctx, "e-b", idxPriv.PublicKey()))
	must(ad.CreateDocSealed(ctx, "e-b", "s", map[string]any{"$schema": ref, "title": "zq s"}))
	x.caughtUp("e-b")
	after := p37Kids(t, x.fetch("/e-b?q=zq", "").body)
	if after["r"] != before || after["s"] != fmt.Sprintf("e-b#%d", e) {
		t.Errorf("kids after e-b rotated to %d: %v, want r still under %s", e, after, before)
	}
	if got := p37Kids(t, x.fetch(refs, "").body)["e-b/r"]; got != before {
		t.Errorf("/_refs: e-b/r under %s after the rotation, want %s", got, before)
	}
}

// v77RaisedPR is pr, public and in the clear, with one document, and an
// index of it whose grant gets pr's keys once it is sealed; raise raises
// pr to sealed and waits until the index applied it (§9: a raise purges
// idx:pr, §A.1).
func v77RaisedPR(t *testing.T) (x *svc, raise func()) {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret"}))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"}, map[string]any{"enc": jwk})), client.WithKeys(client.NewKeys(priv)))
	x = startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("pr")
	return x, func() {
		must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
		x.appliedUpTo(x.caughtUp("pr"))
	}
}

// v77AllSealed fails t for each hit of a result of pr in the clear.
func v77AllSealed(t *testing.T, what string, body []byte) {
	t.Helper()
	hits, _ := decodeJSON(t, body)["hits"].([]any)
	if len(hits) == 0 {
		t.Errorf("%s: no hits: %s", what, body)
	}
	for _, h := range hits {
		if jwe, _ := h.(map[string]any)["sealed"].(string); jwe == "" {
			t.Errorf("%s: a hit of pr, sealed now, in the clear: %v", what, h)
		}
	}
}

// TestV077AfterPurgeRaisedToSealed (FSVC-9 review; §A.1: "serving or
// keeping none computed from what was read before it", §9, §E.2.6): pr is
// raised to sealed while a query of it at its at is computed. The raise
// purges idx:pr, so the result is computed again at the at after it, and
// with pr's encryption as it is then: sealed per entry, as the same at
// computed afresh is. Before, it was computed again with what was read
// before the raise, in the clear, kept, and served there to everyone.
func TestV077AfterPurgeRaisedToSealed(t *testing.T) {
	t.Parallel()
	x, raise := v77RaisedPR(t)
	cur := x.caughtUp("pr")
	var once atomic.Bool
	x.ix.OnAnswerRead(func() {
		if once.CompareAndSwap(false, true) {
			raise()
		}
	})
	r := x.raw("/pr/at/"+cur+"?limit=5", "")
	if !once.Load() {
		t.Fatalf("never computed: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	if r.status != 302 || loc == "" {
		t.Fatalf("after the raise: %d %v", r.status, r.body)
	}
	v77AllSealed(t, "GET "+loc, x.fetch(loc, "").body)
	v77AllSealed(t, "control /pr?limit=6", x.fetch("/pr?limit=6", "").body)
}

// TestV077BeforeAnswerRaisedToSealed (FSVC-9 review; §A.1, §9, §E.2.6): pr
// is raised to sealed, and the raise applied with its purge, between the
// head pointer's read of pr's encryption and its answer. The answer isn't
// computed under what the raise replaced: the redirect's result is sealed
// per entry. Before, it was computed in the clear and kept, the purge
// having counted before it began.
func TestV077BeforeAnswerRaisedToSealed(t *testing.T) {
	t.Parallel()
	x, raise := v77RaisedPR(t)
	var once atomic.Bool
	x.ix.OnBeforeAnswer(func() {
		if once.CompareAndSwap(false, true) {
			raise()
		}
	})
	f := x.fetch("/pr?limit=7", "")
	if !once.Load() {
		t.Fatalf("never computed: %s %s", f.path, f.body)
	}
	v77AllSealed(t, "GET "+f.path, f.body)
}

// TestV077RootFailureUncovered (FSVC-5 review; §B.11.9 Where; §A.4): docs
// names no catalog and is none, so §B.11.9 can never cover it, and its
// partial readers read it by their rules (scope marker) whatever the
// core's root says. While GET / fails, they are answered at /docs and at
// /_refs as before. Before, coverage read the root first, and they got 502.
func TestV077RootFailureUncovered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var down atomic.Bool
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" && down.Load() {
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(503)
				rw.Write([]byte(`{"code":"unavailable","message":"down"}`))
				return
			}
			h.ServeHTTP(rw, r)
		})
	}})
	admin, k1 := clienttest.NewKey("admin"), clienttest.NewKey("k1")
	e := k1.Entry("read")
	e["rules"] = []any{v77TypeRule}
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), e}}))
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"docs"}, []string{"read", "create"})))
	sch := must(w.CreateDoc(ctx, "docs", "schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	must(w.CreateDoc(ctx, "docs", "a", map[string]any{"$schema": "/r/docs/schema/rev/" + sch.ID, "title": "word a"}))
	ev := must(edge.New([]byte("s3cret"), "", ""))
	x := startSvcWith(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"docs"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"docs"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		})
	x.caughtUp("docs")
	g := k1.Grant(t, s.Now(), "user:li", []string{"docs"}, []string{"read"})
	if got := resources(x.search("/docs?q=word", g)); len(got) != 1 {
		t.Fatalf("before: %v", got)
	}
	down.Store(true)
	time.Sleep(5 * time.Millisecond) // CheckerTTL
	x.ix.ExpireGrantChecks()
	if r := x.raw("/docs?q=word&limit=3", g); r.status != 302 {
		t.Errorf("/docs, uncovered, while GET / fails: %d %v", r.status, r.body)
	}
	if r := x.raw("/_refs?to="+url.QueryEscape("/r/docs/schema"), g); r.status != 302 {
		t.Errorf("/_refs while GET / fails: %d %v", r.status, r.body)
	}
	if r := p37Do(t, x, "POST", "/edge-grants", g, "", nil, ""); r.status != 200 {
		t.Errorf("exchange while GET / fails: %d %v", r.status, r.body)
	}
}

// TestV077RootFailureCovered (FSVC-5 review; §B.11.9 Where; transient as
// §A.1 and §12.1 answer it): matches, which §B.11.9 covers while the
// core's authentication is on, can't be judged while GET / fails: a
// partial reader is 503 behind, with Retry-After, while the failure is for
// now (a 503, a 408), and 502 upstream otherwise; neither names a
// namespace. Before, each was 502.
func TestV077RootFailureCovered(t *testing.T) {
	t.Parallel()
	var status atomic.Int32
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if st := int(status.Load()); r.URL.Path == "/" && st != 0 {
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(st)
				rw.Write([]byte(`{"code":"x","message":"x"}`))
				return
			}
			h.ServeHTTP(rw, r)
		})
	}}))
	w.x = w.start(false, "matches")
	li := w.reader("user:li", []any{"fans"})
	if r := w.x.raw("/matches", li); r.status != 302 || !strings.Contains(r.header.Get("Location"), "/g/") {
		t.Fatalf("li: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	for _, c := range []struct {
		root, want int
		code       string
	}{{503, 503, "behind"}, {408, 503, "behind"}, {404, 502, "upstream"}} {
		status.Store(int32(c.root))
		time.Sleep(5 * time.Millisecond) // the index's CheckerTTL
		w.x.ix.ExpireGrantChecks()
		r := w.x.raw("/matches", li)
		if r.status != c.want || r.body["code"] != c.code {
			t.Errorf("GET / %d: %d %v, want %d %s", c.root, r.status, r.body, c.want, c.code)
		}
		if c.want == 503 && r.header.Get("Retry-After") == "" {
			t.Errorf("GET / %d: no Retry-After", c.root)
		}
		if m, _ := r.body["message"].(string); strings.Contains(m, "matches") || strings.Contains(m, "cat-season") {
			t.Errorf("GET / %d: names a namespace: %q", c.root, m)
		}
	}
}
