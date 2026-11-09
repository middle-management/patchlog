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
