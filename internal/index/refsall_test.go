package index_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/seal"
)

// refsAllHits lists the hits of a /_refs answer as ns/resource.
func refsAllHits(body map[string]any) string {
	var out []string
	for _, h := range body["hits"].([]any) {
		m := h.(map[string]any)
		out = append(out, m["ns"].(string)+"/"+m["resource"].(string))
	}
	return strings.Join(out, " ")
}

// refsPointer asks GET /_refs{query} and returns the at and gs it
// redirects to, and the Location.
func (s *svc) refsPointer(query, token string) (at, gs, loc string) {
	s.t.Helper()
	r := s.raw("/_refs"+query, token)
	loc = r.header.Get("Location")
	p := strings.Split(strings.SplitN(loc, "?", 2)[0], "/")
	if r.status != 302 || len(p) != 6 || p[1] != "_refs" || p[2] != "at" || p[4] != "g" {
		s.t.Fatalf("GET /_refs%s: %d %q %v", query, r.status, loc, r.body)
	}
	return p[3], p[5], loc
}

// GET /_refs asks every namespace the index follows that the reader may
// read (§A.4 "Across namespaces"): two readers who see different
// namespaces get different subject sets and checkpoints, and writes in a
// namespace one can't see never move its at.
func TestRefsAcrossNamespaces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// With failPB set, pb's namespace document can't be read.
	var failPB atomic.Bool
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if failPB.Load() && r.URL.Path == "/ns/pb" {
				http.Error(w, "unavailable", http.StatusInternalServerError)
				return
			}
			h.ServeHTTP(w, r)
		})
	}})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	onlyB1 := map[string]any{"op": "test", "path": "/resource", "value": "b1"}
	isNow := map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	for _, ns := range []string{"schemas", "pub", "pa", "pb"} {
		doc := map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}
		if ns == "pa" || ns == "pb" {
			doc = map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		}
		if ns == "pb" {
			doc["roles"] = map[string]any{
				"reader": map[string]any{"can": []any{"read"}},
				"timed":  map[string]any{"can": []any{"read"}, "rules": []any{onlyB1, isNow}},
				"editor": map[string]any{"can": []any{"append"}, "rules": []any{onlyB1}},
			}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"schemas", "pub", "pa", "pb"}, []string{"read", "create", "append", "purge"})))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	mk := func(ns, name string, f map[string]any) string {
		f["$schema"] = "/r/schemas/page/rev/" + sch.ID
		return must(w.CreateDoc(ctx, ns, name, f)).NSID
	}
	mk("pub", "p1", map[string]any{"related": []any{x}})
	mk("pub", "p2", map[string]any{"related": []any{"/r/target/y"}})
	a1 := mk("pa", "a1", map[string]any{"related": []any{x, "/r/pa/a1"}})
	mk("pa", "a2", map[string]any{"trigger": x + "#t-1"})
	mk("pb", "b1", map[string]any{"related": []any{x}})
	mk("pb", "b2", map[string]any{"related": []any{"/r/target/y", x}})

	nss := []string{"pub", "pa", "pb"}
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	idx := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, now: s.Now})
	for _, ns := range nss {
		idx.caughtUp(ns)
	}
	editors := map[string]any{"groups": []any{"editors"}}
	amy := issuer.Grant(t, s.Now(), "user:amy", []string{"pa"}, []string{"read"}, editors)
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"pa", "pb"}, []string{"read"}, editors)
	li := issuer.Grant(t, s.Now(), "user:li", []string{"pb"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b1"}}})
	q := "?to=" + url.QueryEscape(x)

	// amy reads pa and the public namespace: a private pointer and answer.
	amyAt, amyGs, amyLoc := idx.refsPointer(q, amy)
	if r := idx.raw("/_refs"+q, amy); r.header.Get("Cache-Control") != "private, no-cache" || r.header.Get("Vary") != "Authorization" || !strings.HasSuffix(amyLoc, q) {
		t.Errorf("pointer %s %v", amyLoc, r.header)
	}
	r := idx.raw(amyLoc, amy)
	if r.status != 200 || refsAllHits(r.body) != "pa/a1 pa/a2 pub/p1" {
		t.Fatalf("amy: %d %v", r.status, r.body)
	}
	if fmt.Sprint(r.body["namespaces"]) != fmt.Sprint(map[string]any{"pa": idx.ix.Checkpoint("pa"), "pub": idx.ix.Checkpoint("pub")}) || r.body["at"] != amyAt {
		t.Errorf("namespaces %v at %v", r.body["namespaces"], r.body["at"])
	}
	h := r.body["hits"].([]any)
	if a1 := h[0].(map[string]any); fmt.Sprint(a1["refs"]) != "[map[path:/related/0 ref:"+x+"]]" || a1["self"] != nil ||
		!strings.HasPrefix(a1["url"].(string), clienttest.Origin+"/r/pa/a1/rev/") || a1["schema"] == nil {
		t.Errorf("a1 %v", a1)
	}
	if a2 := h[1].(map[string]any); fmt.Sprint(a2["refs"]) != "[map[path:/trigger ref:"+x+"#t-1]]" {
		t.Errorf("a2 %v", a2)
	}
	if r.header.Get("Cache-Control") != "private, max-age=300" || r.header.Get("CDN-Cache-Control") != "no-store" ||
		r.header.Get("Cache-Tag") != "idx:pa,idx:pub,r:pa/a1,r:pa/a2,r:pub/p1" || r.header.Get("X-Namespace-Revision") != amyAt {
		t.Errorf("headers %v", r.header)
	}
	if b := idx.search("/_refs?to="+url.QueryEscape("/r/pa/a1"), amy); refsAllHits(b) != "pa/a1" || b["hits"].([]any)[0].(map[string]any)["self"] != true {
		t.Errorf("self %v", b)
	}

	// bob reads both private namespaces: another subject set and at.
	bobAt, bobGs, bobLoc := idx.refsPointer(q, bob)
	if bobGs == amyGs || bobAt == amyAt {
		t.Errorf("bob shares amy's gs or at: %s %s", bobLoc, amyLoc)
	}
	if got := refsAllHits(idx.search(bobLoc, bob)); got != "pa/a1 pa/a2 pb/b1 pb/b2 pub/p1" {
		t.Errorf("bob: %s", got)
	}
	// li reads one resource of pb: filtered per item, under its own gs.
	_, liGs, liLoc := idx.refsPointer(q, li)
	if got := refsAllHits(idx.search(liLoc, li)); got != "pb/b1 pub/p1" || liGs == bobGs {
		t.Errorf("li: %s (gs %s)", got, liGs)
	}
	// gs is over markers of what the answer depends on alone: readers of
	// the same namespaces share it whatever their subjects and groups, and
	// so do readers limited by the same rules, unless the /principal
	// values those refer to differ.
	carl := issuer.Grant(t, s.Now(), "user:carl", []string{"pa"}, []string{"read"}, map[string]any{"groups": []any{"writers"}})
	if _, gs, _ := idx.refsPointer(q, carl); gs != amyGs {
		t.Errorf("carl reads what amy does, under gs %s, not %s", gs, amyGs)
	}
	lu := issuer.Grant(t, s.Now(), "user:lu", []string{"pb"}, []string{"read"}, map[string]any{"groups": []any{"x"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b1"}}})
	if _, gs, _ := idx.refsPointer(q, lu); gs != liGs {
		t.Errorf("lu has li's rules, under gs %s, not %s", gs, liGs)
	}
	byGroups := func(sub string, groups ...any) string {
		return issuer.Grant(t, s.Now(), sub, []string{"pb"}, []string{"read"}, map[string]any{"groups": groups, "rules": []any{
			map[string]any{"op": "test", "path": "/resource", "value": "b1"},
			map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "editors"}}},
		}})
	}
	_, gs1, _ := idx.refsPointer(q, byGroups("user:g1", "editors"))
	_, gs2, _ := idx.refsPointer(q, byGroups("user:g2", "editors"))
	_, gs3, loc3 := idx.refsPointer(q, byGroups("user:g3", "editors", "x"))
	if gs1 != gs2 || gs1 == gs3 || gs1 == liGs || refsAllHits(idx.search(loc3, byGroups("user:g3", "editors", "x"))) != "pb/b1 pub/p1" {
		t.Errorf("rules on /principal/groups: gs %s %s %s", gs1, gs2, gs3)
	}
	// Without a grant, or with one that reads nothing private here, the
	// public answer: public caching, tagged with the public namespace.
	_, anonGs, anonLoc := idx.refsPointer(q, "")
	if r := idx.raw("/_refs"+q, ""); r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" || r.header.Get("Cache-Tag") != "ns:pub" {
		t.Errorf("public pointer %v", r.header)
	}
	r = idx.raw(anonLoc, "")
	if r.status != 200 || refsAllHits(r.body) != "pub/p1" || r.header.Get("Cache-Control") != "public, max-age=86400, s-maxage=31536000, immutable" || r.header.Get("Cache-Tag") != "idx:pub,r:pub/p1" {
		t.Errorf("anonymous: %d %v %v", r.status, r.body, r.header)
	}
	other := issuer.Grant(t, s.Now(), "user:zed", []string{"elsewhere"}, []string{"read"}, editors)
	if _, gs, _ := idx.refsPointer(q, other); gs != anonGs || anonGs == amyGs {
		t.Errorf("a grant reading nothing private: gs %s, anonymous %s", gs, anonGs)
	}
	// A namespace read in part by rules on /now counts as unreadable: an
	// answer at an at can't change.
	soon := issuer.Grant(t, s.Now(), "user:soon", []string{"pb"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "value": "b1"},
		map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}},
	}})
	if _, gs, loc := idx.refsPointer(q, soon); gs != anonGs || refsAllHits(idx.search(loc, soon)) != "pub/p1" {
		t.Errorf("rules on /now: %s", loc)
	}
	// One read role without rules on /resource reads pb whole (§C.5),
	// whatever the grant's other roles, so rules on /now elsewhere don't
	// make it unreadable: such a grant shares a plain reader's answer.
	_, pbGs, _ := idx.refsPointer(q, issuer.Grant(t, s.Now(), "user:pbr", []string{"pb"}, []string{"read"}))
	for name, g := range map[string]string{
		"reader and timed": issuer.Grant(t, s.Now(), "user:r1", []string{"pb"}, nil, map[string]any{"roles": []any{"reader", "timed"}}),
		"reader and editor, a rule on /now": issuer.Grant(t, s.Now(), "user:r2", []string{"pb"}, nil,
			map[string]any{"roles": []any{"reader", "editor"}, "rules": []any{isNow}}),
	} {
		if _, gs, loc := idx.refsPointer(q, g); gs != pbGs || refsAllHits(idx.search(loc, g)) != "pb/b1 pb/b2 pub/p1" {
			t.Errorf("%s: %s", name, loc)
		}
	}

	// A write in pb moves bob's at, not amy's.
	mk("pb", "b3", map[string]any{"related": []any{x}})
	pbHead := idx.caughtUp("pb")
	if at, _, _ := idx.refsPointer(q, amy); at != amyAt {
		t.Errorf("a write amy can't see moved her at")
	}
	if at, _, loc := idx.refsPointer(q, bob); at == bobAt || !strings.Contains(refsAllHits(idx.search(loc, bob)), "pb/b3") {
		t.Errorf("bob's at after the write: %s", loc)
	}

	// min: only for namespaces the answer covers, in the {ns}:{ns_id} form.
	for _, m := range []string{"pb:" + pbHead, "nope:" + pbHead, pbHead, "pa:garbage"} {
		if r := idx.raw("/_refs"+q+"&min="+url.QueryEscape(m), amy); r.status != 400 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("amy min=%s: %d %v", m, r.status, r.body)
		}
	}
	if _, _, loc := idx.refsPointer(q+"&min=pa:"+idx.ix.Checkpoint("pa"), amy); loc != amyLoc {
		t.Errorf("amy with min: %s", loc)
	}
	if _, _, loc := idx.refsPointer(q+"&min=pb:"+pbHead, bob); !strings.Contains(refsAllHits(idx.search(loc, bob)), "pb/b3") {
		t.Errorf("bob with min: %s", loc)
	}

	// An answer is kept at its at after the namespaces move on; an at
	// whose answer isn't kept redirects to the current one.
	mk("pa", "a4", map[string]any{"related": []any{x}})
	idx.caughtUp("pa")
	newAt, _, newLoc := idx.refsPointer(q, amy)
	if newAt == amyAt || refsAllHits(idx.search(newLoc, amy)) != "pa/a1 pa/a2 pa/a4 pub/p1" {
		t.Fatalf("after a write in pa: %s", newLoc)
	}
	r = idx.raw(amyLoc, amy)
	if r.status != 200 || refsAllHits(r.body) != "pa/a1 pa/a2 pub/p1" {
		t.Errorf("kept answer: %d %v", r.status, r.body)
	}
	// It is answered with a min it already includes: its checkpoint of
	// that namespace, or one before it.
	paAt := r.body["namespaces"].(map[string]any)["pa"].(string)
	for _, m := range []string{paAt, a1} {
		if r := idx.raw(amyLoc+"&min=pa:"+m, amy); r.status != 200 || refsAllHits(r.body) != "pa/a1 pa/a2 pub/p1" || r.body["at"] != amyAt {
			t.Errorf("kept answer with min pa:%s: %d %v", m, r.status, r.body)
		}
	}
	for _, p := range []string{
		"/_refs/at/" + idx.ix.Checkpoint("pa") + "/g/" + amyGs + q, // never computed
		"/_refs/at/" + amyAt + "/g/" + amyGs + q + "&min=pa:" + idx.ix.Checkpoint("pa"),
	} {
		if r := idx.raw(p, amy); r.status != 302 || r.header.Get("Location") != newLoc {
			t.Errorf("%s: %d %s", p, r.status, r.header.Get("Location"))
		}
	}
	// The query in another form is the same query: a client adds after to
	// an at URL (below).
	if r := idx.raw("/_refs/at/"+amyAt+"/g/"+amyGs+"?to="+x, amy); r.status != 200 || refsAllHits(r.body) != "pa/a1 pa/a2 pub/p1" {
		t.Errorf("not canonical: %d %v", r.status, r.body)
	}
	// Someone else's subject set redirects to one's own, at the same at.
	if r := idx.raw(bobLoc, amy); r.status != 302 || r.header.Get("Location") != "/_refs/at/"+bobAt+"/g/"+amyGs+q {
		t.Errorf("foreign gs: %d %s", r.status, r.header.Get("Location"))
	}

	// Pages: in namespace, then resource order; next is the after of the
	// following page, {ns}/{name}, at the same at.
	var pages []string
	_, _, loc := idx.refsPointer(q+"&limit=2", bob)
	b := idx.search(loc, bob)
	for {
		pages = append(pages, refsAllHits(b))
		next, ok := b["next"].(string)
		if !ok {
			break
		}
		r := idx.raw(loc+"&after="+url.QueryEscape(next), bob)
		if r.status != 200 || r.body["at"] != b["at"] {
			t.Fatalf("after %s: %d %v", next, r.status, r.body)
		}
		b = r.body
	}
	if got := strings.Join(pages, " | "); got != "pa/a1 pa/a2 | pa/a4 pb/b1 | pb/b2 pb/b3 | pub/p1" {
		t.Errorf("pages %s", got)
	}
	// after is a plain bound, compared as the pair split at its first /.
	for after, want := range map[string]string{"pa/a2": "pa/a4 pb/b1", "pa/": "pa/a1 pa/a2", "pab/x": "pb/b1 pb/b2", "pb/b0": "pb/b1 pb/b2", "zz/": ""} {
		if got := refsAllHits(idx.search("/_refs"+q+"&limit=2&after="+url.QueryEscape(after), bob)); got != want {
			t.Errorf("after %s: %s, want %s", after, got, want)
		}
	}

	// If the namespace document of one the grant names can't be read, the
	// answer is 502; one it doesn't name is left out, as a private one.
	failPB.Store(true)
	if r := idx.raw("/_refs"+q, bob); r.status != 502 {
		t.Errorf("bob without pb's document: %d %v", r.status, r.body)
	}
	if got := refsAllHits(idx.search("/_refs"+q, amy)); got != "pa/a1 pa/a2 pa/a4 pub/p1" {
		t.Errorf("amy without pb's document: %s", got)
	}
	if got := refsAllHits(idx.search("/_refs"+q, "")); got != "pub/p1" {
		t.Errorf("anonymous without pb's document: %s", got)
	}
	failPB.Store(false)

	// Bad input.
	for _, p := range []string{
		"/_refs", "/_refs?to=garbage", "/_refs" + q + "&to=" + url.QueryEscape("/r/target/y"), "/_refs" + q + "&q=x",
		"/_refs" + q + "&limit=0", "/_refs" + q + "&limit=101", "/_refs/at/zzz/g/" + amyGs + q,
		"/_refs" + q + "&after=pa", "/_refs" + q + "&after=pa/a1&after=pa/a2",
	} {
		if r := idx.raw(p, amy); r.status != 400 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
	for _, p := range []string{"/_refs/x", "/_refs/at/" + amyAt + q, "/_refs/at/" + amyAt + "/g/zzz" + q} {
		if r := idx.raw(p, amy); r.status != 404 {
			t.Errorf("%s: %d", p, r.status)
		}
	}

	// A purge drops the kept answers that show the resource.
	must(w.Purge(ctx, "pa", "a1", must(w.Head(ctx, "pa", "a1")).ID, false))
	idx.caughtUp("pa")
	for _, loc := range []string{amyLoc, newLoc} {
		if r := idx.raw(loc, amy); r.status != 302 {
			t.Errorf("%s after the purge: %d %v", loc, r.status, r.body)
		}
	}
	if got := refsAllHits(idx.search("/_refs"+q, amy)); got != "pa/a2 pa/a4 pub/p1" {
		t.Errorf("after the purge: %s", got)
	}
	idx.mu.Lock()
	purged := slices.ContainsFunc(idx.purges, func(tags []string) bool { return slices.Contains(tags, "r:pa/a1") })
	idx.mu.Unlock()
	if !purged {
		t.Error("r:pa/a1 not purged")
	}

	// An index of private namespaces only: a reader needs a grant, and
	// behind a verifying edge (§9) the answer comes through it.
	ev := must(edge.New([]byte("s3cret"), ""))
	y := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "y.db"), ns: []string{"pa", "pb"}, now: s.Now}, func(o *indexOpts) { o.Edge = ev })
	y.caughtUp("pa")
	y.caughtUp("pb")
	for _, tok := range []string{"", "garbage"} {
		if r := y.raw("/_refs"+q, tok); r.status != 401 || r.header.Get("WWW-Authenticate") != "Bearer" || r.body["message"] != "missing or unverifiable grant" {
			t.Errorf("token %q: %d %v", tok, r.status, r.body)
		}
	}
	// Refusals name no namespace: one the reader can't see is like one the
	// service doesn't follow.
	if r := y.raw("/_refs"+q, other); r.status != 403 || r.body["message"] != "the grant reads no namespace the service follows" {
		t.Errorf("a grant for no namespace followed: %d %v", r.status, r.body)
	}
	get := func(path, secret string) *http.Response {
		req := must(http.NewRequest("GET", y.http.URL+path, nil))
		req.Header.Set("Authorization", "Bearer "+bob)
		if secret != "" {
			req.Header.Set(edge.DefaultHeader, secret)
		}
		res := must(noFollow.Do(req))
		res.Body.Close()
		return res
	}
	if res := get("/_refs"+q, ""); res.StatusCode != 403 {
		t.Errorf("without the edge: %d", res.StatusCode)
	}
	res := get("/_refs"+q, "s3cret")
	for res.StatusCode == 302 {
		res = get(res.Header.Get("Location"), "s3cret")
	}
	if res.StatusCode != 200 || res.Header.Get("CDN-Cache-Control") != "max-age=31536000" {
		t.Errorf("through the edge: %d %v", res.StatusCode, res.Header)
	}
}

// The answer covers only the namespaces the index has reached (§A.4
// "Coverage"): a min naming another is 400, as for one it doesn't follow.
func TestRefsUnreached(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Nobody reads late's log or heads: the index never reaches it.
			if strings.HasPrefix(r.URL.Path, "/ns/late/rev/") && (strings.HasSuffix(r.URL.Path, "/log") || strings.HasSuffix(r.URL.Path, "/heads")) {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		})
	}})
	c := s.Client(t, client.WithAuthor("admin"))
	for _, ns := range []string{"schemas", "pub", "late"} {
		must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
	}
	sch := must(c.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	doc := map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{x}}
	must(c.CreateDoc(ctx, "pub", "p", doc))
	late := must(c.CreateDoc(ctx, "late", "l", doc)).NSID
	idx := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pub", "late"}})
	idx.caughtUp("pub")
	q := "/_refs?to=" + url.QueryEscape(x)
	if b := idx.search(q, ""); refsAllHits(b) != "pub/p" || fmt.Sprint(b["namespaces"]) != fmt.Sprint(map[string]any{"pub": idx.ix.Checkpoint("pub")}) {
		t.Errorf("answer %v", b)
	}
	if r := idx.raw(q+"&min=late:"+late, ""); r.status != 400 {
		t.Errorf("min of an unreached namespace: %d %v", r.status, r.body)
	}
}

// An answer is served at its at only while the reader may still see every
// namespace it covers: a namespace that turns private moves no subject set
// (public ones add no marker), so the at URL alone doesn't say.
func TestRefsAfterPrivate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	for _, ns := range []string{"schemas", "pub", "pub2", "pa"} {
		doc := map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}
		if ns == "pa" {
			doc = map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"schemas", "pub", "pub2", "pa"}, []string{"read", "create", "config"})))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	for _, d := range []struct{ ns, name, ref string }{{"pub", "p1", x}, {"pub2", "q1", "/r/target/y"}, {"pa", "a1", x}} {
		must(w.CreateDoc(ctx, d.ns, d.name, map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{d.ref}}))
	}
	nss := []string{"pub", "pub2", "pa"}
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	idx := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, now: s.Now})
	for _, ns := range nss {
		idx.caughtUp(ns)
	}
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"pa"}, []string{"read"}, map[string]any{"groups": []any{"editors"}})
	q := "?to=" + url.QueryEscape(x)
	_, _, anonLoc := idx.refsPointer(q, "")
	_, _, bobLoc := idx.refsPointer(q, bob)
	if a, b := refsAllHits(idx.search(anonLoc, "")), refsAllHits(idx.search(bobLoc, bob)); a != "pub/p1" || b != "pa/a1 pub/p1" {
		t.Fatalf("before: %q %q", a, b)
	}

	must(w.PatchConfig(ctx, "pub", must(w.NSHead(ctx, "pub")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	idx.caughtUp("pub")
	for _, c := range []struct{ loc, token, want string }{{anonLoc, "", ""}, {bobLoc, bob, "pa/a1"}} {
		if r := idx.raw(c.loc, c.token); r.status != 302 {
			t.Errorf("%s after pub went private: %d %v", c.loc, r.status, r.body)
		}
		if got := refsAllHits(idx.search("/_refs"+q, c.token)); got != c.want {
			t.Errorf("current answer for %q: %q", c.token, got)
		}
	}
}

// Hits from sealed and e2e namespaces are sealed per entry (§E.2.6), once;
// an e2e namespace whose keys the index doesn't hold is left out.
func TestRefsAcrossSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	levels := map[string]string{"schemas": "", "plain": "", "sec": "sealed", "e": "e2e", "e2": "e2e"}
	for ns, level := range levels {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if level != "" {
			doc["encryption"] = map[string]any{"level": level}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"schemas", "plain", "sec", "e", "e2"}
	wJWK, wPriv, _ := seal.GenerateRecipient()
	iJWK, iPriv, _ := seal.GenerateRecipient()
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "purge", "config"}, map[string]any{"enc": wJWK})),
		client.WithKeys(client.NewKeys(wPriv)))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	doc := map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{x}}
	must(w.CreateDoc(ctx, "plain", "p", doc))
	must(createNonced(w, "sec", "s", doc))
	ad := w.E2E(wPriv)
	must(ad.InitKeyring(ctx, "e", iPriv.PublicKey()))
	must(ad.InitKeyring(ctx, "e2"))
	must(ad.CreateDocSealed(ctx, "e", "d", doc))
	must(ad.CreateDocSealed(ctx, "e2", "d", doc))

	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", all[1:], []string{"read"}, map[string]any{"enc": iJWK})), client.WithKeys(client.NewKeys(iPriv)))
	opts := svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: all[1:], now: s.Now}
	withKey := func(o *indexOpts) { o.Recipient = iPriv }
	idx := startSvcWith(t, ic, opts, withKey)
	for _, ns := range []string{"plain", "sec", "e"} {
		idx.caughtUp(ns)
	}
	waitFor(t, "e2 skipped", func() bool {
		for _, st := range idx.raw("/_status", "").body["namespaces"].([]any) {
			if st := st.(map[string]any); st["ns"] == "e2" && st["skipped"] == true {
				return true
			}
		}
		return false
	})

	f := idx.fetch("/_refs?to="+url.QueryEscape(x), "")
	b := decodeJSON(t, f.body)
	if fmt.Sprint(b["namespaces"]) != fmt.Sprint(map[string]any{"e": idx.ix.Checkpoint("e"), "plain": idx.ix.Checkpoint("plain"), "sec": idx.ix.Checkpoint("sec")}) || refsAllHits(b) != "e/d plain/p sec/s" {
		t.Fatalf("answer %s", f.body)
	}
	// Sealed hits are bound to the URL redirects give: the answer is
	// served there alone, also with a min it includes.
	for _, p := range []string{f.path + "&min=plain:" + idx.ix.Checkpoint("plain"), strings.Replace(f.path, url.QueryEscape(x), x, 1)} {
		if r := idx.raw(p, ""); r.status != 302 || r.header.Get("Location") != f.path {
			t.Errorf("%s: %d %s", p, r.status, r.header.Get("Location"))
		}
	}
	hits := b["hits"].([]any)
	if p := hits[1].(map[string]any); fmt.Sprint(p["refs"]) != "[map[path:/related/0 ref:"+x+"]]" {
		t.Errorf("plain hit %v", p)
	}
	// Keys in the clear, for a grant without enc.
	kc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec"}, []string{"read"})))
	keyOf := map[string]func(string) []byte{"sec": derived.ItemKey(epochKeys(t, kc, "sec"), "sec", "s")}
	ke := must(ad.Key(ctx, "e#1"))
	keyOf["e"] = derived.ItemKey(func(kid string) []byte {
		if kid == "e#1" {
			return ke
		}
		return nil
	}, "e", "d")
	for _, i := range []int{0, 2} {
		hit := hits[i].(map[string]any)
		ns, name := hit["ns"].(string), hit["resource"].(string)
		jwe, _ := hit["sealed"].(string)
		if len(hit) != 5 || jwe == "" || hit["id"] == nil || hit["url"] == nil {
			t.Fatalf("sealed hit %v", hit)
		}
		if pl := must(seal.ParseHeader(jwe)).PL; fmt.Sprint(pl) != fmt.Sprint(map[string]any{"ns": ns, "name": name, "view": f.path}) {
			t.Errorf("pl %v", pl)
		}
		v := decodeJSON(t, must(derived.OpenItem(jwe, keyOf[ns], derived.View{NS: ns, Target: f.path}, ns, name)))
		if fmt.Sprint(v["refs"]) != "[map[path:/related/0 ref:"+x+"]]" || v["schema"] == nil {
			t.Errorf("%s/%s opens to %v", ns, name, v)
		}
	}
	if strings.Contains(f.header.Get("Cache-Tag"), "e2") {
		t.Errorf("tags %s", f.header.Get("Cache-Tag"))
	}

	// Sealed once: stored, and served unchanged after a restart.
	if tags := idx.ix.SealedViews()[f.path]; !strings.Contains(tags, "r:sec/s") || !strings.Contains(tags, "idx:e") {
		t.Fatalf("stored %q", tags)
	}
	idx.stop()
	idx = startSvcWith(t, ic, opts, withKey)
	idx.caughtUp("sec")
	if again := idx.fetch(f.path, ""); again.path != f.path || string(again.body) != string(f.body) {
		t.Fatalf("resealed after a restart: %s", again.body)
	}

	// A purge removes the stored answer.
	must(w.Purge(ctx, "sec", "s", must(w.Head(ctx, "sec", "s")).ID, false))
	idx.caughtUp("sec")
	if _, ok := idx.ix.SealedViews()[f.path]; ok {
		t.Error("the stored answer survived the purge")
	}
	if r := idx.raw(f.path, ""); r.status != 302 {
		t.Errorf("after the purge: %d", r.status)
	}
	if got := refsAllHits(idx.search("/_refs?to="+url.QueryEscape(x), "")); got != "e/d plain/p" {
		t.Errorf("after the purge: %s", got)
	}

	// A stored answer is not served once a namespace it covers turns
	// private, though the anonymous subject set stays the same.
	must(createNonced(w, "sec", "s2", doc))
	idx.caughtUp("sec")
	f = idx.fetch("/_refs?to="+url.QueryEscape(x), "")
	if got := refsAllHits(decodeJSON(t, f.body)); got != "e/d plain/p sec/s2" {
		t.Fatalf("with s2: %s", got)
	}
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	idx.caughtUp("sec")
	idx.stop()
	idx = startSvcWith(t, ic, opts, withKey)
	idx.caughtUp("sec")
	if _, ok := idx.ix.SealedViews()[f.path]; !ok {
		t.Fatal("the answer with s2 is not stored")
	}
	if r := idx.raw(f.path, ""); r.status != 302 {
		t.Errorf("after sec went private: %d %v", r.status, r.body)
	}
	if got := refsAllHits(idx.search("/_refs?to="+url.QueryEscape(x), "")); got != "e/d plain/p" {
		t.Errorf("after sec went private: %s", got)
	}
}
