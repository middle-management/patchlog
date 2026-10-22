package tree_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/svcedge"
	"github.com/middle-management/patchlog/internal/tree"
)

// Cache-Control values the service sets (http.go).
const (
	ccHeadPointer = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccListing     = "public, max-age=86400, s-maxage=31536000, immutable"
	ccPrivatePtr  = "private, no-cache"
)

// scopeView is a RoleView for tests (§B.11.5): a reader's subject set is
// the names its grant's block rules fix /resource to (a test against a
// value, or a schema of only an enum), and it sees the catalog nodes of
// those names and the items of those names. A tree service serves only
// g/all without a RoleView (§B.11.5), so the tests of listings filtered
// per reader run with this one in place of the catalog's.
type scopeView struct{}

func (scopeView) Resolve(_ context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	set := nameSet{}
	for _, r := range v.BlockRules {
		m, _ := r.(map[string]any)
		if m["op"] != "test" || m["path"] != "/resource" {
			continue
		}
		if s, ok := m["value"].(string); ok {
			set[s] = true
		}
		sch, _ := m["schema"].(map[string]any)
		enum, _ := sch["enum"].([]any)
		for _, e := range enum {
			if s, ok := e.(string); ok {
				set[s] = true
			}
		}
	}
	subjects := []string{}
	for n := range set {
		subjects = append(subjects, "scope:"+n)
	}
	sort.Strings(subjects)
	return subjects, set, nil
}

func (scopeView) ForSubjects(subjects []string) tree.Visibility {
	set := nameSet{}
	for _, s := range subjects {
		if n, ok := strings.CutPrefix(s, "scope:"); ok {
			set[n] = true
		}
	}
	return set
}

// nameSet is the visibility of a scopeView subject set.
type nameSet map[string]bool

func (s nameSet) Node(_ *tree.Graph, n *tree.Node) bool { return s[n.Name] }
func (s nameSet) Item(_ *tree.Graph, n *tree.Node) bool { return s[n.ItemName] }

// withScopeView gives the service scopeView (startSvc).
func withScopeView(o *tree.Options) { o.RoleView = scopeView{} }

// p24World is an authenticated core with the catalog cat (read catRead)
// trusting matches (read matchesRead), keys admin ("*") and reader
// ("read"), and root holding the folder season and matches.derby, and a
// tree service following them (start).
type p24World struct {
	t      *testing.T
	s      *clienttest.Server
	x      *svc
	admin  clienttest.Key
	reader clienttest.Key
	w      *client.Client
}

func newP24World(t *testing.T, catRead, matchesRead string) *p24World {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, reader := clienttest.NewKey("admin"), clienttest.NewKey("reader")
	for _, ns := range []string{"matches", "cat"} {
		doc := map[string]any{"read": matchesRead, "keys": []any{admin.Entry("*"), reader.Entry("read")}}
		if ns == "cat" {
			doc["read"], doc["catalog"] = catRead, map[string]any{"trust": []any{"matches"}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"cat", "matches"}, []string{"read", "create", "append"})))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Season", "parents": parents("root@b0")}))
	must(w.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "Derby"}))
	must(w.CreateDoc(ctx, "cat", "matches.derby", map[string]any{"parents": parents("root@a0")}))
	return &p24World{t: t, s: s, admin: admin, reader: reader, w: w}
}

// start starts the tree service, as mods change its options, and waits
// for it to catch up.
func (p *p24World) start(mods ...func(*tree.Options)) *p24World {
	p.t.Helper()
	p.x = startSvc(p.t, p.s.Client(p.t, client.WithBearer(p.admin.Grant(p.t, p.s.Now(), "svc:tree", []string{"cat", "matches"}, []string{"read"}))),
		svcOpts{now: p.s.Now}, mods...)
	p.x.caughtUp("cat", "matches")
	return p
}

// grant is a read grant of the reader key for sub in nss, with extra
// block members.
func (p *p24World) grant(sub string, nss []string, extra ...map[string]any) string {
	return p.reader.Grant(p.t, p.s.Now(), sub, nss, []string{"read"}, extra...)
}

// scoped is a read grant for sub in cat and matches limited to names.
func (p *p24World) scoped(sub string, names ...any) string {
	return p.grant(sub, []string{"cat", "matches"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}})
}

// do sends a request with token in Authorization ("" for none) and the
// cookies, without following redirects.
func (p *p24World) do(method, path, token, body string, cookies ...*http.Cookie) resp {
	p.t.Helper()
	req := must(http.NewRequest(method, p.x.http.URL+path, strings.NewReader(body)))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	r := must(noRedirect.Do(req))
	defer r.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	return resp{r.StatusCode, r.Header, m}
}

// withEdgeGrants gives the service scopeView and edge grants of its own.
func withEdgeGrants(o *tree.Options) {
	o.RoleView, o.EdgeGrants, o.EdgeGrantsOwnKey = scopeView{}, edge.NewCookies("tree-cat", nil), true
}

// exchange exchanges token at the service's POST /edge-grants and returns
// its one prefix and cookie.
func (p *p24World) exchange(token string) (string, *http.Cookie) {
	p.t.Helper()
	req := must(http.NewRequest("POST", p.x.http.URL+"/edge-grants", nil))
	req.Header.Set("Authorization", "Bearer "+token)
	r := must(noRedirect.Do(req))
	defer r.Body.Close()
	var b map[string]any
	_ = json.NewDecoder(r.Body).Decode(&b)
	ps, _ := b["prefixes"].([]any)
	if r.StatusCode != 200 || len(ps) != 1 || len(r.Cookies()) != 1 {
		p.t.Fatalf("exchange: %d %v", r.StatusCode, b)
	}
	return ps[0].(string), r.Cookies()[0]
}

// TC-10 (§B.5 Behind): a listing while the service is behind is 503
// behind, once the reader's grant verifies, with a message that names
// nothing; the namespace waited for is the body's ns, only to a reader
// with unrestricted read of the catalog.
func TestV073BehindNamesNSToCatalogReaders(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant")
	var hold atomic.Bool
	hold.Store(true)
	t.Cleanup(func() { hold.Store(false) })
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		for hold.Load() && strings.HasPrefix(req.URL.Path, "/ns/matches/") &&
			(strings.Contains(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events") || strings.Contains(req.URL.Path, "/heads")) {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		return base.RoundTrip(req)
	})
	c := p.s.Client(t, client.WithBearer(p.admin.Grant(t, p.s.Now(), "svc:tree", []string{"cat", "matches"}, []string{"read"})),
		client.WithHTTPClient(&http.Client{Transport: rt}))
	p.x = startSvc(t, c, svcOpts{now: p.s.Now}, withScopeView)
	p.x.caughtUp("cat")
	whole := p.grant("user:amy", []string{"cat", "matches"})
	for name, tc := range map[string]struct {
		token string
		ns    bool
	}{
		"whole":        {whole, true},
		"catalog-only": {p.grant("user:cy", []string{"cat"}), true},
		"scoped":       {p.scoped("user:bob", "root", "season"), false},
	} {
		r := p.x.listingAs("/cat/children?of=root", tc.token)
		msg, _ := r.body["message"].(string)
		if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" ||
			strings.Contains(msg, "matches") || (r.body["ns"] == "matches") != tc.ns || !tc.ns && r.body["ns"] != nil {
			t.Errorf("%s: %d %v %v", name, r.status, r.body, r.header)
		}
	}
	if r := p.x.raw("/cat/children?of=root", ""); r.status != 401 {
		t.Errorf("anonymous: %d %v, the grant comes first", r.status, r.body)
	}
	hold.Store(false)
	p.x.caughtUp("matches")
	if got := names(p.x.get("/cat/children?of=root", whole)["children"]); got != "matches.derby,season" {
		t.Errorf("caught up: %s", got)
	}
}

// TC-11 (§B.11.5 Listing URLs): a listing whose combined checkpoint has
// only public namespaces is served unfiltered at /{catalog}/at/{at}/…, to
// everyone, grant or not; any other only under /{catalog}/g/{gs}/…, and a
// request with neither a grant nor a cookie is 401: there is no anonymous
// filtered listing.
func TestV073PublicURLSpace(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "public", "public").start()
	amy := p.grant("user:amy", []string{"cat", "matches"})
	want := "/cat/at/" + p.x.s.At() + "/children?of=root"
	for name, tok := range map[string]string{"anonymous": "", "a grant": amy} {
		r := p.do("GET", "/cat/children?of=root", tok, "")
		if r.status != 302 || r.header.Get("Location") != want || r.header.Get("Cache-Control") != ccHeadPointer {
			t.Errorf("%s: %d %v", name, r.status, r.header)
		}
	}
	if r := p.do("GET", want, amy, ""); r.status != 200 || r.header.Get("Cache-Control") != ccListing || names(r.body["children"]) != "matches.derby,season" {
		t.Errorf("the public listing to a grant: %d %v %v", r.status, r.header, r.body)
	}
	// A subject set's URL leads to the public one, whoever asks.
	if r := p.do("GET", "/cat/g/all/at/"+p.x.s.At()+"/children?of=root", amy, ""); r.status != 302 || r.header.Get("Location") != want {
		t.Errorf("g/all of an all-public checkpoint: %d %v", r.status, r.header)
	}

	// matches isn't public: no anonymous listing, though cat is public.
	q := newP24World(t, "public", "grant").start()
	at := q.x.s.At()
	for _, path := range []string{"/cat/children?of=root", "/cat/at/" + at + "/children?of=root", "/cat/g/all/at/" + at + "/children?of=root", "/cat/g/all/children?of=root"} {
		if r := q.do("GET", path, "", ""); r.status != 401 || r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("anonymous %s: %d %v", path, r.status, r.body)
		}
	}
	amy = q.grant("user:amy", []string{"cat", "matches"})
	if r := q.do("GET", "/cat/at/"+at+"/children?of=root", amy, ""); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/cat/g/all/at/") {
		t.Errorf("a grant at the public URL: %d %v", r.status, r.header)
	}
}

// TC-12 (§B.11.5): a grant in Authorization reads only at its own gs, or
// at all where it qualifies, and is 403 at any other, never redirected;
// a URL without /g/{gs} is redirected into its own, private, no-store.
func TestV073GrantAtAnotherGS(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start(withScopeView)
	amy := p.grant("user:amy", []string{"cat", "matches"})
	bob := p.scoped("user:bob", "root", "season", "matches.derby", "derby")
	amyLoc, bobLoc := p.x.atURL("/cat/children?of=root", amy), p.x.atURL("/cat/children?of=root", bob)
	if !strings.HasPrefix(amyLoc, "/cat/g/all/at/") || !strings.HasPrefix(bobLoc, "/cat/g/") || strings.HasPrefix(bobLoc, "/cat/g/all/") {
		t.Fatalf("amy %s, bob %s", amyLoc, bobLoc)
	}
	for name, tc := range map[string]struct{ path, token string }{
		"amy at bob's gs": {bobLoc, amy},
		"bob at all":      {amyLoc, bob},
	} {
		if r := p.do("GET", tc.path, tc.token, ""); r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Location") != "" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v %v", name, r.status, r.header, r.body)
		}
	}
	if got := names(p.x.get(bobLoc, bob)["children"]); got != "matches.derby,season" {
		t.Errorf("bob at his own gs: %s", got)
	}
	// amy qualifies for all, and still reads at her own subject set's gs,
	// filtered by its roles: here none.
	own := "/cat/g/" + grantcheck.SubjectSetID([]string{}) + "/roots"
	if r := p.x.raw(own, amy); r.status != 302 {
		t.Errorf("amy's own gs: %d %v", r.status, r.body)
	} else if b := p.x.get(r.header.Get("Location"), amy); len(b["roots"].([]any)) != 0 {
		t.Errorf("amy's subject set's roots: %v", b)
	}
	// Without /g/{gs}: redirected into the grant's own, by the grant.
	r := p.do("GET", "/cat/at/"+p.x.s.At()+"/children?of=root", bob, "")
	if r.status != 302 || r.header.Get("Location") != bobLoc || r.header.Get("Cache-Control") != "private, no-store" {
		t.Errorf("bob at the public URL: %d %v", r.status, r.header)
	}
}

// TC-13 (§B.11.5): the head pointer of a subject set lies under its
// prefix, /{catalog}/g/{gs}/{op}, so its edge grant covers it, and
// redirects to …/g/{gs}/at/{cur}/{op}; the gs must be the reader's (403
// for a grant, 401 without a grant or a cookie covering it). A redirect a
// grant decides is private, no-store.
func TestV073HeadPointerUnderGS(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start(withEdgeGrants)
	bob := p.scoped("user:bob", "root", "season")
	prefix, cookie := p.exchange(bob)
	if !strings.HasPrefix(prefix, "/cat/g/") || prefix == "/cat/g/all" {
		t.Fatalf("prefix %s", prefix)
	}
	want := prefix + "/at/" + p.x.s.At() + "/children?of=root"
	r := p.do("GET", prefix+"/children?of=root", "", "", cookie)
	if r.status != 302 || r.header.Get("Location") != want || r.header.Get("Cache-Control") != ccPrivatePtr {
		t.Fatalf("the cookie's pointer: %d %v %v", r.status, r.header, r.body)
	}
	if r := p.do("GET", want, "", "", cookie); r.status != 200 || names(r.body["children"]) != "season" {
		t.Errorf("the cookie's listing: %d %v", r.status, r.body)
	}
	r = p.do("GET", prefix+"/children?of=root", bob, "")
	if r.status != 302 || r.header.Get("Location") != want || r.header.Get("Cache-Control") != "private, no-store" || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("the grant's pointer: %d %v", r.status, r.header)
	}
	amy := p.grant("user:amy", []string{"cat", "matches"})
	if r := p.do("GET", prefix+"/children?of=root", amy, ""); r.status != 403 || r.header.Get("Location") != "" {
		t.Errorf("amy's grant at bob's pointer: %d %v", r.status, r.header)
	}
	if r := p.do("GET", "/cat/g/all/children?of=root", "", "", cookie); r.status != 401 {
		t.Errorf("bob's cookie at all's pointer: %d %v", r.status, r.body)
	}
	if r := p.do("GET", "/cat/g/all/children?of=root", amy, ""); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/cat/g/all/at/") {
		t.Errorf("amy at all's pointer: %d %v", r.status, r.header)
	}
	if r := p.do("GET", "/cat/g/zz/children?of=root", amy, ""); r.status != 404 {
		t.Errorf("a malformed gs: %d", r.status)
	}
}

// TC-14 (§B.11.5): a tree service without §B.11 (no RoleView) serves only
// g/all, to readers whose grants would be issued namespace-wide edge
// grants on the catalog and every namespace it trusts; any other grant
// is 403, and anonymous readers only all-public checkpoints.
func TestV073PlainTreeServesOnlyAll(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start()
	if r := p.do("GET", "/cat/children?of=root", "", ""); r.status != 401 {
		t.Errorf("anonymous: %d", r.status)
	}
	for name, tok := range map[string]string{
		"catalog-only": p.grant("user:cy", []string{"cat"}),
		"scoped":       p.scoped("user:bob", "root", "season", "matches.derby", "derby"),
	} {
		if r := p.do("GET", "/cat/children?of=root", tok, ""); r.status != 403 || r.header.Get("Location") != "" {
			t.Errorf("%s: %d %v", name, r.status, r.header)
		}
	}
	amy := p.grant("user:amy", []string{"cat", "matches"}, map[string]any{"groups": []any{"eds"}})
	loc := p.x.atURL("/cat/children?of=root", amy)
	if !strings.HasPrefix(loc, "/cat/g/all/at/") || names(p.x.get(loc, amy)["children"]) != "matches.derby,season" {
		t.Errorf("a namespace-wide reader: %s", loc)
	}
	gs := grantcheck.SubjectSetID([]string{"group:eds"})
	if r := p.do("GET", "/cat/g/"+gs+"/at/"+p.x.s.At()+"/children?of=root", amy, ""); r.status != 403 {
		t.Errorf("a subject set's URL: %d %v", r.status, r.body)
	}
	q := newP24World(t, "public", "public").start()
	if got := names(q.x.get("/cat/children?of=root", "")["children"]); got != "matches.derby,season" {
		t.Errorf("an all-public checkpoint, anonymously: %s", got)
	}
}

// TC-15 (§B.11.5, §C.5.2): g/all is for readers whose grants would be
// issued a namespace-wide edge grant, and a rule referring to /now, which
// an edge can't evaluate, rules one out even while it passes. Such a
// reader reads its subject set's listings (none, without §B.11), and its
// unrestricted reads (§2.1), judged on each request, admit problems
// there, kept by no shared cache.
func TestV073AllNeedsNamespaceWide(t *testing.T) {
	t.Parallel()
	clock := map[string]any{"rules": []any{map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": "2999-01-01T00:00:00Z"}}}}
	p := newP24World(t, "grant", "grant").start()
	if r := p.do("GET", "/cat/children?of=root", p.grant("user:cl", []string{"cat", "matches"}, clock), ""); r.status != 403 {
		t.Errorf("a rule on /now, without §B.11: %d %v", r.status, r.header)
	}
	q := newP24World(t, "grant", "grant").start(withEdgeGrants)
	cl := q.grant("user:cl", []string{"cat", "matches"}, clock)
	loc := q.x.atURL("/cat/children?of=root", cl)
	if !strings.HasPrefix(loc, "/cat/g/") || strings.HasPrefix(loc, "/cat/g/all/") {
		t.Errorf("a rule on /now: %s", loc)
	}
	if r := q.do("GET", q.x.atURL("/cat/problems", cl), cl, ""); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" ||
		!strings.HasPrefix(r.header.Get("Cache-Control"), "private") {
		t.Errorf("problems: %d %v", r.status, r.header)
	}
	if prefix, _ := q.exchange(cl); prefix == "/cat/g/all" {
		t.Errorf("exchanged for %s", prefix)
	}
	if prefix, _ := q.exchange(q.grant("user:amy", []string{"cat", "matches"})); prefix != "/cat/g/all" {
		t.Errorf("a namespace-wide reader exchanged for %s", prefix)
	}
}

// TC-16 (§B.11.5, §6.6): the service's exchangeRate buckets are shared by
// its instances through its database: what one instance drew, another
// on the same database sees drawn, and the other way round.
func TestV073ExchangeRateShared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newP24World(t, "grant", "grant")
	db := filepath.Join(t.TempDir(), "tree.db")
	rate := tree.Rate{Rate: 0.001, Burst: 1}
	p.x = startSvc(t, p.s.Client(t, client.WithBearer(p.admin.Grant(t, p.s.Now(), "svc:tree", []string{"cat", "matches"}, []string{"read"}))),
		svcOpts{now: p.s.Now, db: db}, withEdgeGrants, func(o *tree.Options) { o.ExchangeRate = rate })
	p.x.caughtUp("cat", "matches")
	sdb := must(sql.Open("sqlite", sqlitedsn.DSN(db, "_pragma=busy_timeout(10000)")))
	t.Cleanup(func() { sdb.Close() })
	other := must(svcedge.NewStore(ctx, sdb))
	p.exchange(p.scoped("user:bob", "root"))
	if wait := must(other.Draw(ctx, p.s.Now(), rate, []string{"user:bob\x00reader"})); wait == 0 {
		t.Fatal("another instance drew from the bucket the service drained")
	}
	if wait := must(other.Draw(ctx, p.s.Now(), rate, []string{"user:cy\x00reader"})); wait != 0 {
		t.Fatalf("cy's first draw: %v", wait)
	}
	if r := p.do("POST", "/edge-grants", p.scoped("user:cy", "root"), ""); r.status != 429 || r.body["limit"] != "exchangeRate" || r.header.Get("Retry-After") == "" {
		t.Errorf("cy's exchange after another instance drained his bucket: %d %v", r.status, r.body)
	}
}

// GR-20 (§C.8, §C.6, F-C3 default): the service answers a grant over
// grantSize or rulesPerGrant as the origin does, 413 limit naming the
// limit, on listings and at its exchange, once decoded; public reads
// ignore any grant. The exchange's body is I-JSON without noncharacters
// (§3.1, 400).
func TestV073GrantOverLimits(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start(withEdgeGrants)
	both := []string{"cat", "matches"}
	many := make([]any, 40)
	for i := range many {
		many[i] = map[string]any{"op": "test", "path": "/action", "value": "read"}
	}
	for limit, tok := range map[string]string{
		"grantSize":     p.grant("user:h", both, map[string]any{"attrs": map[string]any{"x": strings.Repeat("a", 9000)}}),
		"rulesPerGrant": p.grant("user:m", both, map[string]any{"rules": []any{map[string]any{"all": many}}}),
	} {
		r := p.do("GET", "/cat/children?of=root", tok, "")
		if r.status != 413 || r.body["code"] != "limit" || r.body["limit"] != limit || r.body["max"] == nil || r.body["measured"] == nil {
			t.Errorf("%s, listing: %d %v", limit, r.status, r.body)
		}
		r = p.do("POST", "/edge-grants", "", `{"grants":["`+tok+`"]}`)
		if r.status != 413 || r.body["code"] != "limit" || r.body["limit"] != limit {
			t.Errorf("%s, exchange: %d %v", limit, r.status, r.body)
		}
	}
	if r := p.do("POST", "/edge-grants", "", "{\"grants\":[\"a￾\"]}"); r.status != 400 || r.body["code"] != "bad_input" {
		t.Errorf("a noncharacter: %d %v", r.status, r.body)
	}
	q := newP24World(t, "public", "public").start()
	huge := q.grant("user:h", both, map[string]any{"attrs": map[string]any{"x": strings.Repeat("a", 9000)}})
	if r := q.do("GET", "/cat/children?of=root", huge, ""); r.status != 302 {
		t.Errorf("a public listing with a grant over grantSize: %d %v", r.status, r.body)
	}
}

// ENC-33 (§E.2.6, §B.11.5): a sealed catalog's listing is sealed whole
// only where the catalog isn't public and every reader the URL admits
// reads it whole, which is g/all; a public sealed catalog's are sealed
// per entry, in the public URL space and under g/all alike. A listing a
// release before stored sealed whole elsewhere isn't served.
func TestV073SealsWholeOnlyForAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"pub":  {"read": "public", "keys": []any{k.Entry("*")}},
		"priv": {"read": "grant", "keys": []any{k.Entry("*")}},
		"cat": {"read": "public", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"},
			"catalog": map[string]any{"trust": []any{"pub"}}},
		"cat2": {"read": "public", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"},
			"catalog": map[string]any{"trust": []any{"priv"}}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "cat2", "pub", "priv"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	for _, cat := range []string{"cat", "cat2"} {
		createNonced(t, w, cat, "root", map[string]any{"title": "Root zq8x", "parents": []any{}})
	}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	perEntry := func(f fetched) bool {
		return f.header.Get("Content-Type") == "application/json" && !strings.Contains(string(f.body), "zq8x") && strings.Contains(string(f.body), `"sealed"`)
	}
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "pub")
	f := x.fetch("/cat/roots", "")
	if !strings.HasPrefix(f.path, "/cat/at/") || !perEntry(f) {
		t.Fatalf("anonymous, public sealed catalog: %s %v %s", f.path, f.header, f.body)
	}
	y := startSvc(t, sc, svcOpts{now: s.Now, catalog: "cat2"})
	y.caughtUp("cat2", "priv")
	if g := y.fetch("/cat2/roots", k.Grant(t, s.Now(), "user:r", []string{"cat2", "priv"}, []string{"read"})); !strings.HasPrefix(g.path, "/cat2/g/all/") || !perEntry(g) {
		t.Fatalf("g/all of a public sealed catalog: %s %v %s", g.path, g.header, g.body)
	}
	// Stored sealed whole by an earlier release: dropped at start.
	x.stop()
	sdb := must(sql.Open("sqlite", sqlitedsn.DSN(db, "_pragma=busy_timeout(10000)")))
	if n := must(must(sdb.Exec(`UPDATE sealed_views SET body = 'a.b.c.d.e', json = 0`)).RowsAffected()); n == 0 {
		t.Fatal("no stored listing")
	}
	sdb.Close()
	x = startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "pub")
	if again := x.fetch(f.path, ""); !perEntry(again) {
		t.Fatalf("after a restart over a listing stored whole: %v %s", again.header, again.body)
	}
}

// ENC-33 (§E.2.6, §B.11.5): releases before v0.73 sealed a public
// catalog's g/all listings whole too, stored under the URL and shape a
// g/all reader's listing has now; they are dropped at start and served
// per entry. A catalog that isn't public keeps its stored g/all listings
// across a restart byte for byte: stored once, served forever.
func TestV073WholeGAllDroppedForPublicCatalog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	sealed := map[string]any{"level": "sealed"}
	for ns, doc := range map[string]map[string]any{
		"priv":    {"read": "grant", "keys": []any{k.Entry("*")}},
		"pubcat":  {"read": "public", "keys": []any{k.Entry("*")}, "encryption": sealed, "catalog": map[string]any{"trust": []any{"priv"}}},
		"privcat": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": sealed, "catalog": map[string]any{"trust": []any{"priv"}}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"priv", "pubcat", "privcat"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	tok := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	perEntry := func(f fetched) bool {
		return f.header.Get("Content-Type") == "application/json" && !strings.Contains(string(f.body), "zq8x") && strings.Contains(string(f.body), `"sealed"`)
	}
	for _, cat := range []string{"pubcat", "privcat"} {
		createNonced(t, w, cat, "root", map[string]any{"title": "Root zq8x", "parents": []any{}})
		db := filepath.Join(t.TempDir(), "tree.db")
		x := startSvc(t, sc, svcOpts{now: s.Now, catalog: cat, db: db})
		x.caughtUp(cat, "priv")
		f := x.fetch("/"+cat+"/roots", tok)
		if !strings.HasPrefix(f.path, "/"+cat+"/g/all/") {
			t.Fatalf("%s: %s", cat, f.path)
		}
		x.stop()
		if cat == "pubcat" {
			if !perEntry(f) {
				t.Fatalf("g/all of a public sealed catalog: %v %s", f.header, f.body)
			}
			// What a release before v0.73 stored for this URL and shape.
			sdb := must(sql.Open("sqlite", sqlitedsn.DSN(db, "_pragma=busy_timeout(10000)")))
			if n := must(must(sdb.Exec(`UPDATE sealed_views SET body = 'a.b.c.d.e', json = 0 WHERE view LIKE '/pubcat/g/all/%'`)).RowsAffected()); n == 0 {
				t.Fatal("no stored g/all listing")
			}
			sdb.Close()
		} else if f.header.Get("Content-Type") != "application/jose" || strings.Contains(string(f.body), "zq8x") {
			t.Fatalf("g/all of a sealed catalog that isn't public: %v %s", f.header, f.body)
		}
		x = startSvc(t, sc, svcOpts{now: s.Now, catalog: cat, db: db})
		x.caughtUp(cat, "priv")
		again := x.fetch(f.path, tok)
		switch {
		case cat == "pubcat" && !perEntry(again):
			t.Errorf("after a restart over a g/all listing of a public catalog stored whole: %v %s", again.header, again.body)
		case cat == "privcat" && string(again.body) != string(f.body):
			t.Errorf("after a restart, g/all of a catalog that isn't public is sealed again: %s, was %s", again.body, f.body)
		}
	}
}

// TC-11, TC-15 (§B.11.5): g/all needs a grant that would be issued a
// namespace-wide edge grant on every namespace in the combined checkpoint
// that isn't public, so with the catalog public a grant naming only the
// content namespace qualifies, at the listings and at the exchange. One
// that isn't namespace-wide there doesn't, and a subject set is resolved
// only from a grant verified for the catalog; a grant over the limits is
// 413 still.
func TestV073PublicCatalogNeedsNoGrant(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "public", "grant").start()
	m := p.grant("user:m", []string{"matches"})
	loc := p.x.atURL("/cat/children?of=root", m)
	if !strings.HasPrefix(loc, "/cat/g/all/at/") {
		t.Fatalf("a namespace-wide reader of matches alone: %s", loc)
	}
	if got := names(p.x.get(loc, m)["children"]); got != "matches.derby,season" {
		t.Errorf("its listing: %s", got)
	}
	derby := p.grant("user:d", []string{"matches"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "derby"}}})
	if r := p.do("GET", "/cat/children?of=root", derby, ""); r.status != 403 || r.header.Get("Location") != "" {
		t.Errorf("a grant for one item of matches: %d %v %v", r.status, r.header, r.body)
	}
	huge := p.grant("user:h", []string{"matches"}, map[string]any{"attrs": map[string]any{"x": strings.Repeat("a", 9000)}})
	if r := p.do("GET", "/cat/children?of=root", huge, ""); r.status != 413 || r.body["limit"] != "grantSize" {
		t.Errorf("a grant over grantSize: %d %v", r.status, r.body)
	}

	q := newP24World(t, "public", "grant").start(withEdgeGrants)
	m = q.grant("user:m", []string{"matches"})
	if prefix, _ := q.exchange(m); prefix != "/cat/g/all" {
		t.Errorf("exchanged for %s", prefix)
	}
	if r := q.do("GET", "/cat/g/"+grantcheck.SubjectSetID([]string{})+"/roots", m, ""); r.status != 403 {
		t.Errorf("at a subject set's URL, without a grant for the catalog: %d %v", r.status, r.body)
	}
}

// TC-15 (§B.11.5): problems and orphans need unrestricted read of the
// catalog and of every content namespace in the combined checkpoint; a
// trusted one the service can't follow has no checkpoint and isn't
// required, as the public URL space and g/all are judged without it.
func TestV073ProblemsCoverCheckpointedNamespaces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newP24World(t, "grant", "grant").start()
	cfg := p.s.Client(t, client.WithBearer(p.admin.Grant(t, p.s.Now(), "user:w", []string{"cat"}, []string{"read", "config"})))
	h := must(cfg.NSHead(ctx, "cat"))
	must(cfg.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "nosuch"}}))
	p.x.caughtUp("cat")
	amy := p.grant("user:amy", []string{"cat", "matches"})
	waitFor(t, "a listing while nosuch can't be followed", func() bool {
		return p.do("GET", "/cat/children?of=root", amy, "").status == http.StatusFound
	})
	for _, op := range []string{"problems", "orphans"} {
		loc := p.x.atURL("/cat/"+op, amy)
		if r := p.do("GET", loc, amy, ""); !strings.HasPrefix(loc, "/cat/g/all/at/") || r.status != 200 {
			t.Errorf("%s for g/all: %s %d %v", op, loc, r.status, r.body)
		}
	}

	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	h = must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "nosuch"}}))
	x.caughtUp("cat")
	waitFor(t, "a listing while nosuch can't be followed", func() bool {
		return x.listing("/cat/children?of=season").status == http.StatusOK
	})
	for _, op := range []string{"problems", "orphans"} {
		if r := x.listing("/cat/" + op); r.status != 200 {
			t.Errorf("%s in the public URL space: %d %v", op, r.status, r.body)
		}
	}
}
