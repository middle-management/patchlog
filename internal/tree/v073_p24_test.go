package tree_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
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
// limit, on listings and at its exchange, once decoded. The exchange's
// body is I-JSON without noncharacters (§3.1, 400).
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
}
