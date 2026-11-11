package tree_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// SVC-11t (SERVICES §B.5 table, Shared nodes in DAGs; CONFORMANCE
// SVC-24): ancestors answers paths, every path to a root, each an array
// of node names from a root down to the node itself; where the same,
// ending at the placement's node. nodes gives each named node's href and
// title, for breadcrumbs. A cut is reported by the top-level members
// "tooDeep": true and "truncated": true, JSON booleans, absent otherwise.
func TestV082AncestorsShape(t *testing.T) {
	t.Parallel()
	w := setup(t)
	ctx := context.Background()
	w.folder(t, "root", "Root")
	w.folder(t, "a", "A", "root")
	w.folder(t, "b", "B", "root", "a")
	w.content(t, "matches", "m")
	w.place(t, "matches.m", "a")
	w.place(t, "matches.dag", "b")
	// A chain deeper than the depth limit, 64.
	w.folder(t, "d0", "D0")
	for i := 1; i <= 66; i++ {
		w.folder(t, fmt.Sprintf("d%d", i), "", fmt.Sprintf("d%d", i-1))
	}
	// More paths than one answer gives (1000): ten layers of two
	// folders, each under both of the layer above, 2^10 paths to top.
	w.folder(t, "top", "Top")
	prev := []string{"top"}
	for l := 1; l <= 10; l++ {
		cur := []string{fmt.Sprintf("l%da", l), fmt.Sprintf("l%db", l)}
		for _, n := range cur {
			w.folder(t, n, "", prev...)
		}
		prev = cur
	}
	w.folder(t, "many", "", prev...)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")

	// Two deep: the last element names the node, the first a root.
	b := x.get("/cat/ancestors?of=/r/matches/m", "")
	if !reflect.DeepEqual(b["paths"], []any{[]any{"root", "a", "matches.m"}}) {
		t.Errorf("ancestors of matches.m: paths %v", b["paths"])
	}
	wantNodes := map[string]any{
		"root":      map[string]any{"href": "/r/cat/root", "title": "Root"},
		"a":         map[string]any{"href": "/r/cat/a", "title": "A"},
		"matches.m": map[string]any{"href": "/r/cat/matches.m"},
	}
	if !reflect.DeepEqual(b["nodes"], wantNodes) {
		t.Errorf("ancestors of matches.m: nodes %v, want %v", b["nodes"], wantNodes)
	}
	for _, k := range []string{"tooDeep", "truncated", "incomplete"} {
		if _, ok := b[k]; ok {
			t.Errorf("ancestors of matches.m: %s present without a cut: %v", k, b[k])
		}
	}
	// A root's own path is itself.
	if b := x.get("/cat/ancestors?of=root", ""); !reflect.DeepEqual(b["paths"], []any{[]any{"root"}}) {
		t.Errorf("ancestors of a root: %v", b["paths"])
	}
	// A DAG: b has two parents, so two paths run down to matches.dag.
	b = x.get("/cat/ancestors?of=matches.dag", "")
	if got := pathsOf(b["paths"]); got != "root/b/matches.dag | root/a/b/matches.dag" {
		t.Errorf("ancestors in a DAG: %s", got)
	}
	// where has the same shape, each path ending at the placement's node.
	b = x.get("/cat/where?item=/r/matches/m", "")
	if !reflect.DeepEqual(b["paths"], []any{[]any{"root", "a", "matches.m"}}) || !reflect.DeepEqual(b["nodes"], wantNodes) ||
		b["placement"].(map[string]any)["name"] != "matches.m" {
		t.Errorf("where: %v", b)
	}

	// The depth limit: "tooDeep": true, a JSON boolean, on ancestors and
	// on a subtree whose folder at depth 64 still has children; a cut at
	// the depth asked for stays the entry's "more".
	if b := x.get("/cat/ancestors?of=d66", ""); b["tooDeep"] != true || b["truncated"] != nil {
		t.Errorf("ancestors past the depth limit: tooDeep %v (%T), truncated %v", b["tooDeep"], b["tooDeep"], b["truncated"])
	}
	if b := x.get("/cat/ancestors?of=d60", ""); b["tooDeep"] != nil || len(b["paths"].([]any)) != 1 {
		t.Errorf("ancestors within the depth limit: %v", b["tooDeep"])
	}
	if b := x.get("/cat/subtree?of=d0&depth=64", ""); b["tooDeep"] != true || b["truncated"] != nil {
		t.Errorf("subtree cut at the depth limit: tooDeep %v, truncated %v", b["tooDeep"], b["truncated"])
	}
	if b := x.get("/cat/subtree?of=d0&depth=3", ""); b["tooDeep"] != nil || !strings.Contains(fmt.Sprint(b["tree"]), "more:true") {
		t.Errorf("subtree cut at the depth asked for: tooDeep %v", b["tooDeep"])
	}
	if b := x.get("/cat/subtree?of=d3&depth=64", ""); b["tooDeep"] != nil {
		t.Errorf("subtree of a chain that ends at depth 63: tooDeep %v", b["tooDeep"])
	}
	// The node limit: "truncated": true.
	if b := x.get("/cat/ancestors?of=many", ""); b["truncated"] != true || b["tooDeep"] != nil || len(b["paths"].([]any)) != 1000 {
		t.Errorf("ancestors past the node limit: truncated %v, %d paths", b["truncated"], len(b["paths"].([]any)))
	}
	if b := x.get("/cat/ancestors?of=l9a", ""); b["truncated"] != nil || len(b["paths"].([]any)) != 256 {
		t.Errorf("ancestors within the node limit: truncated %v, %d paths", b["truncated"], len(b["paths"].([]any)))
	}
	_ = ctx
}

// v82Get is a GET of path at x with the Authorization header auth ("" for
// none), redirects not followed: status, Location, Cache-Control and body.
func v82Get(t *testing.T, x *svc, path, auth string) (int, string, string, string) {
	t.Helper()
	req := must(http.NewRequest("GET", x.http.URL+path, nil))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	r := must(noRedirect.Do(req))
	defer r.Body.Close()
	return r.StatusCode, r.Header.Get("Location"), r.Header.Get("Cache-Control"), string(must(io.ReadAll(r.Body)))
}

// SVC-14t, scenario 118 (SERVICES §B.11.5 Listing URLs): requests for an
// all-public listing, its redirect included, ignore any grant and are
// answered as without one: a grant with a rule on /now, a malformed one,
// an oversized one, one for another namespace and a credential that is
// no Bearer grant all get the anonymous status, Location, body and
// Cache-Control. Where the listing isn't all public (matches by grant),
// nothing is ignored: a grant is judged, and a /now one refused.
func TestV082GrantIgnoredAtAllPublicListing(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "public", "public").start()
	now := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "exists": true}}}
	creds := map[string]string{
		"a grant with a rule on /now":   "Bearer " + p.grant("user:cl", []string{"cat", "matches"}, now),
		"a plain grant":                 "Bearer " + p.grant("user:amy", []string{"cat", "matches"}),
		"a malformed grant":             "Bearer not.a.grant",
		"an oversized grant":            "Bearer " + strings.Repeat("A", 20<<10),
		"a grant for another namespace": "Bearer " + p.grant("user:o", []string{"elsewhere"}),
		"Basic credentials":             "Basic eDp5",
	}
	for _, path := range []string{"/cat/children?of=root", "/cat/roots", "/cat/ancestors?of=matches.derby", "/cat/problems"} {
		st0, loc0, cc0, body0 := v82Get(t, p.x, path, "")
		if st0 != http.StatusFound || !strings.HasPrefix(loc0, "/cat/at/") {
			t.Fatalf("anonymous GET %s: %d %s", path, st0, loc0)
		}
		ast0, _, acc0, abody0 := v82Get(t, p.x, loc0, "")
		if ast0 != 200 || !strings.Contains(acc0, "public") {
			t.Fatalf("anonymous GET %s: %d %q", loc0, ast0, acc0)
		}
		for what, auth := range creds {
			if st, loc, cc, body := v82Get(t, p.x, path, auth); st != st0 || loc != loc0 || cc != cc0 || body != body0 {
				t.Errorf("%s, %s: %d %s %q %s, want the anonymous answer %d %s %q", path, what, st, loc, cc, body, st0, loc0, cc0)
			}
			if st, _, cc, body := v82Get(t, p.x, loc0, auth); st != ast0 || cc != acc0 || body != abody0 {
				t.Errorf("%s, %s: %d %q %s, want the anonymous answer %d %q", loc0, what, st, cc, body, ast0, acc0)
			}
		}
	}

	// Not all public: public only as applied, per the checker and not
	// stopped is unchanged, and so is the refusal of a /now grant.
	q := newP24World(t, "public", "grant").start()
	if st, _, _, _ := v82Get(t, q.x, "/cat/children?of=root", "Bearer "+q.grant("user:cl", []string{"cat", "matches"}, now)); st != 403 {
		t.Errorf("a /now grant where matches reads by grant: %d, want 403", st)
	}
	if st, _, _, _ := v82Get(t, q.x, "/cat/children?of=root", "Basic eDp5"); st != 401 {
		t.Errorf("Basic credentials where matches reads by grant: %d, want 401", st)
	}
}

// SVC-13, scenario 122 (SERVICES §B.5, §A.1): a listing computed before
// an applied purge is neither served nor kept, the listings computed for
// one reader included (problems, orphans and manifests in a subject set's
// URL space), which are never kept: one a purge of what it shows overtook
// is computed again, and after three tries answered 503 behind, never
// served.
func TestV082PerReaderListingAcrossPurge(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start(withScopeView)
	amy := p.grant("user:amy", []string{"cat", "matches"})
	// amy reads both namespaces whole; at her subject set's URLs the
	// unfiltered listings are hers alone (perReader).
	gs := grantcheck.SubjectSetID([]string{})
	for _, op := range []string{"problems", "orphans"} {
		loc := p.x.atURL("/cat/g/"+gs+"/"+op, amy)
		if !strings.HasPrefix(loc, "/cat/g/"+gs+"/at/") {
			t.Fatalf("%s: redirected to %s", op, loc)
		}
		var computed, purges atomic.Int32
		p.x.s.BeforeListing(func() { computed.Add(1) })
		// A purge of matches lands once, after the listing is computed.
		p.x.s.BeforeUnkept(func() {
			if purges.Add(1) == 1 {
				p.x.s.PurgeKept("ns:matches")
			}
		})
		r := p.do("GET", loc, amy, "")
		if r.status != 200 || computed.Load() != 2 || purges.Load() != 2 {
			t.Errorf("%s across one purge: %d, computed %d times (hook %d), want it computed again and served", op, r.status, computed.Load(), purges.Load())
		}
		// A purge of something it doesn't show overtakes nothing.
		computed.Store(0)
		p.x.s.BeforeUnkept(func() { p.x.s.PurgeKept("r:cat/elsewhere") })
		if r := p.do("GET", loc, amy, ""); r.status != 200 || computed.Load() != 1 {
			t.Errorf("%s across a purge of another resource: %d, computed %d times", op, r.status, computed.Load())
		}
		// Every try loses: 503 behind, no-store, never the old body.
		computed.Store(0)
		p.x.s.BeforeUnkept(func() { p.x.s.PurgeKept("ns:cat") })
		r = p.do("GET", loc, amy, "")
		if r.status != http.StatusServiceUnavailable || r.body["code"] != "behind" || r.header.Get("Retry-After") != "1" ||
			r.header.Get("Cache-Control") != "no-store" || computed.Load() != 3 || r.body["cycles"] != nil || r.body["orphans"] != nil || r.body["entries"] != nil {
			t.Errorf("%s with a purge at every try: %d %v %v, computed %d times", op, r.status, r.header, r.body, computed.Load())
		}
		p.x.s.BeforeUnkept(nil)
		p.x.s.BeforeListing(nil)
		if r := p.do("GET", loc, amy, ""); r.status != 200 {
			t.Errorf("%s afterwards: %d %v", op, r.status, r.body)
		}
	}
}

// v82Exchange posts tokens to x's POST /edge-grants, one in Authorization
// or several in the body.
func v82Exchange(t *testing.T, x *svc, tokens ...string) resp {
	t.Helper()
	var req *http.Request
	if len(tokens) == 1 {
		req = must(http.NewRequest("POST", x.http.URL+"/edge-grants", nil))
		req.Header.Set("Authorization", "Bearer "+tokens[0])
	} else {
		req = must(http.NewRequest("POST", x.http.URL+"/edge-grants", strings.NewReader(string(must(json.Marshal(map[string]any{"grants": tokens}))))))
		req.Header.Set("Content-Type", "application/json")
	}
	r := must(noRedirect.Do(req))
	defer r.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	if len(r.Cookies()) != 0 && r.StatusCode != 200 {
		t.Errorf("exchange: %d with cookies", r.StatusCode)
	}
	return resp{r.StatusCode, r.Header, m}
}

// SVC-15t, scenarios 74 and 129 (SPEC §C.4, §C.5.2 All or nothing): at
// the tree service's exchange a grant whose requireAt chain can't be read
// is 503 behind only if every unreadable chain's cause is transient; one
// lasting cause makes it 502 upstream, whichever grant met it; a refusal
// (403) wins over both, and a 401 over that. No answer names a namespace.
func TestV082ExchangePrefersLastingChainError(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant").start(withEdgeGrants)
	a, b := p.grant("user:a", []string{"cat", "matches"}), p.grant("user:b", []string{"cat", "matches"})
	if r := v82Exchange(t, p.x, a, b); r.status != 200 {
		t.Fatalf("exchange of two grants: %d %v", r.status, r.body)
	}
	transient := &grantcheck.ChainError{Transient: true, Err: errors.New("timeout reading cat-season")}
	lasting := &grantcheck.ChainError{Err: errors.New("cat-season: 404")}
	denied := &grant.AuthError{Status: 403, Msg: "at rejected by requireAt"}
	unauth := &grant.AuthError{Status: 401, Msg: "revoked"}
	for _, c := range []struct {
		name   string
		errs   []error
		status int
		code   string
	}{
		{"both transient", []error{transient, transient}, 503, "behind"},
		{"a timeout, then a 404", []error{transient, lasting}, 502, "upstream"},
		{"a 404, then a timeout", []error{lasting, transient}, 502, "upstream"},
		{"a refusal beside an unreadable chain", []error{lasting, denied}, 403, "forbidden"},
		{"an unreadable chain beside a refusal", []error{denied, transient}, 403, "forbidden"},
		{"a 401 beside both", []error{denied, unauth}, 401, "unauthenticated"},
	} {
		var n atomic.Int32
		// The catalog's verification is each grant's first.
		p.x.s.FailVerify(func(ns string) error {
			if ns != "cat" {
				return nil
			}
			if i := int(n.Add(1)) - 1; i < len(c.errs) {
				return c.errs[i]
			}
			return nil
		})
		r := v82Exchange(t, p.x, a, b)
		p.x.s.FailVerify(nil)
		if r.status != c.status || r.body["code"] != c.code {
			t.Errorf("%s: %d %v, want %d %s", c.name, r.status, r.body, c.status, c.code)
		}
		if msg := fmt.Sprint(r.body["message"]); strings.Contains(msg, "cat-season") || strings.Contains(msg, "matches") {
			t.Errorf("%s: the answer names a namespace: %q", c.name, msg)
		}
		if (c.status == 503) != (r.header.Get("Retry-After") != "") {
			t.Errorf("%s: Retry-After %q", c.name, r.header.Get("Retry-After"))
		}
	}
}

// SVC-12 (SERVICES §B.5 Behind): Graph.Stopped is false for a namespace
// the service follows and for the catalog itself, and a hypothetical
// copy of a graph (With) keeps what the graph holds as stopped. The stop
// itself, and what it hides, is TestV082StoppedNamespaceRolesCountForNoFolder
// (internal/catalog) and TestV081XRev2StopWindow.
func TestV082GraphStoppedOfFollowed(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	x.s.View(func(g *tree.Graph, _ map[string]string) {
		for _, ns := range []string{"cat", "matches", "nosuch"} {
			if g.Stopped(ns) || g.With(nil).Stopped(ns) {
				t.Errorf("%s counts as stopped", ns)
			}
		}
	})
}

// SVC-12: a hypothetical graph (Graph.With), which the catalog service
// judges moves and widening on, carries the namespaces the service
// stopped following: their roles count for no folder there either
// (§B.5 Behind, §B.11.5).
func TestV082GraphWithCarriesStopped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"cat", "sec"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	both := []string{"cat", "sec"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	// The service holds no keys and fetches none: sealed, sec is a
	// namespace it can't follow as configured.
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.StaticKeys()))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
	stopped := func(ns string, hypo bool) (is bool) {
		x.s.View(func(g *tree.Graph, _ map[string]string) {
			if hypo {
				g = g.With(map[string]any{"extra": map[string]any{"title": "Extra", "parents": []any{}}})
			}
			is = g.Stopped(ns)
		})
		return is
	}
	waitFor(t, "the service to stop following sec", func() bool { return stopped("sec", false) })
	if !stopped("sec", true) || stopped("cat", true) {
		t.Errorf("the hypothetical graph: sec stopped %v, cat stopped %v", stopped("sec", true), stopped("cat", true))
	}
}
