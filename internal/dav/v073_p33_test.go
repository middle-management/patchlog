package dav_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/tree"
)

// preV056 is a transport that answers GET /ns/{ns}/principal as a core
// before v0.56 did (§7.4): without the members named (key, operator).
func preV056(members ...string) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			res, err := next.RoundTrip(r)
			if err != nil || res.StatusCode != http.StatusOK || !strings.HasSuffix(r.URL.Path, "/principal") {
				return res, err
			}
			b, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				return nil, err
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, err
			}
			for _, k := range members {
				delete(m, k)
			}
			b, _ = json.Marshal(m)
			res.Body = io.NopCloser(bytes.NewReader(b))
			res.ContentLength = int64(len(b))
			res.Header.Set("Content-Length", strconv.Itoa(len(b)))
			return res, nil
		})
	}
}

// preKey sets a gateway's core to answer /principal without key, as
// before v0.56: a user is then the verifying namespace, kid and sub.
func preKey(o *dav.Options) { o.Client = o.Client.With(client.WithTransport(preV056("key"))) }

// GW-26 (§H.7 "Users", §7.4 key): a user is the root sub with the key
// that verified the root block, by its thumbprint, the same in every
// namespace and under any kid: alice's two tokens of one key, listed
// in docs under two kids, are one user, whose save without If-Match is
// rebased on what the other token read; a token of another key under
// the same kid elsewhere is someone else, who doesn't read her swap
// file; and after docs rotates the key under the same kid, her token of
// the new key is a new user too.
func TestGatewayUserIsKeyV073(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	kb := clienttest.Key{Kid: "kb", Pub: k.Pub, Priv: k.Priv} // k's key under another kid
	other := clienttest.NewKey("k")                           // another key under k's kid
	for ns, keys := range map[string][]any{"docs": {k.Entry("*"), kb.Entry("*")}, "notes": {other.Entry("*")}} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "grant", "keys": keys}))
	}
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, writer)))}
	e.dav = newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs", "notes"}, Gateway: true, Logf: t.Logf})))

	viaK := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, writer)
	viaKB := kb.Grant(t, s.Now(), "user:alice", []string{"docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(viaK, "GET", "/docs/x.json", ""), 200, "alice's GET under kid k").body
	h, _ := e.load("docs", "x")
	must(e.c.Append(ctx, "docs", "x", h.ID, []any{replace("/w", 2)}))
	e.expect(e.doAs(viaKB, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "her save under kid kb, no If-Match")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 2, "w": 2})

	// Same kid, same sub, same rights, another key: another user.
	both := []string{"docs", "notes"}
	e.expect(e.doAs(k.Grant(t, s.Now(), "user:alice", both, writer), "PUT", "/docs/.x.json.swp", "alice's swap"), 201, "alice's swap file")
	e.expect(e.doAs(other.Grant(t, s.Now(), "user:alice", both, writer), "GET", "/docs/.x.json.swp", ""), 404, "the swap file to notes' key named k, for user:alice")

	// docs rotates alice's key, keeping the kid: her token of the new key
	// is a new user, with neither her swap file nor her records.
	rotated := clienttest.NewKey("k")
	nh := must(e.c.NSHead(ctx, "docs"))
	must(e.c.PatchConfig(ctx, "docs", nh.Config, []any{replace("/keys", []any{rotated.Entry("*"), kb.Entry("*")})}))
	e.expect(e.doAs(rotated.Grant(t, s.Now(), "user:alice", both, writer), "GET", "/docs/.x.json.swp", ""), 404, "the swap file to alice's token of the rotated key")
}

// GW-27 (§H.7 "Users", §7.4 operator): an operator grant is never a user
// of a gateway: 403, as /principal's operator says, and kept refused for
// a while without asking the core again.
func TestGatewayOperatorGrantRefusedV073(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var principals atomic.Int64
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, Wrap: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/principal") {
				principals.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	}})
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs"))).CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{clienttest.NewKey("k").Entry("*")}}))
	e := &env{t: t, ctx: ctx, s: s, dav: newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf})))}
	op := clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"docs"},
		"can": []any{"read"}, "exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
	r := e.expect(e.doAs(op, "PROPFIND", "/docs/", "", "Depth", "1"), 403, "an operator grant")
	if !strings.Contains(r.body, "operator") || r.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("403 %v %q", r.header, r.body)
	}
	asked := principals.Load()
	e.expect(e.doAs(op, "GET", "/docs/x.json", ""), 403, "the operator grant again")
	if n := principals.Load() - asked; n != 0 {
		t.Fatalf("the core was asked /principal %d more times for the refused operator grant", n)
	}
}

// GW-28 (§H.7 "Users", §H.4 "Others' writes"): a user's own entries are
// also those the core recorded under the user's grant (its sub, and a
// kid that names its key) or, with authentication disabled, its
// X-Author, written through another program: a save from before such an
// edit, touching the same member, is no conflict with it.
func TestOwnEntriesByIdentityV073(t *testing.T) {
	t.Parallel()
	t.Run("grant", func(t *testing.T) {
		t.Parallel()
		e, k := authEnv(t, true)
		writer := []string{"read", "create", "append", "restore", "delete"}
		alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)
		e.create("docs", "x", map[string]any{"v": 1, "w": 1})
		buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET").body
		// Alice's script, with another token of hers, straight to the core.
		script := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"docs"}, writer)))
		h, _ := e.load("docs", "x")
		must(script.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 5)}))
		e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "alice's save from before her script's edit of v")
		_, doc := e.load("docs", "x")
		sameJSON(t, doc, map[string]any{"v": 2, "w": 1})
		// Bob's edit of the same member is someone else's.
		bob := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)))
		buf = e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice reads again").body
		h, _ = e.load("docs", "x")
		must(bob.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 7)}))
		e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 2`, `"v": 3`, 1)), 409, "alice's save over bob's edit of v")
		// A delete by alice's script is hers too: her save from before it
		// makes the file anew, where one over bob's delete is refused.
		e.create("docs", "y", map[string]any{"v": 1})
		e.create("docs", "z", map[string]any{"v": 1})
		e.expect(e.doAs(alice, "GET", "/docs/y.json", ""), 200, "alice's GET of y")
		e.expect(e.doAs(alice, "GET", "/docs/z.json", ""), 200, "alice's GET of z")
		h, _ = e.load("docs", "y")
		must(script.Delete(e.ctx, "docs", "y", h.ID))
		h, _ = e.load("docs", "z")
		must(bob.Delete(e.ctx, "docs", "z", h.ID))
		e.expect(e.doAs(alice, "PUT", "/docs/y.json", `{"v": 2}`), 201, "alice's save over her script's delete of y")
		e.expect(e.doAs(alice, "PUT", "/docs/z.json", `{"v": 2}`), 409, "alice's save over bob's delete of z")
	})
	t.Run("author", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, []string{"docs"}, nil, nil)
		e.create("docs", "x", map[string]any{"v": 1, "w": 1})
		buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
		// Another program writing as the server's X-Author, dav.
		mine := e.s.Client(t, client.WithAuthor("dav"))
		h, _ := e.load("docs", "x")
		must(mine.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 5)}))
		e.expect(e.do("PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "the save from before the same author's edit of v")
		_, doc := e.load("docs", "x")
		sameJSON(t, doc, map[string]any{"v": 2, "w": 1})
		buf = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET again").body
		h, _ = e.load("docs", "x")
		must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 7)}))
		e.expect(e.do("PUT", "/docs/x.json", strings.Replace(buf, `"v": 2`, `"v": 3`, 1)), 409, "the save over another author's edit of v")
	})
}

// GW-29 (§H.7 "Users": with authentication disabled, a user is an
// X-Author): a gateway over a development core takes the Basic user
// name as the X-Author of each user's requests, which keys the user:
// two names are two users, with their own scratch files, and their
// writes are recorded under their names.
func TestGatewayAuthorUsersV073(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	must(s.Client(t, client.WithAuthor("setup")).CreateNamespace(ctx, "docs", map[string]any{"read": "public"}))
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithAuthor("other"))}
	e.dav = newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf})))
	as := func(user, method, p, body string) resp {
		t.Helper()
		req := must(http.NewRequest(method, e.dav.URL+p, strings.NewReader(body)))
		req.SetBasicAuth(user, "anything")
		res := must(testHTTP.Do(req))
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return resp{status: res.StatusCode, header: res.Header, body: string(b)}
	}
	e.expect(as("ann", "PUT", "/docs/a.json", `{"by": "ann"}`), 201, "ann's PUT")
	if a := e.lastEntry("docs", "a").Author; a != "ann" {
		t.Fatalf("a's author %q", a)
	}
	e.expect(as("ann", "PUT", "/docs/.a.json.swp", "ann's swap"), 201, "ann's swap file")
	e.expect(as("bob", "GET", "/docs/.a.json.swp", ""), 404, "ann's swap file to bob")
	if r := e.expect(as("ann", "GET", "/docs/.a.json.swp", ""), 200, "ann's swap file to ann"); r.body != "ann's swap" {
		t.Fatalf("ann's swap file %q", r.body)
	}
	e.expect(as("bob", "PUT", "/docs/b.json", `{"by": "bob"}`), 201, "bob's PUT")
	if a := e.lastEntry("docs", "b").Author; a != "bob" {
		t.Fatalf("b's author %q", a)
	}
	e.expect(as("", "GET", "/docs/a.json", ""), 401, "no user name")
}

// treeFront is a proxy in front of tree service target that records the
// paths it is asked (take returns those since the last take).
func treeFront(t *testing.T, target string) (string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	rp := httputil.NewSingleHostReverseProxy(must(url.Parse(target)))
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		rp.ServeHTTP(w, r)
	}))
	return front.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := paths
		paths = nil
		return out
	}
}

// count is how many of paths end in suffix.
func count(paths []string, suffix string) int {
	n := 0
	for _, p := range paths {
		if strings.HasSuffix(p, suffix) {
			n++
		}
	}
	return n
}

// GW-33 (§H.7 "Limited grants", §7.4 catalog): a grant limited to some
// resources learns the tree's settings (catalog.files, and whether
// files.ns is trusted) from its own GET /ns/{ns}/principal: it lists,
// reads and edits through the tree service with no other grant having
// read the catalog's document before, nor ever with what another grant
// read.
func TestTreeServiceLimitedGrantOwnSettingsV073(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	g := a.gateway(t, a.tr.http.URL)
	li := a.k.Grant(t, a.s.Now(), "user:li", a.both, []string{"read", "append"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "season", "matches.derby", "derby"}}}}})
	sameStrings(t, "li's top level, the first listing of the gateway", names(g.propfindAs(li, "/cat/"), "/cat/"), []string{"Season/"})
	sameStrings(t, "li's Season", names(g.propfindAs(li, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	buf := g.expect(g.doAs(li, "GET", "/cat/Season/derby.json", ""), 200, "li's GET").body
	g.expect(g.doAs(li, "PUT", "/cat/Season/derby.json", strings.Replace(buf, "Derby", "Derby 2", 1)), 201, "li's edit")
	if _, doc := g.load("matches", "derby"); doc.(map[string]any)["title"] != "Derby 2" {
		t.Fatalf("derby after li's edit: %v", doc)
	}
}

// GW-19 (§H.3, §B.5 total and born): a folder whose listing's total is
// over what the gateway lists is refused at once (403), not after the
// pages that fit; and duplicate titles are numbered in order of the born
// the listing gives, no node's log read from the core for it.
func TestTreeServiceTotalAndBornV073(t *testing.T) {
	t.Parallel()
	var log coreLog
	e := treeEnv(t, log.wrap)
	var items, places []client.BatchItem
	for i := 0; i < 21; i++ {
		name := fmt.Sprintf("big%02d", i)
		items = append(items, client.BatchItem{Resource: name, IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"n": i}))}})
		places = append(places, client.BatchItem{Resource: "matches." + name, IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": name + ".json", "parents": parents("cat", "big")}))}})
	}
	e.create("cat", "big", map[string]any{"title": "Big", "parents": parents("cat", "root")})
	must(e.c.Batch(e.ctx, "matches", client.BatchRequest{Items: items}, false))
	must(e.c.Batch(e.ctx, "cat", client.BatchRequest{Items: places}, false))
	for _, item := range []string{"second", "first"} {
		e.create("matches", item, map[string]any{"item": item})
	}
	// first is placed first, though its node name sorts after second's.
	e.create("cat", "matches.second", map[string]any{"title": "dup.json", "parents": parents("cat", "empty")})
	e.s.Clock.Advance(time.Second)
	e.create("cat", "matches.first", map[string]any{"title": "dup.json", "parents": parents("cat", "empty")})
	// ...and second's born is the earlier: first's node is made anew.
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	front, take := treeFront(t, tr.http.URL)
	ts := treeDav(e, front, func(_ *dav.Options, s *dav.Server) {
		if s != nil {
			dav.SetTreePage(s, 2)
		}
	})
	take()
	ts.expect(ts.do("PROPFIND", "/cat/Big/", "", "Depth", "1"), 403, "PROPFIND of a folder over the bound")
	if n := count(take(), "/children"); n > 2 {
		t.Fatalf("%d children requests for a folder whose first page's total is over the bound", n)
	}
	log.take()
	sameStrings(t, "Empty", names(ts.propfind("/cat/Empty/"), "/cat/Empty/"), []string{"dup (2).json", "dup.json"})
	noneOf(t, "a listing with duplicates", log.take(), "/r/cat/")
	for p, item := range map[string]string{"/cat/Empty/dup.json": "second", "/cat/Empty/dup%20(2).json": "first"} {
		if b := ts.expect(ts.do("GET", p, ""), 200, "GET "+p).body; b != rendered(map[string]any{"item": item}) {
			t.Errorf("%s reads %q, want item %s", p, b, item)
		}
	}
}

// GW-19 (§H.3, §B.5 lookup): a path of titles that a read names is
// resolved with one lookup, not a listing of each folder on the way; a
// name lookup doesn't resolve, as a duplicate's number, is found by
// listing the folder.
func TestTreeServiceLookupV073(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "season")})
	e.create("matches", "deep", map[string]any{"n": "deep"})
	e.create("cat", "matches.deep", map[string]any{"title": "deep.json", "parents": parents("cat", "sub")})
	e.create("matches", "deep2", map[string]any{"n": "deep2"})
	e.s.Clock.Advance(time.Second)
	e.create("cat", "matches.deep2", map[string]any{"title": "deep.json", "parents": parents("cat", "sub")})
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	front, take := treeFront(t, tr.http.URL)
	ts := treeDav(e, front)
	take()
	if b := ts.expect(ts.do("GET", "/cat/Season/Sub/deep.json", ""), 200, "GET of a deep path").body; b != rendered(map[string]any{"n": "deep"}) {
		t.Fatalf("deep.json reads %q", b)
	}
	paths := take()
	if count(paths, "/children") != 0 || count(paths, "/lookup") == 0 {
		t.Fatalf("a GET of a deep path asked the tree service %q", paths)
	}
	if b := ts.expect(ts.do("GET", "/cat/season/sub/DEEP.json", ""), 200, "GET under another case").body; b != rendered(map[string]any{"n": "deep"}) {
		t.Fatalf("DEEP.json reads %q", b)
	}
	if b := ts.expect(ts.do("GET", "/cat/Season/Sub/deep%20(2).json", ""), 200, "GET of a duplicate's numbered name").body; b != rendered(map[string]any{"n": "deep2"}) {
		t.Fatalf("deep (2).json reads %q", b)
	}
	if paths := take(); count(paths, "/children") == 0 {
		t.Fatalf("a numbered name wasn't found by listing: %q", paths)
	}
	ts.expect(ts.do("GET", "/cat/Season/Sub/nothing.json", ""), 404, "GET of no file")
}

// GW-18 (§H.3, §B.11.5, scenario 39): where files.root is hidden from
// the user, the top level is the tree service's roots for the user's
// subject set, folders by their titles, and paths resolve from them; a
// new file or folder at the top level (to: [root]) is 404, and a top
// level node, whose parents are hidden, isn't renamed or deleted (403).
func TestTreeServiceRootsWhereRootHiddenV073(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	g := a.gateway(t, a.tr.http.URL)
	li := a.k.Grant(t, a.s.Now(), "user:li", a.both, []string{"read", "create", "append", "delete"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"season", "matches.derby", "derby"}}}}})
	sameStrings(t, "li's top level, root hidden", names(g.propfindAs(li, "/cat/"), "/cat/"), []string{"Season/"})
	sameStrings(t, "li's Season", names(g.propfindAs(li, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	if b := g.expect(g.doAs(li, "GET", "/cat/Season/derby.json", ""), 200, "li's GET from a root").body; b != rendered(map[string]any{"title": "Derby"}) {
		t.Fatalf("derby.json reads %q", b)
	}
	g.expect(g.doAs(li, "PUT", "/cat/new.txt", "hello"), 404, "a new file at the top level")
	g.expect(g.doAs(li, "MKCOL", "/cat/New", ""), 404, "a new folder at the top level")
	g.expect(g.doAs(li, "MOVE", "/cat/Season", "", "Destination", "/cat/Renamed"), 403, "a rename of a top level folder")
	g.expect(g.doAs(li, "DELETE", "/cat/Season", ""), 403, "a delete of a top level folder")
	if h, _ := a.w.Head(a.ctx, "cat", "season"); h.State != client.Live {
		t.Fatalf("season is %v", h.State)
	}
}

// Carry-over (P24, F-T6): a tree service without tree-derived access
// serves only unfiltered listings (§B.11.5) and refuses a grant that
// doesn't read every namespace it follows whole (403): the gateway lists
// the folder from the node documents where the grant reads them, and
// otherwise says why it can't list it.
func TestPlainTreeServiceRefusalV073(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	bare := startTreeWith(t, a.s, "cat", nil, client.WithBearer(a.k.Grant(t, a.s.Now(), "svc:tree", a.both, []string{"read"})))
	bare.caughtUp("cat", "matches")
	g := a.gateway(t, bare.http.URL)
	catOnly := a.k.Grant(t, a.s.Now(), "user:cat-reader", []string{"cat"}, []string{"read"})
	sameStrings(t, "the catalog reader's top level, from the node documents", names(g.propfindAs(catOnly, "/cat/"), "/cat/"), []string{"Hidden/", "Season/"})
	limited := a.limitedTo(t, "user:li", "root", "season", "matches.derby", "derby")
	r := g.expect(g.doAs(limited, "PROPFIND", "/cat/", "", "Depth", "1"), 403, "a limited grant through a tree service without §B.11")
	if !strings.Contains(r.body, "node documents") || !strings.Contains(r.body, "§B.11") {
		t.Fatalf("403 %q", r.body)
	}
}

// derivedWorld is a file tree with tree-derived access (§B.11): catalog
// cat, served by a catalog service, whose key catalog-01 is listed in cat
// and in its content namespace matches as §B.11.3 lists it; users hold
// identity grants from idp for cat only, with no verbs of their own
// (§B.11.6), and get their rights from the catalog's grants (§H.2
// "Access"). root has no $access, so it is hidden from them (§B.11.5);
// Season 2026 gives match-desk desk (move, place) and li reader:
//
//	root
//	└── season "Season 2026"  $access: group:match-desk desk, user:li reader
//	    ├── matches.derby "derby.json"
//	    └── sub "Sub"
type derivedWorld struct {
	ctx    context.Context
	s      *clienttest.Server
	ops    *client.Client // catalog-admins, straight to the core
	idp    clienttest.Key
	catURL string
	svc    *catalog.Service
	g      *env
}

func newDerivedWorld(t *testing.T) *derivedWorld {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	opsKey, idp, catKey := clienttest.NewKey("ops"), clienttest.NewKey("idp"), clienttest.NewKey("catalog-01")
	var catKeyRules, catNSRules []any
	must(0, json.Unmarshal([]byte(`[
        { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } }],
          "then": [{ "op": "test", "path": "/doc/$access", "exists": false }] },
        { "if":   [{ "not": { "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } } }],
          "then": [{ "not": { "op": "writes", "overlaps": "/$access" } }] } ]`), &catKeyRules))
	must(0, json.Unmarshal([]byte(`[
    { "if":   [{ "any": [
                { "all": [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } },
                          { "op": "test", "path": "/doc/$access", "exists": true }] },
                { "all": [{ "not": { "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } } },
                          { "op": "writes", "overlaps": "/$access" }] } ] }],
      "then": [{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "catalog-admins" } } }] } ]`), &catNSRules))
	catEntry := catKey.Entry("read", "create", "append", "delete", "restore")
	catEntry["maxTtl"], catEntry["requireAt"] = "PT15M", true
	catEntry["groups"] = map[string]any{"deny": []any{"catalog-admins", "ops"}}
	catEntry["rules"] = catKeyRules
	contentEntry := catKey.Entry("read", "create", "append", "restore")
	contentEntry["maxTtl"], contentEntry["readScope"], contentEntry["requireAt"] = "PT15M", "resource", "cat"
	contentEntry["groups"] = map[string]any{"deny": []any{"ops"}}
	contentEntry["roles"] = map[string]any{"allow": []any{"desk", "reader"}}
	catDoc := map[string]any{"read": "grant", "keys": []any{opsKey.Entry("*"), idp.Entry(), catEntry}, "maxLag": "PT60S",
		"catalog": map[string]any{"trust": []any{"matches"}, "mode": "tree", "files": map[string]any{"ns": "matches", "root": "root"}},
		"roles":   map[string]any{"desk": map[string]any{"move": true, "place": true}, "reader": map[string]any{}},
		"rules":   catNSRules}
	matchesDoc := map[string]any{"read": "grant", "keys": []any{opsKey.Entry("*"), idp.Entry(), contentEntry},
		"roles": map[string]any{"desk": map[string]any{"can": []any{"read", "create", "append", "restore"}}, "reader": map[string]any{"can": []any{"read"}}},
		// A document marked bad is refused (§6.4.2), so a create fails
		// after its placement.
		"rules":    []any{map[string]any{"op": "test", "path": "/doc/bad", "exists": false}},
		"catalogs": map[string]any{"cat": map[string]any{"place": []any{"group:match-desk"}}}}
	for ns, doc := range map[string]map[string]any{"cat": catDoc, "matches": matchesDoc} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	both := []string{"cat", "matches"}
	ops := s.Client(t, client.WithBearer(opsKey.Grant(t, s.Now(), "user:ops", both, []string{"read", "create", "append", "delete", "restore"},
		map[string]any{"groups": []any{"catalog-admins"}})))
	for _, d := range []struct {
		ns, name string
		doc      map[string]any
	}{
		{"matches", "derby", map[string]any{"title": "Derby", "score": "0-0"}},
		{"cat", "root", map[string]any{"title": "Root", "parents": []any{}}},
		{"cat", "season", map[string]any{"title": "Season 2026", "parents": parents("cat", "root"),
			"$access": map[string]any{"group:match-desk": []any{"desk"}, "user:li": []any{"reader"}}}},
		{"cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")}},
		{"cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "season")}},
	} {
		must(ops.CreateDoc(ctx, d.ns, d.name, d.doc))
	}
	svcClient := s.Client(t, client.WithBearer(opsKey.Grant(t, s.Now(), "svc:catalog", both, []string{"read"},
		map[string]any{"exp": s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	svc := must(catalog.Open(ctx, catalog.Options{
		Tree: tree.Options{Client: svcClient, Catalog: "cat", DB: filepath.Join(t.TempDir(), "catalog.db"), MinWait: 2 * time.Second,
			RepurgeInterval: -1, CheckerTTL: time.Millisecond, Logf: t.Logf,
			FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}},
		Key: catKey.Priv, Kid: "catalog-01"}))
	hs := httptest.NewServer(svc.Handler())
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.Run(rctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); svc.Close() })
	w := &derivedWorld{ctx: ctx, s: s, ops: ops, idp: idp, catURL: hs.URL, svc: svc}
	w.caughtUp(t)
	opt := dav.Options{Client: s.Client(t), Catalogs: []string{"cat"}, Gateway: true, TreeService: hs.URL, Logf: t.Logf}
	w.g = &env{t: t, ctx: ctx, s: s, c: ops, dav: newTestServer(t, must(dav.New(opt)))}
	return w
}

// caughtUp waits until the catalog service reached the core's heads.
func (w *derivedWorld) caughtUp(t *testing.T) {
	t.Helper()
	for _, ns := range []string{"cat", "matches"} {
		deadline := time.Now().Add(30 * time.Second)
		for {
			h, err := w.ops.NSHead(w.ctx, ns)
			if err == nil && w.svc.Tree().Checkpoint(ns) == h.ID {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the catalog service didn't catch up with %s", ns)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// user is an identity grant of sub for cat with groups, no verbs.
func (w *derivedWorld) user(t *testing.T, sub string, groups ...string) string {
	return w.idp.Grant(t, w.s.Now(), sub, []string{"cat"}, []string{}, map[string]any{"groups": toAnyT(groups)})
}

func toAnyT(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// titled is the live node of cat titled title, and its document.
func (w *derivedWorld) titled(t *testing.T, title string) (string, map[string]any) {
	t.Helper()
	for _, it := range must(w.ops.Heads(w.ctx, "cat", must(w.ops.NSHead(w.ctx, "cat")).ID)) {
		if it.Kind != "head" {
			continue
		}
		h, doc := w.g.load("cat", it.Resource)
		if m, _ := doc.(map[string]any); h.State == client.Live && m["title"] == title {
			return it.Resource, m
		}
	}
	return "", nil
}

// GW-31 (§H.2 "Access", §H.4 "New files", §H.5, §B.11.4): in a tree with
// tree-derived access, a user whose own grant only proves who they are
// lists the tree from its roots (root hidden, §B.11.5), reads and edits a
// file under the catalog's grants for its item, makes a new file by
// placing it first and then creating its item under the Create grant the
// catalog resolves from the placement, renames it under a Move grant
// whose patch set begins with the test of /parents, and, without reading
// the node documents, deletes no folder (403); a new file whose create
// fails has its placement deleted again.
func TestTreeDerivedWritesV073(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	g := w.g
	bob := w.user(t, "user:bob", "match-desk")
	sameStrings(t, "bob's top level", names(g.propfindAs(bob, "/cat/"), "/cat/"), []string{"Season 2026/"})
	sameStrings(t, "bob's Season 2026", names(g.propfindAs(bob, "/cat/Season%202026/"), "/cat/Season 2026/"), []string{"Sub/", "derby.json"})
	buf := g.expect(g.doAs(bob, "GET", "/cat/Season%202026/derby.json", ""), 200, "bob's GET").body
	g.expect(g.doAs(bob, "PUT", "/cat/Season%202026/derby.json", strings.Replace(buf, `"0-0"`, `"1-0"`, 1)), 201, "bob's edit of derby.json")
	if _, doc := g.load("matches", "derby"); doc.(map[string]any)["score"] != "1-0" {
		t.Fatalf("derby after bob's edit: %v", doc)
	}
	if e := g.lastEntry("matches", "derby"); e.Grant == nil || e.Grant.Sub != "user:bob" || e.Grant.Kid != "catalog-01" {
		t.Fatalf("bob's edit was written under %+v, not a grant the catalog issued him", e.Grant)
	}

	// A new file: its placement first, then its item.
	g.expect(g.doAs(bob, "PUT", "/cat/Season%202026/new.json", `{"n": 1}`), 201, "bob's new file")
	node, doc := w.titled(t, "new.json")
	if node == "" || !strings.HasSuffix(doc["parents"].([]any)[0].(map[string]any)["href"].(string), "/season") {
		t.Fatalf("new.json's placement %s: %v", node, doc)
	}
	item := strings.TrimPrefix(node, "matches.")
	if _, idoc := g.load("matches", item); !reflect.DeepEqual(idoc, map[string]any{"n": 1.0}) {
		t.Fatalf("new.json's item %s: %v", item, idoc)
	}
	pe, ie := g.lastEntry("cat", node), g.lastEntry("matches", item)
	if pe.Created > ie.Created || ie.Grant == nil || ie.Grant.Kid != "catalog-01" || ie.Grant.Sub != "user:bob" {
		t.Fatalf("the placement (%s, %+v) wasn't first, or the item (%s, %+v) not under the catalog's Create grant", pe.Created, pe.Grant, ie.Created, ie.Grant)
	}

	// A rename under a Move grant: its patch set begins with the test of
	// /parents.
	w.caughtUp(t)
	g.expect(g.doAs(bob, "MOVE", "/cat/Season%202026/new.json", "", "Destination", "/cat/Season%202026/renamed.json"), 201, "bob's rename")
	if _, doc := g.load("cat", node); doc.(map[string]any)["title"] != "renamed.json" {
		t.Fatalf("the placement after the rename: %v", doc)
	}
	ps, _ := g.lastEntry("cat", node).Patches.([]any)
	if first, _ := ps[0].(map[string]any); len(ps) < 2 || first["op"] != "test" || first["path"] != "/parents" {
		t.Fatalf("the rename's patch set %v", ps)
	}

	// A folder made under a Create a folder grant; the file moved into
	// it under a Move grant; deleted, its placement goes under an Unplace
	// grant, and its item stays, which the catalog's key never deletes
	// (§B.11.3, §H.5).
	g.expect(g.doAs(bob, "MKCOL", "/cat/Season%202026/New", ""), 201, "bob's new folder")
	folder, fdoc := w.titled(t, "New")
	if folder == "" || !strings.HasSuffix(fdoc["parents"].([]any)[0].(map[string]any)["href"].(string), "/season") {
		t.Fatalf("New's node %s: %v", folder, fdoc)
	}
	w.caughtUp(t)
	g.expect(g.doAs(bob, "MOVE", "/cat/Season%202026/renamed.json", "", "Destination", "/cat/Season%202026/New/renamed.json"), 201, "bob's move into New")
	if _, doc := g.load("cat", node); !strings.HasSuffix(doc.(map[string]any)["parents"].([]any)[0].(map[string]any)["href"].(string), "/"+folder) {
		t.Fatalf("the placement after the move: %v", doc)
	}
	w.caughtUp(t)
	g.expect(g.doAs(bob, "DELETE", "/cat/Season%202026/New/renamed.json", ""), 204, "bob's DELETE of renamed.json")
	g.expectTombstoned("cat", node, "renamed.json's placement")
	if h, _ := g.load("matches", item); h.State != client.Live {
		t.Fatalf("the item of renamed.json is %v", h.State)
	}

	// No folder deleted without the node documents; no new file at the
	// top level, which is root's (hidden).
	if r := g.expect(g.doAs(bob, "DELETE", "/cat/Season%202026/Sub", ""), 403, "bob's DELETE of a folder"); !strings.Contains(r.body, "node documents") {
		t.Fatalf("403 %q", r.body)
	}
	g.expect(g.doAs(bob, "PUT", "/cat/top.json", `{"n": 1}`), 404, "bob's new file at the top level")

	// A create refused after the placement: the placement goes again.
	w.caughtUp(t)
	r := g.expect(g.doAs(bob, "PUT", "/cat/Season%202026/bad.json", `{"bad": true}`), 422, "bob's new file the content namespace refuses")
	if !strings.Contains(r.body, "deleted again") {
		t.Fatalf("422 %q", r.body)
	}
	if node, _ := w.titled(t, "bad.json"); node != "" {
		t.Fatalf("bad.json's placement %s is live", node)
	}
}

// GW-28 with tree-derived access (§H.7 "Users"): a user's own entries in
// a content namespace include those under the catalog's key there for
// the user's sub (§B.11.4), written by another program of the user's
// with a grant the catalog issued it.
func TestTreeDerivedOwnEntriesV073(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	g := w.g
	bob := w.user(t, "user:bob", "match-desk")
	buf := g.expect(g.doAs(bob, "GET", "/cat/Season%202026/derby.json", ""), 200, "bob's GET").body
	// bob's script asks the catalog for a grant of its own, and edits the
	// score straight at the core.
	body := strings.NewReader(`{"item": "/r/matches/derby", "want": ["read", "append"]}`)
	req := must(http.NewRequest("POST", w.catURL+"/grants", body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bob)
	res := must(testHTTP.Do(req))
	var a struct{ Grant string }
	must(0, json.NewDecoder(res.Body).Decode(&a))
	res.Body.Close()
	script := w.s.Client(t, client.WithBearer(a.Grant))
	h, _ := g.load("matches", "derby")
	must(script.Append(w.ctx, "matches", "derby", h.ID, []any{replace("/score", "2-0")}))
	g.expect(g.doAs(bob, "PUT", "/cat/Season%202026/derby.json", strings.Replace(buf, `"0-0"`, `"3-0"`, 1)), 201, "bob's save from before his script's edit")
	if _, doc := g.load("matches", "derby"); doc.(map[string]any)["score"] != "3-0" {
		t.Fatalf("derby: %v", doc)
	}
}

// GW-31 (§H.5, §B.11.4): a Move grant's patch set begins with the test
// of /parents the catalog decided; where that is stale (the node moved
// since the decision), the core refuses the test (422), and the gateway
// answers 409, asking for a reload; nothing is written.
func TestTreeDerivedStaleMoveV073(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	// The catalog's answers pass through a proxy that makes the parents
	// of a Move decision stale: another order than the node's.
	rp := httputil.NewSingleHostReverseProxy(must(url.Parse(w.catURL)))
	rp.ModifyResponse = func(r *http.Response) error {
		if r.Request.URL.Path != "/grants" || r.StatusCode != http.StatusOK || r.Request.Header.Get("X-Want") != "move" {
			return nil
		}
		var a map[string]any
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			return err
		}
		r.Body.Close()
		if ps, _ := a["parents"].([]any); len(ps) > 0 {
			ps[0].(map[string]any)["order"] = "zz"
		}
		b, _ := json.Marshal(a)
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
		return nil
	}
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/grants" {
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), `"move"`) {
				r.Header.Set("X-Want", "move")
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
		}
		rp.ServeHTTP(w, r)
	}))
	opt := dav.Options{Client: w.s.Client(t), Catalogs: []string{"cat"}, Gateway: true, TreeService: front.URL, Logf: t.Logf}
	g := &env{t: t, ctx: w.ctx, s: w.s, c: w.ops, dav: newTestServer(t, must(dav.New(opt)))}
	bob := w.user(t, "user:bob", "match-desk")
	before, _ := g.load("cat", "matches.derby")
	r := g.expect(g.doAs(bob, "MOVE", "/cat/Season%202026/derby.json", "", "Destination", "/cat/Season%202026/d2.json"), 409, "bob's rename, the catalog's decision stale")
	if !strings.Contains(r.body, "test of its parents failed") || !strings.Contains(r.body, "reload") {
		t.Fatalf("409 %q", r.body)
	}
	if after, doc := g.load("cat", "matches.derby"); after.ID != before.ID {
		t.Fatalf("the placement changed: %v", doc)
	}
}
