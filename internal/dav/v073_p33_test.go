package dav_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
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
