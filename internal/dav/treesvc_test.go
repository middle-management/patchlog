package dav_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// rtFunc adapts a function to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// treeRun is a tree service (§B.5) following a catalog of a test core, run
// in-process as patchlog tree runs it. While paused, it follows nothing
// (its log reads wait), so it lags the core.
type treeRun struct {
	t      *testing.T
	core   *client.Client
	s      *tree.Service
	http   *httptest.Server
	paused atomic.Bool
	hits   atomic.Int64 // listing requests
}

// scopeRoles is a RoleView for tests (§B.11.5): a reader's subject set is
// the names its grant's block rules fix /resource to (a test against a
// schema of only an enum), and it sees the catalog nodes and the items of
// those names. A tree service without §B.11 serves only g/all (§B.11.5),
// so the tree services of these tests filter with it, as the catalog
// service filters by roles, to list to grants limited to some resources.
type scopeRoles struct{}

func (scopeRoles) Resolve(_ context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	set := scopeSet{}
	for _, r := range v.BlockRules {
		m, _ := r.(map[string]any)
		sch, _ := m["schema"].(map[string]any)
		enum, _ := sch["enum"].([]any)
		for _, e := range enum {
			if s, ok := e.(string); ok && m["op"] == "test" && m["path"] == "/resource" {
				set[s] = true
			}
		}
	}
	var subjects []string
	for n := range set {
		subjects = append(subjects, "scope:"+n)
	}
	slices.Sort(subjects)
	return subjects, set, nil
}

func (scopeRoles) ForSubjects(subjects []string) tree.Visibility {
	set := scopeSet{}
	for _, s := range subjects {
		set[strings.TrimPrefix(s, "scope:")] = true
	}
	return set
}

// scopeSet is the visibility of a scopeRoles subject set.
type scopeSet map[string]bool

func (s scopeSet) Node(_ *tree.Graph, n *tree.Node) bool { return s[n.Name] }
func (s scopeSet) Item(_ *tree.Graph, n *tree.Node) bool { return s[n.ItemName] }

func startTree(t *testing.T, cs *clienttest.Server, cat string, opts ...client.Option) *treeRun {
	t.Helper()
	return startTreeWith(t, cs, cat, scopeRoles{}, opts...)
}

// startTreeWith is startTree with rv the tree service's RoleView: nil for
// a tree service without §B.11.
func startTreeWith(t *testing.T, cs *clienttest.Server, cat string, rv tree.RoleView, opts ...client.Option) *treeRun {
	t.Helper()
	return startTreeWait(t, cs, cat, rv, 200*time.Millisecond, opts...)
}

// startTreeWait is startTreeWith with minWait the tree service's MinWait:
// how long a listing with ?min= waits for the service to reach the
// entries before it answers 503.
func startTreeWait(t *testing.T, cs *clienttest.Server, cat string, rv tree.RoleView, minWait time.Duration, opts ...client.Option) *treeRun {
	t.Helper()
	r := &treeRun{t: t}
	base := http.DefaultTransport.(*http.Transport).Clone()
	hold := func(ctx context.Context) error {
		for r.paused.Load() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		return nil
	}
	rt := rtFunc(func(req *http.Request) (*http.Response, error) {
		following := strings.Contains(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events")
		if following {
			if err := hold(req.Context()); err != nil {
				return nil, err
			}
		}
		res, err := base.RoundTrip(req)
		if following && err == nil {
			// A long poll that returns while paused is held too.
			if err := hold(req.Context()); err != nil {
				res.Body.Close()
				return nil, err
			}
		}
		return res, err
	})
	r.core = cs.Client(t, append([]client.Option{client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt})}, opts...)...)
	svc, err := tree.Open(context.Background(), tree.Options{Client: r.core, Catalog: cat, DB: filepath.Join(t.TempDir(), "tree.db"),
		MinWait: minWait, RepurgeInterval: -1, Logf: t.Logf, RoleView: rv,
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}})
	if err != nil {
		t.Fatal(err)
	}
	r.s = svc
	r.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		svc.Handler().ServeHTTP(w, req)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	t.Cleanup(func() {
		r.paused.Store(false)
		cancel()
		<-done
		r.http.Close()
		svc.Close()
	})
	return r
}

// caughtUp waits until the service reached the core's head of every ns.
func (r *treeRun) caughtUp(nss ...string) {
	r.t.Helper()
	for _, ns := range nss {
		deadline := time.Now().Add(30 * time.Second)
		for {
			h, err := r.core.NSHead(context.Background(), ns)
			if err == nil && r.s.Checkpoint(ns) == h.ID {
				break
			}
			if time.Now().After(deadline) {
				r.t.Fatalf("the tree service didn't catch up with %s", ns)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// coreLog records the requests the core gets from the WebDAV server
// whose client says X-Author davtree.
type coreLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *coreLog) wrap(c *clienttest.Options, _ *dav.Options) {
	c.Wrap = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Author") == "davtree" {
				l.mu.Lock()
				l.paths = append(l.paths, r.Method+" "+r.URL.Path)
				l.mu.Unlock()
			}
			next.ServeHTTP(w, r)
		})
	}
}

// take returns the requests recorded since the last take.
func (l *coreLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.paths
	l.paths = nil
	return out
}

// noneOf fails if any recorded request's path holds one of parts.
func noneOf(t *testing.T, what string, paths []string, parts ...string) {
	t.Helper()
	for _, p := range paths {
		for _, part := range parts {
			if strings.Contains(p, part) {
				t.Fatalf("%s: the core was asked %s: %q", what, p, paths)
			}
		}
	}
}

// treeDav is another WebDAV server over e's core, as e's was set up, but
// listing e's trees through tree service url, its client saying X-Author
// davtree (coreLog), and as f changes it.
func treeDav(e *env, url string, f ...func(*dav.Options, *dav.Server)) *env {
	e.t.Helper()
	opt := e.opt
	opt.Client = e.s.Client(e.t, client.WithAuthor("davtree"))
	opt.TreeService = url
	for _, g := range f {
		g(&opt, nil)
	}
	srv, err := dav.New(opt)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, g := range f {
		g(&opt, srv)
	}
	o := *e
	o.opt = opt
	o.dav = newTestServer(e.t, srv)
	return &o
}

// sameListing fails unless two PROPFIND listings, through the tree
// service and from the node documents, are equal, but for the time of
// folders, a server's start.
func sameListing(t *testing.T, what string, got, want map[string]entry) {
	t.Helper()
	for _, m := range []map[string]entry{got, want} {
		for k, en := range m {
			if en.dir {
				en.modified = ""
				m[k] = en
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s through the tree service:\n%v\nfrom the node documents:\n%v", what, got, want)
	}
}

// options sets dav options before the server is made.
func options(f func(*dav.Options)) func(*dav.Options, *dav.Server) {
	return func(o *dav.Options, s *dav.Server) {
		if s == nil {
			f(o)
		}
	}
}

// §H.3: through a tree service, a folder lists what the node documents
// list, by the same names (escaped titles, duplicates numbered in order of
// creation, a placement without a title by its item's name), with the
// same sizes, types, times and ETags, and paths resolve to what was
// listed. It lists in one request: no item's head or document is read
// from the core, nor the catalog's /heads.
func TestTreeServiceListing(t *testing.T) {
	t.Parallel()
	var log coreLog
	e := treeEnv(t, log.wrap)
	for name, title := range map[string]string{"odd": "a/b\\c", "dots": "..", "nfd": "Résumé", "spaced": "Match Reports 2026", "kanji": "日本語"} {
		e.create("cat", name, map[string]any{"title": title, "parents": parents("cat", "root")})
	}
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "season")})
	mk := func(item, title, folder string) {
		e.create("matches", item, map[string]any{"item": item})
		e.create("cat", "matches."+item, map[string]any{"title": title, "parents": parents("cat", folder)})
		e.s.Clock.Advance(time.Second)
	}
	mk("zz", "notes.md", "season") // the first, though its name sorts last
	mk("real", "notes (2).md", "season")
	mk("aa", "notes.md", "season")
	mk("mm", "Notes.md", "season")
	mk("slash", "a/b.json", "empty")
	mk("pct", "a%2Fb.json", "empty")
	mk("deep", "deep.json", "sub")
	e.create("matches", "cup", map[string]any{"title": "Cup"})
	e.create("cat", "matches.cup", map[string]any{"parents": parents("cat", "season")})
	data := []byte("\x89PNG not really")
	bid := must(e.c.UploadBlob(e.ctx, "matches", "logo", "image/png", "", data))
	e.create("matches", "logo", map[string]any{"$blob": bid, "type": "image/png", "size": len(data)})
	e.create("cat", "matches.logo", map[string]any{"title": "logo.png", "parents": parents("cat", "season")})
	e.create("matches", "gone", map[string]any{"title": "Gone"})
	e.create("cat", "matches.gone", map[string]any{"title": "gone.json", "parents": parents("cat", "season")})
	must(e.c.Delete(e.ctx, "matches", "gone", must(e.c.Head(e.ctx, "matches", "gone")).ID))

	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	ts := treeDav(e, tr.http.URL)
	for _, dir := range []string{"/cat/", "/cat/Season/", "/cat/Empty/", "/cat/Season/Sub/"} {
		sameListing(t, dir, ts.propfind(dir), e.propfind(dir))
	}
	sameStrings(t, "Season", names(ts.propfind("/cat/Season/"), "/cat/Season/"),
		[]string{"Notes (4).md", "Sub/", "cup", "derby.json", "logo.png", "notes (2).md", "notes (3).md", "notes.md"})
	sameStrings(t, "Empty", names(ts.propfind("/cat/Empty/"), "/cat/Empty/"), []string{"a%2Fb (2).json", "a%2Fb.json"})
	for p, item := range map[string]string{"/cat/Season/notes.md": "zz", "/cat/Season/notes%20(2).md": "real", "/cat/Season/notes%20(3).md": "aa",
		"/cat/Season/Notes%20(4).md": "mm", "/cat/season/sub/DEEP.json": "deep", "/cat/Empty/a%252Fb.json": "pct", "/cat/Empty/a%252Fb%20(2).json": "slash"} {
		if b := ts.expect(ts.do("GET", p, ""), 200, "GET "+p).body; b != rendered(map[string]any{"item": item}) {
			t.Errorf("%s reads %q, want item %s", p, b, item)
		}
	}
	if b := ts.expect(ts.do("GET", "/cat/Season/logo.png", ""), 200, "GET logo.png").body; b != string(data) {
		t.Errorf("logo.png reads %q", b)
	}
	ts.expect(ts.do("PROPFIND", "/cat/Season/gone.json", "", "Depth", "0"), 404, "a dangling placement")

	// A server of its own, which read nothing yet: its listing reads no
	// item from the core, nor the catalog's nodes.
	fresh := treeDav(e, tr.http.URL)
	log.take()
	hits := tr.hits.Load()
	fresh.propfind("/cat/Season/")
	noneOf(t, "a listing through the tree service", log.take(), "/r/matches/", "/heads")
	if tr.hits.Load() == hits {
		t.Fatal("the tree service wasn't asked")
	}
}

// File metadata (§H.3): a file's size, type and time come from the tree
// service's file member, its ETag from the entry's head.
func TestTreeServiceFileMetadata(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	data := []byte("<svg/>")
	bid := must(e.c.UploadBlob(e.ctx, "matches", "pic", "image/svg+xml", "", data))
	e.create("matches", "pic", map[string]any{"$blob": bid, "type": "image/svg+xml", "size": len(data)})
	e.create("cat", "matches.pic", map[string]any{"title": "pic.svg", "parents": parents("cat", "season")})
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")

	// What the tree service says, changed: the files' metadata is what is
	// shown.
	px := rewriting(t, tr.http.URL, func(es []map[string]any) []map[string]any {
		for _, en := range es {
			if f, _ := en["file"].(map[string]any); f != nil && en["name"] == "matches.pic" {
				f["size"], f["type"], f["modified"] = 4242, "image/x-test", "2026-01-02T03:04:05Z"
			}
		}
		return es
	})
	ts := treeDav(e, px)
	l := ts.propfind("/cat/Season/")
	pic := l["/cat/Season/pic.svg"]
	if pic.size != "4242" || pic.ctype != "image/x-test" || pic.modified != "Fri, 02 Jan 2026 03:04:05 GMT" ||
		pic.etag != `"`+must(e.c.Head(e.ctx, "matches", "pic")).ID+`"` {
		t.Fatalf("pic.svg %+v", pic)
	}
	derby := l["/cat/Season/derby.json"]
	h := must(e.c.Head(e.ctx, "matches", "derby"))
	created := ""
	for _, it := range must(e.c.Heads(e.ctx, "matches", must(e.c.NSHead(e.ctx, "matches")).ID)) {
		if it.Resource == "derby" {
			created = it.Created
		}
	}
	if derby.size != strconv.Itoa(len(rendered(map[string]any{"title": "Derby"}))) || derby.ctype != "application/json" ||
		derby.etag != `"`+h.ID+`"` || derby.modified != must(time.Parse(time.RFC3339Nano, created)).UTC().Format(http.TimeFormat) {
		t.Fatalf("derby.json %+v (created %s)", derby, created)
	}
	// The file itself is the item's, read from the core.
	if b := ts.expect(ts.do("GET", "/cat/Season/pic.svg", ""), 200, "GET").body; b != string(data) {
		t.Fatalf("pic.svg reads %q", b)
	}
}

// rewriting is a proxy in front of tree service url whose children
// listings f changes.
func rewriting(t *testing.T, target string, f func([]map[string]any) []map[string]any) string {
	t.Helper()
	rp := proxyTo(target)
	rp.ModifyResponse = func(res *http.Response) error {
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
			return nil
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if list, ok := m["children"].([]any); ok {
				es := make([]map[string]any, 0, len(list))
				for _, x := range list {
					es = append(es, x.(map[string]any))
				}
				es = f(es)
				out := make([]any, len(es))
				for i, x := range es {
					out[i] = x
				}
				m["children"] = out
				b, _ = json.Marshal(m)
			}
		}
		res.Body = io.NopCloser(bytes.NewReader(b))
		res.ContentLength = int64(len(b))
		res.Header.Set("Content-Length", strconv.Itoa(len(b)))
		return nil
	}
	return newTestServer(t, rp).URL
}

// A placement whose file is sealed ({"sealed": JWE}, an item of a sealed
// namespace) isn't offered (§H.7), nor one without file in a sealed or
// end-to-end namespace; one without file elsewhere (a head the tree
// service hasn't read yet) is shown, read from the core, as the node
// documents show it. A listing whose titles are sealed is a sealed
// catalog's, not offered (§H.3).
func TestTreeServiceSealedEntries(t *testing.T) {
	t.Parallel()
	ks := must(keystore.New(keystore.Generate()))
	var log coreLog
	e := newEnv(t, []string{"matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}},
		func(c *clienttest.Options, d *dav.Options) { c.KeyStore = ks; log.wrap(c, d) })
	must(e.c.CreateNamespace(e.ctx, "e2e", map[string]any{"read": "public", "encryption": map[string]any{"level": "e2e"}}))
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("matches", "cup", map[string]any{"title": "Cup"})
	e.create("matches", "final", map[string]any{"title": "Final"})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	for _, item := range []string{"derby", "cup", "final"} {
		e.create("cat", "matches."+item, map[string]any{"title": item + ".json", "parents": parents("cat", "root")})
	}
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	head := must(e.c.Head(e.ctx, "matches", "final")).ID
	var sealTitles atomic.Bool
	px := rewriting(t, tr.http.URL, func(es []map[string]any) []map[string]any {
		for _, en := range es {
			switch en["name"] {
			case "matches.cup":
				en["file"] = map[string]any{"sealed": "eyJhbGciOi.x.y.z.w"}
			case "matches.final":
				delete(en, "file")
			}
			if sealTitles.Load() && en["title"] != nil {
				en["sealed"] = "eyJhbGciOi.x.y.z.w"
				delete(en, "title")
			}
		}
		// An item of an end-to-end namespace, which has no file.
		return append(es, map[string]any{"name": "e2e.secret", "kind": "item", "item": "/r/e2e/secret", "head": head, "title": "secret.json"})
	})
	ts := treeDav(e, px)
	sameStrings(t, "root", names(ts.propfind("/cat/"), "/cat/"), []string{"derby.json", "final.json"})
	noneOf(t, "the e2e item", log.take(), "/r/e2e/")
	if en := ts.propfind("/cat/")["/cat/final.json"]; en.size != strconv.Itoa(len(rendered(map[string]any{"title": "Final"}))) {
		t.Fatalf("final.json, without file, %+v", en)
	}
	ts.expect(ts.do("GET", "/cat/cup.json", ""), 404, "GET of a sealed one")

	sealTitles.Store(true)
	fresh := treeDav(e, px)
	if r := fresh.do("PROPFIND", "/cat/", "", "Depth", "1"); r.status != 404 || !strings.Contains(r.body, "doesn't offer it (§H.7)") {
		t.Fatalf("a listing with sealed titles: %d %s", r.status, r.body)
	}
}

// Read-your-writes (§B.5 "Fresh listings after a write"): after a write
// through the server (a new file, a folder, a rename and a move, a
// delete, an edit), the writer's next listing shows it, the tree service
// waiting for the entries the write produced (?min=), so it is still
// listed by the tree service. While the tree service lags further than
// TreeWait, the writer's folder is listed from the node documents, as the
// tree service lists it (a placement of a namespace the catalog doesn't
// trust is dangling there, §B.5, and is left out with or without a tree
// service, §H.2 "Untrusted namespaces"); other users' listings don't wait.
//
// The gateway waits ownWait for the tree service to reach a write, and the
// tree service itself longer (a ?min= answers 503 only after its MinWait):
// on a loaded machine following the write can take a second or more, and
// a listing that gave up sooner would come from the node documents.
// ownWait stays under the gateway's slowFor (5s), which a slow tree
// service's catalog is marked for from when its listing began: so the
// lagging listing below waits once, not once per folder.
func TestTreeServiceOwnWrites(t *testing.T) {
	t.Parallel()
	const ownWait = 2 * time.Second
	var log coreLog
	e := treeEnv(t, log.wrap)
	must(e.c.CreateNamespace(e.ctx, "secret", map[string]any{"read": "public"}))
	e.create("secret", "plans", map[string]any{"launch": "monday"})
	e.create("cat", "secret.plans", map[string]any{"title": "plans.json", "parents": parents("cat", "season")})
	sameStrings(t, "Season without a tree service", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	tr := startTreeWait(t, e.s, "cat", scopeRoles{}, 2*ownWait)
	tr.caughtUp("cat", "matches")
	ts := treeDav(e, tr.http.URL, options(func(o *dav.Options) { o.TreeWait = ownWait }))
	sameStrings(t, "Season", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})

	viaTree := func(what string) {
		t.Helper()
		noneOf(t, what, log.take(), "/heads")
	}
	ts.expect(ts.do("PUT", "/cat/Season/new.txt", "hello"), 201, "PUT of a new file")
	log.take()
	sameStrings(t, "Season after a PUT", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json", "new.txt"})
	viaTree("the listing after a PUT")
	ts.expect(ts.do("MKCOL", "/cat/Season/Box", ""), 201, "MKCOL")
	log.take()
	sameStrings(t, "Season after a MKCOL", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"Box/", "derby.json", "new.txt"})
	viaTree("the listing after a MKCOL")
	ts.expect(ts.do("MOVE", "/cat/Season/new.txt", "", "Destination", "/cat/Season/Box/renamed.txt"), 201, "MOVE")
	log.take()
	sameStrings(t, "Season after a MOVE", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"Box/", "derby.json"})
	sameStrings(t, "Box after a MOVE", names(ts.propfind("/cat/Season/Box/"), "/cat/Season/Box/"), []string{"renamed.txt"})
	viaTree("the listings after a MOVE")
	ts.expect(ts.do("DELETE", "/cat/Season/Box/renamed.txt", ""), 204, "DELETE")
	log.take()
	sameStrings(t, "Box after a DELETE", names(ts.propfind("/cat/Season/Box/"), "/cat/Season/Box/"), nil)
	viaTree("the listing after a DELETE")
	ts.expect(ts.do("DELETE", "/cat/Season/Box", ""), 204, "DELETE of the folder emptied")
	b := ts.expect(ts.do("GET", "/cat/Season/derby.json", ""), 200, "GET").body
	edited := edit(t, b, "Derby", "The derby, at last")
	ts.expect(ts.do("PUT", "/cat/Season/derby.json", edited), 201, "PUT of an edit")
	log.take()
	en := ts.propfind("/cat/Season/")["/cat/Season/derby.json"]
	if en.etag != `"`+must(e.c.Head(e.ctx, "matches", "derby")).ID+`"` || en.size != strconv.Itoa(len(edited)) {
		t.Fatalf("derby.json after an edit %+v", en)
	}
	viaTree("the listing after an edit")

	// The tree service stops following: the writer's listing waits up to
	// TreeWait, then reads the node documents.
	tr.paused.Store(true)
	ts.expect(ts.do("PUT", "/cat/Season/late.txt", "late"), 201, "PUT while the tree service lags")
	log.take()
	start := time.Now()
	sameStrings(t, "Season while the tree service lags", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json", "late.txt"})
	if d := time.Since(start); d > ownWait+2*time.Second {
		t.Fatalf("the listing took %v, waiting up to %v", d, ownWait)
	}
	if paths := log.take(); !strings.Contains(strings.Join(paths, " "), "/ns/cat/rev/") {
		t.Fatalf("not listed from the node documents: %q", paths)
	}
	// Another user's listing doesn't wait: what the tree service has.
	other := treeDav(e, tr.http.URL, options(func(o *dav.Options) { o.TreeWait = 3 * time.Second }))
	start = time.Now()
	sameStrings(t, "Season, another user's", names(other.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	if d := time.Since(start); d > time.Second {
		t.Fatalf("another user's listing took %v", d)
	}
	tr.paused.Store(false)
	tr.caughtUp("cat", "matches")
	sameStrings(t, "Season once caught up", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json", "late.txt"})
}

// authTree is an authenticating core whose catalog cat, a file tree of
// matches, has folders Season (derby.json, cup.json) and Hidden, and a tree
// service following it with a grant of its own; grants of key k name both
// namespaces.
type authTree struct {
	ctx  context.Context
	s    *clienttest.Server
	k    clienttest.Key
	both []string
	w    *client.Client // a writer's, straight to the core
	tr   *treeRun
}

func newAuthTree(t *testing.T) *authTree {
	t.Helper()
	a := &authTree{ctx: context.Background(), s: clienttest.New(t, clienttest.Options{Auth: true, RealClock: true}), k: clienttest.NewKey("k"), both: []string{"cat", "matches"}}
	for ns, doc := range map[string]map[string]any{
		"matches": {"read": "grant", "keys": []any{a.k.Entry("*")}},
		"cat":     {"read": "grant", "keys": []any{a.k.Entry("*")}, "catalog": treeCatalog("matches")},
	} {
		must(a.s.Client(t, client.WithBearer(a.s.OperatorGrant(t, ns))).CreateNamespace(a.ctx, ns, doc))
	}
	a.w = a.s.Client(t, client.WithBearer(a.k.Grant(t, a.s.Now(), "user:w", a.both, []string{"read", "create", "append", "delete"})))
	for _, d := range []struct {
		ns, name string
		doc      map[string]any
	}{
		{"matches", "derby", map[string]any{"title": "Derby"}},
		{"matches", "cup", map[string]any{"title": "Cup"}},
		{"cat", "root", map[string]any{"title": "Root", "parents": []any{}}},
		{"cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")}},
		{"cat", "hidden", map[string]any{"title": "Hidden", "parents": parents("cat", "root")}},
		{"cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")}},
		{"cat", "matches.cup", map[string]any{"title": "cup.json", "parents": parents("cat", "season")}},
	} {
		must(a.w.CreateDoc(a.ctx, d.ns, d.name, d.doc))
	}
	a.tr = startTree(t, a.s, "cat", client.WithBearer(a.k.Grant(t, a.s.Now(), "svc:tree", a.both, []string{"read"})))
	a.tr.caughtUp("cat", "matches")
	return a
}

// gateway is a gateway serving cat, listing it through treeURL ("" for
// none), as f changes its options.
func (a *authTree) gateway(t *testing.T, treeURL string, f ...func(*dav.Options)) *env {
	t.Helper()
	opt := dav.Options{Client: a.s.Client(t), Catalogs: []string{"cat"}, Gateway: true, TreeService: treeURL, Logf: t.Logf}
	for _, g := range f {
		g(&opt)
	}
	return &env{t: t, ctx: a.ctx, s: a.s, c: a.w, dav: newTestServer(t, must(dav.New(opt)))}
}

// limitedTo is a grant of sub limited to the resources named (§C.5).
func (a *authTree) limitedTo(t *testing.T, sub string, resources ...any) string {
	return a.k.Grant(t, a.s.Now(), sub, a.both, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": resources}}}})
}

// §H.7: a grant limited to some resources reads neither the catalog's
// // namespace document nor its /heads (they take unrestricted read, §2.1,
// §7.4), so without a tree service it can't list a tree; through one it
// lists what the tree service shows it (§B.11.5): the folders and the
// files it may read, and opens those.
func TestTreeServiceLimitedGrant(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	g := a.gateway(t, a.tr.http.URL)
	admin := a.k.Grant(t, a.s.Now(), "user:admin", a.both, []string{"read"})
	limited := a.limitedTo(t, "user:li", "root", "season", "matches.derby", "derby")

	sameStrings(t, "the admin's top level", names(g.propfindAs(admin, "/cat/"), "/cat/"), []string{"Hidden/", "Season/"})
	sameStrings(t, "the limited grant's top level", names(g.propfindAs(limited, "/cat/"), "/cat/"), []string{"Season/"})
	sameStrings(t, "the limited grant's Season", names(g.propfindAs(limited, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	if b := g.expect(g.doAs(limited, "GET", "/cat/Season/derby.json", ""), 200, "the limited grant's GET").body; b != rendered(map[string]any{"title": "Derby"}) {
		t.Fatalf("derby.json reads %q", b)
	}
	g.expect(g.doAs(limited, "GET", "/cat/Season/cup.json", ""), 404, "the limited grant's GET of a file it doesn't read")
	g.expect(g.doAs(limited, "PROPFIND", "/cat/Hidden/", "", "Depth", "1"), 404, "the limited grant's PROPFIND of a folder it doesn't read")

	// Without a tree service, the node documents: the limited grant can't
	// list the tree.
	plain := a.gateway(t, "")
	plain.propfindAs(admin, "/cat/")
	if r := plain.doAs(limited, "PROPFIND", "/cat/", "", "Depth", "1"); r.status < 400 {
		t.Fatalf("the limited grant listed the tree from the node documents: %d %s", r.status, r.body)
	}
	// Nor through a tree service without §B.11, which serves only g/all
	// (§B.11.5): it refuses the limited grant, 403, which the gateway
	// answers.
	bare := startTreeWith(t, a.s, "cat", nil, client.WithBearer(a.k.Grant(t, a.s.Now(), "svc:tree", a.both, []string{"read"})))
	bare.caughtUp("cat", "matches")
	bg := a.gateway(t, bare.http.URL)
	sameStrings(t, "the admin's top level through a tree service without §B.11", names(bg.propfindAs(admin, "/cat/"), "/cat/"), []string{"Hidden/", "Season/"})
	bg.expect(bg.doAs(limited, "PROPFIND", "/cat/", "", "Depth", "1"), 403, "the limited grant through a tree service without §B.11")
}

// §H.7 through a tree service: what the tree service listed to one token
// is kept for that token only, so another token of the same user, which
// may read less, is never shown it; the writes a user made through one
// token are waited for (?min=) by their listings through another, while
// another user's listings don't wait.
func TestTreeServiceUserTokens(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	g := a.gateway(t, a.tr.http.URL, func(o *dav.Options) { o.CatalogTTL, o.TreeWait = time.Minute, 500*time.Millisecond })
	now := a.s.Now()
	ann := a.k.Grant(t, now, "user:ann", a.both, []string{"read", "create", "append", "delete"})
	again := a.k.Grant(t, now.Add(time.Second), "user:ann", a.both, []string{"read"})
	narrow := a.limitedTo(t, "user:ann", "root", "season", "matches.derby", "derby")
	bob := a.k.Grant(t, now, "user:bob", a.both, []string{"read"})

	sameStrings(t, "ann's top level", names(g.propfindAs(ann, "/cat/"), "/cat/"), []string{"Hidden/", "Season/"})
	sameStrings(t, "ann's Season", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
	sameStrings(t, "ann's top level through her limited token", names(g.propfindAs(narrow, "/cat/"), "/cat/"), []string{"Season/"})
	sameStrings(t, "ann's Season through her limited token", names(g.propfindAs(narrow, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	g.expect(g.doAs(narrow, "PROPFIND", "/cat/Hidden/", "", "Depth", "1"), 404, "Hidden through ann's limited token")

	// The tree service stops following. Ann's write through one token is
	// waited for by her listing through another, up to TreeWait, which
	// then reads the node documents; bob's listing doesn't wait.
	a.tr.paused.Store(true)
	g.expect(g.doAs(ann, "PUT", "/cat/Season/new.txt", "hello"), 201, "ann's PUT")
	sameStrings(t, "Season through ann's other token", names(g.propfindAs(again, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json", "new.txt"})
	sameStrings(t, "bob's Season", names(g.propfindAs(bob, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
	a.tr.paused.Store(false)
	a.tr.caughtUp("cat", "matches")
	sameStrings(t, "Season through ann's first token, caught up", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json", "new.txt"})
}

// The tree service down, or failing, is a 502 or a 503 with Retry-After,
// never an empty folder; a folder whose path needs a listing can't be
// opened either.
func TestTreeServiceDown(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	var failing atomic.Bool
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.Header().Set("Retry-After", "7")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"behind","message":"the tree service has not reached the catalog yet"}`)
			return
		}
		proxyTo(tr.http.URL).ServeHTTP(w, r)
	}))
	ts := treeDav(e, front.URL, options(func(o *dav.Options) { o.CatalogTTL = time.Nanosecond }))
	sameStrings(t, "Season", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})

	failing.Store(true)
	r := ts.expect(ts.do("PROPFIND", "/cat/Season/", "", "Depth", "1"), 503, "PROPFIND while the tree service fails")
	if r.header.Get("Retry-After") != "7" {
		t.Fatalf("503 without the tree service's Retry-After: %v", r.header)
	}
	failing.Store(false)

	down := treeDav(e, "http://127.0.0.1:1")
	for _, p := range []string{"/cat/", "/cat/Season/"} {
		r := down.expect(down.do("PROPFIND", p, "", "Depth", "1"), 502, "PROPFIND of "+p+" with the tree service down")
		if !strings.Contains(r.body, "tree service can't be reached") {
			t.Fatalf("502 %q", r.body)
		}
	}
	down.expect(down.do("GET", "/cat/Season/derby.json", ""), 502, "GET with the tree service down")
}

// A tree service's 401 refuses the server's own grant in local mode
// (-bearer): a 502 naming the tree service, not the core; in a gateway it
// refuses the user's grant, a 401 with the challenge, as the core's is.
func TestTreeServiceRefusedGrant(t *testing.T) {
	t.Parallel()
	refusing := func(target string) string {
		front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/children") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"code":"unauthorized","message":"no key verifies the grant"}`)
				return
			}
			proxyTo(target).ServeHTTP(w, r)
		}))
		return front.URL
	}
	e := treeEnv(t)
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	local := treeDav(e, refusing(tr.http.URL))
	r := local.expect(local.do("PROPFIND", "/cat/Season/", "", "Depth", "1"), 502, "local mode, the tree service refusing -bearer")
	if !strings.Contains(r.body, "tree service refused this server's grant (-bearer)") || strings.Contains(r.body, "the core refused") {
		t.Fatalf("502 %q", r.body)
	}

	a := newAuthTree(t)
	g := a.gateway(t, refusing(a.tr.http.URL))
	r = g.expect(g.doAs(a.k.Grant(t, a.s.Now(), "user:ann", a.both, []string{"read"}), "PROPFIND", "/cat/", "", "Depth", "1"), 401, "a gateway, the tree service refusing the user's grant")
	if r.header.Get("WWW-Authenticate") == "" || !strings.Contains(r.body, "tree service refused the listing") {
		t.Fatalf("401 %v %q", r.header, r.body)
	}
}

// A folder lists over every page of the tree service's listing (§B.5
// "paginated"), within a bound: a folder larger is refused, never listed
// cut short.
func TestTreeServicePages(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	add := func(n int, folder string) {
		var items, places []client.BatchItem
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("%s%02d", folder, i)
			items = append(items, client.BatchItem{Resource: name, IfNoneMatch: true,
				Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"n": i}))}})
			places = append(places, client.BatchItem{Resource: "matches." + name, IfNoneMatch: true,
				Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": name + ".json", "parents": parents("cat", folder)}))}})
		}
		must(e.c.Batch(e.ctx, "matches", client.BatchRequest{Items: items}, false))
		must(e.c.Batch(e.ctx, "cat", client.BatchRequest{Items: places}, false))
	}
	add(5, "season")
	e.create("cat", "big", map[string]any{"title": "Big", "parents": parents("cat", "root")})
	add(21, "big")
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	ts := treeDav(e, tr.http.URL, func(_ *dav.Options, s *dav.Server) {
		if s != nil {
			dav.SetTreePage(s, 2)
		}
	})
	hits := tr.hits.Load()
	got := ts.propfind("/cat/Season/")
	if sameListing(t, "Season over pages of 2", got, e.propfind("/cat/Season/")); len(got) != 7 {
		t.Fatalf("Season over pages of 2: %v", got)
	}
	if n := tr.hits.Load() - hits; n < 3 {
		t.Fatalf("%d requests to the tree service for 6 entries in pages of 2", n)
	}
	r := ts.expect(ts.do("PROPFIND", "/cat/Big/", "", "Depth", "1"), 403, "PROPFIND of a folder over the bound")
	if !strings.Contains(r.body, "more than 20") {
		t.Fatalf("403 %q", r.body)
	}
}

// testClock is a dav.Options.Now a test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Through a tree service, which lags the core and doesn't wait for other
// users' writes through this gateway (§B.5), a write checks what the
// listing named against the node documents, so it does what it does
// without a tree service: another user's DELETE or MOVE of a file's old
// name, moments after its owner renamed it or moved it to another folder,
// touches nothing (the name is no file's now); a PUT of the name a file
// was just given is that file's, never a second file by its name (§H.2
// "Siblings"); a MKCOL of a folder just made finds it there; and a DELETE
// of a folder someone just put a file in is a 409 naming it (§H.5), never
// the folder deleted over the file, which it would orphan.
func TestTreeServiceStaleNameWrites(t *testing.T) {
	t.Parallel()
	for _, viaTree := range []bool{false, true} {
		a := newAuthTree(t)
		url := ""
		if viaTree {
			url = a.tr.http.URL
		}
		g := a.gateway(t, url, func(o *dav.Options) { o.TreeWait = 300 * time.Millisecond })
		now := a.s.Now()
		writer := []string{"read", "create", "append", "delete"}
		ann := a.k.Grant(t, now, "user:ann", a.both, writer)
		bob := a.k.Grant(t, now, "user:bob", a.both, writer)
		w := fmt.Sprintf("tree service %v: ", viaTree)
		g.expect(g.doAs(ann, "MKCOL", "/cat/Box", ""), 201, w+"ann's MKCOL of Box")
		a.tr.caughtUp("cat", "matches")
		sameStrings(t, w+"bob's top level", names(g.propfindAs(bob, "/cat/"), "/cat/"), []string{"Box/", "Hidden/", "Season/"})
		sameStrings(t, w+"bob's Season", names(g.propfindAs(bob, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
		sameStrings(t, w+"bob's Box", names(g.propfindAs(bob, "/cat/Box/"), "/cat/Box/"), nil)

		a.tr.paused.Store(true)
		g.expect(g.doAs(ann, "MOVE", "/cat/Season/cup.json", "", "Destination", "/cat/Season/final.json"), 201, w+"ann renames cup.json")
		g.expect(g.doAs(ann, "MOVE", "/cat/Season/derby.json", "", "Destination", "/cat/Hidden/derby.json"), 201, w+"ann moves derby.json into Hidden")
		g.expect(g.doAs(ann, "PUT", "/cat/Box/report.txt", "ann's report"), 201, w+"ann's PUT into Box")
		g.expect(g.doAs(ann, "MKCOL", "/cat/Season/Sub", ""), 201, w+"ann's MKCOL of Season/Sub")

		g.expect(g.doAs(bob, "DELETE", "/cat/Season/cup.json", ""), 404, w+"bob's DELETE of cup.json, renamed final.json")
		if r := g.doAs(bob, "MOVE", "/cat/Season/cup.json", "", "Destination", "/cat/Season/bobs.json"); r.status < 400 {
			t.Errorf("%sbob's MOVE of cup.json, renamed final.json: %d", w, r.status)
		}
		g.expect(g.doAs(bob, "DELETE", "/cat/Season/derby.json", ""), 404, w+"bob's DELETE of Season/derby.json, moved to Hidden")
		if r := g.expect(g.doAs(bob, "DELETE", "/cat/Box/", ""), 409, w+"bob's DELETE of Box, holding ann's report.txt"); !strings.Contains(r.body, `"report.txt"`) {
			t.Errorf("%s409 %q", w, r.body)
		}
		g.expect(g.doAs(bob, "MKCOL", "/cat/Season/Sub", ""), 405, w+"bob's MKCOL of Season/Sub, which ann made")
		g.expect(g.doAs(bob, "PUT", "/cat/Season/final.json", `{"title": "Bob's"}`), 201, w+"bob's PUT of final.json")
		a.tr.paused.Store(false)

		e := &env{t: t, ctx: a.ctx, c: a.w}
		if doc := e.nodeDoc("cat", "matches.cup"); doc["title"] != "final.json" {
			t.Errorf("%sthe file ann renamed final.json is titled %v", w, doc["title"])
		}
		if ps := e.parentsOf("matches.derby"); len(ps) != 1 || !strings.HasSuffix(ps[0].(map[string]any)["href"].(string), "/hidden") {
			t.Errorf("%sthe file ann moved to Hidden has parents %v", w, ps)
		}
		e.expectLive("matches", "derby", must(a.w.Head(a.ctx, "matches", "derby")), w+"ann's derby")
		a.tr.caughtUp("cat", "matches")
		sameStrings(t, w+"Season", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"Sub/", "final.json"})
		sameStrings(t, w+"Box", names(g.propfindAs(ann, "/cat/Box/"), "/cat/Box/"), []string{"report.txt"})
		if b := g.expect(g.doAs(ann, "GET", "/cat/Season/final.json", ""), 200, w+"GET final.json").body; !strings.Contains(b, "Bob's") {
			t.Errorf("%sfinal.json %q, without bob's save", w, b)
		}
	}
}

// A tree service that has reached the catalog but not a namespace it
// trusts (just started, rebuilt, or trusting it lately) answers 503
// behind, which the gateway passes on with Retry-After, never a folder
// shown empty (every placement there dangling), which a sync client
// mirrors as deleted files; nor is a folder deleted as empty meanwhile.
func TestTreeServiceBehindContent(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	var hold atomic.Bool
	hold.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := rtFunc(func(req *http.Request) (*http.Response, error) {
		for hold.Load() && strings.HasPrefix(req.URL.Path, "/ns/matches/") && (strings.Contains(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events")) {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		return base.RoundTrip(req)
	})
	core := e.s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	svc := must(tree.Open(context.Background(), tree.Options{Client: core, Catalog: "cat", DB: filepath.Join(t.TempDir(), "tree.db"),
		MinWait: 200 * time.Millisecond, RepurgeInterval: -1, Logf: t.Logf,
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}}))
	hs := httptest.NewServer(svc.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	t.Cleanup(func() { hold.Store(false); cancel(); <-done; hs.Close(); svc.Close() })
	h := must(e.c.NSHead(e.ctx, "cat"))
	for deadline := time.Now().Add(10 * time.Second); svc.Checkpoint("cat") != h.ID; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the tree service didn't reach cat")
		}
	}
	ts := treeDav(e, hs.URL)
	// The tree service's message is generic, naming what it waits for
	// only as ns, to readers of the whole catalog (§B.5).
	r := ts.expect(ts.do("PROPFIND", "/cat/Season/", "", "Depth", "1"), 503, "PROPFIND of Season before the tree service reached matches")
	if r.header.Get("Retry-After") == "" || !strings.Contains(r.body, "behind") {
		t.Fatalf("503 %v %q", r.header, r.body)
	}
	if r := ts.do("DELETE", "/cat/Season", ""); r.status < 400 {
		t.Fatalf("DELETE of Season, which holds derby.json: %d", r.status)
	}
	e.nodeDoc("cat", "season")
	hold.Store(false)
	for deadline := time.Now().Add(10 * time.Second); svc.Checkpoint("matches") == ""; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the tree service didn't reach matches")
		}
	}
	sameStrings(t, "Season once caught up", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
}

// A user's own writes through this server are waited for (?min=) by their
// listings until one that waited came back, however long the tree
// service lags (§B.5 "Fresh listings after a write"): their new file
// stays listed, and the name they renamed a file away from doesn't come
// back, the folder listed from the node documents meanwhile, so a sync
// client neither uploads the file again nor deletes the old name, which
// deleted the renamed file. Once a listing that waited came back, the
// next doesn't wait.
func TestTreeServiceOwnWritesUntilReached(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	var mins atomic.Int64
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("min") {
			mins.Add(1)
		}
		proxyTo(tr.http.URL).ServeHTTP(w, r)
	}))
	clk := &testClock{t: time.Now()}
	ts := treeDav(e, front.URL, options(func(o *dav.Options) { o.TreeWait = 300 * time.Millisecond; o.Now = clk.now }))
	ts.expect(ts.do("PUT", "/cat/Season/a.txt", "precious"), 201, "PUT a.txt")
	tr.caughtUp("cat", "matches")
	sameStrings(t, "Season", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"a.txt", "derby.json"})

	tr.paused.Store(true)
	ts.expect(ts.do("PUT", "/cat/Season/new.txt", "hello"), 201, "PUT new.txt")
	ts.expect(ts.do("MOVE", "/cat/Season/a.txt", "", "Destination", "/cat/Season/b.txt"), 201, "MOVE a.txt to b.txt")
	for _, d := range []time.Duration{0, 31 * time.Second, 9 * time.Minute} {
		clk.add(d)
		sameStrings(t, fmt.Sprintf("Season %v later, the tree service behind", d), names(ts.propfind("/cat/Season/"), "/cat/Season/"),
			[]string{"b.txt", "derby.json", "new.txt"})
	}
	ts.expect(ts.do("PUT", "/cat/Season/new.txt", "hello"), 201, "PUT of new.txt again, as a sync client would")
	ts.expect(ts.do("DELETE", "/cat/Season/a.txt", ""), 404, "DELETE of a.txt, renamed b.txt")
	tr.paused.Store(false)
	tr.caughtUp("cat", "matches")
	clk.add(time.Minute) // past the folder's time listed from the node documents
	sameStrings(t, "Season once caught up", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"b.txt", "derby.json", "new.txt"})
	n := mins.Load()
	tr.paused.Store(true)
	clk.add(time.Minute)
	sameStrings(t, "Season, the tree service behind again", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"b.txt", "derby.json", "new.txt"})
	if mins.Load() != n {
		t.Fatal("a listing waited for writes a listing that waited for them already showed")
	}
	if items := e.liveNames("matches"); len(items) != 3 {
		t.Fatalf("matches holds %q: one item per file", items)
	}
}

// A folder larger than a listing takes (maxTreePages pages) is refused
// as a listing (403), never listed cut short; its files are opened,
// written, moved and deleted by name all the same, found in the node
// documents with only the items of the names asked for read, as they are
// without a tree service.
func TestTreeServiceBigFolderPaths(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("cat", "big", map[string]any{"title": "Big", "parents": parents("cat", "root")})
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "big")})
	e.create("matches", "deep", map[string]any{"n": "deep"})
	e.create("cat", "matches.deep", map[string]any{"title": "deep.json", "parents": parents("cat", "sub")})
	var items, places []client.BatchItem
	for i := 0; i < 21; i++ {
		name := "big" + string(rune('a'+i))
		items = append(items, client.BatchItem{Resource: name, IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"n": i}))}})
		places = append(places, client.BatchItem{Resource: "matches." + name, IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": name + ".json", "parents": parents("cat", "big")}))}})
	}
	must(e.c.Batch(e.ctx, "matches", client.BatchRequest{Items: items}, false))
	must(e.c.Batch(e.ctx, "cat", client.BatchRequest{Items: places}, false))
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	ts := treeDav(e, tr.http.URL, func(_ *dav.Options, s *dav.Server) {
		if s != nil {
			dav.SetTreePage(s, 2)
		}
	})
	ts.expect(ts.do("PROPFIND", "/cat/Big/", "", "Depth", "1"), 403, "PROPFIND of a folder over the bound")
	if b := ts.expect(ts.do("GET", "/cat/Big/biga.json", ""), 200, "GET of a file in it").body; b != rendered(map[string]any{"n": 0}) {
		t.Fatalf("biga.json %q", b)
	}
	ts.expect(ts.do("PROPFIND", "/cat/Big/bigb.json", "", "Depth", "0"), 207, "PROPFIND of a file in it")
	if b := ts.expect(ts.do("GET", "/cat/Big/Sub/deep.json", ""), 200, "GET of a file in a folder in it").body; b != rendered(map[string]any{"n": "deep"}) {
		t.Fatalf("deep.json %q", b)
	}
	ts.expect(ts.do("PUT", "/cat/Big/biga.json", `{"n": 100}`), 201, "PUT of a file in it")
	if _, doc := e.load("matches", "biga"); doc.(map[string]any)["n"] != 100.0 {
		t.Fatalf("biga after the PUT: %v", doc)
	}
	ts.expect(ts.do("PUT", "/cat/Big/new.json", `{"n": "new"}`), 201, "PUT of a new file in it")
	if name, doc := e.titled("cat", "new.json"); !strings.HasSuffix(doc["parents"].([]any)[0].(map[string]any)["href"].(string), "/big") {
		t.Fatalf("new.json, %s, is in %v", name, doc["parents"])
	}
	ts.expect(ts.do("MOVE", "/cat/Big/bigb.json", "", "Destination", "/cat/Big/renamed.json"), 201, "MOVE of a file in it")
	if doc := e.nodeDoc("cat", "matches.bigb"); doc["title"] != "renamed.json" {
		t.Fatalf("bigb's title %v", doc["title"])
	}
	ts.expect(ts.do("DELETE", "/cat/Big/bigc.json", ""), 204, "DELETE of a file in it")
	e.expectTombstoned("cat", "matches.bigc", "bigc's placement")
}

// A file renamed by another program (not through this server), which
// neither the tree service's listing nor the catalog read the token keeps
// for CatalogTTL show yet: a DELETE of its old name finds its node changed
// since that read (If-Match, 409), and a MOVE finds it renamed in the
// node's document as the core has it now (404), so neither deletes,
// renames or moves it.
func TestTreeServiceRenamedElsewhere(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	e := &env{t: t, ctx: a.ctx, c: a.w}
	for _, c := range []struct {
		node, method, path string
		status             int
		says               string
	}{
		{"matches.derby", "DELETE", "/cat/Season/derby.json", 409, "changed by someone else"},
		{"matches.cup", "MOVE", "/cat/Season/cup.json", 404, "renamed or moved"},
	} {
		g := a.gateway(t, a.tr.http.URL, func(o *dav.Options) { o.TreeWait, o.CatalogTTL = 300*time.Millisecond, time.Minute })
		bob := a.k.Grant(t, a.s.Now(), "user:bob", a.both, []string{"read", "create", "append", "delete"})
		a.tr.caughtUp("cat", "matches")
		names(g.propfindAs(bob, "/cat/Season/"), "/cat/Season/")
		a.tr.paused.Store(true)
		// A request that reads the catalog for bob, kept for CatalogTTL.
		g.expect(g.doAs(bob, "DELETE", "/cat/Season/none.json", ""), 404, "bob's DELETE of no file")
		h, doc := e.load("cat", c.node)
		title := strings.TrimSuffix(doc.(map[string]any)["title"].(string), ".json") + "-final.json"
		must(a.w.Append(a.ctx, "cat", c.node, h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": title}}))
		r := g.expect(g.doAs(bob, c.method, c.path, "", "Destination", "/cat/Season/bobs.json"), c.status, "bob's "+c.method+" of a file renamed elsewhere")
		if !strings.Contains(r.body, c.says) {
			t.Fatalf("%d %q", r.status, r.body)
		}
		a.tr.paused.Store(false)
		if doc := e.nodeDoc("cat", c.node); doc["title"] != title {
			t.Fatalf("%s's title %v", c.node, doc["title"])
		}
	}
}

// A user's writes to a namespace the tree service can't follow (its grant
// doesn't name ghost: 403) make a ?min= it refuses (400, §A.5), with the
// user's others in one query: found per namespace (one entry asked for
// each alone), the refused one is dropped, one the tree service is still
// behind on kept and waited for until reached, then dropped too; later
// listings send none, and a grant of the user's limited to some
// resources, which can't read the node documents, lists and reads again.
// A listing whose answer takes longer than TreeWait (a loaded machine;
// here forced, slow) keeps every entry, so each step is checked at the
// first listing the tree service answered in time, within a few.
func TestTreeServiceMinRefusedPerNamespace(t *testing.T) {
	t.Parallel()
	for _, slow := range []bool{false, true} {
		t.Run(fmt.Sprintf("slow=%v", slow), func(t *testing.T) {
			t.Parallel()
			minRefusedPerNamespace(t, slow)
		})
	}
}

func minRefusedPerNamespace(t *testing.T, slow bool) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	all := []string{"cat", "matches", "ghost"}
	for ns, doc := range map[string]map[string]any{
		"matches": {"read": "grant", "keys": []any{k.Entry("*")}},
		"ghost":   {"read": "grant", "keys": []any{k.Entry("*")}},
		"cat":     {"read": "grant", "keys": []any{k.Entry("*")}, "catalog": treeCatalog("matches", "ghost")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "delete"})))
	for _, d := range []struct {
		ns, name string
		doc      map[string]any
	}{
		{"matches", "derby", map[string]any{"title": "Derby"}},
		{"ghost", "g", map[string]any{"text": "g"}},
		{"cat", "root", map[string]any{"title": "Root", "parents": []any{}}},
		{"cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")}},
		{"cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")}},
		{"cat", "ghost.g", map[string]any{"title": "g.json", "parents": parents("cat", "season")}},
	} {
		must(w.CreateDoc(ctx, d.ns, d.name, d.doc))
	}
	tr := startTree(t, s, "cat", client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat", "matches"}, []string{"read"})))
	tr.caughtUp("cat", "matches")
	var mu sync.Mutex
	var sent []string // every ?min= value sent
	var delayed atomic.Bool
	front := newTestServer(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sent = append(sent, r.URL.Query()["min"]...)
		mu.Unlock()
		if slow && strings.Contains(strings.Join(r.URL.Query()["min"], " "), "ghost:") && delayed.CompareAndSwap(false, true) {
			// The first listing naming ghost answered after TreeWait.
			time.Sleep(time.Second)
		}
		proxyTo(tr.http.URL).ServeHTTP(rw, r)
	}))
	sentSince := func(n int) []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sent[n:]...)
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(sent) }
	clk := &testClock{t: time.Now()}
	g := &env{t: t, ctx: ctx, s: s, c: w, dav: newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Catalogs: []string{"cat"},
		Gateway: true, TreeService: front.URL, Logf: t.Logf, TreeWait: 300 * time.Millisecond, Now: clk.now})))}
	ann := k.Grant(t, s.Now(), "user:ann", all, []string{"read", "create", "append", "delete"})
	limited := k.Grant(t, s.Now(), "user:ann", all, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "season", "matches.derby", "derby"}}}}})
	// ghost, which the tree service can't follow, isn't waited for, and
	// mins naming it are refused.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		req := must(http.NewRequest("GET", tr.http.URL+"/cat/children?of=season&min=ghost:"+tr.s.Checkpoint("matches"), nil))
		req.Header.Set("Authorization", "Bearer "+ann)
		res := must(testHTTP.Do(req))
		res.Body.Close()
		if res.StatusCode == http.StatusBadRequest {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a min naming ghost: %d", res.StatusCode)
		}
	}

	sameStrings(t, "ann's Season", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	sameStrings(t, "the limited grant's Season", names(g.propfindAs(limited, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	tr.paused.Store(true)
	g.expect(g.doAs(ann, "PUT", "/cat/Season/derby.json", `{"title": "Derby!"}`), 201, "ann's PUT of derby.json")
	g.expect(g.doAs(ann, "PUT", "/cat/Season/g.json", `{"text": "edited"}`), 201, "ann's PUT of g.json, an item of ghost")
	if h, doc := g.load("ghost", "g"); h.State != client.Live || doc.(map[string]any)["text"] != "edited" {
		t.Fatalf("ghost/g: %v %v", h.State, doc)
	}
	of := func(ns string, got []string) bool {
		return slices.ContainsFunc(got, func(m string) bool { return strings.HasPrefix(m, ns+":") })
	}
	clk.add(6 * time.Second) // past slowFor, which the PUT's listing set
	n := count()
	g.propfindAs(ann, "/cat/Season/")
	if got := sentSince(n); !of("ghost", got) {
		t.Fatalf("the first listing after the writes sent %q", got)
	}
	// ghost's is dropped once a listing got the tree service's 400 for it;
	// matches', which the tree service hasn't reached, is waited for
	// still.
	for i := 0; ; i++ {
		clk.add(6 * time.Second) // past slowFor, which a listing that waited set
		n = count()
		g.propfindAs(ann, "/cat/Season/")
		got := sentSince(n)
		if !of("ghost", got) {
			if !of("matches", got) {
				t.Fatalf("a listing after ghost's was dropped sent %q, want matches' min", got)
			}
			break
		}
		if i == 4 {
			t.Fatalf("ghost's min still sent after %d listings: %q", i+2, got)
		}
	}
	tr.paused.Store(false)
	tr.caughtUp("cat", "matches")
	// A listing reaches matches'; the next sends none.
	for i := 0; ; i++ {
		clk.add(6 * time.Second)
		n = count()
		got := names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/")
		sent := sentSince(n)
		if of("ghost", sent) {
			t.Fatalf("a listing sent ghost's min again: %q", sent)
		}
		if len(sent) == 0 {
			sameStrings(t, "ann's Season once caught up", got, []string{"derby.json"})
			break
		}
		if i == 4 {
			t.Fatalf("a listing after every write was reached or refused sent %q", sent)
		}
	}
	g.expect(g.doAs(limited, "PROPFIND", "/cat/Season/", "", "Depth", "1"), 207, "the limited grant's PROPFIND")
	if r := g.expect(g.doAs(limited, "GET", "/cat/Season/derby.json", ""), 200, "the limited grant's GET"); !strings.Contains(r.body, "Derby!") {
		t.Fatalf("derby.json %q", r.body)
	}
}

// A user's writes the tree service never reaches (here a front answering
// every ?min= 503 behind, as for a follower that's stuck) are waited for
// at most maxWroteAge (10 minutes), then not asked for again; a grant of
// the user's that can't read the node documents (§H.7 "Limited grants")
// is a 503 meanwhile for limitedWait (30 s) after the write, then shown
// the tree service's listing without waiting.
func TestTreeServiceMinsBounded(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	var withMin atomic.Int64
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("min") {
			withMin.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"behind","message":"the tree service has not reached min yet"}`)
			return
		}
		proxyTo(a.tr.http.URL).ServeHTTP(w, r)
	}))
	clk := &testClock{t: time.Now()}
	g := a.gateway(t, front.URL, func(o *dav.Options) { o.TreeWait, o.Now = 300*time.Millisecond, clk.now })
	ann := a.k.Grant(t, a.s.Now(), "user:ann", a.both, []string{"read", "create", "append", "delete"})
	narrow := a.limitedTo(t, "user:ann", "root", "season", "matches.derby", "derby")
	g.propfindAs(ann, "/cat/")
	sameStrings(t, "ann's Season through her limited token", names(g.propfindAs(narrow, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	g.expect(g.doAs(ann, "PUT", "/cat/Season/derby.json", `{"title": "Derby!"}`), 201, "ann's PUT of derby.json")
	clk.add(10 * time.Second)
	g.expect(g.doAs(narrow, "PROPFIND", "/cat/Season/", "", "Depth", "1"), 503, "the limited token's PROPFIND 10 s after ann's write")
	clk.add(time.Minute)
	g.expect(g.doAs(narrow, "PROPFIND", "/cat/Season/", "", "Depth", "1"), 207, "the limited token's PROPFIND a minute after ann's write")
	g.expect(g.doAs(narrow, "GET", "/cat/Season/derby.json", ""), 200, "the limited token's GET")
	n := withMin.Load()
	clk.add(time.Minute)
	sameStrings(t, "ann's Season, from the node documents", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
	if withMin.Load() == n {
		t.Fatal("ann's listing 2 minutes after her write didn't wait for it")
	}
	clk.add(10 * time.Minute)
	n = withMin.Load()
	sameStrings(t, "ann's Season 12 minutes after her write", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
	if withMin.Load() != n {
		t.Fatal("ann's listing 12 minutes after her write waited for it")
	}
}

// Renamed elsewhere (another program, within CatalogTTL of the token's
// kept graph): a DELETE of the old name of an empty folder, or of a file
// placed in two folders (a DAG, unlinked from one), is a 404, not a
// delete of the folder renamed or an unlink of the file renamed (§H.5).
func TestTreeServiceRenamedElsewhereDeletes(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	e := &env{t: t, ctx: a.ctx, c: a.w}
	must(a.w.CreateDoc(a.ctx, "cat", "box", map[string]any{"title": "Box", "parents": parents("cat", "root")}))
	h, _ := e.load("cat", "matches.derby")
	must(a.w.Append(a.ctx, "cat", "matches.derby", h.ID, []any{map[string]any{"op": "add", "path": "/parents/-", "value": map[string]any{"href": "/r/cat/hidden"}}}))
	a.tr.caughtUp("cat", "matches")
	for _, mode := range []string{"tree service", "node documents"} {
		u := a.tr.http.URL
		if mode == "node documents" {
			u = ""
		}
		g := a.gateway(t, u, func(o *dav.Options) { o.TreeWait, o.CatalogTTL = 300*time.Millisecond, time.Minute })
		bob := a.k.Grant(t, a.s.Now(), "user:bob", a.both, []string{"read", "create", "append", "delete"})
		sameStrings(t, mode+": bob's top level", names(g.propfindAs(bob, "/cat/"), "/cat/"), []string{"Box/", "Hidden/", "Season/"})
		sameStrings(t, mode+": bob's Season", names(g.propfindAs(bob, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
		a.tr.paused.Store(true)
		g.expect(g.doAs(bob, "DELETE", "/cat/Season/none.json", ""), 404, mode+": bob's DELETE of no file, which reads the catalog")
		hb, _ := e.load("cat", "box")
		must(a.w.Append(a.ctx, "cat", "box", hb.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Archive"}}))
		hd, _ := e.load("cat", "matches.derby")
		must(a.w.Append(a.ctx, "cat", "matches.derby", hd.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "derby-final.json"}}))

		g.expect(g.doAs(bob, "DELETE", "/cat/Box/", ""), 404, mode+": bob's DELETE of Box, renamed Archive elsewhere")
		if hb, _ := e.load("cat", "box"); hb.State != client.Live {
			t.Fatalf("%s: the folder renamed Archive is %v", mode, hb.State)
		}
		g.expect(g.doAs(bob, "DELETE", "/cat/Season/derby.json", ""), 404, mode+": bob's DELETE of derby.json, renamed elsewhere")
		if ps := e.parentsOf("matches.derby"); len(ps) != 2 {
			t.Fatalf("%s: derby-final.json's parents %v", mode, ps)
		}
		// Back as they were for the next mode.
		hb, _ = e.load("cat", "box")
		must(a.w.Append(a.ctx, "cat", "box", hb.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Box"}}))
		hd, _ = e.load("cat", "matches.derby")
		must(a.w.Append(a.ctx, "cat", "matches.derby", hd.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "derby.json"}}))
		a.tr.paused.Store(false)
		a.tr.caughtUp("cat", "matches")
	}
}

// A grant limited to some resources (§H.7), which doesn't read the
// catalog's node documents (the core answers it 404 for them), keeps the
// listing's view for names (§H.4 "Names before writes"): it edits a file
// it lists and reads, through the tree's trust as its own /principal
// says it; it renames and deletes a file whose placement's own document
// it reads, checked against it, as the core lets it; a new file or folder
// its grant can't make is the core's 403; and it deletes no folder (403,
// saying why).
func TestTreeServiceLimitedGrantWrites(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	g := a.gateway(t, a.tr.http.URL)
	g.propfindAs(a.k.Grant(t, a.s.Now(), "user:admin", a.both, []string{"read"}), "/cat/")
	ann := a.k.Grant(t, a.s.Now(), "user:ann", a.both, []string{"read", "create", "append", "delete"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "season", "matches.derby", "derby"}}}}})
	sameStrings(t, "ann's Season", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	g.expect(g.doAs(ann, "GET", "/cat/Season/derby.json", ""), 200, "ann's GET of derby.json")
	if r := g.doAs(ann, "PUT", "/cat/Season/derby.json", `{"title": "Derby!"}`); r.status != 201 && r.status != 204 {
		t.Fatalf("ann's PUT of derby.json: %d %q", r.status, r.body)
	}
	if _, doc := g.load("matches", "derby"); doc.(map[string]any)["title"] != "Derby!" {
		t.Fatalf("matches/derby %v", doc)
	}
	g.expect(g.doAs(ann, "PUT", "/cat/Season/new.json", `{"x": 1}`), 403, "ann's PUT of a new file, whose placement her grant can't make")
	g.expect(g.doAs(ann, "MKCOL", "/cat/Season/F", ""), 403, "ann's MKCOL, whose node her grant can't make")
	if r := g.expect(g.doAs(ann, "DELETE", "/cat/Season", ""), 403, "ann's DELETE of a folder"); !strings.Contains(r.body, "node documents") {
		t.Fatalf("DELETE of a folder: 403 %q", r.body)
	}
	g.expect(g.doAs(ann, "MOVE", "/cat/Season/derby.json", "", "Destination", "/cat/Season/d2.json"), 201, "ann's rename of derby.json")
	if doc := g.nodeDoc("cat", "matches.derby"); doc["title"] != "d2.json" {
		t.Fatalf("derby's placement after the rename: %v", doc)
	}
	g.expect(g.doAs(ann, "DELETE", "/cat/Season/d2.json", ""), 204, "ann's DELETE of d2.json")
	g.expectTombstoned("cat", "matches.derby", "derby's placement")
	g.expectTombstoned("matches", "derby", "derby")
}

// A MOVE of a tree's file by a grant limited to some resources, which
// keeps the listing's view for names (§H.4, §H.7 "Limited grants") and
// can't delete the file there (its verbs lack delete, §C.2), is refused
// before anything is written: onto another listed file (a temporary file
// renamed over), the destination keeps its content; to a new name in a
// flat namespace it can write (docs, which no tree owns, §H.2), no copy
// is made. The source stays either way.
func TestTreeServiceLimitedGrantMoveWritesNothing(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	w := a.docsNS(t)
	g := a.gateway(t, a.tr.http.URL, func(o *dav.Options) { o.Namespaces = []string{"docs"} })
	g.propfindAs(a.k.Grant(t, a.s.Now(), "user:admin", a.both, []string{"read"}), "/cat/")
	ann := a.k.Grant(t, a.s.Now(), "user:ann", []string{"cat", "matches", "docs"}, []string{"read", "create", "append"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "season", "matches.derby", "derby", "matches.cup", "cup", "moved"}}}}})
	sameStrings(t, "ann's Season", names(g.propfindAs(ann, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
	cupBefore, _ := g.load("matches", "cup")
	for _, dst := range []string{"/cat/Season/cup.json", "/docs/moved.json"} {
		if r := g.expect(g.doAs(ann, "MOVE", "/cat/Season/derby.json", "", "Destination", dst, "Overwrite", "T"), 403, "ann's MOVE of derby.json to "+dst); !strings.Contains(r.body, "nothing was written") {
			t.Fatalf("MOVE to %s: 403 %q", dst, r.body)
		}
	}
	if cupAfter, doc := g.load("matches", "cup"); cupAfter.ID != cupBefore.ID {
		t.Fatalf("matches/cup changed by a refused MOVE: %s -> %s, now %v", cupBefore.ID, cupAfter.ID, doc)
	}
	if h := must(w.Head(a.ctx, "docs", "moved")); h.State != client.NotFound {
		t.Fatalf("docs/moved made by a refused MOVE: %v", h.State)
	}
	if h, _ := g.load("matches", "derby"); h.State != client.Live {
		t.Fatalf("derby is %v", h.State)
	}
}

// A MOVE whose source the grant can't delete, its verbs in the namespace
// the delete is made in lacking delete (§C.2: here a common editor's
// read, create and append), or, a flat file moved to another namespace,
// the append setting its $successor (§8.1), is refused before anything is
// written (§H.5): a tree's file onto another listed file or to a new name
// in a flat namespace, a flat file onto another or into a tree (in docs,
// which no tree owns, §H.2). The destination keeps its content or isn't
// made, and the source stays.
func TestTreeServiceNoDeleteMoveWritesNothing(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	w := a.docsNS(t)
	g := a.gateway(t, a.tr.http.URL, func(o *dav.Options) { o.Namespaces = []string{"docs"} })
	three := []string{"cat", "matches", "docs"}
	bob := a.k.Grant(t, a.s.Now(), "user:bob", three, []string{"read", "create", "append"})
	carl := a.k.Grant(t, a.s.Now(), "user:carl", three, []string{"read", "create", "delete"})
	sameStrings(t, "bob's Season", names(g.propfindAs(bob, "/cat/Season/"), "/cat/Season/"), []string{"cup.json", "derby.json"})
	// Each namespace's head moves with any write in it (§7.4).
	heads := func() string {
		return must(a.w.NSHead(a.ctx, "matches")).ID + " " + must(a.w.NSHead(a.ctx, "cat")).ID + " " + must(w.NSHead(a.ctx, "docs")).ID
	}
	for _, c := range []struct{ who, tok, src, dst, verb string }{
		{"bob", bob, "/cat/Season/derby.json", "/cat/Season/cup.json", "delete"},
		{"bob", bob, "/cat/Season/derby.json", "/docs/moved.json", "delete"},
		{"bob", bob, "/docs/derby.json", "/docs/cup.json", "delete"},
		{"bob", bob, "/docs/derby.json", "/cat/Season/moved.json", "delete"},
		{"carl", carl, "/docs/derby.json", "/cat/Season/moved.json", "append"},
	} {
		before := heads()
		r := g.doAs(c.tok, "MOVE", c.src, "", "Destination", c.dst, "Overwrite", "T")
		if r.status != 403 || !strings.Contains(r.body, "doesn't allow "+c.verb) || !strings.Contains(r.body, "nothing was written") {
			t.Errorf("%s's MOVE of %s to %s: %d %q", c.who, c.src, c.dst, r.status, r.body)
		}
		if after := heads(); after != before {
			t.Errorf("%s's refused MOVE of %s to %s wrote: heads %s -> %s", c.who, c.src, c.dst, before, after)
		}
	}
	if h, _ := g.load("matches", "derby"); h.State != client.Live {
		t.Errorf("derby is %v", h.State)
	}
}
