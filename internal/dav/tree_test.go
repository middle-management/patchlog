package dav_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// gate holds the index's reads of a namespace's log while closed, their
// answers too, so the index lags the core for as long as a test says
// (§A.5): an index behind.
type gate struct {
	mu   sync.Mutex
	open chan struct{} // nil while open
}

func (g *gate) hold() {
	g.mu.Lock()
	if g.open == nil {
		g.open = make(chan struct{})
	}
	g.mu.Unlock()
}

func (g *gate) release() {
	g.mu.Lock()
	if g.open != nil {
		close(g.open)
		g.open = nil
	}
	g.mu.Unlock()
}

func (g *gate) wait(r *http.Request) {
	if !strings.Contains(r.URL.Path, "/log") && !strings.HasSuffix(r.URL.Path, "/events") {
		return
	}
	g.mu.Lock()
	ch := g.open
	g.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		case <-r.Context().Done():
		}
	}
}

func (g *gate) RoundTrip(r *http.Request) (*http.Response, error) {
	g.wait(r)
	res, err := http.DefaultTransport.RoundTrip(r)
	// An answer on its way when the gate closed waits too: a long-poll
	// that a write ends mustn't bring the index past it.
	g.wait(r)
	return res, err
}

// treeEnv is a core, an index following its tree namespace, and a WebDAV
// server serving that namespace as a file tree (§H.2) listed through the
// index (§H.3).
type treeEnv struct {
	*env
	ix   *index.Index
	gate *gate
}

// newTreeEnv starts a development core with a public schemas namespace
// holding the file schema, public tree namespaces trees, an index
// following them, and a local-mode WebDAV server serving them as trees.
func newTreeEnv(t *testing.T, trees ...string) *treeEnv {
	t.Helper()
	return newTreeEnvWith(t, treeOpts{}, trees...)
}

// treeOpts adjust newTreeEnvWith: how long the index waits for a ?min
// (default 5s; the lag tests' short, so an index behind answers soon)
// and the gateway's MaxListing.
type treeOpts struct {
	minWait    time.Duration
	maxListing int
}

func newTreeEnvWith(t *testing.T, o treeOpts, trees ...string) *treeEnv {
	t.Helper()
	if o.minWait == 0 {
		o.minWait = 5 * time.Second
	}
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 100 * time.Millisecond})
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithAuthor("other")), pw: "secret"}
	must(e.c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(e.c.CreateDoc(ctx, "schemas", "file", files.Schema()))
	for _, ns := range trees {
		must(e.c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
	}
	g := &gate{}
	ixc := s.Client(t, client.WithHTTPClient(&http.Client{Transport: g}))
	ix := must(index.Open(ctx, index.Options{Client: ixc, DB: filepath.Join(t.TempDir(), "i.db"), Namespaces: trees,
		Now: s.Now, CheckerTTL: time.Millisecond, MinWait: o.minWait, RepurgeInterval: -1,
		Logf: func(string, ...any) {}}))
	ihs := httptest.NewServer(ix.Handler())
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { ix.Run(rctx); close(done) }()
	t.Cleanup(func() { g.release(); cancel(); <-done; ihs.Close(); ix.Close() })
	// The index answers once it has a checkpoint of each tree.
	for _, ns := range trees {
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			res, err := testHTTP.Get(ihs.URL + "/" + ns + "?limit=1")
			if err == nil {
				res.Body.Close()
				if res.StatusCode != http.StatusServiceUnavailable {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("the index didn't reach %s", ns)
			}
		}
	}
	opt := dav.Options{Client: s.Client(t, client.WithAuthor("dav")), Trees: trees, Index: ihs.URL, Password: e.pw, MaxListing: o.maxListing, Logf: t.Logf}
	srv := must(dav.New(opt))
	e.dav = newTestServer(t, srv)
	e.opt = opt
	return &treeEnv{env: e, ix: ix, gate: g}
}

// placed finds the live document of tree ns placed as folder/name, as the
// core holds it, and its resource name; it fails the test if there is
// not exactly one.
func (e *treeEnv) placed(ns, folder, name string) (string, map[string]any) {
	e.t.Helper()
	got := e.find(ns, folder, name)
	if len(got) != 1 {
		e.t.Fatalf("%d documents placed as %s %q in %s, want 1", len(got), folder, name, ns)
	}
	for r, d := range got {
		return r, d
	}
	return "", nil
}

// find returns the live documents of ns placed as folder/name.
func (e *treeEnv) find(ns, folder, name string) map[string]map[string]any {
	e.t.Helper()
	h := must(e.c.NSHead(e.ctx, ns))
	out := map[string]map[string]any{}
	for _, it := range must(e.c.Heads(e.ctx, ns, h.ID)) {
		if it.Kind != "head" {
			continue
		}
		d := must(e.c.Doc(e.ctx, ns, it.Resource, it.Target))
		m, _ := d.Value.(map[string]any)
		if m["folder"] == folder && m["name"] == name {
			out[it.Resource] = m
		}
	}
	return out
}

// otherDoc creates a document of the file schema in ns as someone else,
// straight at the core.
func (e *treeEnv) otherDoc(ns, res string, doc map[string]any) *client.WriteResult {
	e.t.Helper()
	h := must(e.c.Head(e.ctx, "schemas", "file"))
	doc["$schema"] = "/r/schemas/file/rev/" + h.ID
	return must(e.c.CreateDoc(e.ctx, ns, res, doc))
}

// ls lists folder p (ending in /) as PROPFIND Depth 1 does: the names of
// its entries, sorted, folders with a trailing /.
func (e *treeEnv) ls(p string) []string {
	e.t.Helper()
	return names(e.propfind(p), p)
}

// want fails unless r has status.
func (e *treeEnv) want(r resp, status int) resp {
	e.t.Helper()
	return e.expect(r, status, "request")
}

func TestTreeCreateAndRead(t *testing.T) {
	t.Parallel()
	e := newTreeEnv(t, "files")
	if got := e.ls("/files/"); len(got) != 0 {
		t.Fatalf("an empty tree lists %v", got)
	}
	e.want(e.do("PUT", "/files/notes.txt", "hello\n", "Content-Type", "text/plain"), http.StatusCreated)
	e.want(e.do("PUT", "/files/data.json", `{"b":2,"a":1}`), http.StatusCreated)

	res, doc := e.placed("files", "/", "notes.txt")
	if res == "notes.txt" || !strings.HasPrefix(doc["$schema"].(string), "/r/schemas/file/rev/") {
		t.Errorf("new file: resource %q, $schema %v: want an opaque name and the file schema pinned", res, doc["$schema"])
	}
	c, _ := doc["content"].(map[string]any)
	if c["type"] != "text/plain" || c["size"] != 6.0 || c["$blob"] == nil {
		t.Errorf("raw file's content %v, want its blob reference", c)
	}
	_, jdoc := e.placed("files", "/", "data.json")
	if !jsonv.Equal(jdoc["content"], map[string]any{"a": 1.0, "b": 2.0}) {
		t.Errorf("JSON file's content %v", jdoc["content"])
	}

	if got := e.ls("/files/"); strings.Join(got, ",") != "data.json,notes.txt" {
		t.Errorf("listing %v", got)
	}
	if r := e.do("GET", "/files/notes.txt", ""); r.status != 200 || r.body != "hello\n" {
		t.Errorf("GET raw: %d %q", r.status, r.body)
	}
	// Its writer gets its own bytes back, under a weak tag; anyone else
	// the rendering (§H.1).
	if r := e.do("GET", "/files/data.json", ""); r.status != 200 || r.body != `{"b":2,"a":1}` || !strings.HasPrefix(r.header.Get("ETag"), "W/") {
		t.Errorf("GET JSON by its writer: %d %q %s", r.status, r.body, r.header.Get("ETag"))
	}
	if r := e.another().do("GET", "/files/data.json", ""); r.status != 200 || r.body != "{\n  \"a\": 1,\n  \"b\": 2\n}\n" {
		t.Errorf("GET JSON: %d %q", r.status, r.body)
	}

	// A save edits the content, the place kept.
	e.want(e.do("PUT", "/files/data.json", `{"a":1,"b":3}`), http.StatusCreated)
	_, jdoc = e.placed("files", "/", "data.json")
	if !jsonv.Equal(jdoc["content"], map[string]any{"a": 1.0, "b": 3.0}) {
		t.Errorf("saved content %v", jdoc["content"])
	}
	e.want(e.do("PUT", "/files/notes.txt", "bye\n"), http.StatusCreated)
	if r := e.do("GET", "/files/notes.txt", ""); r.body != "bye\n" {
		t.Errorf("GET after save: %q", r.body)
	}

	// A title that breaks the rules is 403.
	e.want(e.do("PUT", "/files/trailing.", "x"), http.StatusForbidden)
	// A name a sibling has under another case is 409, naming it.
	if r := e.do("PUT", "/files/NOTES.txt", "x"); r.status != http.StatusConflict || !strings.Contains(r.body, "notes.txt") {
		t.Errorf("case variant: %d %s", r.status, r.body)
	}
}

func TestTreeNestedFolders(t *testing.T) {
	t.Parallel()
	e := newTreeEnv(t, "files")
	e.want(e.do("MKCOL", "/files/reports", ""), http.StatusCreated)
	e.want(e.do("MKCOL", "/files/reports/2026", ""), http.StatusCreated)
	e.want(e.do("MKCOL", "/files/reports", ""), http.StatusMethodNotAllowed)
	e.want(e.do("MKCOL", "/files/nowhere/x", ""), http.StatusConflict)
	e.want(e.do("PUT", "/files/reports/2026/q3.txt", "q3"), http.StatusCreated)

	_, f := e.placed("files", "/", "reports")
	if _, has := f["content"]; has {
		t.Errorf("a folder document has content: %v", f)
	}
	e.placed("files", "/reports", "2026")
	e.placed("files", "/reports/2026", "q3.txt")

	if got := e.ls("/files/"); strings.Join(got, ",") != "reports/" {
		t.Errorf("top: %v", got)
	}
	if got := e.ls("/files/reports/2026/"); strings.Join(got, ",") != "q3.txt" {
		t.Errorf("/reports/2026: %v", got)
	}
	// A folder in the middle of a path matches whatever its case.
	if r := e.do("GET", "/files/REPORTS/2026/q3.txt", ""); r.status != 200 || r.body != "q3" {
		t.Errorf("GET through a case variant: %d %q", r.status, r.body)
	}
	// MKCOL of a case variant is 405.
	e.want(e.do("MKCOL", "/files/Reports", ""), http.StatusMethodNotAllowed)

	// A folder with something in it isn't deleted.
	if r := e.do("DELETE", "/files/reports/2026", ""); r.status != http.StatusConflict || !strings.Contains(r.body, "q3.txt") {
		t.Errorf("DELETE of a folder with a file: %d %s", r.status, r.body)
	}
	e.want(e.do("DELETE", "/files/reports/2026/q3.txt", ""), http.StatusNoContent)
	e.want(e.do("DELETE", "/files/reports/2026", ""), http.StatusNoContent)
	if got := e.find("files", "/reports", "2026"); len(got) != 0 {
		t.Errorf("deleted folder still has documents: %v", got)
	}
	if got := e.ls("/files/reports/"); len(got) != 0 {
		t.Errorf("/reports after deletes: %v", got)
	}
}

func TestTreeMoveIsReplace(t *testing.T) {
	t.Parallel()
	e := newTreeEnv(t, "files")
	e.want(e.do("MKCOL", "/files/a", ""), http.StatusCreated)
	e.want(e.do("MKCOL", "/files/a/b", ""), http.StatusCreated)
	e.want(e.do("MKCOL", "/files/c", ""), http.StatusCreated)
	e.want(e.do("PUT", "/files/a/b/x.txt", "x"), http.StatusCreated)
	res, _ := e.placed("files", "/a/b", "x.txt")
	before := must(e.c.Head(e.ctx, "files", res))

	// A rename and a move of a file: one append replacing /name and
	// /folder, the same resource.
	e.want(e.do("MOVE", "/files/a/b/x.txt", "", "Destination", "/files/c/y.txt"), http.StatusCreated)
	res2, _ := e.placed("files", "/c", "y.txt")
	if res2 != res {
		t.Fatalf("moved file is %s, want %s", res2, res)
	}
	log := must(e.c.Log(e.ctx, "files", res, must(e.c.Head(e.ctx, "files", res)).ID, before.ID))
	if len(log) != 1 {
		t.Fatalf("a move wrote %d entries, want 1", len(log))
	}
	ops := map[string]any{}
	for _, op := range log[0].Patches.([]any) {
		m := op.(map[string]any)
		if m["op"] != "replace" {
			t.Errorf("a move's op %v, want replace", m)
		}
		ops[m["path"].(string)] = m["value"]
	}
	if ops["/name"] != "y.txt" || ops["/folder"] != "/c" {
		t.Errorf("a move's ops %v", ops)
	}
	if r := e.do("GET", "/files/c/y.txt", ""); r.body != "x" {
		t.Errorf("GET moved: %d %q", r.status, r.body)
	}
	e.want(e.do("GET", "/files/a/b/x.txt", ""), http.StatusNotFound)
	// A case-only rename is allowed.
	e.want(e.do("MOVE", "/files/c/y.txt", "", "Destination", "/files/c/Y.txt"), http.StatusCreated)
	e.placed("files", "/c", "Y.txt")

	// A folder's move: one batch over it and everything under it.
	e.want(e.do("PUT", "/files/a/b/z.txt", "z"), http.StatusCreated)
	e.want(e.do("MOVE", "/files/a", "", "Destination", "/files/c/a2"), http.StatusCreated)
	e.placed("files", "/c", "a2")
	e.placed("files", "/c/a2", "b")
	e.placed("files", "/c/a2/b", "z.txt")
	if r := e.do("GET", "/files/c/a2/b/z.txt", ""); r.body != "z" {
		t.Errorf("GET under the moved folder: %d %q", r.status, r.body)
	}
	if got := e.ls("/files/"); strings.Join(got, ",") != "c/" {
		t.Errorf("top after the move: %v", got)
	}
	// Into itself is 403.
	e.want(e.do("MOVE", "/files/c", "", "Destination", "/files/c/a2/c"), http.StatusForbidden)

	// A copy is a new document.
	e.want(e.do("COPY", "/files/c/Y.txt", "", "Destination", "/files/copy.txt"), http.StatusCreated)
	cres, _ := e.placed("files", "/", "copy.txt")
	if cres == res {
		t.Errorf("a copy is the same document")
	}
	if r := e.do("GET", "/files/copy.txt", ""); r.body != "x" {
		t.Errorf("GET copy: %q", r.body)
	}
	// A folder's copy: a new folder document and copies of its files.
	e.want(e.do("COPY", "/files/c/a2", "", "Destination", "/files/a3"), http.StatusCreated)
	e.placed("files", "/", "a3")
	e.placed("files", "/a3/b", "z.txt")
	e.placed("files", "/c/a2/b", "z.txt")
}

// FILE-17: a new file's folder must be one the user can see; a document
// whose folder has no folder document isn't in the tree (§H.2).
func TestTreeInvisibleFolder(t *testing.T) {
	t.Parallel()
	e := newTreeEnv(t, "files")
	e.otherDoc("files", "orphan", map[string]any{"folder": "/ghost", "name": "lost.txt", "content": "hi"})
	e.otherDoc("files", "seen", map[string]any{"folder": "/", "name": "seen.json", "content": map[string]any{}})
	// The index has the other's documents once a write of the gateway's
	// is listed past them.
	e.want(e.do("MKCOL", "/files/real", ""), http.StatusCreated)
	if got := e.ls("/files/"); strings.Join(got, ",") != "real/,seen.json" {
		t.Errorf("top: %v (the orphan's folder has no folder document)", got)
	}
	e.want(e.do("PROPFIND", "/files/ghost", "", "Depth", "1"), http.StatusNotFound)
	e.want(e.do("GET", "/files/ghost/lost.txt", ""), http.StatusNotFound)
	e.want(e.do("PUT", "/files/ghost/new.txt", "x"), http.StatusConflict)
	e.want(e.do("MKCOL", "/files/ghost/sub", ""), http.StatusConflict)
	if got := e.find("files", "/ghost", "new.txt"); len(got) != 0 {
		t.Errorf("a file was made in an invisible folder: %v", got)
	}

	// The folder deleted after the listing named it: the create is 409.
	h := must(e.c.Head(e.ctx, "files", must2(e.placed("files", "/", "real"))))
	must(e.c.Delete(e.ctx, "files", must2(e.placed("files", "/", "real")), h.ID))
	e.want(e.do("PUT", "/files/real/late.txt", "x"), http.StatusConflict)
}

func must2[A, B any](a A, _ B) A { return a }

// FILE-15: the index lags the core, so before a write the documents a
// listing resolved are read again; one that no longer has the name the
// listing gave is looked up again at the namespace's head, which an index
// behind answers 503, and nothing is written meanwhile.
func TestTreeIndexLag(t *testing.T) {
	t.Parallel()
	e := newTreeEnvWith(t, treeOpts{minWait: 400 * time.Millisecond}, "files")
	e.want(e.do("PUT", "/files/a.txt", "a"), http.StatusCreated)
	e.want(e.do("PUT", "/files/j.json", `{"v":1}`), http.StatusCreated)
	e.want(e.do("MKCOL", "/files/docs", ""), http.StatusCreated)
	if got := e.ls("/files/"); strings.Join(got, ",") != "a.txt,docs/,j.json" {
		t.Fatalf("top: %v", got)
	}
	res, _ := e.placed("files", "/", "a.txt")
	jres, _ := e.placed("files", "/", "j.json")
	other := e.another()
	other.expect(other.do("GET", "/files/j.json", ""), http.StatusOK, "GET j.json")

	e.gate.hold()
	// A file read while the index lags is read at its head, under its tag.
	jh := must(e.c.Head(e.ctx, "files", jres))
	jw := must(e.c.Append(e.ctx, "files", jres, jh.ID, []any{map[string]any{"op": "replace", "path": "/content/v", "value": 2.0}}))
	if r := other.do("GET", "/files/j.json", ""); r.status != 200 || r.header.Get("ETag") != `"`+jw.ID+`"` || !strings.Contains(r.body, "2") {
		t.Errorf("GET of a file the index lags: %d %s %q, want the head %s", r.status, r.header.Get("ETag"), r.body, jw.ID)
	}
	// Someone renames a.txt at the core; the index doesn't see it.
	h := must(e.c.Head(e.ctx, "files", res))
	must(e.c.Append(e.ctx, "files", res, h.ID, []any{map[string]any{"op": "replace", "path": "/name", "value": "b.txt"}}))
	if got := e.ls("/files/"); strings.Join(got, ",") != "a.txt,docs/,j.json" {
		t.Fatalf("the index isn't held: %v", got)
	}
	r := e.do("DELETE", "/files/a.txt", "")
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Errorf("DELETE of a name the index still lists: %d %s, want 503 with Retry-After", r.status, r.body)
	}
	e.want(e.do("MOVE", "/files/a.txt", "", "Destination", "/files/c.txt"), http.StatusServiceUnavailable)
	e.want(e.do("PUT", "/files/a.txt", "overwrite"), http.StatusServiceUnavailable)
	if hh := must(e.c.Head(e.ctx, "files", res)); hh.State != client.Live {
		t.Fatalf("the renamed file was deleted while the index lagged")
	}
	if _, d := e.placed("files", "/", "b.txt"); d["content"].(map[string]any)["size"] != 1.0 {
		t.Errorf("the renamed file was written while the index lagged: %v", d)
	}

	// A folder is empty only when a listing at or past the gateway's last
	// write in the namespace has nothing in it.
	e.gate.release()
	e.settle("/files/docs/")
	if got := e.ls("/files/docs/"); len(got) != 0 {
		t.Fatalf("docs: %v", got)
	}
	e.gate.hold()
	e.want(e.do("PUT", "/files/docs/kept.txt", "k"), http.StatusCreated)
	e.want(e.do("DELETE", "/files/docs", ""), http.StatusServiceUnavailable)
	e.placed("files", "/", "docs")

	e.gate.release()
	e.settle("/files/")
	e.want(e.do("DELETE", "/files/a.txt", ""), http.StatusNotFound)
	if got := e.ls("/files/"); strings.Join(got, ",") != "b.txt,docs/,j.json" {
		t.Errorf("top once the index caught up: %v", got)
	}
	e.want(e.do("DELETE", "/files/docs", ""), http.StatusConflict)

	// The name the user wrote names another document now: a save without
	// a tag isn't written over it (§H.4 "Records"), and a GET reloads it.
	e.otherDoc("files", "newa", map[string]any{"folder": "/", "name": "a.txt", "content": map[string]any{"theirs": true}})
	for deadline := time.Now().Add(10 * time.Second); !slices.Contains(e.ls("/files/"), "a.txt"); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the index never listed the new a.txt")
		}
	}
	if r := e.do("PUT", "/files/a.txt", "mine"); r.status != http.StatusConflict {
		t.Errorf("tagless PUT over another document now at the path: %d %s, want 409", r.status, r.body)
	}
	if _, d := e.placed("files", "/", "a.txt"); !jsonv.Equal(d["content"], map[string]any{"theirs": true}) {
		t.Errorf("the other document was written: %v", d)
	}
	e.want(e.do("GET", "/files/a.txt", ""), http.StatusOK)
	e.want(e.do("PUT", "/files/a.txt", `{"mine":true}`), http.StatusCreated)
}

// settle waits until folder p lists, past an index's 503 behind.
func (e *treeEnv) settle(p string) {
	e.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		r := e.do("PROPFIND", p, "", "Depth", "1")
		if r.status == http.StatusMultiStatus {
			return
		}
		if r.status != http.StatusServiceUnavailable || time.Now().After(deadline) {
			e.t.Fatalf("PROPFIND %s: %d %s", p, r.status, r.body)
		}
	}
}

// Names arrive in NFC or NFD (macOS); titles are NFC (§H.2 "Titles"),
// and either form names the file.
func TestTreeNFD(t *testing.T) {
	t.Parallel()
	e := newTreeEnv(t, "files")
	nfd, nfc := "été.txt", "été.txt"
	e.want(e.do("PUT", "/files/"+nfd, "summer"), http.StatusCreated)
	e.placed("files", "/", nfc)
	for _, n := range []string{nfd, nfc} {
		if r := e.do("GET", "/files/"+n, ""); r.status != 200 || r.body != "summer" {
			t.Errorf("GET %q: %d %q", n, r.status, r.body)
		}
	}
	e.want(e.do("PUT", "/files/"+nfd, "winter"), http.StatusCreated)
	if got := e.find("files", "/", nfc); len(got) != 1 {
		t.Errorf("%d documents named %q, want 1", len(got), nfc)
	}
	if got := e.ls("/files/"); strings.Join(got, ",") != nfc {
		t.Errorf("listing %q", got)
	}
}

// FILE-13: a folder is listed through every page of the index's
// listing; one larger than the gateway lists is refused, never listed
// cut short.
func TestTreePaging(t *testing.T) {
	t.Parallel()
	e := newTreeEnvWith(t, treeOpts{maxListing: 115}, "files")
	e.want(e.do("MKCOL", "/files/big", ""), http.StatusCreated)
	e.want(e.do("MKCOL", "/files/huge", ""), http.StatusCreated)
	ref := "/r/schemas/file/rev/" + must(e.c.Head(e.ctx, "schemas", "file")).ID
	var items []client.BatchItem
	for i := range 230 {
		folder := "/big"
		if i >= 105 {
			folder = "/huge"
		}
		doc := map[string]any{"$schema": ref, "folder": folder, "name": fmt.Sprintf("f%03d.json", i), "content": float64(i)}
		items = append(items, client.BatchItem{Resource: fmt.Sprintf("d%03d", i), IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(doc))}})
		if len(items) == 50 || i == 229 {
			// One writer per batch: each has its own rate bucket (§6.6).
			w := e.s.Client(t, client.WithAuthor(fmt.Sprintf("bulk%d", i)))
			must(w.Batch(e.ctx, "files", client.BatchRequest{Items: items}, false))
			items = nil
		}
	}
	e.want(e.do("PUT", "/files/marker.txt", "m"), http.StatusCreated)
	got := e.ls("/files/big/")
	if len(got) != 105 || got[0] != "f000.json" || got[104] != "f104.json" {
		t.Errorf("a folder of 105 lists %d: %v…", len(got), got[:min(3, len(got))])
	}
	if r := e.do("PROPFIND", "/files/huge/", "", "Depth", "1"); r.status != http.StatusForbidden {
		t.Errorf("a folder over MaxListing: %d %s, want 403", r.status, r.body)
	}
}

// FILE-16: a save from an older version is merged with others' edits of
// the content since; the place and the document's other members aren't
// the file's, so others' writes there never conflict with a save, and
// stay.
func TestTreeMergeContent(t *testing.T) {
	t.Parallel()
	e := newTreeEnv(t, "files")
	r := e.want(e.do("PUT", "/files/doc.json", `{"a":1,"b":1}`), http.StatusCreated)
	base := r.header.Get("ETag")
	res, _ := e.placed("files", "/", "doc.json")
	h := must(e.c.Head(e.ctx, "files", res))
	h2 := must(e.c.Append(e.ctx, "files", res, h.ID, []any{map[string]any{"op": "replace", "path": "/content/a", "value": 2.0}}))
	must(e.c.Append(e.ctx, "files", res, h2.ID, []any{map[string]any{"op": "add", "path": "/tag", "value": "x"}}))
	e.want(e.do("PUT", "/files/doc.json", `{"a":1,"b":3}`, "If-Match", base), http.StatusCreated)
	_, d := e.placed("files", "/", "doc.json")
	if !jsonv.Equal(d["content"], map[string]any{"a": 2.0, "b": 3.0}) || d["tag"] != "x" {
		t.Errorf("merged save: %v", d)
	}
	// An overlapping edit is a 409.
	h3 := must(e.c.Head(e.ctx, "files", res))
	must(e.c.Append(e.ctx, "files", res, h3.ID, []any{map[string]any{"op": "replace", "path": "/content/b", "value": 9.0}}))
	if r := e.do("PUT", "/files/doc.json", `{"a":2,"b":4}`, "If-Match", `"`+h3.ID+`"`); r.status != http.StatusConflict {
		t.Errorf("overlapping save: %d %s", r.status, r.body)
	}
}

// FILE-23: read rules on /doc/folder give a grant a subtree, its own
// folder document included (§H.7 "Folders as access"): through a gateway
// passing the user's grant on, the reader under H.7's team-a rule sees
// /team-a and what is under it, and nothing else.
func TestTreeFolderAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, LongPoll: 100 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"schemas", "files"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "files" {
			doc["read"] = "grant"
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"files", "schemas"}, []string{"read", "create", "append", "delete"})))
	sch := must(admin.CreateDoc(ctx, "schemas", "file", files.Schema()))
	ref := "/r/schemas/file/rev/" + sch.ID
	for _, d := range []struct{ res, folder, name string }{
		{"ta", "/", "team-a"}, {"tb", "/", "team-b"}, {"top", "/", "top.txt"},
		{"ax", "/team-a", "x.txt"}, {"as", "/team-a", "sub"}, {"az", "/team-a/sub", "z.txt"}, {"by", "/team-b", "y.txt"},
	} {
		doc := map[string]any{"$schema": ref, "folder": d.folder, "name": d.name}
		if strings.Contains(d.name, ".") {
			doc["content"] = map[string]any{"in": d.folder}
		}
		must(admin.CreateDoc(ctx, "files", d.res, doc))
	}
	rule := map[string]any{"any": []any{
		map[string]any{"op": "test", "path": "/doc/folder", "schema": map[string]any{"pattern": "^/team-a(/|$)"}},
		map[string]any{"all": []any{
			map[string]any{"op": "test", "path": "/doc/folder", "value": "/"},
			map[string]any{"op": "test", "path": "/doc/name", "value": "team-a"},
		}},
	}}
	svc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:index", []string{"files", "schemas"}, []string{"read"})))
	ix := must(index.Open(ctx, index.Options{Client: svc, DB: filepath.Join(t.TempDir(), "i.db"), Namespaces: []string{"files"},
		CheckerTTL: time.Millisecond, MinWait: time.Second, RepurgeInterval: -1, Logf: func(string, ...any) {}}))
	ihs := httptest.NewServer(ix.Handler())
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { ix.Run(rctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; ihs.Close(); ix.Close() })

	srv := must(dav.New(dav.Options{Client: s.Client(t), Gateway: true, Trees: []string{"files"}, Index: ihs.URL, Logf: t.Logf}))
	// A reader of everything, through the gateway, which passes its
	// grant on to the core and the index, sees the whole tree.
	all := k.Grant(t, s.Now(), "user:all", []string{"files", "schemas"}, []string{"read"})
	e := &treeEnv{env: &env{t: t, ctx: ctx, s: s, c: admin, pw: all, dav: newTestServer(t, srv)}}
	var top []string
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		r := e.do("PROPFIND", "/files/", "", "Depth", "1")
		if r.status == http.StatusMultiStatus {
			if top = e.ls("/files/"); len(top) == 3 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the index never listed /files: %d %s (%v)", r.status, r.body, top)
		}
	}
	if strings.Join(top, ",") != "team-a/,team-b/,top.txt" {
		t.Errorf("top for a reader of everything: %v", top)
	}
	if r := e.do("GET", "/files/team-b/y.txt", ""); r.status != 200 || !strings.Contains(r.body, "/team-b") {
		t.Errorf("GET /team-b/y.txt: %d %s", r.status, r.body)
	}
	// A reader without the file schema's grant is refused the write
	// (it reads only).
	e.want(e.do("PUT", "/files/team-a/new.txt", "x"), http.StatusForbidden)

	// A partial reader whose rules name the subtree's resources: the
	// index's hits and the core's reads are filtered alike (§A.4, §7.9).
	byName := k.Grant(t, s.Now(), "user:n", []string{"files", "schemas"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^(ta|ax|as|az)$"}}}})
	e.pw = byName
	if r := e.do("PROPFIND", "/files/", "", "Depth", "1"); r.status != http.StatusMultiStatus {
		t.Fatalf("a partial reader's listing: %d %s", r.status, r.body)
	}
	if got := e.ls("/files/"); strings.Join(got, ",") != "team-a/" {
		t.Errorf("top for a partial reader: %v", got)
	}
	if got := e.ls("/files/team-a/"); strings.Join(got, ",") != "sub/,x.txt" {
		t.Errorf("/team-a for a partial reader: %v", got)
	}
	e.want(e.do("GET", "/files/team-b/y.txt", ""), http.StatusNotFound)
	e.want(e.do("GET", "/files/team-a/sub/z.txt", ""), http.StatusOK)

	teamA := k.Grant(t, s.Now(), "user:a", []string{"files", "schemas"}, []string{"read"}, map[string]any{"rules": []any{rule}})
	ta := s.Client(t, client.WithBearer(teamA))
	if h, err := ta.Head(ctx, "files", "ax"); err != nil || h.State != client.Live {
		t.Skipf("the core doesn't serve a /doc/folder read rule's subtree yet (§7.9 filtered reads by document): head of /team-a/x.txt: %+v %v", h, err)
	}
	e.pw = teamA
	if top = e.ls("/files/"); strings.Join(top, ",") != "team-a/" {
		t.Errorf("top for team-a: %v", top)
	}
	if got := e.ls("/files/team-a/"); strings.Join(got, ",") != "sub/,x.txt" {
		t.Errorf("/team-a: %v", got)
	}
	if got := e.ls("/files/team-a/sub/"); strings.Join(got, ",") != "z.txt" {
		t.Errorf("/team-a/sub: %v", got)
	}
	if r := e.do("GET", "/files/team-a/sub/z.txt", ""); r.status != 200 || !strings.Contains(r.body, "/team-a/sub") {
		t.Errorf("GET in the subtree: %d %s", r.status, r.body)
	}
	e.want(e.do("GET", "/files/team-b/y.txt", ""), http.StatusNotFound)
	e.want(e.do("GET", "/files/top.txt", ""), http.StatusNotFound)
}
