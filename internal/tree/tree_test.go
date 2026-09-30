package tree_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/tree"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// svc is a running tree service with its HTTP server.
type svc struct {
	t      *testing.T
	s      *tree.Service
	http   *httptest.Server
	core   *client.Client
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	nbatch int
	purges [][]string
}

func (s *svc) PurgeTags(tags []string) {
	s.mu.Lock()
	s.purges = append(s.purges, tags)
	s.mu.Unlock()
}

type svcOpts struct {
	db          string
	catalog     string
	selfPlacing bool
	now         func() time.Time
}

func startSvc(t *testing.T, core *client.Client, o svcOpts) *svc {
	t.Helper()
	if o.catalog == "" {
		o.catalog = "cat"
	}
	if o.db == "" {
		o.db = filepath.Join(t.TempDir(), "tree.db")
	}
	s := &svc{t: t, core: core, done: make(chan struct{})}
	opt := tree.Options{
		Client: core, Catalog: o.catalog, DB: o.db, SelfPlacing: o.selfPlacing, Purger: s, Now: o.now,
		CheckerTTL: time.Millisecond, MinWait: 2 * time.Second,
		Logf:          func(f string, a ...any) { t.Logf(f, a...) },
		OnApply:       func(b *follow.Batch) { s.mu.Lock(); s.nbatch++; s.mu.Unlock() },
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)},
	}
	s.s = must(tree.Open(context.Background(), opt))
	s.http = httptest.NewServer(s.s.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() { s.s.Run(ctx); close(s.done) }()
	t.Cleanup(s.stop)
	return s
}

func (s *svc) stop() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	<-s.done
	s.http.Close()
	s.s.Close()
	s.cancel = nil
}

func (s *svc) batches() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nbatch
}

// caughtUp waits until the service reached the core's head of every ns.
func (s *svc) caughtUp(nss ...string) {
	s.t.Helper()
	for _, ns := range nss {
		waitFor(s.t, "tree to catch up with "+ns, func() bool {
			h, err := s.core.NSHead(context.Background(), ns)
			return err == nil && s.s.Checkpoint(ns) == h.ID
		})
	}
}

type resp struct {
	status int
	header http.Header
	body   map[string]any
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (s *svc) raw(path, token string) resp {
	s.t.Helper()
	req := must(http.NewRequest("GET", s.http.URL+path, nil))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r := must(noRedirect.Do(req))
	defer r.Body.Close()
	b := must(io.ReadAll(r.Body))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp{r.StatusCode, r.Header, m}
}

// get follows redirects and expects 200.
func (s *svc) get(path, token string) map[string]any {
	s.t.Helper()
	for i := 0; i < 4; i++ {
		r := s.raw(path, token)
		if r.status == 302 {
			loc := r.header.Get("Location")
			if strings.HasPrefix(loc, "?") {
				loc = path[:strings.IndexByte(path+"?", '?')] + loc
			}
			path = loc
			continue
		}
		if r.status != 200 {
			s.t.Fatalf("GET %s: %d %v", path, r.status, r.body)
		}
		return r.body
	}
	s.t.Fatalf("GET %s: too many redirects", path)
	return nil
}

// names returns the "name" of each object in a list.
func names(v any) string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return strings.Join(out, ",")
}

func pathsOf(v any) string {
	var out []string
	for _, p := range v.([]any) {
		var seg []string
		for _, x := range p.([]any) {
			seg = append(seg, x.(map[string]any)["name"].(string))
		}
		out = append(out, strings.Join(seg, "/"))
	}
	return strings.Join(out, " | ")
}

// world is a dev-mode core with a catalog "cat" trusting "matches".
type world struct {
	s *clienttest.Server
	c *client.Client
}

func setup(t *testing.T) *world {
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	ctx := context.Background()
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "docs", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	return &world{s: s, c: c}
}

func parents(ps ...string) []any {
	var out []any
	for _, p := range ps {
		href, order, _ := strings.Cut(p, "@")
		e := map[string]any{"href": "/r/cat/" + href}
		if order != "" {
			e["order"] = order
		}
		out = append(out, e)
	}
	if out == nil {
		out = []any{}
	}
	return out
}

func (w *world) folder(t *testing.T, name, title string, ps ...string) {
	t.Helper()
	must(w.c.CreateDoc(context.Background(), "cat", name, map[string]any{"title": title, "parents": parents(ps...)}))
}

func (w *world) place(t *testing.T, item string, ps ...string) {
	t.Helper()
	must(w.c.CreateDoc(context.Background(), "cat", item, map[string]any{"parents": parents(ps...)}))
}

func (w *world) content(t *testing.T, ns, name string) string {
	t.Helper()
	return must(w.c.CreateDoc(context.Background(), ns, name, map[string]any{"title": name})).ID
}

func (w *world) replace(t *testing.T, ns, name, path string, v any) {
	t.Helper()
	ctx := context.Background()
	h := must(w.c.Head(ctx, ns, name))
	must(w.c.Append(ctx, ns, name, h.ID, []any{map[string]any{"op": "replace", "path": path, "value": v}}))
}

func (w *world) del(t *testing.T, ns, name string) {
	t.Helper()
	ctx := context.Background()
	h := must(w.c.Head(ctx, ns, name))
	must(w.c.Delete(ctx, ns, name, h.ID))
}

func (w *world) seed(t *testing.T) {
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season 2026", "root@a0")
	w.folder(t, "derbies", "Derbies", "root@a1")
	w.content(t, "matches", "derby")
	w.content(t, "matches", "opener")
	w.place(t, "matches.derby", "season@a1", "derbies@Zz")
	w.place(t, "matches.opener", "season@a0")
	w.place(t, "matches.cup", "season") // dangling: no such item yet
}

func TestTreeListings(t *testing.T) {
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")

	// The head pointer redirects to the combined checkpoint (§B.5).
	cp := x.s.At()
	if want := combined(map[string]any{"cat": x.s.Checkpoint("cat"), "matches": x.s.Checkpoint("matches")}); cp != want {
		t.Fatalf("combined checkpoint %s, want %s", cp, want)
	}
	r := x.raw("/cat/children?of=season", "")
	if r.status != 302 || r.header.Get("Location") != "/cat/at/"+cp+"/children?of=season" ||
		!strings.Contains(r.header.Get("Cache-Control"), "s-maxage=1") {
		t.Fatalf("pointer: %d %v", r.status, r.header)
	}
	r = x.raw("/cat/at/"+cp+"/children?of=season", "")
	if r.status != 200 || !strings.Contains(r.header.Get("Cache-Control"), "immutable") || r.body["at"] != cp {
		t.Fatalf("listing: %d %v", r.status, r.header)
	}
	// Tagged with every item shown and every namespace in the checkpoint.
	tags := tagSet(r)
	for _, want := range []string{"ns:cat", "ns:matches", "r:cat/season", "r:cat/matches.derby", "r:matches/derby", "r:matches/opener"} {
		if !tags[want] {
			t.Errorf("listing lacks tag %s: %s", want, r.header.Get("Cache-Tag"))
		}
	}
	if tags["r:cat/derbies"] || tags["r:cat/root"] {
		t.Errorf("listing tags nodes it doesn't show: %s", r.header.Get("Cache-Tag"))
	}
	// A stale checkpoint redirects to the current one.
	w.folder(t, "extra", "Extra", "root@b0")
	x.caughtUp("cat")
	if r := x.raw("/cat/at/"+cp+"/children?of=season", ""); r.status != 302 || !strings.Contains(r.header.Get("Location"), x.s.At()) || x.s.At() == cp {
		t.Errorf("stale at: %d %v", r.status, r.header)
	}
	// A content change alone moves the combined checkpoint too.
	cp = x.s.At()
	w.replace(t, "matches", "opener", "/title", "Opener!")
	x.caughtUp("matches")
	if x.s.At() == cp {
		t.Error("content change did not change at")
	}
	if r := x.raw("/cat/at/"+cp+"/children?of=season", ""); r.status != 302 || r.header.Get("Location") != "/cat/at/"+x.s.At()+"/children?of=season" {
		t.Errorf("at after content change: %d %v", r.status, r.header)
	}

	b := x.get("/cat/children?of=season", "")
	if got := names(b["children"]); got != "matches.opener,matches.derby" {
		t.Errorf("children of season: %s", got)
	}
	kid := b["children"].([]any)[1].(map[string]any)
	if kid["item"] != "/r/matches/derby" || kid["order"] != "a1" || kid["kind"] != "item" ||
		!strings.HasPrefix(kid["url"].(string), clienttest.Origin+"/r/matches/derby/rev/"+kid["head"].(string)) {
		t.Errorf("item entry %v", kid)
	}
	if got := names(x.get("/cat/children?of=/r/cat/root", "")["children"]); got != "season,derbies,extra" {
		t.Errorf("children of root: %s", got)
	}

	// The dangling placement appears once its item exists (read-your-writes with min).
	must(w.c.CreateDoc(context.Background(), "matches", "cup", map[string]any{"title": "cup"}))
	nsHead := must(w.c.NSHead(context.Background(), "matches")).ID
	b = x.get("/cat/children?of=season&min=matches:"+nsHead+"&min=cat:"+x.s.Checkpoint("cat"), "")
	if got := names(b["children"]); got != "matches.opener,matches.derby,matches.cup" {
		t.Errorf("children after create: %s", got)
	}
	// A bare ns_id still works; unknown namespaces and malformed values are 400.
	x.get("/cat/children?of=season&min="+nsHead, "")
	for _, m := range []string{"docs:" + nsHead, "Bad:" + nsHead, "matches:nope"} {
		if r := x.raw("/cat/children?of=season&min="+m, ""); r.status != 400 {
			t.Errorf("min=%s: %d", m, r.status)
		}
	}
	// Pagination with ?after and next links.
	b = x.get("/cat/children?of=season&limit=1", "")
	if names(b["children"]) != "matches.opener" || b["next"] == nil {
		t.Fatalf("page 1: %v", b)
	}
	b = x.get("/cat/children"+b["next"].(string), "")
	if names(b["children"]) != "matches.derby" {
		t.Fatalf("page 2: %v", b)
	}
	b = x.get("/cat/children"+b["next"].(string), "")
	if names(b["children"]) != "matches.cup" || b["next"] != nil {
		t.Fatalf("page 3: %v", b)
	}
	if got := names(x.get("/cat/children?of=season&after=a0", "")["children"]); got != "matches.derby,matches.cup" {
		t.Errorf("after=a0: %s", got)
	}

	// Ancestors: every path to a root, for an item or a folder.
	b = x.get("/cat/ancestors?of=/r/matches/derby", "")
	if got := pathsOf(b["paths"]); got != "root/season | root/derbies" {
		t.Errorf("ancestors: %s", got)
	}
	if got := pathsOf(x.get("/cat/ancestors?of=root", "")["paths"]); got != "" {
		t.Errorf("ancestors of root: %q", got)
	}
	// Subtree.
	b = x.get("/cat/subtree?of=root&depth=1", "")
	tr := b["tree"].(map[string]any)
	if names(tr["children"]) != "season,derbies,extra" || tr["children"].([]any)[0].(map[string]any)["more"] != true {
		t.Errorf("subtree depth 1: %v", tr)
	}
	b = x.get("/cat/subtree?of=root", "")
	season := b["tree"].(map[string]any)["children"].([]any)[0].(map[string]any)
	if names(season["children"]) != "matches.opener,matches.derby,matches.cup" {
		t.Errorf("subtree: %v", season)
	}
	// Roots and where.
	if got := names(x.get("/cat/roots", "")["roots"]); got != "root" {
		t.Errorf("roots: %s", got)
	}
	b = x.get("/cat/where?item=/r/matches/opener", "")
	if b["placement"].(map[string]any)["href"] != "/r/cat/matches.opener" || pathsOf(b["paths"]) != "root/season" {
		t.Errorf("where: %v", b)
	}
	if b := x.get("/cat/where?item=/r/matches/nowhere", ""); b["placement"] != nil {
		t.Errorf("where unplaced: %v", b)
	}
	if r := x.raw("/cat/at/"+x.s.At()+"/children?of=nope", ""); r.status != 404 {
		t.Errorf("unknown folder: %d", r.status)
	}
	if r := x.raw("/other/children?of=x", ""); r.status != 404 {
		t.Errorf("other catalog: %d", r.status)
	}
}

func combined(m map[string]any) string {
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(m)))
	return ids.FromBytes(sum[:ids.Size]).String()
}

func tagSet(r resp) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Split(r.header.Get("Cache-Tag"), ",") {
		if t != "" {
			out[t] = true
		}
	}
	return out
}

func TestMovesAndDeletes(t *testing.T) {
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")

	// Move: replace /parents (one write on the node).
	w.replace(t, "cat", "matches.opener", "/parents", parents("derbies@A0"))
	x.caughtUp("cat")
	if got := names(x.get("/cat/children?of=season", "")["children"]); got != "matches.derby" {
		t.Errorf("season after move: %s", got)
	}
	if got := names(x.get("/cat/children?of=derbies", "")["children"]); got != "matches.opener,matches.derby" {
		t.Errorf("derbies after move: %s", got)
	}
	// Reorder.
	w.replace(t, "cat", "matches.opener", "/parents/0/order", "zz")
	x.caughtUp("cat")
	if got := names(x.get("/cat/children?of=derbies", "")["children"]); got != "matches.derby,matches.opener" {
		t.Errorf("derbies after reorder: %s", got)
	}
	// Moving a subtree is one write on its top node.
	w.replace(t, "cat", "season", "/parents", parents("derbies"))
	x.caughtUp("cat")
	if got := pathsOf(x.get("/cat/ancestors?of=/r/matches/derby", "")["paths"]); got != "root/derbies/season | root/derbies" {
		t.Errorf("paths after subtree move: %s", got)
	}

	// Unplace: the item leaves the catalog, the content is untouched.
	w.del(t, "cat", "matches.opener")
	x.caughtUp("cat")
	if got := names(x.get("/cat/children?of=derbies", "")["children"]); got != "matches.derby,season" {
		t.Errorf("after unplace: %s", got)
	}
	if b := x.get("/cat/where?item=/r/matches/opener", ""); b["placement"] != nil {
		t.Errorf("where after unplace: %v", b)
	}

	// Deleting content leaves its placement dangling: out of listings, into problems.
	w.del(t, "matches", "derby")
	x.caughtUp("matches")
	if got := names(x.get("/cat/children?of=derbies", "")["children"]); got != "season" {
		t.Errorf("after content delete: %s", got)
	}
	pr := x.get("/cat/problems", "")
	di := pr["danglingItems"].([]any)
	found := false
	for _, d := range di {
		m := d.(map[string]any)
		if m["href"] == "/r/cat/matches.derby" && m["reason"] == "tombstoned" {
			found = true
		}
	}
	if !found {
		t.Errorf("problems: %v", pr)
	}
	// A tombstone moves at; nothing cached needs purging.
	x.mu.Lock()
	all := fmt.Sprint(x.purges)
	x.mu.Unlock()
	if all != "[]" {
		t.Errorf("purges: %s", all)
	}
	// A purge removes every cached listing showing the resource.
	h0 := must(w.c.Head(context.Background(), "matches", "derby"))
	must(w.c.Purge(context.Background(), "matches", "derby", h0.ID, false))
	x.caughtUp("matches")
	x.mu.Lock()
	all = fmt.Sprint(x.purges)
	x.mu.Unlock()
	if all != "[[r:matches/derby rs:cat]]" {
		t.Errorf("purges after purge: %s", all)
	}

	// Deleting a folder doesn't cascade: its children become orphans.
	w.del(t, "cat", "season")
	x.caughtUp("cat")
	orph := x.get("/cat/orphans", "")["orphans"]
	if got := names(orph); !strings.Contains(got, "matches.cup") {
		t.Errorf("orphans: %s", got)
	}
	p0 := orph.([]any)[0].(map[string]any)["parents"].([]any)[0].(map[string]any)
	if p0["state"] != "dangling" || p0["href"] != "/r/cat/season" {
		t.Errorf("orphan parents: %v", p0)
	}
	// Restoring re-attaches everything that pointed at it.
	h := must(w.c.Head(context.Background(), "cat", "season"))
	must(w.c.Restore(context.Background(), "cat", "season", h.ID, []any{}))
	x.caughtUp("cat")
	if got := names(x.get("/cat/orphans", "")["orphans"]); got != "" {
		t.Errorf("orphans after restore: %s", got)
	}
	if got := names(x.get("/cat/children?of=derbies", "")["children"]); got != "season" {
		t.Errorf("derbies after restore: %s", got)
	}
}

func TestCyclesDepthAndDanglingParents(t *testing.T) {
	w := setup(t)
	w.folder(t, "root", "Root")
	// A cycle a -> b -> a, hanging below root through a.
	w.folder(t, "a", "A", "root", "b")
	w.folder(t, "b", "B", "a")
	w.content(t, "matches", "m1")
	w.place(t, "matches.m1", "b")
	// Dangling and invalid parents.
	w.folder(t, "lost", "Lost", "ghost")
	must(w.c.CreateDoc(context.Background(), "cat", "odd", map[string]any{"parents": []any{
		map[string]any{"href": "/r/cat/root/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		map[string]any{"href": "/r/matches/m1"},
		map[string]any{"href": "/r/cat/matches.m1"}}}))
	// A chain deeper than 64.
	prev := "root"
	for i := 0; i < 67; i++ {
		name := fmt.Sprintf("d%02d", i)
		w.folder(t, name, name, prev)
		prev = name
	}
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")

	pr := x.get("/cat/problems", "")
	if got := fmt.Sprint(pr["cycles"]); got != "[[/r/cat/a /r/cat/b]]" {
		t.Errorf("cycles: %s", got)
	}
	dp := fmt.Sprint(pr["danglingParents"])
	for _, want := range []string{"lost parent:/r/cat/ghost state:dangling", "not a live link (pinned or malformed)", "links to another namespace", "state:not-folder"} {
		if !strings.Contains(dp, want) {
			t.Errorf("dangling parents lack %q: %s", want, dp)
		}
	}
	deep := pr["tooDeep"].([]any)
	if len(deep) != 3 || deep[0].(map[string]any)["href"] != "/r/cat/d64" || deep[0].(map[string]any)["depth"] != 65.0 {
		t.Errorf("tooDeep: %v", deep)
	}
	// Cyclic folders are excluded from traversals: root's children lack a,
	// and m1 (whose only parent is in the cycle) is an orphan.
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "d00" {
		t.Errorf("root children: %s", got)
	}
	if got := names(x.get("/cat/orphans", "")["orphans"]); got != "a,b,lost,matches.m1,odd" {
		t.Errorf("orphans: %s", got)
	}
	// Walks stop at depth 64.
	b := x.get("/cat/ancestors?of=d66", "")
	if b["tooDeep"] == nil || len(b["paths"].([]any)) != 0 {
		t.Errorf("deep ancestors: %v", b)
	}
	// Breaking the cycle heals it.
	w.replace(t, "cat", "a", "/parents", parents("root"))
	x.caughtUp("cat")
	pr = x.get("/cat/problems", "")
	if len(pr["cycles"].([]any)) != 0 {
		t.Errorf("cycles after fix: %v", pr["cycles"])
	}
	if got := pathsOf(x.get("/cat/ancestors?of=/r/matches/m1", "")["paths"]); got != "root/a/b" {
		t.Errorf("m1 paths: %s", got)
	}
}

func TestManifest(t *testing.T) {
	w := setup(t)
	w.seed(t)
	w.folder(t, "sub", "Sub", "season@b0")
	w.content(t, "matches", "final")
	w.place(t, "matches.final", "sub@a0")
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	ctx := context.Background()
	derby := must(w.c.Head(ctx, "matches", "derby")).ID
	season := must(w.c.Head(ctx, "cat", "season")).ID

	m := x.get("/cat/manifest?of=season", "")
	if m["catalog"] != "cat" || m["root"] != "/r/cat/season/rev/"+season {
		t.Errorf("manifest header: %v", m)
	}
	got := fmt.Sprint(m["entries"])
	want := fmt.Sprintf("[map[href:/r/matches/opener/rev/%s order:a0 path:[season]] map[href:/r/matches/derby/rev/%s order:a1 path:[season]] map[href:/r/matches/final/rev/%s order:a0 path:[season sub]]]",
		must(w.c.Head(ctx, "matches", "opener")).ID, derby, must(w.c.Head(ctx, "matches", "final")).ID)
	if got != want {
		t.Errorf("entries:\n got %s\nwant %s", got, want)
	}
	// The manifest is a valid document to create as an ordinary resource,
	// and pins exactly the revisions of its checkpoint.
	must(w.c.CreateDoc(ctx, "docs", "release-1", m))
	w.replace(t, "matches", "derby", "/title", "changed")
	x.caughtUp("matches")
	m2 := x.get("/cat/manifest?of=season", "")
	if fmt.Sprint(m2["entries"]) == got {
		t.Error("manifest did not follow the new head")
	}
	d := must(w.c.Doc(ctx, "matches", "derby", derby))
	if d.Value.(map[string]any)["title"] != "derby" {
		t.Error("pinned revision changed")
	}
}

func TestTrustAndRestart(t *testing.T) {
	w := setup(t)
	w.seed(t)
	w.content(t, "docs", "guide")
	w.place(t, "docs.guide", "root")
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, w.c, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	pr := x.get("/cat/problems", "")
	if !strings.Contains(fmt.Sprint(pr["danglingItems"]), "href:/r/cat/docs.guide item:/r/docs/guide reason:untrusted") {
		t.Errorf("untrusted: %v", pr["danglingItems"])
	}
	if x.s.Checkpoint("docs") != "" {
		t.Error("followed an untrusted namespace")
	}
	// Trusting docs starts following it.
	ctx := context.Background()
	h := must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "docs"}}))
	x.caughtUp("cat", "docs")
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "season,derbies,docs.guide" {
		t.Errorf("after trust: %s", got)
	}

	// Restart: nothing is reprocessed, and new entries are picked up.
	before := x.batches()
	x.stop()
	y := startSvc(t, w.c, svcOpts{db: db})
	y.caughtUp("cat", "matches", "docs")
	time.Sleep(200 * time.Millisecond)
	if n := y.batches(); n != 0 {
		t.Errorf("restart reprocessed %d batches (first run: %d)", n, before)
	}
	if got := names(y.get("/cat/children?of=root", "")["children"]); got != "season,derbies,docs.guide" {
		t.Errorf("after restart: %s", got)
	}
	w.content(t, "matches", "cup")
	y.caughtUp("matches")
	if got := names(y.get("/cat/children?of=season", "")["children"]); got != "matches.opener,matches.derby,matches.cup" {
		t.Errorf("after restart and create: %s", got)
	}
	if y.batches() != 1 {
		t.Errorf("batches after one write: %d", y.batches())
	}
	// Untrusting leaves docs' placements dangling.
	h = must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{"matches"}}}))
	y.caughtUp("cat")
	if got := names(y.get("/cat/children?of=root", "")["children"]); got != "season,derbies" {
		t.Errorf("after untrust: %s", got)
	}
}

func TestSelfPlacing(t *testing.T) {
	w := setup(t)
	w.folder(t, "root", "Root")
	w.folder(t, "news", "News", "root")
	must(w.c.CreateDoc(context.Background(), "matches", "s1", map[string]any{"title": "s1",
		"$parents": []any{map[string]any{"href": "/r/cat/news", "order": "b"}, map[string]any{"href": "/r/other/x"}}}))
	// Off by default.
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	if got := names(x.get("/cat/children?of=news", "")["children"]); got != "" {
		t.Errorf("self-placement accepted by default: %s", got)
	}
	x.stop()

	y := startSvc(t, w.c, svcOpts{selfPlacing: true})
	y.caughtUp("cat", "matches")
	b := y.get("/cat/children?of=news", "")
	if got := names(b["children"]); got != "matches.s1" || b["children"].([]any)[0].(map[string]any)["self"] != true {
		t.Errorf("self-placement: %v", b)
	}
	// An explicit placement wins.
	w.place(t, "matches.s1", "root@a")
	y.caughtUp("cat")
	if got := names(y.get("/cat/children?of=news", "")["children"]); got != "" {
		t.Errorf("explicit placement didn't win: %s", got)
	}
	if got := names(y.get("/cat/children?of=root", "")["children"]); got != "matches.s1,news" {
		t.Errorf("root: %s", got)
	}
	// Removing the explicit one brings back the implicit one.
	w.del(t, "cat", "matches.s1")
	y.caughtUp("cat")
	if got := names(y.get("/cat/children?of=news", "")["children"]); got != "matches.s1" {
		t.Errorf("implicit after unplace: %s", got)
	}
	// Moving the implicit placement means editing the content.
	w.replace(t, "matches", "s1", "/$parents", []any{map[string]any{"href": "/r/cat/root"}})
	y.caughtUp("matches")
	if got := names(y.get("/cat/children?of=root", "")["children"]); got != "matches.s1,news" {
		t.Errorf("after content move: %s", got)
	}
}

func TestPrivateCatalog(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, reader := clienttest.NewKey("admin"), clienttest.NewKey("reader")
	for _, ns := range []string{"sec", "cat"} {
		op := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), reader.Entry("read")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}}
		}
		must(op.CreateNamespace(ctx, ns, doc))
	}
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec", "cat"}, []string{"read", "create", "append"})))
	must(root.CreateDoc(ctx, "cat", "top", map[string]any{"title": "Top", "parents": []any{}}))
	must(root.CreateDoc(ctx, "cat", "hidden", map[string]any{"title": "Hidden", "parents": parents("top@b")}))
	must(root.CreateDoc(ctx, "sec", "a", map[string]any{"t": 1}))
	must(root.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("top@a")}))

	svcClient := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"})))
	x := startSvc(t, svcClient, svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")

	if r := x.raw("/cat/children?of=top", ""); r.status != 401 {
		t.Errorf("anonymous: %d", r.status)
	}
	if r := x.raw("/cat/children?of=top", reader.Grant(t, s.Now(), "user:x", []string{"sec"}, []string{"read"})); r.status != 403 {
		t.Errorf("grant for another namespace: %d", r.status)
	}
	// Whole-catalog reader without content read: structure, no heads.
	catOnly := reader.Grant(t, s.Now(), "user:bob", []string{"cat"}, []string{"read"}, map[string]any{"groups": []any{"eds"}})
	r := x.raw("/cat/children?of=top", catOnly)
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.Contains(loc, "/g/") || r.header.Get("Cache-Control") != "private, no-cache" {
		t.Fatalf("pointer: %d %v", r.status, r.header)
	}
	b := x.get("/cat/children?of=top", catOnly)
	if names(b["children"]) != "sec.a,hidden" || b["children"].([]any)[0].(map[string]any)["head"] != nil {
		t.Errorf("catalog-only reader: %v", b)
	}
	// With content read, heads are shown, under another subject set.
	both := reader.Grant(t, s.Now(), "user:bob", []string{"cat", "sec"}, []string{"read"}, map[string]any{"groups": []any{"eds"}})
	b = x.get("/cat/children?of=top", both)
	if b["children"].([]any)[0].(map[string]any)["head"] == nil {
		t.Errorf("content reader sees no head: %v", b)
	}
	if r2 := x.raw("/cat/children?of=top", both); r2.header.Get("Location") == loc {
		t.Error("readers with different content access share a subject set")
	}
	// A second user with the same access shares the URL (and caches).
	amy := reader.Grant(t, s.Now(), "user:amy", []string{"cat"}, []string{"read"}, map[string]any{"groups": []any{"eds"}})
	if r2 := x.raw("/cat/children?of=top", amy); r2.header.Get("Location") != loc {
		t.Errorf("amy: %s vs %s", r2.header.Get("Location"), loc)
	}
	// A resource-scoped reader sees only the nodes it may read.
	scoped := reader.Grant(t, s.Now(), "user:bob", []string{"cat"}, []string{"read"}, map[string]any{"groups": []any{"eds"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"top", "sec.a"}}}}})
	if got := names(x.get("/cat/children?of=top", scoped)["children"]); got != "sec.a" {
		t.Errorf("scoped reader: %s", got)
	}
	if r := x.raw(x.raw("/cat/children?of=hidden", scoped).header.Get("Location"), scoped); r.status != 404 {
		t.Errorf("scoped reader on a hidden folder: %d", r.status)
	}
}

// TestManyTag: a listing showing more resources than fit in its tags
// carries rs:{catalog}, which every purge of a resource purges (§B.5).
func TestManyTag(t *testing.T) {
	w := setup(t)
	w.folder(t, "root", "Root")
	var items []client.BatchItem
	for i := 0; i < 210; i++ {
		items = append(items, client.BatchItem{Resource: fmt.Sprintf("f%03d", i), IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": "x", "parents": parents("root")}))}})
	}
	must(w.c.Batch(context.Background(), "cat", client.BatchRequest{Items: items}, false))
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	r := x.raw("/cat/at/"+x.s.At()+"/children?of=root&limit=1000", "")
	if r.status != 200 || r.header.Get("Cache-Tag") != "ns:cat,ns:matches,rs:cat" {
		t.Fatalf("large listing: %d %s", r.status, r.header.Get("Cache-Tag"))
	}
	// Purging a namespace purges ns:{ns} (every listing whose checkpoint covers it).
	ctx := context.Background()
	cfg := must(w.c.NSHead(ctx, "matches")).Config
	must(w.c.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(w.c.PurgeNamespace(ctx, "matches", must(w.c.NSHead(ctx, "matches")).ID))
	waitFor(t, "purge-ns tags", func() bool {
		x.mu.Lock()
		defer x.mu.Unlock()
		return strings.Contains(fmt.Sprint(x.purges), "ns:matches rs:cat")
	})
}
