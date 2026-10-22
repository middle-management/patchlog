package tree_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// scopedWorld is a private catalog cat trusting sec, with root, season
// under root, a placement of sec/derby under season and a folder lost
// whose one parent doesn't exist; scope gives a reader's grant for cat
// that reads only the named catalog resources.
func scopedWorld(t *testing.T) (x *svc, scope func(names ...any) string, whole string) {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, reader := clienttest.NewKey("admin"), clienttest.NewKey("reader")
	for _, ns := range []string{"sec", "cat"} {
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), reader.Entry("read")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec", "cat"}, []string{"read", "create", "append"})))
	must(root.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(root.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Season", "parents": parents("root@a0")}))
	must(root.CreateDoc(ctx, "cat", "lost", map[string]any{"title": "Lost", "parents": parents("nope")}))
	must(root.CreateDoc(ctx, "sec", "derby", map[string]any{"t": 1}))
	must(root.CreateDoc(ctx, "cat", "sec.derby", map[string]any{"parents": parents("season@a0")}))
	x = startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"}))), svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")
	scope = func(names ...any) string {
		return reader.Grant(t, s.Now(), "user:bob", []string{"cat", "sec"}, []string{"read"}, map[string]any{
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}})
	}
	return x, scope, reader.Grant(t, s.Now(), "user:amy", []string{"cat", "sec"}, []string{"read"})
}

// atURL is the listing URL a reader's head pointer for path redirects to.
func (s *svc) atURL(path, token string) string {
	s.t.Helper()
	r := s.raw(path, token)
	if r.status != 302 {
		s.t.Fatalf("GET %s: %d %v", path, r.status, r.body)
	}
	return r.header.Get("Location")
}

// TC-4 (§B.11.5): a visible node whose parents are all hidden is a root
// for the reader's subject set: roots lists it, and the paths of
// ancestors and where end at it. A node whose parents are all dangling is
// an orphan, never a root.
func TestV073RootsForSubjectSet(t *testing.T) {
	t.Parallel()
	x, scope, whole := scopedWorld(t)
	if got := names(x.get("/cat/roots", whole)["roots"]); got != "root" {
		t.Errorf("roots for a whole reader: %s", got)
	}
	bob := scope("season", "sec.derby", "lost", "derby")
	if got := names(x.get("/cat/roots", bob)["roots"]); got != "season" {
		t.Errorf("roots for a reader who can't see root: %s", got)
	}
	b := x.get("/cat/ancestors?of=/r/sec/derby", bob)
	if got := pathsOf(b["paths"]); got != "season" || b["incomplete"] != nil {
		t.Errorf("ancestors end at the reader's root: %v", b)
	}
	if b := x.get("/cat/ancestors?of=season", bob); len(b["paths"].([]any)) != 1 || b["incomplete"] != nil {
		t.Errorf("a root for the reader has one empty path: %v", b)
	}
	if got := pathsOf(x.get("/cat/where?item=/r/sec/derby", bob)["paths"]); got != "season" {
		t.Errorf("where ends at the reader's root: %s", got)
	}
	if got := pathsOf(x.get("/cat/where?item=/r/sec/derby", whole)["paths"]); got != "root/season" {
		t.Errorf("where for a whole reader: %s", got)
	}
}

// TC-5 (§B.5, §B.11.5): where?item= naming an item that isn't in the
// catalog, or whose placement is hidden from the reader, is 404 with one
// message.
func TestV073WhereNotFound(t *testing.T) {
	t.Parallel()
	x, scope, whole := scopedWorld(t)
	if b := x.get("/cat/where?item=/r/sec/derby", whole); b["placement"].(map[string]any)["name"] != "sec.derby" {
		t.Fatalf("where: %v", b)
	}
	missing := x.raw(x.atURL("/cat/where?item=/r/sec/nowhere", whole), whole)
	bob := scope("root", "season")
	hidden := x.raw(x.atURL("/cat/where?item=/r/sec/derby", bob), bob)
	for name, r := range map[string]resp{"not in the catalog": missing, "hidden": hidden} {
		if r.status != 404 || r.body["code"] != "not_found" || r.body["placement"] != nil {
			t.Errorf("%s: %d %v", name, r.status, r.body)
		}
	}
	if missing.body["message"] != hidden.body["message"] {
		t.Errorf("messages differ: %v, %v", missing.body, hidden.body)
	}
	if r := x.raw(x.atURL("/cat/where?item=/r/cat/root", whole), whole); r.status != 400 {
		t.Errorf("a catalog node as item: %d", r.status)
	}
}

// TC-18 (§A.5): a refused min is 400 with the refused mins listed as min,
// and a min naming a namespace the service holds as purged counts as
// reached: the listing redirects to the current at, with no wait and no
// read check.
func TestV073MinRefusedAndPurged(t *testing.T) {
	t.Parallel()
	w := setup(t)
	ctx := context.Background()
	w.folder(t, "root", "Root")
	must(w.c.CreateNamespace(ctx, "old", map[string]any{"read": "grant"}))
	cfg := must(w.c.NSHead(ctx, "cat")).Config
	must(w.c.PatchConfig(ctx, "cat", cfg, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{"matches", "old"}}}))
	early := must(w.c.CreateDoc(ctx, "old", "x", map[string]any{"t": 1})).NSID
	must(w.c.PatchConfig(ctx, "old", must(w.c.NSHead(ctx, "old")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(w.c.PurgeNamespace(ctx, "old", must(w.c.NSHead(ctx, "old")).ID))
	// Started after the purge, the service never saw early.
	x := startSvc(t, w.c, svcOpts{}, func(o *tree.Options) { o.MinWait = 300 * time.Millisecond })
	x.caughtUp("cat", "matches", "old")

	r := x.raw("/cat/roots?min=old:"+early, "")
	if r.status != 302 || r.header.Get("Location") != "/cat/at/"+x.s.At()+"/roots" {
		t.Errorf("min naming a purged namespace: %d %v %s", r.status, r.body, r.header.Get("Location"))
	}
	ok := "matches:" + must(w.c.NSHead(ctx, "matches")).ID
	r = x.raw("/cat/roots?min=zz:"+early+"&min="+ok+"&min=Bad:"+early, "")
	if r.status != 400 || r.body["code"] != "bad_input" || r.header.Get("Cache-Control") != "no-store" ||
		fmt.Sprint(r.body["min"]) != fmt.Sprint([]any{"zz:" + early, "Bad:" + early}) {
		t.Errorf("refused mins: %d %v", r.status, r.body)
	}
	r = x.raw("/cat/roots?min=docs:"+early, "")
	if r.status != 400 || fmt.Sprint(r.body["min"]) != "[docs:"+early+"]" {
		t.Errorf("an unfollowed namespace: %d %v", r.status, r.body)
	}
}

// TC-19 (§12.1, §E.2.6): while the keys a listing needs can't be fetched
// yet, it is 503 behind with Retry-After.
func TestV073BehindWhileKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"files": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"cat":   {"read": "grant", "keys": []any{k.Entry("*")}, "catalog": filesCatalog("files")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "files"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"parents": []any{}}))
	createNonced(t, w, "files", "notes", map[string]any{"n": 1})
	must(w.CreateDoc(ctx, "cat", "files.notes", map[string]any{"parents": parents("root")}))
	ft := &flaky{prefix: "/ns/files/keys"}
	sc := s.Client(t, client.WithHTTPClient(&http.Client{Transport: ft}), client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})),
		client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "files")
	reader := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	x.fetch("/cat/children?of=root", reader)

	must(w.PatchConfig(ctx, "files", must(w.NSHead(ctx, "files")).Config, []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": 2}}))
	x.caughtUp("files")
	ft.fail.Store(1 << 20)
	defer ft.fail.Store(0)
	r := x.raw("/cat/children?of=root", reader)
	if loc := r.header.Get("Location"); r.status == 302 {
		r = x.raw(loc, reader)
	}
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || !strings.Contains(r.header.Get("Cache-Control"), "no-store") {
		t.Fatalf("listing without the key: %d %v %v", r.status, r.header, r.body)
	}
}
