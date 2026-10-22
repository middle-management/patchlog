package tree_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
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
	// Readers limited to some resources read a subject set's listings,
	// which need a RoleView (§B.11.5).
	x = startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"}))), svcOpts{now: s.Now}, withScopeView)
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

// ENC-35, TC-9 (§B.2, §B.5, §E.2.6): sibling order keys compare by UTF-8
// bytes, and children pages as /_refs does: next is the query of the
// following page, its after an opaque position that encodes no order
// value, and a limit above the maximum is 400. The cursor of earlier
// releases (after={order}&name=…) is still accepted.
func TestV073ChildrenOrderAndCursor(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	// By UTF-16 code units U+1F600 (a surrogate pair) sorts before U+FF01;
	// by UTF-8 bytes after it.
	w.folder(t, "fw", "Fullwidth", "root@a！")
	w.folder(t, "emoji", "Emoji", "root@a\U0001F600")
	w.folder(t, "plain", "Plain", "root@a0")
	w.folder(t, "un", "Unordered", "root")
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	b := x.get("/cat/children?of=root", "")
	if got := names(b["children"]); got != "plain,fw,emoji,un" {
		t.Errorf("children by UTF-8 bytes: %s", got)
	}
	var seen []string
	next := "?limit=1&of=root"
	for i := 0; next != ""; i++ {
		if i > 5 {
			t.Fatal("too many pages")
		}
		b = x.get("/cat/children"+next, "")
		seen = append(seen, names(b["children"]))
		if b["total"] != float64(4) {
			t.Errorf("page %d total %v", i, b["total"])
		}
		next, _ = b["next"].(string)
		for _, order := range []string{"a0", "a%EF%BC%81", "a%F0%9F%98%80", "unordered"} {
			if strings.Contains(next, order) {
				t.Errorf("next %q carries an order value or the old cursor", next)
			}
		}
	}
	if strings.Join(seen, ",") != "plain,fw,emoji,un" {
		t.Errorf("pages: %v", seen)
	}
	// The old cursor, for one release.
	if got := names(x.get("/cat/children?of=root&after=a0&name=plain", "")["children"]); got != "fw,emoji,un" {
		t.Errorf("old cursor: %s", got)
	}
	if got := names(x.get("/cat/children?of=root&name=plain&unordered=1", "")["children"]); got != "un" {
		t.Errorf("old cursor past the ordered: %s", got)
	}
	at := x.s.At()
	if r := x.raw("/cat/at/"+at+"/children?limit=1001&of=root", ""); r.status != 400 {
		t.Errorf("limit above the maximum: %d", r.status)
	}
	if r := x.raw("/cat/at/"+at+"/children?limit=1000&of=root", ""); r.status != 200 {
		t.Errorf("limit at the maximum: %d", r.status)
	}
}

// TC-50 (§B.9): an explicit placement of an item wins over $parents
// whether it is live, deleted or purged, across a restart.
func TestV073ExplicitPlacementWins(t *testing.T) {
	t.Parallel()
	w := setup(t)
	ctx := context.Background()
	w.folder(t, "root", "Root")
	w.folder(t, "news", "News", "root")
	for _, n := range []string{"a", "b"} {
		must(w.c.CreateDoc(ctx, "matches", n, map[string]any{"$parents": []any{map[string]any{"href": "/r/cat/news"}}}))
		w.place(t, "matches."+n, "root")
	}
	db := t.TempDir() + "/tree.db"
	x := startSvc(t, w.c, svcOpts{selfPlacing: true, db: db})
	x.caughtUp("cat", "matches")
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "matches.a,matches.b,news" {
		t.Fatalf("explicit placements: %s", got)
	}
	w.del(t, "cat", "matches.a")
	must(w.c.Purge(ctx, "cat", "matches.b", must(w.c.Head(ctx, "cat", "matches.b")).ID, false))
	x.caughtUp("cat")
	check := func(when string) {
		t.Helper()
		if got := names(x.get("/cat/children?of=news", "")["children"]); got != "" {
			t.Errorf("%s: $parents won over a deleted or purged placement: %s", when, got)
		}
		if got := names(x.get("/cat/children?of=root", "")["children"]); got != "news" {
			t.Errorf("%s: root %s", when, got)
		}
	}
	check("deleted and purged")
	x.stop()
	x = startSvc(t, w.c, svcOpts{selfPlacing: true, db: db})
	x.caughtUp("cat", "matches")
	check("after a restart")
	// A database from before the records were kept: a start fills them in
	// from the catalog's /heads.
	x.stop()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	for _, q := range []string{`DELETE FROM explicit_gone`, `DELETE FROM meta WHERE k = 'gone'`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sq.Close()
	x = startSvc(t, w.c, svcOpts{selfPlacing: true, db: db})
	x.caughtUp("cat", "matches")
	waitFor(t, "the records filled in", func() bool { return names(x.get("/cat/children?of=news", "")["children"]) == "" })
	check("filled in")
	// Restored, the explicit placement shows.
	th := must(w.c.Head(ctx, "cat", "matches.a"))
	must(w.c.Append(ctx, "cat", "matches.a", th.ID, []any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"parents": parents("root")}}}))
	x.caughtUp("cat")
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "matches.a,news" {
		t.Errorf("restored: %s", got)
	}
}

// DeclaredChildren is every node that names a folder in its parents,
// valid edge or not.
func TestV073DeclaredChildren(t *testing.T) {
	t.Parallel()
	g := tree.BuildGraph("cat", map[string]any{"catalog": map[string]any{"trust": []any{"matches"}}}, map[string]any{
		"root":      map[string]any{"parents": []any{}},
		"a":         map[string]any{"parents": []any{map[string]any{"href": "/r/cat/root"}}},
		"matches.x": map[string]any{"parents": []any{map[string]any{"href": "/r/cat/root"}, map[string]any{"href": "/r/cat/gone"}}},
		"matches.y": map[string]any{"parents": []any{map[string]any{"href": "/r/cat/gone"}}},
	})
	if got := fmt.Sprint(g.DeclaredChildren("root")); got != "[a matches.x]" {
		t.Errorf("root: %s", got)
	}
	if got := fmt.Sprint(g.DeclaredChildren("gone")); got != "[matches.x matches.y]" {
		t.Errorf("a missing folder: %s", got)
	}
	if got := g.DeclaredChildren("a"); got != nil {
		t.Errorf("a: %v", got)
	}
}

// bornOf is the created of the first revision of ns/name, from its log.
func bornOf(t *testing.T, c *client.Client, ns, name string) string {
	t.Helper()
	ctx := context.Background()
	es, _ := must2(c.LogPage(ctx, ns, name, must(c.Head(ctx, ns, name)).ID, ""))
	return es[0].Created
}

// TC-6 (§B.5): children carries total, the number of visible children,
// and every node carries born, the created of its document's first
// revision, which a database from before it gets on start.
func TestV073TotalAndBorn(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season", "root@a0")
	w.content(t, "matches", "derby")
	w.place(t, "matches.derby", "root@a1")
	w.place(t, "matches.nope", "root@a2") // dangling: not listed, not counted
	w.s.Clock.Advance(time.Hour)
	w.replace(t, "cat", "season", "/title", "Season 2026")
	db := t.TempDir() + "/tree.db"
	x := startSvc(t, w.c, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	want := map[string]string{"season": bornOf(t, w.c, "cat", "season"), "matches.derby": bornOf(t, w.c, "cat", "matches.derby")}
	check := func(when string) {
		t.Helper()
		b := x.get("/cat/children?of=root&limit=1", "")
		if b["total"] != float64(2) || names(b["children"]) != "season" {
			t.Errorf("%s: page %v", when, b)
		}
		es := entriesOf(t, x.get("/cat/children?of=root", ""))
		for name, born := range want {
			if es[name]["born"] != born {
				t.Errorf("%s: %s born %v, want %s", when, name, es[name]["born"], born)
			}
		}
		if es["season"]["born"] == createdOf(t, w.c, "cat", "season") {
			t.Errorf("%s: born is the head's created", when)
		}
		if got := x.get("/cat/roots", "")["roots"].([]any)[0].(map[string]any)["born"]; got != bornOf(t, w.c, "cat", "root") {
			t.Errorf("%s: root born %v", when, got)
		}
	}
	check("followed")
	// A database from before born: a start fills it in.
	x.stop()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	if _, err := sq.Exec(`UPDATE nodes SET born = NULL`); err != nil {
		t.Fatal(err)
	}
	sq.Close()
	x = startSvc(t, w.c, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	waitFor(t, "born filled in", func() bool {
		return entriesOf(t, x.get("/cat/children?of=root", ""))["season"]["born"] == want["season"]
	})
	check("filled in")
}

// TC-6 (§B.5, §E.2.6): in a sealed catalog born is sealed per entry with
// the title, never in the clear.
func TestV073BornSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat", "matches"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	createNonced(t, w, "cat", "plain", map[string]any{"parents": []any{}})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat", "matches"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now}, withScopeView)
	x.caughtUp("cat", "matches")
	li := k.Grant(t, s.Now(), "user:li", []string{"cat"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "plain"}}}}})
	r := x.fetch("/cat/roots", li)
	if strings.Contains(string(r.body), "born") {
		t.Fatalf("born in the clear: %s", r.body)
	}
	pr := s.Client(t, client.WithBearer(li))
	for _, e := range decode(t, r.body)["roots"].([]any) {
		e := e.(map[string]any)
		name := e["name"].(string)
		fk := must(pr.FetchKeys(ctx, "cat", nil, []string{name}))
		kr := func(kid string) []byte {
			if kid == fk[0].Kid {
				return fk[0].Key
			}
			return nil
		}
		v := decode(t, must(derived.OpenItem(e["sealed"].(string), kr, derived.View{NS: "cat", Target: r.path}, "cat", name)))
		if v["born"] != bornOf(t, w, "cat", name) || (name == "root") != (v["title"] == "Root") {
			t.Errorf("%s sealed %v", name, v)
		}
	}
}

// TC-8 (§H.3): in a file tree, a placement whose file the service can't
// give says why: pending for a head it hasn't read for it (e2e is in
// TestFileTreeSealed).
func TestV073FilePending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "files", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": filesCatalog("files")}))
	must(c.CreateDoc(ctx, "cat", "root", map[string]any{"parents": []any{}}))
	must(c.CreateDoc(ctx, "files", "a", map[string]any{"n": 1}))
	must(c.CreateDoc(ctx, "cat", "files.a", map[string]any{"title": "a.json", "parents": parents("root")}))
	db := t.TempDir() + "/tree.db"
	x := startSvc(t, c, svcOpts{db: db})
	x.caughtUp("cat", "files")
	if f := fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.a"]); f["size"] == nil {
		t.Fatalf("file %v", f)
	}
	x.stop()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	if _, err := sq.Exec(`UPDATE items SET file = NULL`); err != nil {
		t.Fatal(err)
	}
	sq.Close()
	x = startSvc(t, c, svcOpts{db: db})
	x.caughtUp("cat", "files")
	if f := fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.a"]); fmt.Sprint(f) != "map[absent:pending]" {
		t.Errorf("a head not read for its file: %v", f)
	}
}

// TC-7 (§B.5, §H.2): lookup?path= answers the node a path of titles names,
// from a file tree's root folder, or, where root is hidden from the
// reader, from its roots; titles compare after NFC and simple case
// folding, numbered and escaped display names don't resolve, and siblings
// sharing a title answer the earliest born, then node name.
func TestV073Lookup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, reader := clienttest.NewKey("admin"), clienttest.NewKey("reader")
	for _, ns := range []string{"files", "cat"} {
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), reader.Entry("read")}}
		if ns == "cat" {
			doc["catalog"] = filesCatalog("files")
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"files", "cat"}, []string{"read", "create", "append"})))
	node := func(name, title string, ps ...string) {
		t.Helper()
		must(w.CreateDoc(ctx, "cat", name, map[string]any{"title": title, "parents": parents(ps...)}))
	}
	file := func(item, title string, ps ...string) {
		t.Helper()
		must(w.CreateDoc(ctx, "files", item, map[string]any{"n": 1}))
		node("files."+item, title, ps...)
	}
	node("root", "Root")
	node("docs", "Docs", "root@a0")
	file("a", "Report.txt", "docs@a0")
	file("z", "Notes", "root@a1")
	s.Clock.Advance(time.Minute)
	file("c", "notes", "root@a2") // born later than files.z, though its name sorts first
	node("k1", "Kelvin", "root@a3")
	node("e1", "café", "root@a4")
	node("dot", "a.", "root@a5")
	node("strasse", "Straße", "root@a6")
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"files", "cat"}, []string{"read"}))), svcOpts{now: s.Now}, withScopeView)
	x.caughtUp("cat", "files")
	whole := reader.Grant(t, s.Now(), "user:amy", []string{"cat", "files"}, []string{"read"})
	lookup := func(path, tok string) resp {
		t.Helper()
		loc := x.atURL("/cat/lookup?path="+url.QueryEscape(path), tok)
		return x.raw(loc, tok)
	}
	for path, want := range map[string]string{
		"Docs":              "docs",
		"docs/REPORT.TXT":   "files.a",
		"Notes":             "files.z",
		"NOTES":             "files.z",
		"Kelvin":            "k1", // the Kelvin sign folds with k
		"café":             "e1", // NFD
		"straße":            "strasse",
		"Docs/Report.txt/x": "",
		"Notes (2)":         "", // a numbered display name
		"a%2E":              "", // an escaped display name
		"STRASSE":           "", // full folding, not simple
		"Nope":              "",
		"Root":              "", // root is where paths start
		"Docs//Report.txt":  "",
	} {
		r := lookup(path, whole)
		got := ""
		if n, _ := r.body["node"].(map[string]any); n != nil {
			got, _ = n["name"].(string)
		}
		switch {
		case want == "" && (r.status != 404 || r.body["code"] != "not_found"):
			t.Errorf("%q: %d %v", path, r.status, r.body)
		case want != "" && (r.status != 200 || got != want):
			t.Errorf("%q: %d %v, want %s", path, r.status, r.body, want)
		}
	}
	if n := lookup("Notes", whole).body["node"].(map[string]any); n["born"] != bornOf(t, w, "cat", "files.z") || n["head"] == nil {
		t.Errorf("node %v", n)
	}
	// Root hidden from the reader: from its roots, filtered like children.
	scoped := reader.Grant(t, s.Now(), "user:bob", []string{"cat", "files"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"docs", "files.a", "a"}}}}})
	if r := lookup("Docs/Report.txt", scoped); r.status != 200 || r.body["node"].(map[string]any)["name"] != "files.a" {
		t.Errorf("from the reader's roots: %d %v", r.status, r.body)
	}
	hidden, missing := lookup("Notes", scoped), lookup("Nope", scoped)
	if hidden.status != 404 || hidden.body["message"] != missing.body["message"] {
		t.Errorf("hidden %d %v, missing %d %v", hidden.status, hidden.body, missing.status, missing.body)
	}
	if r := x.raw(x.atURL("/cat/lookup", whole), whole); r.status != 400 {
		t.Errorf("no path: %d", r.status)
	}
}

// TC-7 (§B.5): lookup isn't offered in a catalog without files, nor in a
// sealed or end-to-end one: 404 not_offered.
func TestV073LookupNotOffered(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	if r := x.raw(x.atURL("/cat/lookup?path=Root", ""), ""); r.status != 404 || r.body["code"] != "not_offered" {
		t.Errorf("without files: %d %v", r.status, r.body)
	}

	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "files"))).CreateNamespace(ctx, "files", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": filesCatalog("files")}))
	sw := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat", "files"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, sw, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, sw, "cat", "docs", map[string]any{"title": "Docs", "parents": parents("root")})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat", "files"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	y := startSvc(t, sc, svcOpts{now: s.Now})
	y.caughtUp("cat", "files")
	tok := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
	if r := y.raw(y.atURL("/cat/lookup?path=Docs", tok), tok); r.status != 404 || r.body["code"] != "not_offered" {
		t.Errorf("sealed: %d %v", r.status, r.body)
	}
}

// TC-6 (§B.5, §B.9, §E.2.2, §E.2.6): an implicit placement's born is a
// value of its item, the created of the content document's first
// revision: shown only with the item's head, to readers of the item, and
// never for items of a sealed namespace, whose logs alone carry the exact
// created of their revisions, nor once a namespace is raised to sealed
// (with the item's title).
func TestV073BornOfImplicitPlacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"sec":  {"read": "public", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"priv": {"read": "grant", "keys": []any{k.Entry("*")}},
		"pub":  {"read": "public", "keys": []any{k.Entry("*")}},
		"cat":  {"read": "public", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"sec", "priv", "pub"}, "title": "/title"}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "sec", "priv", "pub"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	self := map[string]any{"title": "Doc", "$parents": []any{map[string]any{"href": "/r/cat/root"}}}
	createNonced(t, w, "sec", "doc", self)
	must(w.CreateDoc(ctx, "priv", "doc", self))
	must(w.CreateDoc(ctx, "pub", "doc", self))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now, selfPlacing: true}, withScopeView)
	x.caughtUp(all...)

	// priv isn't public, so listings are a subject set's (§B.11.5): this
	// reader's sees every node and no item of priv.
	nodes := k.Grant(t, s.Now(), "user:n", all, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource",
		"schema": map[string]any{"enum": []any{"root", "sec.doc", "priv.doc", "pub.doc"}}}}})
	es := entriesOf(t, x.get("/cat/children?of=root", nodes))
	if e := es["pub.doc"]; e["born"] != bornOf(t, w, "pub", "doc") || e["title"] != "Doc" {
		t.Errorf("an item of a public namespace: %v", e)
	}
	if e := es["sec.doc"]; e == nil || e["head"] == nil || e["born"] != nil || e["title"] != nil {
		t.Errorf("an item of a sealed namespace: %v", e)
	}
	if e := es["priv.doc"]; e == nil || e["head"] != nil || e["born"] != nil {
		t.Errorf("an item the reader can't read: %v", e)
	}
	r := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	if e := entriesOf(t, x.get("/cat/children?of=root", r))["priv.doc"]; e["head"] == nil || e["born"] != bornOf(t, w, "priv", "doc") {
		t.Errorf("an item the reader can read: %v", e)
	}

	// Raised to sealed: the values listings took from its items go.
	h := must(w.NSHead(ctx, "pub"))
	must(w.PatchConfig(ctx, "pub", h.Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
	x.caughtUp("pub")
	if e := entriesOf(t, x.get("/cat/children?of=root", nodes))["pub.doc"]; e == nil || e["head"] == nil || e["born"] != nil || e["title"] != nil {
		t.Errorf("an item of a namespace raised to sealed: %v", e)
	}
}

// logGate counts the resource log requests (…/rev/{id}/log) under prefix
// and, while hold is open, holds them.
type logGate struct {
	prefix string
	n      atomic.Int32
	hold   chan struct{}
}

func (g *logGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, g.prefix) && strings.HasSuffix(r.URL.Path, "/log") {
		g.n.Add(1)
		if g.hold != nil {
			select {
			case <-g.hold:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// TC-6 (§B.5, §7.1): a born that can't be known, its chain cut by a
// prune (410 pruned), is recorded with the node: neither a later head nor
// a restart reads the log for it again, and a 410 pruned isn't logged as
// a failure.
func TestV073BornUnknownRecorded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.folder(t, "root", "Root")
	a := must(w.c.CreateDoc(ctx, "cat", "season", map[string]any{"title": "S", "parents": parents("root")}))
	a1 := must(w.c.Append(ctx, "cat", "season", a.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "S1"}}))
	w.s.Clock.Advance(10 * time.Minute)
	must(w.c.Append(ctx, "cat", "season", a1.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "S2"}}))
	must(w.c.Prune(ctx, "cat", "season", client.PruneRequest{Horizon: a1.ID}))
	g := &logGate{prefix: "/r/cat/season/"}
	sc := w.s.Client(t, client.WithAuthor("tester"), client.WithHTTPClient(&http.Client{Transport: g}))
	var mu sync.Mutex
	var logged []string
	logf := func(o *tree.Options) {
		o.Logf = func(f string, a ...any) {
			mu.Lock()
			logged = append(logged, fmt.Sprintf(f, a...))
			mu.Unlock()
			t.Logf(f, a...)
		}
	}
	db := t.TempDir() + "/tree.db"
	x := startSvc(t, sc, svcOpts{db: db}, logf)
	x.caughtUp("cat", "matches")
	if e := entriesOf(t, x.get("/cat/children?of=root", ""))["season"]; e == nil || e["born"] != nil {
		t.Fatalf("season %v", e)
	}
	first := g.n.Load()
	for i := range 3 {
		w.replace(t, "cat", "season", "/title", fmt.Sprint("T", i))
		x.caughtUp("cat")
	}
	x.stop()
	x = startSvc(t, sc, svcOpts{db: db}, logf)
	x.caughtUp("cat", "matches")
	// A node created since is read as before.
	w.folder(t, "late", "Late", "root")
	x.caughtUp("cat")
	if e := entriesOf(t, x.get("/cat/children?of=root", ""))["late"]; e["born"] != bornOf(t, w.c, "cat", "late") {
		t.Errorf("late %v", e)
	}
	x.stop()
	if n := g.n.Load(); first != 1 || n != first {
		t.Errorf("season's log read %d times for its first head, %d for three more and a restart", first, n-first)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logged {
		if strings.Contains(l, "born") {
			t.Errorf("logged: %s", l)
		}
	}
}

// TC-6 (§B.5, §B.9): a start that fills in born for a database from
// before it reads the logs beside the followers, outside the write lock:
// the service follows and lists new writes while those reads wait.
func TestV073BackfillBesideFollowers(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season", "root@a0")
	db := t.TempDir() + "/tree.db"
	x := startSvc(t, w.c, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	x.stop()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	if _, err := sq.Exec(`UPDATE nodes SET born = NULL`); err != nil {
		t.Fatal(err)
	}
	sq.Close()
	g := &logGate{prefix: "/r/cat/season/", hold: make(chan struct{})}
	sc := w.s.Client(t, client.WithAuthor("tester"), client.WithHTTPClient(&http.Client{Transport: g}))
	x = startSvc(t, sc, svcOpts{db: db})
	waitFor(t, "the backfill reading season's log", func() bool { return g.n.Load() > 0 })
	w.folder(t, "late", "Late", "root@a1")
	x.caughtUp("cat")
	es := entriesOf(t, x.get("/cat/children?of=root", ""))
	if es["late"] == nil || es["season"]["born"] != nil {
		t.Fatalf("while the backfill waits: %v", es)
	}
	close(g.hold)
	want := bornOf(t, w.c, "cat", "season")
	waitFor(t, "season's born filled in", func() bool {
		return entriesOf(t, x.get("/cat/children?of=root", ""))["season"]["born"] == want
	})
}

// ENC-35 (§A.4, §B.5, §H.3): the pages after a children page are kept
// with it at its at, so a tool following next there pages through one
// folder however it changes meanwhile: nothing deleted, moved or
// reordered after page 1 makes it skip a child. A position given at an at
// whose pages are no longer kept starts the folder again at the current
// at, where some children come twice and none is skipped.
func TestV073ChildrenPagesKept(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	for i, n := range []string{"a", "b", "c", "d"} {
		w.folder(t, n, strings.ToUpper(n), fmt.Sprintf("root@a%d", i))
	}
	x := startSvc(t, w.c, svcOpts{now: w.s.Now})
	x.caughtUp("cat", "matches")
	page := func(at, query string) resp {
		t.Helper()
		r := x.raw("/cat/at/"+at+"/children"+query, "")
		if r.status != 200 {
			t.Fatalf("GET at %s %s: %d %v", at, query, r.status, r.body)
		}
		return r
	}
	for _, change := range []func(){
		func() { w.del(t, "cat", "b") },
		func() { w.replace(t, "cat", "c", "/parents/0/order", "a9") },
	} {
		at := x.s.At()
		p1 := page(at, "?limit=2&of=root")
		next, _ := p1.body["next"].(string)
		want := names(page(at, "?limit=1000&of=root").body["children"])
		change()
		x.caughtUp("cat")
		if x.s.At() == at {
			t.Fatal("the at didn't move")
		}
		seen := names(p1.body["children"])
		for next != "" {
			p := page(at, next)
			seen += "," + names(p.body["children"])
			next, _ = p.body["next"].(string)
		}
		if seen != want {
			t.Errorf("pages at %s: %s, the folder there %s", at, seen, want)
		}
	}

	// Not kept any more: the folder again, at the current at.
	at := x.s.At()
	p1 := page(at, "?limit=1&of=root")
	next := p1.body["next"].(string)
	w.s.Clock.Advance(2 * time.Minute)
	w.del(t, "cat", "a")
	x.caughtUp("cat")
	var got []string
	for b := x.get("/cat/at/"+at+"/children"+next, ""); ; {
		got = append(got, names(b["children"]))
		n, _ := b["next"].(string)
		if n == "" {
			break
		}
		b = x.get("/cat/at/"+b["at"].(string)+"/children"+n, "")
	}
	if want := names(x.get("/cat/children?of=root&limit=1000", "")["children"]); strings.Join(got, ",") != want {
		t.Errorf("after a position not kept: %v, want the folder again (%s)", got, want)
	}
}

// ENC-35 (§A.4, §B.5): next sent as after, as /_refs' is, continues at
// the following page; a malformed position is 400; an order key alone,
// the earlier releases' after, is still accepted.
func TestV073ChildrenNextAsAfter(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	for i, n := range []string{"a", "b", "c"} {
		w.folder(t, n, strings.ToUpper(n), fmt.Sprintf("root@a%d", i))
	}
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	at := x.s.At()
	next := x.raw("/cat/at/"+at+"/children?limit=1&of=root", "").body["next"].(string)
	q := url.Values{"of": {"root"}, "limit": {"1"}, "after": {next}}
	if got := names(x.get("/cat/at/"+at+"/children?"+q.Encode(), "")["children"]); got != "b" {
		t.Errorf("after=<next>: %q", got)
	}
	inner := must(url.ParseQuery(next[1:]))
	cur := strings.Split(inner.Get("after"), "~") // pos, at, last
	if len(cur) != 3 || cur[2] != "a" {
		t.Fatalf("next %s", next)
	}
	for _, bad := range []string{"1~nope~a", cur[0] + "~" + cur[1] + "~A", "0" + strings.Join(cur, "~")} {
		if r := x.raw(x.atURL("/cat/children?of=root&after="+url.QueryEscape(bad), ""), ""); r.status != 400 {
			t.Errorf("after=%s: %d %v", bad, r.status, r.body)
		}
	}
	if got := names(x.get("/cat/children?of=root&after=a0", "")["children"]); got != "b,c" {
		t.Errorf("after=a0: %q", got)
	}
}

// ENC-35 (§E.2.6): in a sealed catalog the pages kept with the one asked
// for are each bound to their own URL: a reader given per-entry sealing
// opens a following page's entries with that page's view.
func TestV073ChildrenPagesSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{}}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	for i, n := range []string{"a", "b", "c"} {
		createNonced(t, w, "cat", n, map[string]any{"title": strings.ToUpper(n), "parents": parents(fmt.Sprintf("root@a%d", i))})
	}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now}, withScopeView)
	x.caughtUp("cat")
	names := []any{"root", "a", "b", "c"}
	li := k.Grant(t, s.Now(), "user:li", []string{"cat"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}})
	kr := func(name string) func(string) []byte {
		fk := must(s.Client(t, client.WithBearer(li)).FetchKeys(ctx, "cat", nil, []string{name}))
		return func(kid string) []byte {
			if kid == fk[0].Kid {
				return fk[0].Key
			}
			return nil
		}
	}
	f := x.fetch("/cat/children?of=root&limit=1", li)
	path, _, _ := strings.Cut(f.path, "?")
	// The at moves on: the following pages are answered at theirs from
	// what was kept with the first.
	createNonced(t, w, "cat", "x", map[string]any{"title": "X", "parents": parents("a")})
	x.caughtUp("cat")
	for i, want := range []string{"A", "B", "C"} {
		b := decode(t, f.body)
		e := b["children"].([]any)[0].(map[string]any)
		name := e["name"].(string)
		v := decode(t, must(derived.OpenItem(e["sealed"].(string), kr(name), derived.View{NS: "cat", Target: f.path}, "cat", name)))
		if v["title"] != want {
			t.Errorf("page %d: %v", i, v)
		}
		next, _ := b["next"].(string)
		if next == "" {
			break
		}
		r := x.raw(path+next, li)
		if r.status != 200 {
			t.Fatalf("page %d at its at: %d", i+1, r.status)
		}
		f = x.fetch(path+next, li)
	}
}
