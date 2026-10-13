package tree_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// Two catalogs, a tree and a DAG over the same content namespace, served
// by one origin.
func TestMulti(t *testing.T) {
	t.Parallel()
	w := setup(t)
	ctx := context.Background()
	w.seed(t)
	must(w.c.CreateNamespace(ctx, "topics", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	tp := func(ps ...string) []any {
		var out []any
		for _, p := range ps {
			out = append(out, map[string]any{"href": "/r/topics/" + p})
		}
		return out
	}
	folder := func(name string, ps ...string) {
		must(w.c.CreateDoc(ctx, "topics", name, map[string]any{"title": strings.ToUpper(name[:1]) + name[1:], "parents": tp(ps...)}))
	}
	folder("root")
	folder("stockholm", "root")
	folder("rivalries", "root")
	folder("derbies", "stockholm", "rivalries") // a diamond: root→stockholm→derbies, root→rivalries→derbies
	folder("loop-a", "root")
	folder("loop-b", "loop-a")
	h := must(w.c.Head(ctx, "topics", "loop-a"))
	must(w.c.Append(ctx, "topics", "loop-a", h.ID, []any{map[string]any{"op": "add", "path": "/parents/-", "value": map[string]any{"href": "/r/topics/loop-b"}}}))
	must(w.c.CreateDoc(ctx, "topics", "matches.derby", map[string]any{"parents": tp("derbies", "rivalries")}))

	cat := startSvc(t, w.c, svcOpts{})
	topics := startSvc(t, w.c, svcOpts{catalog: "topics", db: filepath.Join(t.TempDir(), "topics.db")})
	cat.caughtUp("cat", "matches")
	topics.caughtUp("topics", "matches")
	if _, err := tree.Multi(cat.s, cat.s); err == nil {
		t.Fatal("a catalog served twice was accepted")
	}
	m := httptest.NewServer(must(tree.Multi(cat.s, topics.s)))
	defer m.Close()
	// Route through the Multi handler with the svc helpers.
	x := &svc{t: t, http: m}

	if r := x.raw("/topics/roots", ""); r.status != 302 || r.header.Get("Location") != "/topics/at/"+topics.s.At()+"/roots" {
		t.Fatalf("topics roots: %d %v", r.status, r.header)
	}
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "season,derbies" {
		t.Errorf("cat children of root: %s", got)
	}
	if got := names(x.get("/topics/children?of=root", "")["children"]); got != "rivalries,stockholm" {
		t.Errorf("topics children of root: %s", got)
	}
	// The shared folder is listed under both parents, the item under both folders.
	for _, f := range []string{"stockholm", "rivalries"} {
		if got := names(x.get("/topics/children?of="+f, "")["children"]); !strings.Contains(got, "derbies") {
			t.Errorf("children of %s: %s", f, got)
		}
	}
	if got := pathsOf(x.get("/topics/ancestors?of=/r/matches/derby", "")["paths"]); got != "root/stockholm/derbies | root/rivalries/derbies | root/rivalries" {
		t.Errorf("paths of the derby: %s", got)
	}
	// The cycle is flagged and not traversed.
	pr := x.get("/topics/problems", "")
	if fmt.Sprint(pr["cycles"]) != "[[/r/topics/loop-a /r/topics/loop-b]]" {
		t.Errorf("cycles: %v", pr["cycles"])
	}
	sub := x.get("/topics/subtree?of=root&depth=64", "")["tree"].(map[string]any)
	if got := names(sub["children"]); got != "rivalries,stockholm" {
		t.Errorf("subtree: %s", got)
	}
	// The diamond's shared folder is expanded where it is first listed
	// (under rivalries) and marked "repeat", without children, under
	// stockholm (§B.5).
	child := func(e map[string]any, name string) map[string]any {
		for _, c := range e["children"].([]any) {
			if c := c.(map[string]any); c["name"] == name {
				return c
			}
		}
		t.Fatalf("%v has no child %s", e["name"], name)
		return nil
	}
	first := child(child(sub, "rivalries"), "derbies")
	again := child(child(sub, "stockholm"), "derbies")
	if first["repeat"] != nil || names(first["children"]) == "" {
		t.Errorf("first derbies: %v", first)
	}
	if again["repeat"] != true || again["children"] != nil {
		t.Errorf("repeated derbies: %v", again)
	}

	st := x.raw("/_status", "").body
	if fmt.Sprint(st["catalogs"]) != "[cat topics]" || len(st["namespaces"].([]any)) != 3 || len(st["byCatalog"].(map[string]any)) != 2 {
		t.Errorf("status: %v", st)
	}
	st = x.raw("/_status?catalog=topics", "").body
	if fmt.Sprint(st["catalogs"]) != "[topics]" || len(st["namespaces"].([]any)) != 2 {
		t.Errorf("status of topics: %v", st)
	}
	for _, p := range []string{"/_status?catalog=nope", "/nope/roots", "/"} {
		if r := x.raw(p, ""); r.status != 404 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
}

// TestMultiMinElsewhere (§A.5, §B.5): behind Multi, a min naming a
// namespace that only another catalog's service follows isn't covered by
// this catalog's at; if the reader may see it, it is waited for there and
// the listing redirects to this catalog's current at in one hop, without
// min. A namespace no catalog follows, and one the reader can't see, are
// 400 with one message.
func TestMultiMinElsewhere(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, reader := clienttest.NewKey("admin"), clienttest.NewKey("reader")
	nss := []string{"a", "b", "c", "cat", "topics"}
	for _, ns := range nss {
		doc := map[string]any{"read": "public", "keys": []any{admin.Entry("*"), reader.Entry("read")}}
		switch ns {
		case "b":
			doc["read"] = "grant"
		case "cat":
			doc["catalog"] = map[string]any{"trust": []any{"a"}}
		case "topics":
			doc["catalog"] = map[string]any{"trust": []any{"b", "c"}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append"})))
	must(root.CreateDoc(ctx, "cat", "top", map[string]any{"title": "Top", "parents": []any{}}))
	svcClient := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", nss, []string{"read"})))
	cat := startSvc(t, svcClient, svcOpts{now: s.Now})
	topics := startSvc(t, svcClient, svcOpts{catalog: "topics", db: filepath.Join(t.TempDir(), "topics.db"), now: s.Now})
	cat.caughtUp("cat", "a")
	topics.caughtUp("topics", "b", "c")
	cw := must(root.CreateDoc(ctx, "c", "x", map[string]any{"t": 1})).NSID
	// Served alone, cat knows nothing of c.
	if r := cat.raw("/cat/roots?min=c:"+cw, ""); r.status != 400 {
		t.Errorf("min for c without Multi: %d", r.status)
	}
	m := httptest.NewServer(must(tree.Multi(cat.s, topics.s)))
	defer m.Close()
	x := &svc{t: t, http: m}

	// c is public and followed by topics only: waited for there.
	want := "/cat/at/" + cat.s.At() + "/roots"
	if r := x.raw("/cat/roots?min=c:"+cw, ""); r.status != 302 || r.header.Get("Location") != want {
		t.Errorf("min for topics' public c: %d %s, want %s", r.status, r.header.Get("Location"), want)
	}
	if got := topics.s.Checkpoint("c"); got != cw {
		t.Errorf("redirected before topics reached c: %s, want %s", got, cw)
	}
	// From an at URL too: one hop to the current at.
	old := "/cat/at/" + cat.s.At() + "/roots"
	must(root.CreateDoc(ctx, "a", "y", map[string]any{"t": 1}))
	cat.caughtUp("a")
	want = "/cat/at/" + cat.s.At() + "/roots"
	if r := x.raw(old+"?min=c:"+cw, ""); r.status != 302 || r.header.Get("Location") != want {
		t.Errorf("min for c from an at: %d %s, want %s", r.status, r.header.Get("Location"), want)
	}
	// b is private: a reader whose grant reads it is redirected; one
	// without a grant for it gets the same 400 as for a namespace no
	// catalog follows.
	bw := must(root.CreateDoc(ctx, "b", "x", map[string]any{"t": 1})).NSID
	bReader := reader.Grant(t, s.Now(), "user:bea", []string{"cat", "b"}, []string{"read"})
	if r := x.raw("/cat/roots?min=b:"+bw, bReader); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/cat/g/") ||
		!strings.HasSuffix(r.header.Get("Location"), "/at/"+cat.s.At()+"/roots") {
		t.Errorf("min for b with a grant for it: %d %s", r.status, r.header.Get("Location"))
	}
	hidden, unknown := x.raw("/cat/roots?min=b:"+bw, ""), x.raw("/cat/roots?min=zz:"+bw, "")
	if hidden.status != 400 || unknown.status != 400 || hidden.body["message"] != unknown.body["message"] ||
		hidden.header.Get("Cache-Control") != "no-store" {
		t.Errorf("hidden %d %v, unknown %d %v", hidden.status, hidden.body, unknown.status, unknown.body)
	}
}

// TestMultiMinPurgedSealed (§A.5, §8.5): behind Multi, a min naming a
// purged sealed namespace that another catalog's service follows, whose
// document is 410 purged, is judged by the core's read check: a reader
// who passes is redirected to the current at, any other gets the 400 of a
// namespace no catalog follows. Never a 502.
func TestMultiMinPurgedSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	nss := []string{"a", "cat", "sec", "topics"}
	for _, ns := range nss {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		switch ns {
		case "sec":
			doc["read"], doc["encryption"] = "grant", map[string]any{"level": "sealed"}
		case "cat":
			doc["catalog"] = map[string]any{"trust": []any{"a"}}
		case "topics":
			doc["catalog"] = map[string]any{"trust": []any{"sec"}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", nss, []string{"read", "create", "config", "purge-ns"})),
		client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "top", map[string]any{"title": "Top", "parents": []any{}}))
	createNonced(t, w, "sec", "x", map[string]any{"t": 1})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", nss, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	cat := startSvc(t, sc, svcOpts{now: s.Now})
	topics := startSvc(t, sc, svcOpts{catalog: "topics", db: filepath.Join(t.TempDir(), "topics.db"), now: s.Now})
	cat.caughtUp("cat", "a")
	topics.caughtUp("topics", "sec")
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.PurgeNamespace(ctx, "sec", must(w.NSHead(ctx, "sec")).ID))
	waitFor(t, "the purge", func() bool { return topics.s.Checkpoint("sec") == purged })
	m := httptest.NewServer(must(tree.Multi(cat.s, topics.s)))
	defer m.Close()
	x := &svc{t: t, http: m}

	reader := k.Grant(t, s.Now(), "user:r", []string{"cat", "sec"}, []string{"read"})
	if r := x.raw("/cat/roots?min=sec:"+purged, reader); r.status != 302 || !strings.HasSuffix(r.header.Get("Location"), "/at/"+cat.s.At()+"/roots") {
		t.Errorf("a reader of sec: %d %v %s", r.status, r.body, r.header.Get("Location"))
	}
	catOnly := k.Grant(t, s.Now(), "user:c", []string{"cat"}, []string{"read"})
	for name, tok := range map[string]string{"anonymous": "", "a grant for cat only": catOnly} {
		hidden, unknown := x.raw("/cat/roots?min=sec:"+purged, tok), x.raw("/cat/roots?min=zz:"+purged, tok)
		if hidden.status != 400 || hidden.body["message"] != unknown.body["message"] || hidden.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v, unknown %d %v", name, hidden.status, hidden.body, unknown.status, unknown.body)
		}
	}
}
