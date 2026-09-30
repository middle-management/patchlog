package tree_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/tree"
)

// Two catalogs, a tree and a DAG over the same content namespace, served
// by one origin.
func TestMulti(t *testing.T) {
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
	if got := names(x.get("/topics/subtree?of=root&depth=64", "")["tree"].(map[string]any)["children"]); got != "rivalries,stockholm" {
		t.Errorf("subtree: %s", got)
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
