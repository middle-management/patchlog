package dav_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/tree"
)

// W3X (P33 GW-29 x GW-31 x the catalog service; §1, §B.11, §H.2): over a
// core with authentication disabled every request counts as holding a *
// key, and a user is an X-Author with no grant, which a catalog service's
// POST /grants refuses (401). A tree a catalog service serves is then not
// tree-derived: a gateway user's GET and PUT of a file go to the core as
// that user, as through a plain tree service, and so do local mode's
// with -author.
func TestW3XDevCoreTreeNotDerived(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{RealClock: true})
	c := s.Client(t, client.WithAuthor("setup"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public",
		"catalog": map[string]any{"trust": []any{"matches"}, "mode": "tree", "files": map[string]any{"ns": "matches", "root": "root"}}}))
	must(c.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "Derby"}))
	must(c.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(c.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Season", "parents": []any{map[string]any{"href": "/r/cat/root"}}}))
	must(c.CreateDoc(ctx, "cat", "matches.derby", map[string]any{"title": "derby.json", "parents": []any{map[string]any{"href": "/r/cat/season"}}}))

	catKey := clienttest.NewKey("catalog-01")
	svc := must(catalog.Open(ctx, catalog.Options{
		Tree: tree.Options{Client: s.Client(t), Catalog: "cat", DB: filepath.Join(t.TempDir(), "catalog.db"), MinWait: 2 * time.Second,
			RepurgeInterval: -1, CheckerTTL: time.Millisecond, Logf: t.Logf,
			FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}},
		Key: catKey.Priv, Kid: "catalog-01"}))
	hs := httptest.NewServer(svc.Handler())
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.Run(rctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); svc.Close() })
	for _, ns := range []string{"cat", "matches"} {
		deadline := time.Now().Add(30 * time.Second)
		for {
			h, err := c.NSHead(ctx, ns)
			if err == nil && svc.Tree().Checkpoint(ns) == h.ID {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the catalog service didn't catch up with %s", ns)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	do := func(srv *httptest.Server, user, pw, method, p, body string) (int, string) {
		t.Helper()
		req := must(http.NewRequest(method, srv.URL+p, strings.NewReader(body)))
		req.SetBasicAuth(user, pw)
		res := must(testHTTP.Do(req))
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	for _, m := range []struct {
		name     string
		opt      dav.Options
		user, pw string
		author   string
	}{
		{"gateway", dav.Options{Client: s.Client(t), Gateway: true}, "alice", "anything", "alice"},
		{"local", dav.Options{Client: s.Client(t, client.WithAuthor("dav")), Password: "pw"}, "bob", "pw", "dav"},
	} {
		m.opt.Catalogs, m.opt.TreeService, m.opt.Logf = []string{"cat"}, hs.URL, t.Logf
		g := newTestServer(t, must(dav.New(m.opt)))
		if st, b := do(g, m.user, m.pw, "PROPFIND", "/cat/Season/", ""); st != 207 {
			t.Fatalf("%s: listing: %d %s", m.name, st, b)
		}
		if st, b := do(g, m.user, m.pw, "GET", "/cat/Season/derby.json", ""); st != 200 {
			t.Errorf("%s: GET of a file in a tree a catalog service serves, over a core with authentication disabled: %d %s", m.name, st, b)
		}
		body := `{"title": "Derby, edited by ` + m.name + `"}`
		if st, b := do(g, m.user, m.pw, "PUT", "/cat/Season/derby.json", body); st != 204 && st != 201 {
			t.Errorf("%s: PUT of that file: %d %s", m.name, st, b)
		}
		h := must(c.Head(ctx, "matches", "derby"))
		lg := must(c.Log(ctx, "matches", "derby", h.ID, ""))
		if last := lg[len(lg)-1]; last.Author != m.author {
			t.Errorf("%s: the edit was written by %q, want %q", m.name, last.Author, m.author)
		}
	}
}
