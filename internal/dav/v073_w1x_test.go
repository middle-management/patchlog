package dav_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/tree"
)

// W1X (P09 x P13): the tree service keeps a children listing's later pages
// at the first page's at only while they are kept (package kept, a minute
// or the memory budget). A position followed after that is redirected to
// the current at, where the folder starts again (§B.5, childCursor.start).
// The gateway keeps that listing alone (svcList): appending it to the
// pages already read showed its first children twice, numbered as
// duplicate titles (nameDir), files that aren't there.
func TestW1XTreePagesRestartShowPhantomDuplicates(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	for _, n := range []string{"a1", "a2", "a3", "a4"} {
		e.create("matches", n, map[string]any{"item": n})
		e.create("cat", "matches."+n, map[string]any{"title": n + ".json", "parents": parents("cat", "season")})
	}

	// A tree service on the test core's clock, so kept listings expire
	// when the test says.
	core := e.s.Client(t, client.WithAuthor("tree"))
	svc, err := tree.Open(context.Background(), tree.Options{Client: core, Catalog: "cat", DB: filepath.Join(t.TempDir(), "tree.db"),
		MinWait: 200 * time.Millisecond, RepurgeInterval: -1, Logf: t.Logf, Now: e.s.Clock.Now,
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; svc.Close() })
	back := httptest.NewServer(svc.Handler())
	t.Cleanup(back.Close)
	caughtUp := func() {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for _, ns := range []string{"cat", "matches"} {
			for {
				h, err := core.NSHead(context.Background(), ns)
				if err == nil && svc.Checkpoint(ns) == h.ID {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the tree service didn't catch up with %s", ns)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
	caughtUp()

	// In front of it: the first time the gateway follows a next (a page
	// after the first), someone writes to the catalog elsewhere and more
	// than a minute passes before the request arrives.
	proxy := proxyTo(back.URL)
	var moved atomic.Bool
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/children") && r.URL.Query().Get("after") != "" && moved.CompareAndSwap(false, true) {
			e.create("cat", "elsewhere", map[string]any{"title": "Elsewhere", "parents": parents("cat", "root")})
			caughtUp()
			e.s.Clock.Advance(2 * time.Minute)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)

	ts := treeDav(e, front.URL, func(_ *dav.Options, s *dav.Server) {
		if s != nil {
			dav.SetTreePage(s, 2)
		}
	})
	got := names(ts.propfind("/cat/Season/"), "/cat/Season/")
	if !moved.Load() {
		t.Fatal("the listing took one page")
	}
	sameStrings(t, "Season", got, []string{"a1.json", "a2.json", "a3.json", "a4.json", "derby.json"})
}
