package tree_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// §B.5 Behind, §B.9, §B.11.9 (ACCESS-11): catalog cat trusts pub and
// private sec, whose documents self-place (§B.9). The tree service
// follows sec with its own grant; once the core refuses it, sec is
// stopped and leaves the combined checkpoint that problems and orphans
// are judged against. Its self-placed nodes, derived from sec's private
// documents, leave the graph with it: no reader without read on sec
// learns their names from problems, orphans or where, running or
// restarted on the same store; followed again, they are derived again.
func TestV081SvcStoppedSelfPlacedNamesLeave(t *testing.T) {
	t.Parallel()
	// catRead: the catalog's (and pub's) read mode. With "grant", the
	// reader rd has read on cat and pub only, never on sec.
	for _, tc := range []struct {
		catRead string
		written bool // a sec document written while it is stopped
	}{{"public", false}, {"grant", false}, {"public", true}} {
		catRead, written := tc.catRead, tc.written
		name := catRead
		if written {
			name += " written meanwhile"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			refuse := &atomic.Bool{}
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
				Wrap: func(h http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if refuse.Load() && (r.URL.Path == "/ns/sec" || strings.HasPrefix(r.URL.Path, "/ns/sec/")) {
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(403)
							w.Write([]byte(`{"code":"forbidden","message":"injected"}`))
							return
						}
						h.ServeHTTP(w, r)
					})
				}})
			k := clienttest.NewKey("k")
			all := []string{"cat", "pub", "sec"}
			for _, ns := range all {
				doc := map[string]any{"read": catRead, "keys": []any{k.Entry("*")}}
				switch ns {
				case "cat":
					doc["catalog"] = map[string]any{"trust": []any{"pub", "sec"}, "mode": "dag", "title": "/title"}
				case "sec":
					doc["read"] = "grant"
				}
				must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
			}
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})))
			must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
			must(w.CreateDoc(ctx, "cat", "lost", map[string]any{"title": "Lost", "parents": parents("gone")}))
			must(w.CreateDoc(ctx, "pub", "p", map[string]any{"title": "Open p8qz"}))
			must(w.CreateDoc(ctx, "sec", "hiddenq7k", map[string]any{"title": "Secret", "$parents": []any{map[string]any{"href": "/r/cat/lost"}}}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})))
			db := filepath.Join(t.TempDir(), "tree.db")
			x := startSvc(t, sc, svcOpts{now: s.Now, db: db, selfPlacing: true}, func(o *tree.Options) {})
			x.caughtUp("cat", "pub", "sec")
			rd := ""
			if catRead != "public" {
				rd = k.Grant(t, s.Now(), "user:rd", []string{"cat", "pub"}, []string{"read"})
			}
			paths := []string{"/cat/problems", "/cat/orphans", "/cat/where?item=/r/sec/hiddenq7k"}
			for _, p := range paths {
				if st, _, b, _ := v0261Get(x, p, rd); st == 200 {
					t.Fatalf("setup: %s by a reader without read on sec, sec private and followed: %d %s", p, st, b)
				}
			}
			refuse.Store(true)
			waitFor(t, "sec stopped", func() bool { return v0261Stopped(t, db, "sec") })
			leak := func(when string) {
				t.Helper()
				// problems and orphans are served, cat and pub alone in
				// the combined checkpoint; where names no node.
				for i, p := range paths {
					want := 200
					if i == 2 {
						want = 404
					}
					if st, _, b, loc := v0261Get(x, p, rd); st != want || strings.Contains(b, "hiddenq7k") {
						t.Errorf("%s: %s (at %s) by a reader without read on sec, sec stopped: %d %s, want %d without sec's private self-placed name", when, p, loc, st, b, want)
					}
				}
			}
			leak("running")
			// Restarted on the same store, still refused: the stop and
			// what it took out of the graph hold.
			x.stop()
			x = startSvc(t, sc, svcOpts{now: s.Now, db: db, selfPlacing: true}, func(o *tree.Options) {})
			x.caughtUp("cat", "pub")
			leak("restarted")
			// Followed again, at the checkpoint it was stopped at (unstop)
			// or past a batch written meanwhile (applied, the stop ends):
			// sec's implicit placement is derived again.
			full := k.Grant(t, s.Now(), "user:full", all, []string{"read"})
			if written {
				must(w.CreateDoc(ctx, "sec", "meanwhile", map[string]any{"title": "Meanwhile"}))
			}
			refuse.Store(false)
			waitFor(t, "sec followed again", func() bool { return !v0261Stopped(t, db, "sec") })
			waitFor(t, "sec's self-placement back", func() bool {
				st, _, b, _ := v0261Get(x, "/cat/where?item=/r/sec/hiddenq7k", full)
				return st == 200 && strings.Contains(b, `"self":true`) && !strings.Contains(b, "unfollowed")
			})
		})
	}
}

// §C.2 item 5, §B.11.5 (ACCESS-3): a grant with a block rule on /now is
// refused every read, whatever the catalog's read mode: its filtered
// listings are 403 where the catalog is private (TestV081SvcReadNowTree)
// and where it is public, and it exchanges for no cookie.
func TestV081SvcReadNowPublicCatalog(t *testing.T) {
	t.Parallel()
	for _, catRead := range []string{"grant", "public"} {
		t.Run(catRead, func(t *testing.T) {
			t.Parallel()
			q := newP24World(t, catRead, "grant").start(withEdgeGrants)
			cl := q.grant("user:cl", []string{"cat", "matches"}, map[string]any{"rules": []any{
				map[string]any{"op": "test", "path": "/now", "exists": true},
				map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "season", "matches.derby", "derby"}}}}})
			r := q.do("GET", "/cat/children?of=root", cl, "")
			for r.status == 302 {
				r = q.do("GET", r.header.Get("Location"), cl, "")
			}
			if r.status != 403 {
				t.Errorf("catalog %s, private matches, a block rule on /now: %d %v", catRead, r.status, r.body)
			}
			// A grant for the content namespace alone, which a public
			// catalog refuses: verified in matches only, where its /now
			// rule has it read nothing (§C.2 item 5).
			cm := q.grant("user:cm", []string{"matches"}, map[string]any{"rules": []any{
				map[string]any{"op": "test", "path": "/now", "exists": true}}})
			r = q.do("GET", "/cat/children?of=root", cm, "")
			for r.status == 302 {
				r = q.do("GET", r.header.Get("Location"), cm, "")
			}
			if r.status == 200 {
				t.Errorf("catalog %s, a grant for matches alone with a block rule on /now: %d %v", catRead, r.status, r.body)
			}
			req := must(http.NewRequest("POST", q.x.http.URL+"/edge-grants", nil))
			req.Header.Set("Authorization", "Bearer "+cl)
			er := must(noRedirect.Do(req))
			er.Body.Close()
			if er.StatusCode != 403 || len(er.Cookies()) != 0 {
				t.Errorf("catalog %s: exchange with a block rule on /now: %d %v", catRead, er.StatusCode, er.Cookies())
			}
		})
	}
}
