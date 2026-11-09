package index_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Cross-review (conformance lens), end to end: Tree-derived access 123
// and Grant scope 65 against a real core and the index's real grantcheck
// (§C.4 requireAt: "A verifier that can't read the chain answers 503
// (behind) while the cause is transient (§A.1), and 502 (upstream)
// otherwise, naming no namespace, never 403").
func TestV077XconfChainUnreadableEndToEnd(t *testing.T) {
	t.Parallel()
	var fail atomic.Int32
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if st := fail.Load(); st != 0 && r.Method == "GET" && r.URL.Path == "/ns/cat-season" {
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(int(st))
				rw.Write([]byte(`{"code":"x","message":"no"}`))
				return
			}
			h.ServeHTTP(rw, r)
		})
	}}))
	w.x = w.start(false, "matches")
	li := w.reader("user:li", []any{"fans"})
	if r := w.x.raw("/matches", li); r.status != 302 {
		t.Fatalf("before: %d %v", r.status, r.body)
	}
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	for _, c := range []struct {
		st   int32
		want int
		code string
	}{{503, 503, "behind"}, {403, 502, "upstream"}} {
		fail.Store(c.st)
		w.x.ix.ExpireGrantChecks()
		for _, path := range []string{"/matches", refs} {
			r := w.x.raw(path, li)
			msg, _ := r.body["message"].(string)
			if r.status != c.want || r.body["code"] != c.code || strings.Contains(msg, "cat-season") {
				t.Errorf("cat-season answering %d: %s → %d %v, want %d %s naming no namespace", c.st, path, r.status, r.body, c.want, c.code)
			}
			if c.want == 503 && r.header.Get("Retry-After") == "" {
				t.Errorf("%s: 503 without Retry-After", path)
			}
		}
		w.x.ix.ExpireGrantChecks()
		r := p37Do(t, w.x, "POST", "/edge-grants", li, "", nil, "")
		msg, _ := r.body["message"].(string)
		if r.status != c.want || r.body["code"] != c.code || strings.Contains(msg, "cat-season") {
			t.Errorf("cat-season answering %d: exchange → %d %v, want %d %s", c.st, r.status, r.body, c.want, c.code)
		}
	}
	fail.Store(0)
}

// Cross-review (conformance lens), §B.11.9 Where ("as their documents
// alone decide"): a purged catalog counts for coverage only if its last
// catalog.trust listed the namespace, as at the origin. cat-season stops
// trusting matches, which is then uncovered (a partial reader: 403, no
// marker, §A.4), and is purged: matches stays uncovered. Before, the
// index counted a purged catalog wherever the namespace named it through
// a requireAt key, and li got a g: marker and empty answers.
func TestV077XrevPurgedCatalogLastTrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans"})
	if r := w.x.raw("/matches", li); r.status != 302 || !strings.Contains(r.header.Get("Location"), "/g/") {
		t.Fatalf("li while cat-season trusts matches: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config,
		[]any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
	waitFor(t, "matches uncovered", func() bool {
		w.x.ix.ExpireGrantChecks()
		return w.x.raw("/matches", li).status == 403
	})
	purger := w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "user:root", []string{"cat-season"}, []string{"purge-ns"})))
	must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(purger.PurgeNamespace(ctx, "cat-season", w.head("cat-season")))
	waitFor(t, "the index learns cat-season is purged", func() bool {
		_, following := w.x.ix.Members()["cat-season"]
		return !following
	})
	w.x.ix.ExpireGrantChecks()
	if r := w.x.raw("/matches", li); r.status != 403 {
		t.Errorf("li once cat-season, which no longer trusted matches, is purged: %d %s %v, want 403 with no marker", r.status, r.header.Get("Location"), r.body)
	}
}
