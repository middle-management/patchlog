package index_test

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
