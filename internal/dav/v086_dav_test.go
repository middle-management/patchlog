package dav_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// v86Upstream checks a gateway's 502 or 503 for a failed upstream (§H.4
// "Answers", v0.86: "A gateway's 502 and 503 name only the upstream that
// failed, the core or a service, and carry nothing of its answer …; the
// 503's Retry-After is the gateway's own"): the body is want and nothing
// else, and a 503's Retry-After is the gateway's (ra), not the
// upstream's.
func v86Upstream(t *testing.T, r resp, status int, want, ra, what string) {
	t.Helper()
	if r.status != status || r.body != want+"\n" {
		t.Fatalf("%s: %d %q, want %d %q", what, r.status, r.body, status, want)
	}
	if got := r.header.Get("Retry-After"); got != ra {
		t.Fatalf("%s: Retry-After %q, want the gateway's own %q", what, got, ra)
	}
	for _, h := range []string{"ETag", "Last-Modified"} {
		if r.header.Get(h) != "" {
			t.Fatalf("%s: the %d carries %s %q", what, status, h, r.header.Get(h))
		}
	}
}

// §H.4 "Answers" (v0.86): the 502 and 503 for a read the answer does need
// name the core alone too: not its status ("the core answered 503: …"
// before), not its code or message, and not its Retry-After (5 here).
func TestV086CoreFailureNamesOnlyTheCore(t *testing.T) {
	t.Parallel()
	for _, f := range []struct {
		status, want int
		body, ra     string
	}{
		{500, 502, "the core failed", ""},
		{408, 502, "the core failed", ""},
		{429, 503, "the core is busy or behind for now; try again", "1"},
		{503, 503, "the core is busy or behind for now; try again", "1"},
	} {
		for _, c := range []struct{ method, path string }{{"GET", "/docs/x.json"}, {"PROPFIND", "/docs/"}, {"DELETE", "/docs/x.json"}, {"PUT", "/docs/x.json"}} {
			t.Run(fmt.Sprintf("%d %s", f.status, c.method), func(t *testing.T) {
				t.Parallel()
				e, rt := failingEnv(t, f.status)
				e.create("docs", "x", map[string]any{"a": "1"})
				rt.match.Store(func(q *http.Request) bool {
					return strings.HasPrefix(q.URL.Path, "/r/docs/") || strings.HasPrefix(q.URL.Path, "/ns/docs")
				})
				rt.armed.Store(true)
				body := ""
				if c.method == "PUT" {
					body = `{"a": "2"}`
				}
				what := fmt.Sprintf("%s %s, the core answering %d", c.method, c.path, f.status)
				r := e.do(c.method, c.path, body, "Depth", "1")
				v86Upstream(t, r, f.want, f.body, f.ra, what)
				rt.armed.Store(false)
				if _, doc := e.load("docs", "x"); doc.(map[string]any)["a"] != "1" {
					t.Fatalf("%s wrote: %v", what, doc)
				}
			})
		}
	}
}
