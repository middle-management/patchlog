package dav_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/dav"
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

// v0.86 (TOOLS §H.4 "Answers", FILE-18; CONFORMANCE Grant scope 87): "A
// core or service request the gateway makes for the user's request fails
// (408, 429, 5xx, no connection, or no answer in time), a read of another
// namespace's documents or a write included, whether or not the answer
// needed it; a failed read never counts as a refusal" → 503 with
// Retry-After after a 429, a 503 or no answer in time, else 502. Scenario
// 87: a GET of a file while the core answers 500 to a read of another
// namespace's document that the gateway made resolving the folder (a
// sibling item's namespace) → 502 naming only the core, never 200 from
// the rest and never 403. Before, a request that only read went on
// without what it could do without.
//
// The catalog here places docs/derby and other/sib in Season; the reads
// of namespace other fail.
func TestV086SiblingReadFailsRequest(t *testing.T) {
	t.Parallel()
	const busy, failed, late, down = "the core is busy or behind for now; try again", "the core failed", "the core didn't answer in time", "the core can't be reached"
	for _, f := range []struct {
		status, want int // status 0: no answer in time; -1: no connection
		body, ra     string
	}{{500, 502, failed, ""}, {408, 502, failed, ""}, {502, 502, failed, ""}, {429, 503, busy, "1"}, {503, 503, busy, "1"}, {0, 503, late, "5"}, {-1, 502, down, ""}} {
		for _, c := range []struct {
			method, path string
			ok           int
		}{
			{"GET", "/cat/Season/derby.json", 200},
			{"HEAD", "/cat/Season/derby.json", 200},
			{"PROPFIND", "/cat/Season/", 207},
		} {
			t.Run(fmt.Sprintf("%d %s %s", f.status, c.method, c.path), func(t *testing.T) {
				t.Parallel()
				rt := &failRT{status: f.status}
				e := newEnv(t, nil, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("docs", "other")}})
				for _, ns := range []string{"docs", "other"} {
					must(e.c.CreateNamespace(e.ctx, ns, map[string]any{"read": "public"}))
				}
				e.create("docs", "derby", map[string]any{"title": "Derby"})
				e.create("other", "sib", map[string]any{"title": "Sibling"})
				e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
				e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
				e.create("cat", "docs.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
				e.create("cat", "other.sib", map[string]any{"title": "sib.json", "parents": parents("cat", "season")})
				e = v82With(t, e, rt)
				var hit atomic.Int64
				rt.match.Store(func(q *http.Request) bool {
					// What the gateway asks of the sibling's namespace to
					// show its item: who the user is there, and its
					// document (sealed or not, §H.3), not the item itself.
					if q.Method == "GET" && (q.URL.Path == "/ns/other" || q.URL.Path == "/ns/other/principal") {
						hit.Add(1)
						return true
					}
					return false
				})
				rt.armed.Store(true)
				what := fmt.Sprintf("%s %s, the core failing the reads of a sibling item's namespace (%d)", c.method, c.path, f.status)
				r := e.do(c.method, c.path, "", "Depth", "1")
				if hit.Load() == 0 {
					t.Fatalf("%s made no read of the sibling's namespace", what)
				}
				if c.method == "HEAD" {
					// No body to compare.
					if r.status != f.want || r.header.Get("Retry-After") != f.ra || r.header.Get("ETag") != "" {
						t.Fatalf("%s: %d %v, want %d", what, r.status, r.header, f.want)
					}
				} else {
					v86Upstream(t, r, f.want, f.body, f.ra, what)
				}
				rt.armed.Store(false)
				e.expect(e.do(c.method, c.path, "", "Depth", "1"), c.ok, c.method+" "+c.path+", the core answering")
			})
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
				rt.match.Store(func(q *http.Request) bool { return strings.HasPrefix(q.URL.Path, "/r/docs/") || strings.HasPrefix(q.URL.Path, "/ns/docs") })
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

// §H.4 "Answers" (v0.86), the reading taken where the text is silent: a
// request counts by how it ends. A core 429 the gateway waits out and
// sends again, as §6.6 has a client do, has not failed: the save is made
// and answered as made.
func TestV086WaitedOut429IsNoFailure(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1"})
	var limited atomic.Int64
	rt := rtFunc(func(q *http.Request) (*http.Response, error) {
		if q.Method != "GET" && q.Method != "HEAD" && strings.HasPrefix(q.URL.Path, "/r/docs/x") && limited.Add(1) == 1 {
			if q.Body != nil {
				io.Copy(io.Discard, q.Body)
				q.Body.Close()
			}
			return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"1"}, "Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"code":"rate_limited","message":"slow down","retryAfter":0.05}`)), Request: q}, nil
		}
		return http.DefaultTransport.RoundTrip(q)
	})
	e = v82With(t, e, rt)
	b := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	r := e.do("PUT", "/docs/x.json", strings.Replace(b, `"1"`, `"2"`, 1))
	if r.status != 204 && r.status != 201 {
		t.Fatalf("a PUT whose first write the core answered 429 and whose second it took: %d %s", r.status, r.body)
	}
	if limited.Load() < 2 {
		t.Fatalf("the write was sent %d times, want the 429 and then again", limited.Load())
	}
	if _, doc := e.load("docs", "x"); doc.(map[string]any)["a"] != "2" {
		t.Fatalf("the save wasn't made: %v", doc)
	}
}

// v0.86 (TOOLS §H.3 "A tree service that is behind": "a tool answers 503
// (§H.4 Answers)", was "passes it on"; CONFORMANCE Grant scope 86): a
// gateway user's PROPFIND of a folder while the tree service answers 503
// (behind) naming a namespace → 503 with Retry-After, naming only the
// service: no ns, none of the tree service's text, and not its
// Retry-After. A 429 and another 5xx of the tree service's are named the
// same way (503 and 502).
func TestV086TreeServiceFailureNamesOnlyTheService(t *testing.T) {
	t.Parallel()
	a := newAuthTree(t)
	a.tr.caughtUp("cat", "matches")
	var status atomic.Int64
	front := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := int(status.Load()); s != 0 {
			w.Header().Set("Retry-After", "7")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s)
			io.WriteString(w, `{"code":"behind","message":"the tree service has not reached matches yet","ns":"matches"}`)
			return
		}
		proxyTo(a.tr.http.URL).ServeHTTP(w, r)
	}))
	g := a.gateway(t, front.URL, func(o *dav.Options) { o.CatalogTTL, o.TreeWait = time.Nanosecond, 300*time.Millisecond })
	// A user whose grant doesn't read the catalog unrestricted: the
	// folder is the tree service's to list.
	user := a.limitedTo(t, "user:li", "root", "season", "matches.derby", "derby")
	sameStrings(t, "Season", names(g.propfindAs(user, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
	for _, c := range []struct {
		status, want int
		body, ra     string
	}{
		{503, 503, "catalog cat's tree service is busy or behind for now; try again", "1"},
		{429, 503, "catalog cat's tree service is busy or behind for now; try again", "1"},
		{500, 502, "catalog cat's tree service failed", ""},
		{502, 502, "catalog cat's tree service failed", ""},
	} {
		status.Store(int64(c.status))
		for _, p := range []string{"/cat/Season/", "/cat/"} {
			what := fmt.Sprintf("PROPFIND %s while the tree service answers %d naming matches", p, c.status)
			r := g.doAs(user, "PROPFIND", p, "", "Depth", "1")
			v86Upstream(t, r, c.want, c.body, c.ra, what)
			for _, leak := range []string{"matches", "reached", "behind\"", "7"} {
				if strings.Contains(r.body, leak) || r.header.Get("Retry-After") == leak {
					t.Fatalf("%s: the answer carries %q of the tree service's: %q %v", what, leak, r.body, r.header)
				}
			}
		}
		r := g.doAs(user, "GET", "/cat/Season/derby.json", "")
		v86Upstream(t, r, c.want, c.body, c.ra, fmt.Sprintf("GET of a file while the tree service answers %d", c.status))
	}
	status.Store(0)
	sameStrings(t, "Season, the tree service answering", names(g.propfindAs(user, "/cat/Season/"), "/cat/Season/"), []string{"derby.json"})
}
