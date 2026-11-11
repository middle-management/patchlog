package dav_test

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/dav"
)

// failRT answers the core requests match picks with status while armed
// (status 0: a transport timeout, as an http.Client's Timeout gives), and
// passes every other request through.
type failRT struct {
	armed  atomic.Bool
	match  atomic.Value // func(*http.Request) bool
	status int
}

func (f *failRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if m, _ := f.match.Load().(func(*http.Request) bool); f.armed.Load() && m != nil && m(r) {
		if f.status == 0 {
			return nil, timeoutErr{}
		}
		return &http.Response{StatusCode: f.status, Header: http.Header{"Retry-After": {"5"}, "Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"code":"unavailable","message":"try later"}`)), Request: r}, nil
	}
	return http.DefaultTransport.RoundTrip(r)
}

// timeoutErr is a net.Error that timed out.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// failingEnv is newEnv's flat docs, served by a WebDAV server whose core
// requests go through a failRT answering status.
func failingEnv(t *testing.T, status int) (*env, *failRT) {
	t.Helper()
	e := newEnv(t, []string{"docs"}, nil, nil)
	rt := &failRT{status: status}
	opt := e.opt
	opt.Client = e.s.Client(t, client.WithAuthor("dav"), client.WithHTTPClient(&http.Client{Transport: rt}))
	g := *e
	g.opt = opt
	g.dav = newTestServer(t, must(dav.New(opt)))
	return &g, rt
}

// OTHER-2 (§H.4 "The base", "The reload", Answers; §H.6): a save with a
// base over someone else's delete reads the file's last revision to find
// out whether it moved; a failed read of it (408, 429, a timeout, 5xx)
// fails the save, 503 with Retry-After after the core's 429 or 503 (and
// a timeout of the gateway's own), else 502 (v0.82), rather than taking
// it as a revision the gateway can't read (409). Nothing is written. A
// refusal of the read (403) still leaves the 409.
func TestV077SaveOverDeleteFailedRead(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		status, want int
		what         string
	}{
		{503, 503, "a 503"},
		{500, 502, "a 500"},
		{429, 503, "a 429"},
		{408, 502, "a 408"},
		{0, 503, "a timeout"},
		{403, 409, "a refusal (not a failed read)"},
	} {
		e, rt := failingEnv(t, c.status)
		e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
		g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
		// Someone else changes it, so its last revision isn't the one the
		// gateway served and holds, then deletes it.
		e.theirs("docs", "x", replace("/b", "2"))
		h, _ := e.load("docs", "x")
		must(e.c.Delete(e.ctx, "docs", "x", h.ID))
		rt.match.Store(at("GET", "/r/docs/x/rev/"+h.ID))
		rt.armed.Store(true)
		r := e.expect(e.do("PUT", "/docs/x.json", edit(t, g.body, `"a": "1"`, `"a": "mine"`), "If-Match", g.header.Get("ETag")), c.want, "PUT with "+c.what+" reading the last revision")
		if c.want == 503 && r.header.Get("Retry-After") == "" {
			t.Fatalf("%s: 503 without Retry-After", c.what)
		}
		e.expectTombstoned("docs", "x", "after "+c.what)
	}
}

// OTHER-2 (§H.4 "The base"): whether the tombstone is the user's own is
// read from its log entry; a failed read of that fails the save (503
// with Retry-After after the core's 503, v0.82) rather than counting the
// delete as someone else's (409).
func TestV077SaveOverDeleteFailedLogRead(t *testing.T) {
	t.Parallel()
	e, rt := failingEnv(t, 503)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	h, _ := e.load("docs", "x")
	tomb := must(e.c.Delete(e.ctx, "docs", "x", h.ID))
	rt.match.Store(func(r *http.Request) bool {
		return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/r/docs/x/rev/"+tomb.ID+"/log")
	})
	rt.armed.Store(true)
	if r := e.expect(e.do("PUT", "/docs/x.json", edit(t, g.body, `"a": "1"`, `"a": "mine"`), "If-Match", g.header.Get("ETag")), 503, "PUT, the tombstone's log read failing"); r.header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	e.expectTombstoned("docs", "x", "after the failed log read")
	// Once the core answers again, the delete is someone else's: 409.
	rt.armed.Store(false)
	e.expect(e.do("PUT", "/docs/x.json", edit(t, g.body, `"a": "1"`, `"a": "mine"`), "If-Match", g.header.Get("ETag")), 409, "PUT, the core answering")
}

// OTHER-2 (§H.4 "Raw files", "The base"): a raw save over someone else's
// delete fails the same way when the last revision's read fails.
func TestV077RawSaveOverDeleteFailedRead(t *testing.T) {
	t.Parallel()
	e, rt := failingEnv(t, 503)
	e.rawDoc("docs", "a.txt", "text/plain", []byte("one"), nil)
	g := e.expect(e.do("GET", "/docs/a.txt", ""), 200, "GET")
	h, _ := e.load("docs", "a.txt")
	// A revision of identical content, so the last revision isn't the one
	// the gateway served.
	must(e.c.Append(e.ctx, "docs", "a.txt", h.ID, []any{}))
	h, _ = e.load("docs", "a.txt")
	must(e.c.Delete(e.ctx, "docs", "a.txt", h.ID))
	rt.match.Store(at("GET", "/r/docs/a.txt/rev/"+h.ID))
	rt.armed.Store(true)
	if r := e.expect(e.do("PUT", "/docs/a.txt", "two", "If-Match", g.header.Get("ETag")), 503, "raw PUT, the last revision's read failing"); r.header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	e.expectTombstoned("docs", "a.txt", "after the failed read")
}
