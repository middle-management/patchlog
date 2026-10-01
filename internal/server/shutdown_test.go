package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/verify"
)

// commitHook runs an armed function once, in a write transaction right
// before it commits (core.Options.BeforeCommit).
type commitHook struct {
	mu sync.Mutex
	fn func(context.Context)
}

func (h *commitHook) arm(fn func(context.Context)) { h.mu.Lock(); h.fn = fn; h.mu.Unlock() }

func (h *commitHook) run(ctx context.Context) {
	h.mu.Lock()
	fn := h.fn
	h.fn = nil
	h.mu.Unlock()
	if fn != nil {
		fn(ctx)
	}
}

// sdEnv is a server behind a lifecycle.Server, on a database that
// outlives the engine (reopen).
type sdEnv struct {
	*tenv
	ls   *lifecycle.Server
	opt  core.Options
	hook *commitHook
}

func newShutdownEnv(t *testing.T, lopt lifecycle.Options) *sdEnv {
	t.Helper()
	hook := &commitHook{}
	c := &clock{t: t0}
	o := core.Options{Origin: "https://cms.example", AuthDisabled: true, Now: c.Now, Purger: nopPurger{},
		BeforeCommit: hook.run, LongPollInterval: 10 * time.Minute}
	withFileDB(t)(&o)
	if pgtest.Enabled() {
		o.BlobDir = t.TempDir()
	}
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(New(e))
	if lopt.Logf == nil {
		lopt.Logf = t.Logf
	}
	ls := lifecycle.New(ts.Config, lopt)
	ts.Start()
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Close()
		e.Close()
	})
	return &sdEnv{tenv: &tenv{t: t, e: e, srv: ts, clock: c}, ls: ls, opt: o, hook: hook}
}

// reopen closes the engine and opens the database again behind a plain
// test server: what a restarted deployment sees.
func (s *sdEnv) reopen() *tenv {
	s.t.Helper()
	s.e.Close()
	o := s.opt
	o.BeforeCommit = nil
	e, err := core.Open(o)
	if err != nil {
		s.t.Fatal(err)
	}
	ts := httptest.NewServer(New(e))
	s.t.Cleanup(func() { ts.Close(); e.Close() })
	return &tenv{t: s.t, e: e, srv: ts, clock: s.clock}
}

// shutdown starts the phased shutdown; the channel gets its result.
func (s *sdEnv) shutdown() <-chan bool {
	done := make(chan bool, 1)
	go func() { done <- s.ls.Shutdown() }()
	return done
}

// waitInFlight waits until n requests are being handled.
func (s *sdEnv) waitInFlight(n int) {
	s.t.Helper()
	for i := 0; i < 500; i++ {
		if s.ls.InFlight() == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.t.Fatalf("%d requests in flight, want %d", s.ls.InFlight(), n)
}

type result struct {
	code int
	hdr  http.Header
	err  error
}

// send makes a request from any goroutine (tenv.do may only be used from
// the test's).
func send(method, url, ifMatch, ifNoneMatch string, body any) result {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	hr, _ := http.NewRequest(method, url, rd)
	if body != nil {
		ct := "application/json"
		if method == "PATCH" {
			ct = "application/json-patch+json"
		}
		hr.Header.Set("Content-Type", ct)
	}
	hr.Header.Set("X-Author", "alice")
	if ifMatch != "" {
		hr.Header.Set("If-Match", `"`+ifMatch+`"`)
	}
	if ifNoneMatch != "" {
		hr.Header.Set("If-None-Match", ifNoneMatch)
	}
	r, err := client.Do(hr)
	if err != nil {
		return result{err: err}
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return result{code: r.StatusCode, hdr: r.Header}
}

// verifyChains checks the namespace chain and resource chains of ns.
func verifyChains(t *testing.T, e *tenv, ns string, names ...string) []plclient.NSEntry {
	t.Helper()
	c, _ := plclient.New(e.srv.URL)
	entries, _, err := verify.Namespace(context.Background(), c, ns, "")
	if err != nil {
		t.Fatalf("namespace chain: %v", err)
	}
	for _, n := range names {
		if _, _, err := verify.Resource(context.Background(), c, ns, n, "", ""); err != nil {
			t.Fatalf("resource %s chain: %v", n, err)
		}
	}
	return entries
}

// A write in flight when shutdown starts completes and is durable; during
// -shutdown-delay health says draining and requests are still served.
func TestShutdownWriteInFlightCompletes(t *testing.T) {
	s := newShutdownEnv(t, lifecycle.Options{Timeout: 10 * time.Second, Delay: 300 * time.Millisecond})
	s.mkNS("docs", map[string]any{"read": "public"})
	head := s.create("docs", "a", map[string]any{"n": 1.0})

	entered, release := make(chan struct{}), make(chan struct{})
	s.hook.arm(func(context.Context) { close(entered); <-release })
	res := make(chan result, 1)
	go func() {
		res <- send("PATCH", s.srv.URL+"/r/docs/a", head, "", ops(op("replace", "/n", 2.0)))
	}()
	<-entered
	done := s.shutdown()
	for !s.ls.Draining() {
		time.Sleep(5 * time.Millisecond)
	}
	r := s.get(lifecycle.HealthPath)
	expect(t, r, 503)
	if r.Str("status") != "draining" || r.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("health while draining: %s %v", r.Body, r.H)
	}
	// Reads are still served during the delay.
	expect(t, s.get("/r/docs/a"), 302)
	// Past the delay the listener closes; the write is waited for.
	time.Sleep(400 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("shutdown finished with a write in flight")
	default:
	}
	close(release)
	got := <-res
	if got.err != nil || got.code != 200 && got.code != 201 {
		t.Fatalf("write in flight: %+v", got)
	}
	if !<-done {
		t.Fatal("shutdown not clean")
	}
	if _, err := http.Get(s.srv.URL + "/r/docs/a"); err == nil {
		t.Fatal("still serving after shutdown")
	}

	e := s.reopen()
	if n := e.doc("docs", "a")["n"]; n != 2.0 {
		t.Fatalf("after restart n = %v, want 2", n)
	}
	if h := e.head("docs", "a"); h != strings.Trim(got.hdr.Get("ETag"), `"`) {
		t.Fatalf("head %s, want the in-flight write's %s", h, got.hdr.Get("ETag"))
	}
	verifyChains(t, e, "docs", "a")
}

// A long-poll in flight answers 204 at once when the server stops, instead
// of holding shutdown until its interval ends.
func TestShutdownEndsLongPoll(t *testing.T) {
	s := newShutdownEnv(t, lifecycle.Options{Timeout: 30 * time.Second})
	s.mkNS("docs", map[string]any{"read": "public"})
	s.create("docs", "a", map[string]any{"n": 1.0})
	since := s.nsHead("docs")
	res := make(chan result, 1)
	go func() { res <- send("GET", s.srv.URL+"/ns/docs/log?live=long-poll&since="+since, "", "", nil) }()
	s.waitInFlight(1)
	time.Sleep(50 * time.Millisecond) // into its wait
	t0 := time.Now()
	done := s.shutdown()
	select {
	case got := <-res:
		if got.err != nil || got.code != 204 || got.hdr.Get("X-Cursor") == "" || got.hdr.Get("X-Namespace-Revision") != since {
			t.Fatalf("long-poll answer: %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll still waiting after shutdown started")
	}
	if !<-done {
		t.Fatal("shutdown not clean")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("shutdown took %s", d)
	}
}

// Event streams end cleanly when the server stops.
func TestShutdownEndsEventStreams(t *testing.T) {
	s := newShutdownEnv(t, lifecycle.Options{Timeout: 30 * time.Second})
	s.mkNS("docs", map[string]any{"read": "public"})
	r1 := s.create("docs", "a", map[string]any{"n": 1.0})
	nsCh, _, _ := s.openSSE("/ns/docs/events?since="+s.nsHead("docs"), nil)
	resCh, _, _ := s.openSSE("/r/docs/a/events?since="+r1, nil)
	s.waitInFlight(2)
	time.Sleep(50 * time.Millisecond)
	t0 := time.Now()
	done := s.shutdown()
	for _, ch := range []<-chan sseEvent{nsCh, resCh} {
		timeout := time.After(3 * time.Second)
	drain:
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					break drain
				}
			case <-timeout:
				t.Fatal("event stream still open after shutdown started")
			}
		}
	}
	if !<-done {
		t.Fatal("shutdown not clean")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("shutdown took %s", d)
	}
}

// When -shutdown-timeout expires, a blocked write is cancelled and rolls
// back: nothing of it is stored, and the chains verify.
func TestShutdownTimeoutRollsBackWrite(t *testing.T) {
	s := newShutdownEnv(t, lifecycle.Options{Timeout: 300 * time.Millisecond, CancelGrace: 5 * time.Second})
	s.mkNS("docs", map[string]any{"read": "public"})
	head := s.create("docs", "a", map[string]any{"n": 1.0})
	before := len(verifyChains(t, s.tenv, "docs", "a"))

	entered := make(chan struct{})
	cancelled := make(chan struct{})
	s.hook.arm(func(ctx context.Context) {
		close(entered)
		<-ctx.Done() // stuck until the request is cancelled
		close(cancelled)
	})
	res := make(chan result, 1)
	go func() {
		res <- send("POST", s.srv.URL+"/ns/docs/batch", "", "", map[string]any{"items": []any{
			map[string]any{"resource": "a", "ifMatch": head, "steps": []any{ops(op("replace", "/n", 2.0))}},
			map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"n": 1.0})}},
		}})
	}()
	select {
	case <-entered:
	case got := <-res:
		t.Fatalf("batch answered before the hook: %+v", got)
	}
	if s.ls.Shutdown() {
		t.Fatal("reported clean with a stuck write")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("the stuck write's context was not cancelled")
	}
	if got := <-res; got.err == nil && got.code < 500 {
		t.Fatalf("cancelled batch answered %+v", got)
	}

	e := s.reopen()
	if n := e.doc("docs", "a")["n"]; n != 1.0 {
		t.Fatalf("a.n = %v after a rolled-back batch", n)
	}
	if h := e.head("docs", "a"); h != head {
		t.Fatalf("a's head moved to %s", h)
	}
	expect(t, e.get("/r/docs/b"), 404)
	if after := len(verifyChains(t, e, "docs", "a")); after != before {
		t.Fatalf("namespace chain has %d entries, had %d", after, before)
	}
	// The log goes on from where it was.
	e.appendRev("docs", "a", head, ops(op("replace", "/n", 3.0)))
	verifyChains(t, e, "docs", "a")
}
