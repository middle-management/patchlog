package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// start serves h through a lifecycle Server on a loopback port.
func start(t *testing.T, h http.Handler, opt Options) (*Server, string, *logBuf) {
	t.Helper()
	lb := &logBuf{}
	opt.Logf = lb.logf
	srv := &http.Server{Handler: h}
	s := New(srv, opt)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s, "http://" + ln.Addr().String(), lb
}

type logBuf struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuf) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func get(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	r, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b), r.Header
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") })

func TestHealthAndReady(t *testing.T) {
	var dbErr error
	var mu sync.Mutex
	ready := func(context.Context) error { mu.Lock(); defer mu.Unlock(); return dbErr }
	inner := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { inner++; w.WriteHeader(404) })
	s, url, _ := start(t, h, Options{Ready: ready})

	code, body, hdr := get(t, url+HealthPath)
	if code != 200 || body != `{"status":"ok"}` || hdr.Get("Cache-Control") != "no-store" || hdr.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("health: %d %s %v", code, body, hdr)
	}
	if code, body, _ := get(t, url+ReadyPath); code != 200 || body != `{"status":"ok"}` {
		t.Fatalf("ready: %d %s", code, body)
	}
	mu.Lock()
	dbErr = errors.New("database is down")
	mu.Unlock()
	if code, body, _ := get(t, url+ReadyPath); code != 503 || !strings.Contains(body, `"status":"unavailable"`) || !strings.Contains(body, "database is down") {
		t.Fatalf("ready with a failing check: %d %s", code, body)
	}
	// Liveness doesn't run the check.
	if code, _, _ := get(t, url+HealthPath); code != 200 {
		t.Fatalf("health with a failing ready check: %d", code)
	}
	r, err := http.Post(url+HealthPath, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 405 {
		t.Fatalf("POST health: %d", r.StatusCode)
	}
	if inner != 0 {
		t.Fatalf("health paths reached the handler %d times", inner)
	}
	if s.InFlight() != 0 {
		t.Fatalf("in flight: %d", s.InFlight())
	}
}

// During -shutdown-delay health says draining but requests are served;
// then the listener closes.
func TestDrainDelay(t *testing.T) {
	s, url, lb := start(t, ok, Options{Delay: 500 * time.Millisecond, Timeout: time.Second})
	done := make(chan bool)
	go func() { done <- s.Shutdown() }()
	waitFor(t, "draining", s.Draining)
	code, body, _ := get(t, url+HealthPath)
	if code != 503 || body != `{"status":"draining"}` {
		t.Fatalf("health while draining: %d %s", code, body)
	}
	if code, _, _ := get(t, url+ReadyPath); code != 503 {
		t.Fatalf("ready while draining: %d", code)
	}
	r, err := http.Get(url + "/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || string(b) != "hello" {
		t.Fatalf("request during the delay: %d %s", r.StatusCode, b)
	}
	if !r.Close {
		t.Error("keep-alive not turned off while draining")
	}
	if !<-done {
		t.Fatal("shutdown not clean")
	}
	if _, err := http.Get(url + "/x"); err == nil {
		t.Fatal("still serving after shutdown")
	}
	if !strings.Contains(lb.String(), "draining") {
		t.Errorf("log: %s", lb)
	}
}

// An in-flight request finishes and is answered; Shutdown waits for it.
func TestInFlightCompletes(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		io.WriteString(w, "done")
	})
	s, url, lb := start(t, h, Options{Timeout: 5 * time.Second})
	got := make(chan string, 1)
	go func() {
		r, err := http.Get(url + "/slow")
		if err != nil {
			got <- err.Error()
			return
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		got <- string(b)
	}()
	<-entered
	done := make(chan bool)
	go func() { done <- s.Shutdown() }()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("shutdown returned with a request in flight")
	default:
	}
	close(release)
	if g := <-got; g != "done" {
		t.Fatalf("response: %s", g)
	}
	if !<-done {
		t.Fatal("not clean")
	}
	if !strings.Contains(lb.String(), "GET /slow") || !strings.Contains(lb.String(), "all requests finished") {
		t.Errorf("log: %s", lb)
	}
}

// Handlers waiting on Stopping return at once when the server stops.
func TestStoppingEndsLongRequests(t *testing.T) {
	entered := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-Stopping(r.Context()):
			w.WriteHeader(204)
		case <-time.After(time.Minute):
			w.WriteHeader(500)
		}
	})
	s, url, _ := start(t, h, Options{Timeout: 30 * time.Second})
	got := make(chan int, 1)
	go func() {
		r, err := http.Get(url + "/poll")
		if err != nil {
			got <- -1
			return
		}
		r.Body.Close()
		got <- r.StatusCode
	}()
	<-entered
	t0 := time.Now()
	if !s.Shutdown() {
		t.Fatal("not clean")
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("shutdown took %s", d)
	}
	if c := <-got; c != 204 {
		t.Fatalf("long request answered %d", c)
	}
}

// When the timeout expires, request contexts are cancelled and Shutdown
// waits for the handlers to return.
func TestTimeoutCancels(t *testing.T) {
	entered := make(chan struct{})
	var returned sync.WaitGroup
	returned.Add(1)
	var sawCancel bool
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer returned.Done()
		close(entered)
		<-r.Context().Done() // a handler ignoring Stopping, e.g. a stuck write
		time.Sleep(100 * time.Millisecond)
		sawCancel = true
	})
	s, url, lb := start(t, h, Options{Timeout: 300 * time.Millisecond, CancelGrace: 2 * time.Second})
	go func() {
		if r, err := http.Get(url + "/stuck"); err == nil {
			r.Body.Close()
		}
	}()
	<-entered
	t0 := time.Now()
	if s.Shutdown() {
		t.Fatal("reported clean")
	}
	if !sawCancel {
		t.Fatal("Shutdown returned before the cancelled handler")
	}
	if d := time.Since(t0); d < 300*time.Millisecond || d > 2*time.Second {
		t.Fatalf("shutdown took %s", d)
	}
	returned.Wait()
	if !strings.Contains(lb.String(), "cancelling 1 requests: GET /stuck") || !strings.Contains(lb.String(), "cancelled requests returned") {
		t.Errorf("log: %s", lb)
	}
}

// A handler that ignores cancellation is logged and given up on after the
// grace.
func TestCancelGraceExpires(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	})
	s, url, lb := start(t, h, Options{Timeout: 100 * time.Millisecond, CancelGrace: 100 * time.Millisecond})
	defer close(release)
	go func() {
		if r, err := http.Get(url + "/hung"); err == nil {
			r.Body.Close()
		}
	}()
	<-entered
	if s.Shutdown() {
		t.Fatal("reported clean")
	}
	if !strings.Contains(lb.String(), "1 handlers still running") {
		t.Errorf("log: %s", lb)
	}
}

func TestStoppingOutsideServer(t *testing.T) {
	if Stopping(context.Background()) != nil {
		t.Fatal("Stopping outside a server is not nil")
	}
	c := make(chan struct{})
	if Stopping(WithStopping(context.Background(), c)) != c {
		t.Fatal("WithStopping")
	}
}

func TestForceOnSignal(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	exited := make(chan int, 1)
	var logged string
	var mu sync.Mutex
	ForceOnSignal(sigs, func(f string, a ...any) { mu.Lock(); logged = fmt.Sprintf(f, a...); mu.Unlock() }, func(c int) { exited <- c })
	sigs <- syscall.SIGTERM
	select {
	case c := <-exited:
		if c != 1 {
			t.Fatalf("exit(%d)", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second signal didn't exit")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logged, "second signal") {
		t.Errorf("log: %q", logged)
	}

	// Stopped: a later signal is left alone.
	sigs2 := make(chan os.Signal, 1)
	stop := ForceOnSignal(sigs2, nil, func(int) { t.Error("exited after stop") })
	stop()
	sigs2 <- syscall.SIGTERM
	time.Sleep(50 * time.Millisecond)
}
