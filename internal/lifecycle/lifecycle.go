// Package lifecycle gives patchlog's HTTP servers (serve, index, tree) health
// endpoints and a phased graceful shutdown.
//
// Health. Every server answers two paths before its own routes:
//
//	GET /_health   liveness and drain state: 200 {"status":"ok"} while
//	               serving, 503 {"status":"draining"} once shutdown has
//	               started. It touches no database, so it is cheap enough
//	               for frequent probes.
//	GET /_ready    readiness: 503 {"status":"draining"} while draining, 503
//	               {"status":"unavailable","error":…} if the server's Ready
//	               check fails (the core pings its database), else 200
//	               {"status":"ok"}.
//
// Both are Cache-Control: no-store and CDN-Cache-Control: no-store, so no
// CDN keeps them. The paths start with an underscore, which no namespace or
// catalog name can (§3.6: ^[a-z0-9][a-z0-9_-]{0,63}$), so they can't shadow
// the index's /{ns} or the tree service's /{catalog} routes; they follow the
// services' existing /_status.
//
// Shutdown (Server.Shutdown) runs in phases:
//
//  1. Drain: /_health and /_ready answer 503 and keep-alives are turned
//     off, so load balancers take the instance out of rotation and clients
//     reconnect elsewhere. Requests are still served normally.
//  2. Delay: that goes on for Options.Delay (-shutdown-delay), the time a
//     load balancer needs to notice.
//  3. Stop: the listeners close (http.Server.Shutdown) and Stopping(ctx) is
//     closed, so long-lived requests (long-polls, event streams, ?min=
//     waits) end promptly with their normal answers. In-flight requests
//     are waited for, up to Options.Timeout (-shutdown-timeout).
//  4. Cancel: only if the timeout expires are the remaining requests'
//     contexts cancelled, so their transactions roll back; the handlers
//     are then given Options.CancelGrace to return.
//
// The caller closes its database after Shutdown returns: by then every
// handler has returned (or, after the grace, is logged as still running).
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Health endpoint paths.
const (
	HealthPath = "/_health"
	ReadyPath  = "/_ready"
)

// Defaults of the -shutdown-* flags.
const (
	DefaultTimeout     = 30 * time.Second
	DefaultCancelGrace = 2 * time.Second
)

type stoppingKey struct{}

// Stopping returns a channel that is closed when the server serving ctx (a
// request's context) stops: long-lived handlers select on it and finish
// with their normal answer. Outside such a server it returns nil, which
// blocks forever in a select.
func Stopping(ctx context.Context) <-chan struct{} {
	c, _ := ctx.Value(stoppingKey{}).(<-chan struct{})
	return c
}

// WithStopping returns ctx carrying stop as its Stopping channel, for
// handlers run outside a Server (tests).
func WithStopping(ctx context.Context, stop <-chan struct{}) context.Context {
	return context.WithValue(ctx, stoppingKey{}, stop)
}

// Options configure a Server.
type Options struct {
	// Name prefixes log lines, e.g. "patchlog" or "patchlog index".
	Name string
	// Timeout bounds how long in-flight requests are waited for once the
	// server stops (default DefaultTimeout).
	Timeout time.Duration
	// Delay is how long the server keeps serving, health 503, before it
	// stops (default 0).
	Delay time.Duration
	// CancelGrace is how long handlers get to return after their contexts
	// are cancelled (default DefaultCancelGrace).
	CancelGrace time.Duration
	// Ready, if set, is /_ready's check (e.g. a database ping); it gets a
	// context with a 2 s timeout.
	Ready func(context.Context) error
	// Logf logs (default: discard).
	Logf func(format string, args ...any)
}

// Server wraps an http.Server with health endpoints and phased shutdown.
type Server struct {
	HTTP *http.Server
	opt  Options

	draining chan struct{}
	drainOne sync.Once
	stopping chan struct{}
	stopOnce sync.Once
	cancel   context.CancelFunc

	mu     sync.Mutex
	nextID uint64
	active map[uint64]activeReq
	idle   chan struct{} // closed when active empties; nil while it is empty
}

type activeReq struct {
	method, path string
	start        time.Time
}

// New prepares srv: its handler gets the health endpoints and request
// tracking, and its BaseContext a cancellable parent carrying Stopping.
// Call it before serving; srv.BaseContext must be unset.
func New(srv *http.Server, opt Options) *Server {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.CancelGrace <= 0 {
		opt.CancelGrace = DefaultCancelGrace
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Name == "" {
		opt.Name = "server"
	}
	s := &Server{HTTP: srv, opt: opt, draining: make(chan struct{}), stopping: make(chan struct{}), active: map[uint64]activeReq{}}
	base, cancel := context.WithCancel(WithStopping(context.Background(), s.stopping))
	s.cancel = cancel
	srv.BaseContext = func(net.Listener) context.Context { return base }
	srv.RegisterOnShutdown(s.stop)
	srv.Handler = s.wrap(srv.Handler)
	return s
}

// Draining reports whether shutdown has started.
func (s *Server) Draining() bool {
	select {
	case <-s.draining:
		return true
	default:
		return false
	}
}

func (s *Server) stop() { s.stopOnce.Do(func() { close(s.stopping) }) }

// wrap answers the health paths and tracks every other request.
func (s *Server) wrap(h http.Handler) http.Handler {
	if h == nil {
		h = http.DefaultServeMux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case HealthPath:
			s.serveHealth(w, r, false)
			return
		case ReadyPath:
			s.serveHealth(w, r, true)
			return
		}
		id := s.begin(r)
		defer s.end(id)
		h.ServeHTTP(w, r)
	})
}

func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request, ready bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("CDN-Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, r, http.StatusMethodNotAllowed, map[string]string{"code": "bad_input", "message": "method not allowed"})
		return
	}
	if s.Draining() {
		writeJSON(w, r, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	if ready && s.opt.Ready != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		err := s.opt.Ready(ctx)
		cancel()
		if err != nil {
			writeJSON(w, r, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": err.Error()})
			return
		}
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

func (s *Server) begin(r *http.Request) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	if len(s.active) == 0 {
		s.idle = make(chan struct{})
	}
	s.active[s.nextID] = activeReq{r.Method, r.URL.Path, time.Now()}
	return s.nextID
}

func (s *Server) end(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, id)
	if len(s.active) == 0 && s.idle != nil {
		close(s.idle)
		s.idle = nil
	}
}

// InFlight is the number of requests being handled (health checks aside).
func (s *Server) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// describe lists up to max in-flight requests, longest-running first.
func (s *Server) describe(max int) string {
	s.mu.Lock()
	reqs := make([]activeReq, 0, len(s.active))
	for _, a := range s.active {
		reqs = append(reqs, a)
	}
	s.mu.Unlock()
	sort.Slice(reqs, func(i, j int) bool { return reqs[i].start.Before(reqs[j].start) })
	var parts []string
	for i, a := range reqs {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(reqs)-max))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s (%s)", a.method, a.path, time.Since(a.start).Round(time.Millisecond)))
	}
	return strings.Join(parts, ", ")
}

// waitIdle waits up to d for every tracked handler to return.
func (s *Server) waitIdle(d time.Duration) bool {
	s.mu.Lock()
	idle := s.idle
	s.mu.Unlock()
	if idle == nil {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-idle:
		return true
	case <-t.C:
		return false
	}
}

func (s *Server) logf(format string, args ...any) {
	s.opt.Logf(s.opt.Name+": "+format, args...)
}

// Shutdown runs the phased shutdown (see the package documentation) and
// returns once every handler has returned, or the cancel grace has passed.
// It reports whether every request finished on its own, without being
// cancelled. It is meant to be called once.
func (s *Server) Shutdown() (clean bool) {
	start := time.Now()
	s.drainOne.Do(func() { close(s.draining) })
	s.HTTP.SetKeepAlivesEnabled(false)
	if s.opt.Delay > 0 {
		s.logf("draining: %s answers 503; serving for %s more (-shutdown-delay), %d requests in flight", HealthPath, s.opt.Delay, s.InFlight())
		time.Sleep(s.opt.Delay)
	}
	n := s.InFlight()
	if n > 0 {
		s.logf("stopping: waiting up to %s (-shutdown-timeout) for %d requests: %s; long-polls and event streams end now", s.opt.Timeout, n, s.describe(10))
	} else {
		s.logf("stopping: no requests in flight")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.opt.Timeout)
	defer cancel()
	s.stop()
	err := s.HTTP.Shutdown(ctx)
	// Shutdown returns once connections are idle; handlers of hijacked
	// connections, or a handler finishing after its response, may still run.
	if err == nil && s.waitIdle(time.Until(start.Add(s.opt.Delay+s.opt.Timeout))) {
		s.logf("all requests finished (%s)", time.Since(start).Round(time.Millisecond))
		return true
	}
	n = s.InFlight()
	s.logf("shutdown timeout of %s expired: cancelling %d requests: %s", s.opt.Timeout, n, s.describe(10))
	s.cancel()
	s.HTTP.Close()
	if !s.waitIdle(s.opt.CancelGrace) {
		s.logf("%d handlers still running %s after cancellation: %s", s.InFlight(), s.opt.CancelGrace, s.describe(10))
		return false
	}
	s.logf("cancelled requests returned (%s)", time.Since(start).Round(time.Millisecond))
	return false
}

// Signals returns a channel receiving SIGINT and SIGTERM.
func Signals() <-chan os.Signal {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	return c
}

// ForceOnSignal makes the next signal on sigs exit the process at once
// with exit(1) (os.Exit unless a test passes another), logging why: the
// operator's way past a shutdown that takes too long. It returns a
// function that stops watching.
func ForceOnSignal(sigs <-chan os.Signal, logf func(string, ...any), exit func(int)) (stop func()) {
	if exit == nil {
		exit = os.Exit
	}
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigs:
			select {
			case <-done: // stopped before the signal came
				return
			default:
			}
			if logf != nil {
				logf("second signal (%v): exiting immediately", sig)
			}
			exit(1)
		case <-done:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
