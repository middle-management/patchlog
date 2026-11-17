package streams_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/streams"
)

const (
	nsStreams = "streams"
	nsApp     = "app"
)

// upstream is a test upstream API: each request is answered by script,
// and counted.
type upstream struct {
	srv  *httptest.Server
	hits atomic.Int64
	mu   sync.Mutex
	// script answers one request; nil serves the default event stream.
	script func(w http.ResponseWriter, r *http.Request)
	// last is the last request's headers and body.
	lastHeader http.Header
	lastBody   string
	lastMethod string
	// cancelled is closed when a request's context ends before its script
	// returns.
	cancelled chan struct{}
}

// sseBody is what the default upstream streams, in parts.
var sseParts = []string{
	"data: {\"delta\":\"Hel\"}\n\n",
	"data: {\"delta\":\"lo\"}\n\n",
	"data: {\"delta\":\", wörld \\u2603 ☃\"}\n\ndata: {\"delta\":\"!\"}\n\n",
	"event: done\ndata: [DONE]\n\n",
}

func sseBody() string { return strings.Join(sseParts, "") }

// writeParts streams parts as text/event-stream, a few milliseconds apart.
func writeParts(w http.ResponseWriter, parts []string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	for _, p := range parts {
		io.WriteString(w, p)
		w.(http.Flusher).Flush()
		time.Sleep(15 * time.Millisecond)
	}
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{cancelled: make(chan struct{}, 16)}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.lastHeader, u.lastBody, u.lastMethod = r.Header.Clone(), string(b), r.Method
		script := u.script
		u.mu.Unlock()
		if script == nil {
			writeParts(w, sseParts)
			return
		}
		script(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) set(script func(w http.ResponseWriter, r *http.Request)) {
	u.mu.Lock()
	u.script = script
	u.mu.Unlock()
}

// gated streams first, then waits for release (or the request's
// cancellation, which it reports on u.cancelled) before rest.
func (u *upstream) gated(first []string, release <-chan struct{}, rest []string) {
	u.set(func(w http.ResponseWriter, r *http.Request) {
		writeParts(w, first)
		select {
		case <-release:
			for _, p := range rest {
				io.WriteString(w, p)
				w.(http.Flusher).Flush()
				time.Sleep(15 * time.Millisecond)
			}
		case <-r.Context().Done():
			u.cancelled <- struct{}{}
		}
	})
}

// env is a core, an upstream and a stream proxy in front of them.
type env struct {
	t        *testing.T
	ctx      context.Context
	s        *clienttest.Server
	key      clienttest.Key // signs the proxy's grant in nsStreams
	appKey   clienttest.Key // signs callers' grants in nsApp
	adminKey clienttest.Key
	pc       *client.Client // the proxy's client
	grant    string         // the proxy's grant
	up       *upstream
	opt      streams.Options
	p        *streams.Proxy
	srv      *httptest.Server
	offset   atomic.Int64 // added to the proxy's clock
}

type envOpt struct {
	dev     bool // a core with authentication disabled
	nsDoc   map[string]any
	options func(*streams.Options)
	core    func(*clienttest.Options)
	noProxy bool // the test starts the proxy itself (start)
}

func newEnv(t *testing.T, eo envOpt) *env {
	t.Helper()
	e := &env{t: t, up: newUpstream(t)}
	var cancel context.CancelFunc
	e.ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	co := clienttest.Options{Auth: !eo.dev, RealClock: true, LongPoll: 200 * time.Millisecond}
	if eo.core != nil {
		eo.core(&co)
	}
	e.s = clienttest.New(t, co)
	doc := map[string]any{"read": "grant"}
	for k, v := range eo.nsDoc {
		doc[k] = v
	}
	if eo.dev {
		e.pc = e.s.Client(t, client.WithAuthor("proxy"))
		if _, err := e.pc.CreateNamespace(e.ctx, nsStreams, doc); err != nil {
			t.Fatal(err)
		}
	} else {
		e.key, e.appKey = clienttest.NewKey("proxy-key"), clienttest.NewKey("app-key")
		// The second key is an administrator's (retention prunes with one).
		e.adminKey = clienttest.NewKey("admin-key")
		doc["keys"] = []any{e.key.Entry("create", "append", "read", "purge"), e.adminKey.Entry("*")}
		if _, err := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, nsStreams))).CreateNamespace(e.ctx, nsStreams, doc); err != nil {
			t.Fatal(err)
		}
		if _, err := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, nsApp))).CreateNamespace(e.ctx, nsApp,
			map[string]any{"read": "grant", "keys": []any{e.appKey.Entry("read", "append", "create")}}); err != nil {
			t.Fatal(err)
		}
		e.grant = e.key.Grant(t, e.s.Now(), "svc:streams", []string{nsStreams}, []string{"create", "append", "read", "purge"})
		e.pc = e.s.Client(t, client.WithBearer(e.grant))
	}
	e.opt = streams.Options{Client: e.pc, Grant: e.grant, NS: nsStreams, CallerNS: nsApp, Upstreams: []string{e.up.srv.URL + "/v1"},
		Flush: 20 * time.Millisecond, TTL: 30 * time.Minute, IdleTimeout: 20 * time.Second, Logf: t.Logf,
		Now: func() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) }}
	if eo.dev {
		e.opt.CallerNS = ""
	}
	if eo.options != nil {
		eo.options(&e.opt)
	}
	if !eo.noProxy {
		e.start()
	}
	return e
}

// start starts the proxy with e.opt.
func (e *env) start() {
	e.t.Helper()
	p, err := streams.New(e.ctx, e.opt)
	if err != nil {
		e.t.Fatal(err)
	}
	e.p = p
	e.srv = httptest.NewServer(p)
	e.t.Cleanup(func() {
		e.srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p.Close(ctx)
	})
}

// callerGrant is a grant of nsApp's for sub: what a caller of the proxy
// holds.
func (e *env) callerGrant(sub string) string {
	return e.appKey.Grant(e.t, e.s.Now(), sub, []string{nsApp}, []string{"read"})
}

type postOpt struct {
	bearer  string // default: user:ann's grant
	author  string // X-Author, for a dev core
	url     string // default: the upstream's /v1/messages
	key     string // Request-Key
	headers map[string]string
	body    string
}

// post sends POST /streams and returns the status and the answer.
func (e *env) post(o postOpt) (int, streams.Answer, string) {
	e.t.Helper()
	if o.url == "" {
		o.url = e.up.srv.URL + "/v1/messages"
	}
	req, _ := http.NewRequestWithContext(e.ctx, "POST", e.srv.URL+"/streams", strings.NewReader(o.body))
	req.Header.Set("Upstream-URL", o.url)
	if o.bearer == "" && o.author == "" && e.appKey.Kid != "" {
		o.bearer = e.callerGrant("user:ann")
	}
	if o.bearer != "" && o.bearer != "none" {
		req.Header.Set("Authorization", "Bearer "+o.bearer)
	}
	if o.author != "" {
		req.Header.Set("X-Author", o.author)
	}
	if o.key != "" {
		req.Header.Set("Request-Key", o.key)
	}
	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var a streams.Answer
	json.Unmarshal(b, &a)
	return resp.StatusCode, a, string(b)
}

// mustPost is post for a new stream.
func (e *env) mustPost(o postOpt) streams.Answer {
	e.t.Helper()
	status, a, body := e.post(o)
	if status != 201 || a.ID == "" {
		e.t.Fatalf("POST /streams: %d %s", status, body)
	}
	return a
}

// reader is a client with an answer's read grant; over a dev core, any.
func (e *env) reader(a streams.Answer) *client.Client {
	if a.Grant == "" {
		return e.s.Client(e.t, client.WithAuthor("reader"))
	}
	return e.s.Client(e.t, client.WithBearer(a.Grant))
}

// readAll follows a stream from pos to its end.
func (e *env) readAll(c *client.Client, id string, pos streams.Position) (string, *streams.Closed, []streams.Batch) {
	e.t.Helper()
	var sb strings.Builder
	var batches []streams.Batch
	closed, err := streams.Follow(e.ctx, c, nsStreams, id, pos, func(b streams.Batch) error {
		batches = append(batches, b)
		for _, c := range b.Chunks {
			sb.WriteString(c)
		}
		return nil
	})
	if err != nil {
		e.t.Fatalf("Follow %s: %v", id, err)
	}
	return sb.String(), closed, batches
}

// doc loads a stream resource's document with the proxy's client.
func (e *env) doc(name string) (*streams.Doc, *client.Doc) {
	e.t.Helper()
	h, d, err := e.pc.Load(e.ctx, nsStreams, name)
	if err != nil || h.State != client.Live {
		e.t.Fatalf("load %s: %+v %v", name, h, err)
	}
	sd, err := streams.ParseDoc(d.Value)
	if err != nil {
		e.t.Fatal(err)
	}
	return sd, d
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitClosed waits for resource name to be closed and returns its document.
func (e *env) waitClosed(name string) *streams.Doc {
	e.t.Helper()
	var sd *streams.Doc
	waitFor(e.t, name+" to close", func() bool {
		sd, _ = e.doc(name)
		return sd.Closed != nil
	})
	return sd
}
